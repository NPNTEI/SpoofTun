#!/usr/bin/env python3
"""Bounded, read-only Direct ICMP host diagnostics. Never changes firewall or bans."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import stat
import subprocess
import tempfile
import time

LIMIT = 512 * 1024
SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
INTERFACE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')
UNIT = re.compile(r'ununknowntun-direct-icmp-[a-z0-9][a-z0-9-]{0,23}-(?:origin|egress)\.service')


def validate(peer_ip, interface, unit=None):
    address = ipaddress.IPv4Address(peer_ip)
    if str(address) != peer_ip or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError('A real peer IPv4 address is required.')
    if not INTERFACE.fullmatch(interface) or interface == 'lo':
        raise ValueError('A physical interface name is required.')
    if unit is not None and not UNIT.fullmatch(unit):
        raise ValueError('Unexpected Direct ICMP service name.')


class Runner:
    def __init__(self, budget=25):
        self.deadline = time.monotonic() + budget

    def __call__(self, command):
        executable = shutil.which(command[0], path=SAFE_PATH)
        if not executable:
            return {'state': 'not_installed', 'text': ''}
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return {'state': 'budget_exhausted', 'text': ''}
        def limit_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run([executable, *command[1:]], stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.STDOUT,
                                        env={'PATH': SAFE_PATH, 'LC_ALL': 'C'},
                                        timeout=min(3, remaining), preexec_fn=limit_output)
                output.seek(0)
                data = output.read(LIMIT)
                state = 'ok' if result.returncode == 0 else 'command_failed'
                if len(data) >= LIMIT:
                    state = 'output_truncated'
                return {'state': state, 'text': data.decode('utf-8', 'replace')}
            except subprocess.TimeoutExpired:
                return {'state': 'timeout', 'text': ''}
            except OSError:
                return {'state': 'command_unavailable', 'text': ''}


def iptables_findings(text, peer_ip):
    """Rules are potential blockers: jumps, order and earlier ACCEPTs remain unknown."""
    peer = ipaddress.IPv4Address(peer_ip)
    count, matching, broad, rate_limits, policy = 0, 0, 0, 0, []
    for line in text.splitlines():
        if re.fullmatch(r':(?:INPUT|OUTPUT) DROP \[[0-9:]+\]', line):
            policy.append(line.split()[0][1:])
        if not line.startswith('-A '):
            continue
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        count += 1
        if '!' in args:
            continue
        def option(name):
            try:
                return args[args.index(name) + 1]
            except (ValueError, IndexError):
                return None
        if option('-p') not in (None, 'all', 'icmp', '1'):
            continue
        if any(token in args for token in ('--limit', '--hashlimit', '--hashlimit-above', '--hashlimit-upto')):
            rate_limits += 1
        if option('-j') not in ('DROP', 'REJECT'):
            continue
        ranges = [option('-s'), option('-d')]
        constrained = [r for r in ranges if r and r != '0.0.0.0/0']
        if not constrained:
            broad += 1
        else:
            try:
                if any(peer in ipaddress.IPv4Network(r, strict=False) for r in constrained):
                    matching += 1
            except ValueError:
                pass
    return {'rules_seen': count, 'potential_peer_drop_rules': matching,
            'icmp_or_all_rate_limit_rules': rate_limits,
            'broad_icmp_or_all_drop_rules': broad, 'default_drop_chains': policy,
            'effective_verdict': 'unknown_without_chain_order_and_packet_observation'}


def nft_findings(text, peer_ip, tun_name=None):
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return {'effective_verdict': 'unknown_unreadable_ruleset'}
    if not isinstance(value, dict) or not isinstance(value.get('nftables'), list):
        return {'effective_verdict': 'unknown_unreadable_ruleset'}
    for entry in value['nftables']:
        if not isinstance(entry, dict):
            return {'effective_verdict': 'unknown_unreadable_ruleset'}
        if 'rule' in entry and (not isinstance(entry['rule'], dict) or not isinstance(entry['rule'].get('expr'), list)):
            return {'effective_verdict': 'unknown_unreadable_ruleset'}
        if 'table' in entry and not isinstance(entry['table'], dict):
            return {'effective_verdict': 'unknown_unreadable_ruleset'}
    rules = [entry.get('rule') for entry in value.get('nftables', [])
             if isinstance(entry, dict) and isinstance(entry.get('rule'), dict)]
    drops = peer_mentions = limits = 0
    for rule in rules:
        serialized = json.dumps(rule.get('expr', []), separators=(',', ':'))
        if '"limit":' in serialized:
            limits += 1
        if re.search(r'"(?:drop|reject)":', serialized):
            drops += 1
            if '"' + peer_ip + '"' in serialized:
                peer_mentions += 1
    details = {'rules_seen': len(rules), 'drop_or_reject_rules': drops, 'rate_limit_rules': limits,
            'drop_rules_with_exact_peer': peer_mentions,
            'effective_verdict': 'unknown_without_sets_chain_order_and_packet_observation'}
    if tun_name:
        table_name = 'gdt_icmp_' + hashlib.sha256(tun_name.encode()).hexdigest()[:16]
        details['expected_rotation_table'] = table_name
        details['matching_name_table_present'] = any(isinstance(entry, dict) and
            isinstance(entry.get('table'), dict) and entry['table'].get('family') == 'ip' and
            entry['table'].get('name') == table_name for entry in value.get('nftables', []))
        details['table_ownership'] = 'name_only_not_proven'
    return details


def runtime_counters(text):
    """Only copy allowlisted counters; never include arbitrary journal messages."""
    lines = [line for line in text.splitlines() if '[direct-icmp/stats]' in line]
    if not lines:
        return {'state': 'not_observed_in_recent_journal'}
    line = lines[-1]
    fields = ('Handshakes', 'Reconnects', 'Rekeys', 'Sent', 'Received', 'Dropped',
              'AuthFailures', 'Replays', 'Queued', 'FECPercent', 'FECRawSamples',
              'FECRawLost', 'FECResidualLost', 'FECRecovered', 'FECFeedbackExpired',
              'LocalSendFailures', 'WireSuccessful')
    values = {}
    for name in fields:
        match = re.search(r'\b' + name + r':([0-9]{1,20})\b', line)
        if match:
            values[name] = int(match[1])
    match = re.search(r'\bconnected=(true|false)\b', line)
    if match:
        values['connected'] = match[1] == 'true'
    for name in ('sent', 'received', 'rejected', 'dropped'):
        match = re.search(r'\b' + name + r'=([0-9]{1,20})\b', line)
        if match:
            values['wire_' + name] = int(match[1])
    return {'state': 'recent_snapshot_not_live_probe', 'counters': values}


def collect(peer_ip, interface, unit=None, runner=None, tun_name=None):
    validate(peer_ip, interface, unit)
    if tun_name is not None and (not isinstance(tun_name, str) or not INTERFACE.fullmatch(tun_name) or tun_name == 'lo'):
        raise ValueError('Invalid tunnel interface name.')
    runner = runner or Runner()
    report = {'schema': 'ununknowntun.direct-icmp.doctor.v1',
              'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'peer_ip': peer_ip, 'interface': interface, 'checks': [],
              'read_only': True, 'network_probe_sent': False,
              'path_delivery': 'not_tested'}
    checks = report['checks']
    def add(name, result, details=None):
        entry = {'name': name, 'state': result['state']}
        if details is not None:
            entry['details'] = details
        checks.append(entry)
    route = runner(['ip', '-j', '-4', 'route', 'get', peer_ip])
    details = None
    if route['state'] == 'ok':
        try:
            rows = json.loads(route['text'])
            if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
                raise ValueError('Expected a nonempty list of route objects.')
            for row in rows:
                device = row.get('dev')
                source = row.get('prefsrc', row.get('src'))
                if not isinstance(device, str) or not INTERFACE.fullmatch(device):
                    raise ValueError('Unrecognized route interface.')
                if source is not None and (not isinstance(source, str) or str(ipaddress.IPv4Address(source)) != source):
                    raise ValueError('Unrecognized route source.')
            details = [{'interface': r.get('dev'), 'preferred_source': r.get('prefsrc', r.get('src')),
                        'selected_interface_matches': r.get('dev') == interface} for r in rows[:4]]
        except (ValueError, TypeError, AttributeError, RecursionError):
            route['state'] = 'unreadable'
    add('peer_route', route, details)
    for command in ('iptables-save', 'ip6tables-save'):
        result = runner([command])
        detail = iptables_findings(result['text'], peer_ip) if command == 'iptables-save' and result['state'] == 'ok' else None
        add(command, result, detail)
    result = runner(['nft', '-j', 'list', 'ruleset'])
    add('nftables', result, nft_findings(result['text'], peer_ip, tun_name) if result['state'] == 'ok' else None)
    result = runner(['ufw', 'status'])
    add('ufw', result, {'active': bool(re.search(r'^Status: active$', result['text'], re.M))} if result['state'] == 'ok' else None)
    result = runner(['firewall-cmd', '--state'])
    add('firewalld', result, {'active': result['text'].strip() == 'running'} if result['state'] == 'ok' else None)
    result = runner(['fail2ban-client', 'status'])
    jail_match = re.search(r'Jail list:\s*([^\n]*)', result['text'])
    jails = [s.strip() for s in jail_match.group(1).split(',')] if jail_match else []
    jails = [s for s in jails if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', s)]
    details = {'jails_reported': len(jails), 'jails_checked': 0, 'peer_banned_in': [], 'unknown_jails': 0}
    add('fail2ban', result, details)
    for jail in jails[:16]:
        ban = runner(['fail2ban-client', 'get', jail, 'banip'])
        if ban['state'] != 'ok':
            details['unknown_jails'] += 1
            continue
        details['jails_checked'] += 1
        if peer_ip in re.findall(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])', ban['text']):
            details['peer_banned_in'].append(jail)
    details['unknown_jails'] += max(0, len(jails) - 16)
    if result['state'] == 'ok' and not jail_match:
        details['status_parse'] = 'unknown'
    values = {}
    for name in ('net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.' + interface + '.rp_filter',
                 'net.ipv4.icmp_echo_ignore_all', 'net.ipv4.icmp_ratelimit'):
        result = runner(['sysctl', '-n', name])
        values[name] = int(result['text'].strip()) if result['state'] == 'ok' and re.fullmatch(r'[0-9]{1,20}', result['text'].strip()) else ('unreadable' if result['state'] == 'ok' else result['state'])
    add('kernel_icmp_settings', {'state': 'observed'}, values)
    if unit:
        result = runner(['systemctl', 'show', unit, '--no-pager', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result', '-p', 'NRestarts'])
        values = {}
        for line in result['text'].splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                if key in ('ActiveState', 'SubState', 'Result', 'NRestarts') and re.fullmatch(r'[a-zA-Z0-9_-]{0,40}', value):
                    values[key] = value
        add('service', result, values)
        result = runner(['journalctl', '-u', unit, '-n', '80', '--no-pager', '-o', 'cat'])
        categories = {name: len(re.findall(pattern, result['text'], re.I)) for name, pattern in {
            'timeout': r'timeout|timed out|deadline exceeded',
            'permission': r'permission denied|operation not permitted',
            'route_conflict': r'route.*(?:overlap|conflict|exists)',
            'interface_conflict': r'(?:TUN|interface).*already exists',
            'authentication': r'authentication failed|auth_failures',
            'unreachable': r'unreachable|no route to host',
            'nft_failure': r'nft.*(?:failed|error|unsupported)'
        }.items()}
        add('recent_service_events', result, categories)
        add('recent_tunnel_counters', result, runtime_counters(result['text']) if result['state'] == 'ok' else None)
    report['interpretation'] = ('Matching firewall rules are potential blockers, not proof of the final verdict. '
                                'An observed Fail2ban entry confirms that jail lists the peer; the chain must still apply to ICMP. '
                                'No rules, bans, routes, sysctls or services were changed. '
                                'A rotation table with the expected name is normal while its service runs; an inactive service with that table needs ownership review, not a firewall flush. '
                                'A local check cannot prove delivery through the provider network.')
    return report


def display(report):
    print('Direct ICMP host checks (read-only)')
    for item in report['checks']:
        print('  ' + item['name'] + ': ' + item['state'])
        if item.get('details') is not None:
            print('    ' + json.dumps(item['details'], sort_keys=True))
    print(report['interpretation'])


def endpoint_identity(folder):
    folder = Path(folder)
    path = folder / 'direct-icmp.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
        raise ValueError('Expected a bounded regular endpoint configuration.')
    try:
        config = json.loads(path.read_text())
    except (ValueError, RecursionError):
        raise ValueError('Unreadable endpoint configuration.') from None
    if not isinstance(config, dict) or not isinstance(config.get('peer_ip'), str) or not isinstance(config.get('interface'), str):
        raise ValueError('Expected an endpoint object with peer_ip and interface strings.')
    validate(config['peer_ip'], config['interface'])
    match = re.fullmatch(r'/etc/ununknowntun-direct-icmp/([a-z0-9][a-z0-9-]{0,23})/(origin|egress)', str(folder))
    unit = 'ununknowntun-direct-icmp-' + match[1] + '-' + match[2] + '.service' if match else None
    return config['peer_ip'], config['interface'], unit, config.get('tun_name')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint')
    parser.add_argument('--peer-ip')
    parser.add_argument('--interface')
    parser.add_argument('--unit')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if platform.system() != 'Linux':
            raise ValueError('Host diagnostics require Linux; offline tests can run elsewhere.')
        if args.endpoint:
            if args.peer_ip or args.interface or args.unit:
                raise ValueError('Use either --endpoint or explicit peer/interface arguments.')
            peer, interface, unit, tun_name = endpoint_identity(args.endpoint)
        else:
            peer, interface, unit = args.peer_ip, args.interface, args.unit
            tun_name = None
        report = collect(peer, interface, unit, tun_name=tun_name)
        print(json.dumps(report, indent=2)) if args.json else display(report)
        return 0
    except (ValueError, TypeError, OSError, KeyError) as error:
        print('DIRECT ICMP DOCTOR ERROR: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
