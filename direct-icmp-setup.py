#!/usr/bin/env python3
"""Interactive Direct ICMP L3 setup with private code-based pairing, no file transfer."""
import argparse
import base64
import getpass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
VERSION = '3.7.0-preview.11'
PREFIX = 'GDTICMP3'
CODE_LIMIT = 16384
PAYLOAD_LIMIT = 32768


def load(name):
    loader = importlib.util.spec_from_file_location('gdt_setup_' + name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    return module


pair = load('direct-icmp-pair')
manager = load('direct-icmp-manage')
doctor = load('direct-icmp-doctor')
require = pair.require


def encode_code(spec, key, now=None):
    now = int(time.time()) if now is None else now
    spec = pair.validate_spec(spec)
    require(type(key) is bytes and re.fullmatch(rb'[a-f0-9]{64}\n', key) and key != b'0' * 64 + b'\n', 'Invalid pairing key.')
    data = pair.base.json_bytes({'format': 1, 'version': VERSION, 'issued_at': now,
                                'expires_at': now + 86400, 'spec': spec, 'key': key.decode().strip()})
    compressed = zlib.compress(data, 9)
    payload = base64.urlsafe_b64encode(compressed).decode().rstrip('=')
    # Copy-error detection, not an independent signature: the entire code is a secret bearer credential.
    code = PREFIX + '.' + payload + '.' + hashlib.sha256(compressed).hexdigest()
    require(len(code) <= CODE_LIMIT, 'Pairing code exceeds the size limit.')
    return code


def decode_code(code, trusted_hashes, now=None):
    now = int(time.time()) if now is None else now
    require(type(code) is str and len(code) <= CODE_LIMIT, 'Pairing code is too long.')
    require(re.fullmatch(r'GDTICMP3\.[A-Za-z0-9_-]+\.[a-f0-9]{64}', code), 'Invalid pairing code format.')
    _, encoded, checksum = code.split('.')
    try:
        compressed = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        require(secrets.compare_digest(hashlib.sha256(compressed).hexdigest(), checksum), 'Pairing code checksum failed; copy it again.')
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, PAYLOAD_LIMIT + 1)
        require(len(raw) <= PAYLOAD_LIMIT and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                'Invalid or oversized pairing payload.')
        value = pair.base.strict_json(raw)
    except (ValueError, zlib.error):
        raise pair.base.PairError('Invalid pairing code payload.') from None
    pair.base.fields(value, {'format', 'version', 'issued_at', 'expires_at', 'spec', 'key'}, set(), 'Pairing code')
    require(type(value['format']) is int and value['format'] == 1 and value['version'] == VERSION,
            'Both servers must use this exact release.')
    require(type(value['issued_at']) is int and type(value['expires_at']) is int and
            value['expires_at'] - value['issued_at'] == 86400 and value['issued_at'] <= now + 300 and now <= value['expires_at'],
            'Pairing code expired or clocks disagree; generate a fresh code.')
    require(type(value['key']) is str and re.fullmatch(r'[a-f0-9]{64}', value['key']) and value['key'] != '0' * 64, 'Invalid pairing key.')
    spec = pair.validate_spec(value['spec'])
    require(spec['binary_sha256'] == trusted_hashes, 'Pairing release hashes differ from this trusted local installer.')
    return spec, (value['key'] + '\n').encode()


def command_json(args):
    executable = shutil.which(args[0], path=doctor.SAFE_PATH)
    require(executable is not None, 'Required command is missing: ' + args[0])
    result = subprocess.run([executable, *args[1:]], capture_output=True, text=True,
                            timeout=5, env={'PATH': doctor.SAFE_PATH, 'LC_ALL': 'C'})
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, 'Could not inspect local networking.')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise pair.base.PairError('Invalid network inspection response.') from None


def discover_local(peer_ip, expected_ip=None):
    peer_ip = pair.base.ipv4(peer_ip, 'Peer IPv4')
    route = command_json(['ip', '-j', '-4', 'route', 'get', peer_ip])
    require(type(route) is list and len(route) == 1, 'A single IPv4 route to the peer is required.')
    interface = route[0].get('dev')
    source = route[0].get('prefsrc', route[0].get('src'))
    require(type(interface) is str and pair.base.INTERFACE.fullmatch(interface) and interface != 'lo',
            'Cannot determine the physical interface.')
    source = pair.base.ipv4(source, 'Detected local IPv4')
    addresses = command_json(['ip', '-j', '-4', 'address', 'show', 'dev', interface])
    assigned = {a.get('local') for row in addresses for a in row.get('addr_info', []) if a.get('family') == 'inet'}
    require(source in assigned, 'The selected source IPv4 is not assigned to the selected interface.')
    if expected_ip:
        require(expected_ip == source, 'This code belongs to a different local IPv4. No service was installed.')
    require(source != peer_ip, 'Local and peer IPv4 addresses must differ.')
    return {'real_ip': source, 'interface': interface}


def dependencies(rotation=True):
    require(platform.system() == 'Linux' and os.geteuid() == 0, 'Run this setup as root on Linux.')
    required = ['ip', 'systemctl'] + (['nft'] if rotation else [])
    missing = [name for name in required if not shutil.which(name, path=doctor.SAFE_PATH)]
    require(not missing, 'Missing prerequisites: ' + ', '.join(missing) + '. Run the complete UNUNKNOWNTUN installer to install them automatically.')
    require(Path('/dev/net/tun').exists(), 'Linux /dev/net/tun is unavailable on this server.')


def private_pool(prompt, default):
    value = pair.base.prompt(prompt, default)
    try:
        net = ipaddress.IPv4Network(value, strict=True)
        inner = str(next(net.hosts()))
    except (ValueError, StopIteration):
        raise pair.base.PairError('Enter a canonical private /26 through /30 range.') from None
    return pair.pool_cidr(value, inner, prompt), inner


def foreign_spec(hashes):
    print('ICMP L3 setup - outside server')
    print('[1/4] Identify the two servers')
    peer_ip = pair.base.ipv4(pair.base.prompt('Iran server public IPv4'), 'Iran IPv4')
    local = discover_local(peer_ip)
    print('Detected this server: ' + local['real_ip'] + ' on ' + local['interface'])
    name = pair.base.prompt('Tunnel name', 'icmp1')
    print('[2/4] Private address pools')
    iran_pool, iran_inner = private_pool('Iran private range', '10.79.1.0/28')
    outside_pool, outside_inner = private_pool('Outside private range', '10.79.2.0/28')
    print('New connections rotate through the private addresses; each connection keeps its address until it ends.')
    print('These private ranges do not change either public server IP.')
    raw = pair.base.prompt('Inner MTU (576..1400)', '1200')
    require(re.fullmatch(r'[0-9]{3,4}', raw), 'MTU must be an integer.')
    fec = pair.base.prompt('Packet repair (adaptive, fixed, off)', 'adaptive').lower()
    forwards = pair.prompt_forwards(default='yes')
    return pair.validate_spec({'pair_id': name, 'binary_sha256': hashes,
                               'origin': {'interface': 'eth0', 'real_ip': peer_ip, 'inner_ip': iran_inner, 'pool_cidr': iran_pool},
                               'egress': {**local, 'inner_ip': outside_inner, 'pool_cidr': outside_pool},
                               'source_rotation': 'round-robin', 'mtu': int(raw), 'fec_mode': fec, 'forwards': forwards})


def relay_available(port, protocols):
    """Short loopback binds detect wildcard service conflicts without opening a public port."""
    sockets = []
    try:
        for protocol in sorted(protocols):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
            sockets.append(sock)
            sock.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False
    finally:
        for sock in sockets:
            sock.close()


def select_available_relays(spec, available=None):
    """Finalize relay choices before installing the outside endpoint and encoding its pairing code."""
    available = relay_available if available is None else available
    spec = pair.validate_spec(spec)
    mappings = spec.get('forwards', [])
    used = {rule['foreign_port'] for rule in mappings}
    selected = {}
    for rule in mappings:
        service = rule['foreign_port']
        if service in selected:
            continue
        protocols = {protocol for item in mappings if item['foreign_port'] == service
                     for protocol in (('tcp', 'udp') if item['protocol'] == 'both' else (item['protocol'],))}
        first = rule['relay_port']
        candidates = [first] + [40000 + (first - 40000 + offset) % 20000 for offset in range(1, 129)]
        relay = next((port for port in candidates if port not in used and available(port, protocols)), None)
        require(relay is not None, 'Cannot reserve an unused private relay port; existing services were not changed.')
        selected[service] = relay
        used.add(relay)
    for rule in mappings:
        rule['relay_port'] = selected[rule['foreign_port']]
    return pair.validate_spec(spec)


def start_installed(folder, metadata, contents, binary_path):
    """Only roll back an endpoint created successfully by this call; never touch a pre-existing service."""
    installed = False
    try:
        manager.execute('install', folder, metadata, contents, binary_path)
        installed = True
        manager.execute('start', folder, metadata, contents)
        time.sleep(1)
        result = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', metadata['unit_name']], timeout=10)
        require(result.returncode == 0, 'The new service did not become active.')
        state = subprocess.run(['/usr/bin/systemctl', 'show', metadata['unit_name'], '--property=NRestarts', '--value'],
                               capture_output=True, text=True, timeout=10)
        require(state.returncode == 0 and state.stdout.strip() == '0', 'The new service restarted during setup; inspect its diagnostics.')
    except BaseException:
        if installed:
            try:
                manager.execute('uninstall', folder, metadata, contents)
                print('The newly created endpoint was rolled back; existing tunnels were not changed.', file=sys.stderr)
            except Exception:
                print('Rollback of the newly created endpoint could not complete. Inspect: ' + metadata['unit_name'], file=sys.stderr)
        raise


def setup(role, spec, key, binary_path):
    local = spec[role]
    peer = spec['origin' if role == 'egress' else 'egress']
    dependencies(spec.get('source_rotation') == 'round-robin')
    actual = discover_local(peer['real_ip'], local['real_ip'])
    # The peer's interface is host-local and not part of its wire identity.
    spec = json.loads(json.dumps(spec))
    spec[role].update(actual)
    spec = pair.validate_spec(spec)
    if role == 'egress':
        spec = select_available_relays(spec)
    print(pair.forwarding_summary(spec))
    print('[3/4] Check host routing, firewall and Fail2ban')
    doctor.display(doctor.collect(peer['real_ip'], actual['interface']))
    with tempfile.TemporaryDirectory(prefix='ununknowntun-icmp-setup-', dir='/run') as temporary:
        generated = Path(temporary) / 'pair'
        pair.generate(spec, str(generated), key=key)
        pair.check_pair(str(generated))
        folder = generated / role
        metadata, contents = manager.load_bundle(folder)
        print('[4/4] Install and start this endpoint')
        start_installed(folder, metadata, contents, binary_path)
    print('ACTIVE: ' + pair.unit_name(spec, role))
    print('Local private range: ' + local['pool_cidr'] + '; peer private range: ' + peer['pool_cidr'])
    print('Status: python3 -I ' + pair.home(spec, role) + '/manage.py status')
    print('Timeout checks: python3 -I ' + pair.home(spec, role) + '/manage.py doctor')
    if spec.get('forwards'):
        print('The outside application must listen on the selected localhost service ports. No separate socat service is needed.')
    print('Service activation is not proof that the provider delivers ICMP. Validate the paired path after both endpoints start.')
    return spec


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('foreign', 'iran'))
    parser.add_argument('--binary', required=True, help='Matching release binary extracted by the installer')
    parser.add_argument('--binary-manifest', default=str(HERE / 'direct-icmp-binaries.json'))
    args = parser.parse_args(argv)
    try:
        os.umask(0o077)
        dependencies()
        hashes = pair.binary_manifest(args.binary_manifest)
        if args.role == 'foreign':
            spec = foreign_spec(hashes)
            key = (secrets.token_hex(32) + '\n').encode()
            spec = setup('egress', spec, key, args.binary)
            print('\nPRIVATE PAIRING CODE - valid for 24 hours; contains the tunnel secret.')
            print('On Iran, open the same installer, choose ICMP L3 > Iran, and paste this code when asked.')
            print(encode_code(spec, key))
            print('No file transfer is needed. Do not publish this code.')
        else:
            print('ICMP L3 setup - Iran server')
            code = getpass.getpass('Paste the private pairing code from the outside server (hidden): ').strip()
            spec, key = decode_code(code, hashes)
            del code
            setup('origin', spec, key, args.binary)
            print('Both endpoints are now configured. The first authenticated handshake will establish the tunnel.')
        return 0
    except (pair.base.PairError, manager.ManageError, ValueError, OSError, EOFError, subprocess.SubprocessError) as error:
        print('DIRECT ICMP SETUP ERROR: ' + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Setup cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
