#!/usr/bin/env python3
"""Create one matched, private Direct ICMP IPv4 pair; never deploy or activate it."""
import argparse
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import secrets
import sys

sys.dont_write_bytecode = True
_loader = importlib.util.spec_from_file_location("gdt_direct_pair_base", Path(__file__).with_name("spoof-pair.py"))
base = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(base)
require = base.require
VERSION = "3.7.0-preview.11"
BINARY = "/opt/ununknowntun-direct-icmp/" + VERSION + "/ununknowntun"
FEC_FIELDS = ("fec_mode", "fec_percent", "fec_max_percent", "fec_block_ms")


def validate_forwards(values, pair_id):
    require(type(values) is list and len(values) <= 32, "forwards must contain at most 32 mappings.")
    result, listeners, service_ports, relays = [], set(), set(), {}
    for item in values:
        base.fields(item, {"iran_port", "foreign_port", "protocol"}, {"relay_port"}, "Forward")
        rule = {key: base.integer(item[key], key, 1024, 65535) for key in ("iran_port", "foreign_port")}
        protocol = item["protocol"]
        require(type(protocol) is str and protocol in ("tcp", "udp", "both"), "Forward protocol must be tcp, udp or both.")
        rule["protocol"] = protocol
        for transport in (("tcp", "udp") if protocol == "both" else (protocol,)):
            listener = (transport, rule["iran_port"])
            require(listener not in listeners, "Duplicate/conflicting Iran port and protocol.")
            listeners.add(listener)
        require(len(listeners) <= 32, "At most 32 TCP/UDP forwarding rules are supported (both counts as two).")
        service_ports.add(rule["foreign_port"])
        if "relay_port" in item:
            relay = base.integer(item["relay_port"], "relay_port", 1024, 65535)
            old = relays.get(rule["foreign_port"])
            require(old is None or old == relay, "Mappings to the same foreign port must share one private relay port.")
            relays[rule["foreign_port"]] = relay
        result.append(rule)
    require(not service_ports.intersection(relays.values()), "A private relay port must differ from all foreign service ports.")
    require(len(set(relays.values())) == len(relays), "Private relay ports for different services must differ.")
    used = service_ports | set(relays.values())
    for port in sorted(service_ports):
        if port in relays:
            continue
        seed = int(hashlib.sha256((pair_id + ":" + str(port)).encode()).hexdigest()[:8], 16)
        relay = next((40000 + (seed + offset) % 20000 for offset in range(20000)
                      if 40000 + (seed + offset) % 20000 not in used), None)
        require(relay is not None, "No unused private relay port available.")
        relays[port] = relay
        used.add(relay)
    for rule in result:
        rule["relay_port"] = relays[rule["foreign_port"]]
    return result


def forwarding_summary(spec):
    rules = spec.get("forwards", [])
    if not rules:
        return "Port forwarding: disabled (private L3 tunnel only)."
    return "Port forwarding (built in; no socat needed):\n" + "\n".join(
        "  " + r["protocol"].upper() + " Iran :" + str(r["iran_port"]) + " -> outside localhost:" +
        str(r["foreign_port"]) + " (private relay :" + str(r["relay_port"]) + ")" for r in rules)


def prompt_forwards(default="yes"):
    enabled = base.prompt("Forward application ports through this tunnel? (yes/no)", default).lower()
    require(enabled in ("yes", "no", "y", "n"), "Choose yes or no.")
    if enabled in ("no", "n"):
        return []
    result = []
    while True:
        rule = {}
        for key, label, default_port in (("iran_port", "Iran client entry port", 12055),
                                         ("foreign_port", "Outside application/inbound port", 18082)):
            raw = base.prompt(label + " (1024..65535)", str(default_port))
            require(re.fullmatch(r"[0-9]{1,5}", raw), label + " must be an integer.")
            rule[key] = base.integer(int(raw), label, 1024, 65535)
        rule["protocol"] = base.prompt("Forward protocol (tcp, udp, both)", "both").lower()
        result.append(rule)
        validate_forwards(result, "wizard")
        more = base.prompt("Add another port mapping? (yes/no)", "no").lower()
        require(more in ("yes", "no", "y", "n"), "Choose yes or no.")
        if more in ("no", "n"):
            return result


def cidrs(value, label):
    require(type(value) is list and len(value) <= 16, label + " must contain at most 16 private IPv4 prefixes.")
    result = []
    for item in value:
        try:
            network = ipaddress.IPv4Network(item, strict=True)
        except (ValueError, TypeError):
            raise base.PairError(label + " requires canonical IPv4 CIDRs.") from None
        require(type(item) is str and str(network) == item and any(network.subnet_of(n) for n in base.PRIVATE_NETS),
                label + " accepts RFC1918 prefixes only; no default route.")
        require(not any(network.overlaps(old) for old in result), label + " has duplicate/overlapping ranges.")
        result.append(network)
    return [str(n) for n in result]


def pool_cidr(value, inner_ip, label):
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError):
        raise base.PairError(label + " requires a canonical private IPv4 CIDR.") from None
    require(type(value) is str and str(network) == value and 26 <= network.prefixlen <= 30 and
            any(network.subnet_of(n) for n in base.PRIVATE_NETS),
            label + " must be an RFC1918 /26 through /30 range (2..62 usable addresses).")
    require(ipaddress.IPv4Address(inner_ip) in network and
            inner_ip not in (str(network.network_address), str(network.broadcast_address)),
            label + " must contain its inner IP as a usable host.")
    return str(network)


def validate_spec(value):
    base.fields(value, {"pair_id", "origin", "egress", "binary_sha256"},
                {"mtu", "poll_ms", "timeout_seconds", "rekey_seconds", "source_rotation", "forwards", "forward_idle_seconds", *FEC_FIELDS}, "Spec")
    require(type(value["pair_id"]) is str and base.PAIR_ID.fullmatch(value["pair_id"]), "Pair name must be 1..24 lowercase letters/digits/dashes.")
    hashes = value["binary_sha256"]
    require(type(hashes) is dict and set(hashes) == {"amd64", "arm64"} and
            all(type(v) is str and re.fullmatch(r"[a-f0-9]{64}", v) for v in hashes.values()),
            "The matching release's amd64/arm64 SHA256 manifest is required.")
    spec = {"pair_id": value["pair_id"], "binary_sha256": dict(hashes)}
    if "forwards" in value:
        spec["forwards"] = validate_forwards(value["forwards"], value["pair_id"])
    if spec.get("forwards") or "forward_idle_seconds" in value:
        spec["forward_idle_seconds"] = base.integer(value.get("forward_idle_seconds", 180), "forward_idle_seconds", 10, 3600)
    for key, default, lo, hi in (("mtu", 1200, 576, 1400), ("poll_ms", 20, 5, 1000),
                                ("timeout_seconds", 15, 5, 300), ("rekey_seconds", 3600, 60, 86400)):
        spec[key] = base.integer(value.get(key, default), key, lo, hi)
    require(spec["rekey_seconds"] > 2 * spec["timeout_seconds"], "rekey_seconds must exceed twice timeout_seconds.")
    spec["fec_mode"] = value.get("fec_mode", "adaptive")
    require(type(spec["fec_mode"]) is str and spec["fec_mode"] in ("off", "fixed", "adaptive"),
            "fec_mode must be off, fixed or adaptive.")
    for key, default, lo, hi in (("fec_percent", 20, 0, 50), ("fec_max_percent", 25, 5, 50),
                                ("fec_block_ms", 20, 5, 100)):
        spec[key] = base.integer(value.get(key, default), key, lo, hi)
    require(spec["fec_percent"] <= spec["fec_max_percent"], "fec_percent must not exceed fec_max_percent.")
    suffix = hashlib.sha256(spec["pair_id"].encode()).hexdigest()[:8]
    for role in ("origin", "egress"):
        peer = value[role]
        base.fields(peer, {"interface", "real_ip", "inner_ip"}, {"tun_name", "cidrs", "pool_cidr"}, role)
        peer = dict(peer)
        peer.setdefault("tun_name", "gdl" + suffix + role[0])
        for key in ("interface", "tun_name"):
            require(type(peer[key]) is str and base.INTERFACE.fullmatch(peer[key]) and peer[key] != "lo", role + "." + key + " is invalid.")
        require(peer["interface"] != peer["tun_name"], "Physical and virtual interfaces must differ.")
        peer["real_ip"] = base.ipv4(peer["real_ip"], role + ".real_ip")
        peer["inner_ip"] = base.ipv4(peer["inner_ip"], role + ".inner_ip", inner=True)
        peer["cidrs"] = cidrs(peer.get("cidrs", []), role + ".cidrs")
        if "pool_cidr" in peer:
            peer["pool_cidr"] = pool_cidr(peer["pool_cidr"], peer["inner_ip"], role + ".pool_cidr")
        spec[role] = peer
    origin, egress = spec["origin"], spec["egress"]
    require(origin["real_ip"] != egress["real_ip"] and origin["inner_ip"] != egress["inner_ip"], "The two outer and inner peer addresses must differ.")
    outer = [ipaddress.IPv4Address(p["real_ip"]) for p in (origin, egress)]
    nets = {role: [ipaddress.IPv4Network(spec[role]["inner_ip"] + "/32")] +
                  [ipaddress.IPv4Network(n) for n in spec[role]["cidrs"]] for role in ("origin", "egress")}
    require(not any(a.overlaps(b) for a in nets["origin"] for b in nets["egress"]), "Local and peer inner ranges overlap.")
    require(not any(ip in net for ip in outer for group in nets.values() for net in group), "Inner ranges must not capture either outer peer.")
    rotation = value.get("source_rotation", "off")
    require(type(rotation) is str and rotation in ("off", "round-robin"), "source_rotation must be off or round-robin.")
    pools = [p.get("pool_cidr") for p in (origin, egress)]
    require(all(pools) or not any(pools), "Both endpoints must provide a pool_cidr together.")
    require(rotation == "off" or all(pools), "Round-robin requires a private pool on both endpoints.")
    if all(pools):
        ranges = [ipaddress.IPv4Network(p) for p in pools]
        require(not ranges[0].overlaps(ranges[1]), "The two private pools overlap.")
        routed = [ipaddress.IPv4Network(n) for p in (origin, egress) for n in p["cidrs"]]
        require(not any(a.overlaps(b) for a in ranges for b in routed), "Pool ranges overlap routed CIDRs.")
        require(not any(ip in net for ip in outer for net in ranges), "Private pools capture an outer peer.")
        spec["source_rotation"] = rotation
    elif "source_rotation" in value:
        spec["source_rotation"] = rotation
    return spec


def home(spec, role):
    return "/etc/ununknowntun-direct-icmp/" + spec["pair_id"] + "/" + role


def unit_name(spec, role):
    return "ununknowntun-direct-icmp-" + spec["pair_id"] + "-" + role + ".service"


def endpoint_config(spec, role):
    local, peer = spec[role], spec["egress" if role == "origin" else "origin"]
    result = dict(role=role, interface=local["interface"], tun_name=local["tun_name"], local_ip=local["real_ip"],
                peer_ip=peer["real_ip"], inner_local_ip=local["inner_ip"], inner_peer_ip=peer["inner_ip"],
                key_file=home(spec, role) + "/icmp.key", local_cidrs=local["cidrs"], peer_cidrs=peer["cidrs"],
                **{k: spec[k] for k in ("mtu", "poll_ms", "timeout_seconds", "rekey_seconds", *FEC_FIELDS)})
    if "source_rotation" in spec:
        result["source_rotation"] = spec["source_rotation"]
    if local.get("pool_cidr"):
        result.update(local_pool_cidr=local["pool_cidr"], peer_pool_cidr=peer["pool_cidr"])
    if "forward_idle_seconds" in spec:
        result["forward_idle_seconds"] = spec["forward_idle_seconds"]
    if "forwards" in spec:
        rules, seen = [], set()
        for mapping in spec["forwards"]:
            relay = spec["egress"]["inner_ip"] + ":" + str(mapping["relay_port"])
            listen = "0.0.0.0:" + str(mapping["iran_port"]) if role == "origin" else relay
            target = relay if role == "origin" else "127.0.0.1:" + str(mapping["foreign_port"])
            for protocol in (("tcp", "udp") if mapping["protocol"] == "both" else (mapping["protocol"],)):
                if (protocol, listen) not in seen:
                    rules.append(dict(protocol=protocol, listen=listen, target=target))
                    seen.add((protocol, listen))
        result["port_forwards"] = rules
    return result


def service(spec, role):
    return ("[Unit]\nDescription=UNUNKNOWNTUN Direct ICMP L3 " + spec["pair_id"] + " " + role + "\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\n"
            "UMask=0077\nExecStart=" + BINARY + " -direct-icmp-config " + home(spec, role) + "/direct-icmp.json\n"
            "Restart=on-failure\nRestartSec=3s\nTimeoutStopSec=15s\n"
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n"
            "NoNewPrivileges=yes\nRestrictAddressFamilies=AF_INET AF_NETLINK\nPrivateDevices=no\n"
            "DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\nProtectSystem=strict\nProtectHome=yes\n"
            "RuntimeDirectory=ununknowntun-icmp-rr\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n"
            "ReadWritePaths=/run/ununknowntun-icmp-rr\n"
            "ProtectKernelTunables=yes\nProtectControlGroups=yes\nProtectKernelModules=yes\n"
            "RestrictSUIDSGID=yes\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n").encode()


def readme(spec):
    return ("UNUNKNOWNTUN " + VERSION + " DIRECT ICMP — PRIVATE MATCHED PAIR\n"
            "origin = Iran (initiator); egress = outside (responder). This is IPv4 L3 over encrypted ICMP Echo.\n"
            "No TLS certificate, WebSocket, ECH or Cloudflare DNS proxy. Not Backpack wire-compatible.\n"
            + forwarding_summary(spec) + "\n"
            "FEC mode: " + spec["fec_mode"] + "; repair cap: " + str(spec["fec_max_percent"]) +
            "%; block deadline: " + str(spec["fec_block_ms"]) + " ms.\n"
            "Adaptive FEC adjusts repair separately for each direction; fixed uses fec_percent; off disables repairs.\n"
            "Repairs consume extra traffic, including return-path poll requests. FEC cannot fix a fully blocked ICMP path.\n"
            "FEC requires preview.8 or newer compatible peers on BOTH sides. A preview.7 peer requires off mode.\n"
            "Easy setup: use ICMP L3 > Foreign, then paste its private pairing code into ICMP L3 > Iran.\n"
            "The following folder-transfer procedure is the optional advanced offline method.\n"
            "Send ONLY origin/ to Iran and ONLY egress/ outside through your private file transfer.\n"
            "Both endpoint folders contain the same secret; do not publish them. Generate once, not separately per server.\n"
            "On each host, use the matching trusted release ELF binary and run inside its endpoint folder:\n"
            "  sudo python3 -I manage.py install --binary /absolute/path/to/ununknowntun-linux-ARCH\n"
            "This checks the release SHA256, architecture and version and installs without starting.\n"
            "Start outside first, then Iran:\n  sudo python3 -I manage.py start\n"
            "Status/config/restart/logs/host diagnostics/stop:\n  sudo python3 -I manage.py status\n"
            "  sudo python3 -I manage.py info\n  sudo python3 -I manage.py restart\n  sudo python3 -I manage.py logs\n"
            "  sudo python3 -I manage.py doctor\n"
            "  sudo python3 -I manage.py stop\n"
            "Uninstall this endpoint only (retains shared versioned binary):\n  sudo python3 -I manage.py uninstall\n"
            "From Iran test: ping -c 4 " + spec["egress"]["inner_ip"] + "\n"
            "From outside test: ping -c 4 " + spec["origin"]["inner_ip"] + "\n"
            "Install does not change a default route or start the tunnel. Start creates only the named TUN and configured private routes.\n"
            "When configured, private source pools use a dedicated nftables SNAT table; new connections rotate, existing connections keep their address.\n"
            "No host-wide firewall flush, Fail2ban unban, default route change or forwarding sysctl change is performed.\n"
            "Linux iproute2, systemd, /dev/net/tun and real assigned outer IPv4 are required.\n"
            "Round-robin pools additionally require nftables; the complete easy installer checks required packages.\n"
            "A healthy plain public ping does not prove ICMP tunnel throughput. Validate actual TCP and UDP payload.\n"
            "IP endpoints remain visible; no IP spoofing. IPv6 is not implemented in this mode.\n"
            "Use the Direct ICMP setup wizard for code-based pairing without manual file transfer.\n").encode()


def manager_source():
    return Path(__file__).with_name("direct-icmp-manage.py").read_bytes()


def role_files(spec, role, key):
    entries = {"direct-icmp.json": base.json_bytes(endpoint_config(spec, role)), "icmp.key": key,
               unit_name(spec, role): service(spec, role), "manage.py": manager_source(),
               "doctor.py": Path(__file__).with_name("direct-icmp-doctor.py").read_bytes()}
    metadata = {"format": 1, "version": VERSION, "pair_id": spec["pair_id"], "role": role,
                "install_dir": home(spec, role), "binary_path": BINARY, "unit_name": unit_name(spec, role),
                "binary_sha256": spec["binary_sha256"], "files": {k: hashlib.sha256(v).hexdigest() for k, v in entries.items()}}
    entries["endpoint.json"] = base.json_bytes(metadata)
    return entries


def generate(value, output, key=None):
    spec = validate_spec(value)
    path = Path(base.normalize_local_path(output, "output directory"))
    with base.directory(str(path.parent)) as parent:
        require(path.name not in os.listdir(parent), "Output exists; nothing was overwritten.")
        key = (secrets.token_hex(32) + "\n").encode() if key is None else key
        require(type(key) is bytes and re.fullmatch(rb"[a-f0-9]{64}\n", key) and key != b"0" * 64 + b"\n", "Invalid pairing key format.")
        root = base.create_directory(parent, path.name)
        try:
            base.write_private(root, "pair.json", base.json_bytes(spec))
            base.write_private(root, "README.txt", readme(spec))
            for role in ("origin", "egress"):
                endpoint = base.create_directory(root, role)
                try:
                    for name, data in role_files(spec, role, key).items():
                        base.write_private(endpoint, name, data)
                finally:
                    os.close(endpoint)
        finally:
            os.close(root)
    return spec


def check_pair(output):
    path = base.normalize_local_path(output, "bundle")
    peers = []
    with base.directory(path, private=True) as root:
        require(set(os.listdir(root)) == {"pair.json", "README.txt", "origin", "egress"}, "Unexpected or missing pair files.")
        spec = validate_spec(base.strict_json(base.read_file(root, "pair.json")))
        require(base.read_file(root, "README.txt") == readme(spec), "Pair instructions differ.")
        for role in ("origin", "egress"):
            with base.directory(path + "/" + role, private=True) as endpoint:
                key = base.read_file(endpoint, "icmp.key")
                require(re.fullmatch(rb"[a-f0-9]{64}\n", key), "Invalid key format.")
                expected = role_files(spec, role, key)
                require(set(os.listdir(endpoint)) == set(expected), "Unexpected endpoint files.")
                for name, data in expected.items():
                    require(base.read_file(endpoint, name) == data, "Endpoint file mismatch: " + name)
                peers.append(key)
        require(secrets.compare_digest(*peers), "The endpoint keys do not match.")
    return spec


def binary_manifest(path):
    target = Path(base.normalize_local_path(str(path), "binary manifest"))
    with base.directory(str(target.parent)) as directory:
        data = base.strict_json(base.read_file(directory, target.name, private=False))
    require(type(data) is dict and set(data) == {"version", "binary_sha256"} and data["version"] == VERSION,
            "The binary manifest must be from this exact release.")
    return data["binary_sha256"]


def wizard(hashes):
    print("Direct ICMP L3 - create a matched configuration pair; no service or network changes")
    value = {"pair_id": base.prompt("Pair name", "icmp1"), "binary_sha256": hashes}
    for role, label, inner in (("origin", "IRAN", "10.79.0.1"), ("egress", "OUTSIDE", "10.79.0.2")):
        print("\n" + label)
        value[role] = {"real_ip": base.prompt("Real assigned IPv4"),
                       "interface": base.prompt("Physical interface", "eth0"),
                       "inner_ip": base.prompt("Unused private tunnel IPv4", inner)}
    for key, label, default in (("mtu", "Inner MTU", 1200), ("poll_ms", "Polling milliseconds", 20),
                                ("timeout_seconds", "Reconnect after inactivity (seconds)", 15),
                                ("rekey_seconds", "Session rekey interval (seconds)", 3600)):
        raw = base.prompt(label, str(default))
        require(re.fullmatch(r"[0-9]{1,5}", raw), label + " must be an integer.")
        value[key] = int(raw)
    print("\nFEC: adaptive = automatic repair, fixed = fixed repair, off = no repair")
    print("FEC uses extra traffic; it cannot reopen a fully blocked path.")
    value["fec_mode"] = base.prompt("FEC mode (off, fixed, adaptive)", "adaptive").lower()
    require(value["fec_mode"] in ("off", "fixed", "adaptive"), "FEC mode must be off, fixed or adaptive.")
    value.update(fec_percent=20, fec_max_percent=25, fec_block_ms=20)
    if value["fec_mode"] != "off":
        raw = base.prompt("Maximum repair percent (5..50)", "25")
        require(re.fullmatch(r"[0-9]{1,2}", raw), "Maximum repair percent must be an integer.")
        value["fec_max_percent"] = base.integer(int(raw), "fec_max_percent", 5, 50)
        value["fec_percent"] = min(20, value["fec_max_percent"])
        if value["fec_mode"] == "fixed":
            raw = base.prompt("Fixed repair percent (0..cap)", str(value["fec_percent"]))
            require(re.fullmatch(r"[0-9]{1,2}", raw), "Fixed repair percent must be an integer.")
            value["fec_percent"] = base.integer(int(raw), "fec_percent", 0, value["fec_max_percent"])
        raw = base.prompt("Repair block deadline ms (5..100)", "20")
        require(re.fullmatch(r"[0-9]{1,3}", raw), "Block deadline must be an integer.")
        value["fec_block_ms"] = base.integer(int(raw), "fec_block_ms", 5, 100)
    print("Selected: " + value["fec_mode"] + "; repair cap " +
          str(value["fec_max_percent"]) + "%; block " + str(value["fec_block_ms"]) + " ms")
    value["forwards"] = prompt_forwards(default="no")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--spec")
    actions.add_argument("--check-pair")
    parser.add_argument("--output")
    parser.add_argument("--binary-manifest", default=str(Path(__file__).with_name("direct-icmp-binaries.json")))
    args = parser.parse_args(argv)
    try:
        if args.check_pair:
            require(not args.output and not args.spec, "Check cannot generate output.")
            spec = check_pair(args.check_pair)
            print("PASS: matched private Direct ICMP pair " + spec["pair_id"] + ". Offline only.")
        else:
            require(args.output, "--output must name a new private directory.")
            if args.spec:
                target = Path(base.normalize_local_path(args.spec, "spec"))
                with base.directory(str(target.parent)) as directory:
                    value = base.strict_json(base.read_file(directory, target.name, private=False))
                if "binary_sha256" not in value:
                    value["binary_sha256"] = binary_manifest(args.binary_manifest)
            else:
                value = wizard(binary_manifest(args.binary_manifest))
            spec = generate(value, args.output)
            print("READY: " + args.output + "; origin = Iran, egress = outside. Read README.txt.")
            print(forwarding_summary(spec))
            print("Generation only: no service, route, interface, firewall or existing tunnel changed.")
        return 0
    except (base.PairError, OSError, EOFError) as error:
        print("DIRECT ICMP ERROR: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled; nothing activated.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
