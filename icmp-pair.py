#!/usr/bin/env python3
"""Prepare a private native-ICMP pair or ping-over-existing-WSS adapters.

Offline generation only: no services, interfaces, routes, firewall, existing
tunnels or credentials are read or changed. Keep spoof-pair.py beside this file.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shlex
import sys


sys.dont_write_bytecode = True
_loader = importlib.util.spec_from_file_location("ununknowntun_icmp_pair_utilities", Path(__file__).with_name("spoof-pair.py"))
base = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(base)
PairError = base.PairError
require = base.require
DEFAULT_BINARY = "/opt/ununknowntun-gre-preview/3.7.0-preview.11/ununknowntun"
COMMON = {"mode", "pair_id", "authorized"}
COMMON_OPTIONAL = {"binary_path", "install_dir"}
NATIVE_REQUIRED = {"origin", "egress"}
NATIVE_OPTIONAL = {"carrier_port", "mtu", "mux", "client_listen", "target", "poll_ms"}
RELAY_REQUIRED = {"target"}
RELAY_OPTIONAL = {"relay_listen", "client_connect", "timeout_ms", "count", "interval_ms", "payload_bytes"}


def loopback_endpoint(value, label):
    value = base.endpoint(value, label, listen=True)
    require(ipaddress.IPv4Address(value.split(":")[0]).is_loopback,
            label + " must use a literal 127.x.x.x loopback address and port1024..65535.")
    return value


def validate_spec(value):
    require(type(value) is dict, "Spec must be an object.")
    mode = value.get("mode")
    require(type(mode) is str and mode in ("native-icmp", "icmp-wss"),
            "mode must be native-icmp or icmp-wss.")
    required, optional = (NATIVE_REQUIRED, NATIVE_OPTIONAL) if mode == "native-icmp" else (RELAY_REQUIRED, RELAY_OPTIONAL)
    base.fields(value, COMMON | required, COMMON_OPTIONAL | optional, "Spec")
    require(type(value["pair_id"]) is str and base.PAIR_ID.fullmatch(value["pair_id"]),
            "pair_id must be 1..24 lowercase letters/digits/dashes.")
    require(value["authorized"] is True, "authorized must be true only for endpoints and targets you control or may use.")
    spec = dict(value)
    spec["binary_path"] = base.absolute_path(value.get("binary_path", DEFAULT_BINARY), "binary_path")
    spec["install_dir"] = base.absolute_path(value.get("install_dir", "/etc/ununknowntun-icmp/" + spec["pair_id"]), "install_dir")
    require(not (spec["binary_path"] == spec["install_dir"] or spec["binary_path"].startswith(spec["install_dir"] + "/")),
            "binary_path must be outside install_dir.")
    if mode == "native-icmp":
        # Reuse the mature address/name/port checks, but never accept GRE's
        # source override fields: native ICMP uses the two real peers exactly.
        for role in ("origin", "egress"):
            base.fields(value[role], {"interface", "real_ip", "inner_ip"}, {"tun_name"}, role)
        native = {key: item for key, item in spec.items() if key not in ("mode", "poll_ms")}
        suffix = hashlib.sha256(spec["pair_id"].encode("ascii")).hexdigest()[:8]
        for role in ("origin", "egress"):
            native[role] = dict(native[role])
            native[role].setdefault("tun_name", "gdi" + suffix + role[0])
        native.setdefault("mtu", 1200)
        validated = base.validate_spec(native)
        for role in ("origin", "egress"):
            validated[role].pop("source_ip")
        spec = dict(validated, mode=mode, poll_ms=base.integer(value.get("poll_ms", 20), "poll_ms", 5, 1000))
    else:
        spec["target"] = base.ipv4(value["target"], "target")
        spec["relay_listen"] = loopback_endpoint(value.get("relay_listen", "127.0.0.1:18083"), "relay_listen")
        spec["client_connect"] = loopback_endpoint(value.get("client_connect", "127.0.0.1:12056"), "client_connect")
        for key, default, low, high in (("timeout_ms", 3000, 250, 10000), ("count", 4, 1, 10),
                                        ("interval_ms", 1000, 1000, 10000), ("payload_bytes", 32, 16, 256)):
            spec[key] = base.integer(value.get(key, default), key, low, high)
    return spec


def endpoint_config(spec, role):
    home = spec["install_dir"] + "/" + role
    if spec["mode"] == "native-icmp":
        local, remote = spec[role], spec["egress" if role == "origin" else "origin"]
        return {"interface": local["interface"], "tun_name": local["tun_name"],
                "local_ip": local["real_ip"], "peer_ip": remote["real_ip"],
                "inner_local_ip": local["inner_ip"], "inner_peer_ip": remote["inner_ip"],
                "mtu": spec["mtu"], "carrier_port": spec["carrier_port"], "authorized": True,
                "key_file": home + "/icmp.key", "poll_ms": spec["poll_ms"]}
    config = {"role": role, "target": spec["target"], "authorized": True,
              "key_file": home + "/icmp.key", "timeout_ms": spec["timeout_ms"]}
    if role == "egress":
        config["listen"] = spec["relay_listen"]
    else:
        config.update(connect=spec["client_connect"], count=spec["count"],
                      interval_ms=spec["interval_ms"], payload_bytes=spec["payload_bytes"])
    return config


def config_name(spec, role):
    return "icmp.json" if spec["mode"] == "native-icmp" else "ping.json" if role == "origin" else "relay.json"


def unit_name(spec):
    return "ununknowntun-icmp-" + ("native-" if spec["mode"] == "native-icmp" else "wss-") + spec["pair_id"] + ".service"


def command_args(spec, role, pin="", check=False):
    home = spec["install_dir"] + "/" + role
    config = home + "/" + config_name(spec, role)
    if spec["mode"] == "icmp-wss":
        flag = "-check-icmp-relay-config" if check else "-icmp-ping" if role == "origin" else "-icmp-relay"
        return [spec["binary_path"], flag, config]
    if check:
        return [spec["binary_path"], "-mode", role, "-icmp-config", config, "-check-icmp-config"]
    args = [spec["binary_path"], "-mode", role, "-transport", "tls", "-mux", spec["mux"],
            "-ech-mode", "off", "-tls-fragment", "off", "-token-file", home + "/token", "-icmp-config", config]
    if role == "origin":
        args += ["-listen", spec["client_listen"], "-connect", spec["egress"]["inner_ip"] + ":" + str(spec["carrier_port"]),
                 "-target", spec["target"], "-fingerprint", pin, "-sessions-min", "1", "-sessions", "1"]
    else:
        args += ["-listen", spec["egress"]["inner_ip"] + ":" + str(spec["carrier_port"]), "-allow", spec["target"],
                 "-cert", home + "/server.crt", "-key", home + "/server.key"]
    return args + ["-stats", "30s"]


def launcher(spec, role, pin="", check=False):
    note = "Offline configuration validation only; no packet is sent." if check else "Manual activation only; use solely on authorized endpoints."
    return ("#!/bin/sh\n# " + note + "\nset -eu\numask 077\nexec " +
            " ".join(shlex.quote(item) for item in command_args(spec, role, pin, check)) + "\n").encode("ascii")


def service(spec, role):
    if spec["mode"] == "native-icmp":
        return base.service(spec, role).replace(b"native GRE pair", b"native ICMP pair")
    require(role == "egress", "Origin ping is an ordinary foreground command, not a privileged service.")
    return ("[Unit]\nDescription=UNUNKNOWNTUN ICMP over WSS relay " + spec["pair_id"] + "\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n"
            "ExecStart=/bin/sh " + shlex.quote(spec["install_dir"] + "/egress/run.sh") + "\n"
            "Restart=on-failure\nRestartSec=5s\nTimeoutStopSec=15s\n"
            "CapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\nNoNewPrivileges=yes\n"
            "RestrictAddressFamilies=AF_INET AF_INET6\nPrivateDevices=yes\nDevicePolicy=closed\n"
            "ProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\n"
            "ProtectControlGroups=yes\nProtectKernelModules=yes\nRestrictSUIDSGID=yes\n"
            "LockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def readme(spec):
    home = spec["install_dir"]
    text = ("PRIVATE ICMP PAIR — DO NOT PUBLISH THE BUNDLE OR KEYS\n\n"
            "Mode: " + spec["mode"] + "\nGeneration and --check-pair are offline; nothing is installed or activated.\n"
            "This is NOT source/destination IP spoofing. Use only explicitly authorized endpoints/targets.\n"
            "Install the matching trusted Linux binary manually at: " + spec["binary_path"] + "\n"
            "Copy ONLY origin/ to " + home + "/origin on origin and ONLY egress/ to " + home + "/egress on egress.\n"
            "Never merge/overwrite an existing deployment. Keep directories0700 and files0600, owned by their runtime user.\n"
            "No key is passed on a command line. Each endpoint has the same private ICMP authentication key.\n"
            "Changing only one peer's key breaks the pair; generate and deploy a coordinated replacement.\n"
            "The .service files are templates only. No systemctl, networking or firewall command is run by this helper.\n"
            "Offline validation on each host: /bin/sh " + home + "/ROLE/check.sh\n"
            "An offline PASS is not a reachability or payload test. Never disable host protections blindly.\n\n")
    if spec["mode"] == "native-icmp":
        text += ("NATIVE ICMP CARRIER: existing UNUNKNOWNTUN TCP forwarding runs over an authenticated ICMP TUN underlay.\n"
                 "Real outer IPv4 peers are checked exactly; there are no forged source/destination fields.\n"
                 "The native ICMP key does not replace TLS, the pinned certificate or the UNUNKNOWNTUN token.\n"
                 "The private TLS key exists only on egress. Do not send egress/ to origin.\n"
                 "Linux iproute2, /dev/net/tun, NET_ADMIN and NET_RAW are required. Both service templates grant only these caps.\n"
                 "Check real interface/IP ownership, unused TUN names and inner IPs; physical MTU must be at least inner MTU+96.\n"
                 "Networks may rate-limit/filter ICMP. Ordinary ping success does not prove authenticated carrier success.\n"
                 "This does not route all host traffic, preserve arbitrary IP packets or add CDN camouflage.\n"
                 "Start egress first: /bin/sh " + home + "/egress/run.sh\n"
                 "Then origin:       /bin/sh " + home + "/origin/run.sh\n"
                 "Origin TCP listener: " + spec["client_listen"] + "; egress application: " + spec["target"] + "\n"
                 "Protect a non-loopback origin listener with your existing access policy.\n"
                 "The pinned certificate expires after365days; redeploy a coordinated pair before expiry.\n")
    else:
        text += ("ICMP OVER EXISTING MANAGED WSS: dedicated ping client only; not system ping, a TUN or general IP forwarding.\n"
                 "No WSS/CDN setup or existing credential is generated, read or modified here.\n"
                 "The current managed wizard cannot create a loopback-only origin listener: its direct entry binds publicly.\n"
                 "Do NOT use its default Iran entry for this adapter. Use a separately reviewed manual WSS launcher\n"
                 "with explicit -listen127.0.0.1:PORT, verified TLS, a private token and exact target/allow mapping.\n"
                 "See docs/ICMP.md for the dedicated carrier example; no public Iran/CDN client entry is needed.\n"
                 "Set the UNUNKNOWNTUN origin TCP listener to exactly: " + spec["client_connect"] + "\n"
                 "Set both UNUNKNOWNTUN origin target and egress allow-list to exactly: " + spec["relay_listen"] + "\n"
                 "The ICMP relay listens only on that egress loopback endpoint, never on a public interface.\n"
                 "Its sole authorized ICMP target is: " + spec["target"] + "\n"
                 "The existing managed WSS transport still requires its own TLS and UNUNKNOWNTUN token authentication.\n"
                 "Start the egress relay: /bin/sh " + home + "/egress/run.sh  # NET_RAW only\n"
                 "Then start/check the separate reviewed loopback-only WSS pair with the exact mapping above.\n"
                 "Run the unprivileged origin ping client: /bin/sh " + home + "/origin/run.sh\n"
                 "Origin requires no raw-socket capability or root, but must own/read its private config/key.\n"
                 "Relay probes are bounded/rate-limited. The reported RTT includes tunnel and relay overhead.\n"
                 "The egress service template grants NET_RAW only; no NET_ADMIN and no /dev/net/tun access.\n")
    return text.encode("utf-8")


def role_files(spec, role, icmp_key, token=b"", cert=b"", pin="", tls_key=b""):
    entries = {config_name(spec, role): base.json_bytes(endpoint_config(spec, role)), "icmp.key": icmp_key,
               "run.sh": launcher(spec, role, pin), "check.sh": launcher(spec, role, pin, True)}
    if spec["mode"] == "native-icmp":
        entries.update(token=token, **{"server.crt": cert, "pin.sha256": (pin + "\n").encode("ascii")})
        if role == "egress":
            entries["server.key"] = tls_key
    if spec["mode"] == "native-icmp" or role == "egress":
        entries[unit_name(spec)] = service(spec, role)
    return entries


def generate(value, output):
    spec = validate_spec(value)
    path = Path(base.normalize_local_path(output, "output path"))
    with base.directory(str(path.parent)) as parent:
        require(path.name not in os.listdir(parent), "Output already exists; nothing will be overwritten.")
        icmp_key = (secrets.token_hex(32) + "\n").encode("ascii")
        token, cert, pin, key = b"", b"", "", b""
        if spec["mode"] == "native-icmp":
            token = (secrets.token_hex(32) + "\n").encode("ascii")
            key, cert, pin = base.make_certificate(dict(spec, pair_id="icmp-" + spec["pair_id"]), base.openssl_binary())
        root = base.create_directory(parent, path.name)
        try:
            base.write_private(root, "pair.json", base.json_bytes(spec))
            base.write_private(root, "README.txt", readme(spec))
            for role in ("origin", "egress"):
                directory = base.create_directory(root, role)
                try:
                    for name, data in role_files(spec, role, icmp_key, token, cert, pin, key).items():
                        base.write_private(directory, name, data)
                finally:
                    os.close(directory)
        finally:
            os.close(root)
    return spec


def check_pair(output):
    path = base.normalize_local_path(output, "bundle path")
    with base.directory(path, private=True) as root:
        require(set(os.listdir(root)) == {"pair.json", "README.txt", "origin", "egress"}, "Unexpected or missing bundle entries.")
        spec = validate_spec(base.strict_json(base.read_file(root, "pair.json", limit=base.MAX_JSON)))
        require(base.read_file(root, "README.txt") == readme(spec), "Instructions do not match the paired spec.")
        peers = {}
        for role in ("origin", "egress"):
            with base.directory(path + "/" + role, private=True) as directory:
                names = set(role_files(spec, role, b"", pin=""))
                require(set(os.listdir(directory)) == names, role + " has unexpected or missing files.")
                data = {name: base.read_file(directory, name) for name in names}
                require(re.fullmatch(rb"[0-9a-f]{64}\n", data["icmp.key"]) is not None, "Invalid private ICMP key format.")
                pin = ""
                if spec["mode"] == "native-icmp":
                    for name in ("token", "pin.sha256"):
                        require(re.fullmatch(rb"[0-9a-f]{64}\n", data[name]) is not None, "Invalid token or pin format.")
                    pin = data["pin.sha256"].decode("ascii").strip()
                expected = role_files(spec, role, data["icmp.key"], data.get("token", b""), data.get("server.crt", b""),
                                      pin, data.get("server.key", b""))
                for name, content in expected.items():
                    actual = data[name]
                    if name == config_name(spec, role):
                        actual = base.json_bytes(base.strict_json(actual))
                    require(actual == content, role + " configuration/script/template does not match the paired spec.")
                peers[role] = data
        origin, egress = peers["origin"], peers["egress"]
        shared = ("icmp.key", "token", "server.crt", "pin.sha256") if spec["mode"] == "native-icmp" else ("icmp.key",)
        for name in shared:
            require(secrets.compare_digest(origin[name], egress[name]), "Peer credential files do not match.")
        if spec["mode"] == "native-icmp":
            require(not secrets.compare_digest(origin["icmp.key"], origin["token"]), "ICMP key and TLS carrier token must be independent.")
            executable = base.openssl_binary()
            der = base.openssl_run(executable, ["x509", "-outform", "DER"], origin["server.crt"])
            require(secrets.compare_digest(hashlib.sha256(der).hexdigest().encode() + b"\n", origin["pin.sha256"]),
                    "Certificate fingerprint differs from the pin.")
            base.openssl_run(executable, ["x509", "-checkend", "0", "-noout"], origin["server.crt"])
            public = base.openssl_run(executable, ["x509", "-pubkey", "-noout"], origin["server.crt"])
            private_public = base.openssl_run(executable, ["pkey", "-pubout"], egress["server.key"])
            require(secrets.compare_digest(public, private_public), "Certificate and private TLS key differ.")
    return spec


def read_spec(path):
    path = Path(base.normalize_local_path(path, "spec path"))
    with base.directory(str(path.parent)) as parent:
        return validate_spec(base.strict_json(base.read_file(parent, path.name, private=False, limit=base.MAX_JSON)))


def prompt_integer(label, default):
    raw = base.prompt(label, str(default))
    require(re.fullmatch(r"[0-9]{1,5}", raw) is not None, label + " must be an integer.")
    return int(raw)


def wizard(mode=None):
    print("ICMP pair preparation — private files only, no installation or activation.")
    print("1) native-icmp: existing TCP forwarding over an ICMP TUN carrier")
    print("2) icmp-wss: dedicated ping through an existing managed WSS tunnel (not system ping)")
    mode = mode or base.prompt("Mode (1/2 or exact name)", "1")
    mode = {"1": "native-icmp", "2": "icmp-wss"}.get(mode, mode)
    require(mode in ("native-icmp", "icmp-wss"), "Unknown ICMP mode.")
    require(input("Type AUTHORIZED if you control both endpoints and may contact the configured target: ").strip() == "AUTHORIZED",
            "Explicit authorization was not given; nothing was created.")
    value = {"mode": mode, "authorized": True, "pair_id": base.prompt("Pair name (lowercase letters/digits/dashes)")}
    value["binary_path"] = base.prompt("Absolute installed Linux binary", DEFAULT_BINARY)
    value["install_dir"] = base.prompt("Private configuration parent", "/etc/ununknowntun-icmp/" + value["pair_id"])
    if mode == "native-icmp":
        for role, inner in (("origin", "10.78.0.1"), ("egress", "10.78.0.2")):
            print("\n" + role.upper() + " host (real assigned IP; no source spoofing)")
            value[role] = {"interface": base.prompt("Physical interface", "eth0"),
                           "real_ip": base.prompt("Real assigned IPv4"), "inner_ip": base.prompt("Unused private inner IPv4", inner)}
        value["client_listen"] = base.prompt("Origin TCP listener", "127.0.0.1:12055")
        value["target"] = base.prompt("Egress TCP application target", "127.0.0.1:18082")
        for key, label, default in (("carrier_port", "Inner TLS port", 18443), ("mtu", "Inner MTU (physical must allow +96)", 1200),
                                    ("poll_ms", "ICMP poll interval in milliseconds", 20)):
            value[key] = prompt_integer(label, default)
        value["mux"] = base.prompt("MUX on/off", "on")
    else:
        value["target"] = base.prompt("Single authorized ICMP target IPv4 reachable from egress")
        value["relay_listen"] = base.prompt("Egress loopback relay listener / existing WSS target+allow", "127.0.0.1:18083")
        value["client_connect"] = base.prompt("Origin existing WSS local TCP listener", "127.0.0.1:12056")
        for key, label, default in (("timeout_ms", "Probe timeout milliseconds", 3000), ("count", "Probe count (1..10)", 4),
                                    ("interval_ms", "Interval milliseconds (at least1000)", 1000), ("payload_bytes", "Payload bytes", 32)):
            value[key] = prompt_integer(label, default)
    return validate_spec(value)


def summary(spec, output, checked=False):
    print(("OFFLINE ICMP PAIR CHECK PASSED" if checked else "PRIVATE ICMP PAIR PREPARED") + ": " + spec["pair_id"])
    print("Mode: " + spec["mode"] + "; bundle: " + base.normalize_local_path(output, "bundle path"))
    if spec["mode"] == "icmp-wss":
        print("Existing WSS mapping: origin " + spec["client_connect"] + " -> egress target+allow " + spec["relay_listen"])
    print("No host, service, route, interface or existing tunnel was changed. No network test was performed.")
    print("Keep the bundle private; read README.txt and copy only each host's endpoint directory.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--spec", help="strict JSON input; omit for interactive wizard")
    action.add_argument("--check-pair", metavar="DIRECTORY", help="offline integrity check of the complete private bundle")
    parser.add_argument("--output", help="new private output directory; parent must exist; never overwritten")
    parser.add_argument("--mode", choices=("native-icmp", "icmp-wss"), help="preselect interactive mode; not valid with --spec/--check-pair")
    args = parser.parse_args(argv)
    try:
        require(not args.mode or not (args.spec or args.check_pair), "--mode is only for the interactive wizard.")
        if args.check_pair:
            require(args.output is None, "--output cannot be combined with --check-pair.")
            spec = check_pair(args.check_pair)
            summary(spec, args.check_pair, checked=True)
        else:
            require(args.output is not None, "--output is required and its parent must already exist.")
            spec = generate(read_spec(args.spec) if args.spec else wizard(args.mode), args.output)
            summary(spec, args.output)
        return 0
    except (PairError, OSError, EOFError) as error:
        print("ICMP PAIR ERROR: " + str(error) + " Nothing was activated. Any partial private output must not be used.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled. Nothing was activated. Any partial private output must not be used.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
