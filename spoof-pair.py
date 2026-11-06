#!/usr/bin/env python3
"""Prepare an independent, private GRE pair; never install or activate it.

Only the explicitly requested new output directory is written. OpenSSL is used
locally for a fresh certificate. No existing tunnel, credential, network state,
service or system configuration is read or changed.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys


MAX_JSON = 16384
MAX_FILE = 65536
PAIR_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,23}\Z")
INTERFACE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}\Z")
PATH_PART = re.compile(r"[a-zA-Z0-9_.-]+\Z")
PRIVATE_NETS = tuple(ipaddress.IPv4Network(x) for x in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
REQUIRED = {"pair_id", "authorized", "binary_path", "origin", "egress"}
OPTIONAL = {"install_dir", "carrier_port", "mtu", "mux", "client_listen", "target"}
PEER_REQUIRED = {"interface", "real_ip", "inner_ip"}
PEER_OPTIONAL = {"tun_name", "source_ip"}


class PairError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PairError(message)


def strict_json(data):
    require(len(data) <= MAX_JSON, "JSON exceeds 16 KiB.")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON field.")
            result[key] = value
        return result

    def invalid_constant(_):
        raise PairError("Non-finite JSON numbers are not allowed.")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise PairError("Invalid JSON.") from None


def fields(value, required, optional, label):
    require(type(value) is dict, label + " must be an object.")
    require(required <= value.keys(), label + " is missing required fields.")
    require(value.keys() <= required | optional, label + " contains unknown fields.")


def absolute_path(value, label):
    require(type(value) is str and 1 < len(value) <= 1024 and value.startswith("/"),
            label + " must be an absolute Unix path.")
    parts = value.split("/")[1:]
    require(all(part not in ("", ".", "..") and PATH_PART.fullmatch(part) for part in parts),
            label + " must use simple path components: letters, digits, dot, dash or underscore.")
    return value


def ipv4(value, label, inner=False, endpoint=False, wildcard=False):
    require(type(value) is str, label + " must be a literal IPv4 address.")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise PairError(label + " must be a canonical literal IPv4 address.") from None
    require(str(address) == value, label + " must be canonical IPv4.")
    if wildcard and value == "0.0.0.0":
        return value
    require(not address.is_multicast and not address.is_link_local and
            not address.is_unspecified and 0 < address.packed[0] < 240 and
            (endpoint or not address.is_loopback), label + " is not supported unicast IPv4.")
    if inner:
        require(any(address in network for network in PRIVATE_NETS),
                label + " must be an RFC1918 private address.")
    return value


def integer(value, label, low, high):
    require(type(value) is int and low <= value <= high,
            f"{label} must be an integer from {low} to {high}.")
    return value


def endpoint(value, label, listen=False):
    require(type(value) is str and value.count(":") == 1,
            label + " must be literal IPv4:port, without a hostname.")
    address, port = value.split(":")
    ipv4(address, label, endpoint=True, wildcard=listen)
    require(re.fullmatch(r"[1-9][0-9]{0,4}", port) is not None, label + " has an invalid port.")
    integer(int(port), label + " port", 1024 if listen else 1, 65535)
    return value


def validate_spec(value):
    fields(value, REQUIRED, OPTIONAL, "Spec")
    require(type(value["pair_id"]) is str and PAIR_ID.fullmatch(value["pair_id"]),
            "pair_id must be 1..24 lowercase letters/digits/dashes, starting with a letter or digit.")
    require(value["authorized"] is True,
            "authorized must be true only for endpoints and source IPs you are permitted to use.")
    pair_id = value["pair_id"]
    spec = dict(value)
    spec["binary_path"] = absolute_path(value["binary_path"], "binary_path")
    spec["install_dir"] = absolute_path(value.get("install_dir", "/etc/ununknowntun-gre/" + pair_id), "install_dir")
    require(not (spec["binary_path"] == spec["install_dir"] or
                 spec["binary_path"].startswith(spec["install_dir"] + "/")),
            "binary_path must be outside the private configuration install_dir.")
    spec["carrier_port"] = integer(value.get("carrier_port", 18443), "carrier_port", 1024, 65535)
    spec["mtu"] = integer(value.get("mtu", 1280), "mtu", 576, 1400)
    spec["mux"] = value.get("mux", "on")
    require(type(spec["mux"]) is str and spec["mux"] in ("on", "off"), "mux must be on or off.")
    spec["client_listen"] = endpoint(value.get("client_listen", "127.0.0.1:12055"), "client_listen", listen=True)
    spec["target"] = endpoint(value.get("target", "127.0.0.1:18082"), "target")
    suffix = hashlib.sha256(pair_id.encode("ascii")).hexdigest()[:8]
    for role in ("origin", "egress"):
        peer = value[role]
        fields(peer, PEER_REQUIRED, PEER_OPTIONAL, role)
        peer = dict(peer)
        peer.setdefault("source_ip", peer["real_ip"])
        peer.setdefault("tun_name", "gdt" + suffix + role[0])
        for key in ("interface", "tun_name"):
            require(type(peer[key]) is str and INTERFACE.fullmatch(peer[key]) and peer[key] != "lo",
                    role + "." + key + " must be a safe 1..15-character non-loopback interface name.")
        require(peer["interface"] != peer["tun_name"], role + " physical and TUN interfaces must differ.")
        for key in ("real_ip", "source_ip", "inner_ip"):
            ipv4(peer[key], role + "." + key, inner=key == "inner_ip")
        spec[role] = peer
    origin, egress = spec["origin"], spec["egress"]
    require(origin["real_ip"] != egress["real_ip"], "The two real endpoint IPs must differ.")
    require(origin["inner_ip"] != egress["inner_ip"], "The two inner IPs must differ.")
    outer = {peer[key] for peer in (origin, egress) for key in ("real_ip", "source_ip")}
    require(not outer.intersection({origin["inner_ip"], egress["inner_ip"]}),
            "Inner IPs must not equal any real or claimed outer IP.")
    return spec


def gre_config(spec, role):
    local, peer = spec[role], spec["egress" if role == "origin" else "origin"]
    return {"interface": local["interface"], "tun_name": local["tun_name"],
            "local_ip": local["real_ip"], "peer_ip": peer["real_ip"],
            "source_ip": local["source_ip"], "expected_peer_source_ip": peer["source_ip"],
            "inner_local_ip": local["inner_ip"], "inner_peer_ip": peer["inner_ip"],
            "mtu": spec["mtu"], "carrier_port": spec["carrier_port"], "authorized": True}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def command_args(spec, role, pin, check=False):
    home = spec["install_dir"] + "/" + role
    if check and role == "egress":
        return [spec["binary_path"], "-mode", role, "-spoof-config", home + "/gre.json", "-check-spoof-config"]
    args = [spec["binary_path"], "-mode", role, "-transport", "tls", "-mux", spec["mux"],
            "-ech-mode", "off", "-tls-fragment", "off",
            "-token-file", home + "/token", "-spoof-config", home + "/gre.json"]
    if role == "origin":
        args += ["-listen", spec["client_listen"], "-connect",
                 spec["egress"]["inner_ip"] + ":" + str(spec["carrier_port"]),
                 "-target", spec["target"], "-fingerprint", pin,
                 "-sessions-min", "1", "-sessions", "1"]
    else:
        args += ["-listen", spec["egress"]["inner_ip"] + ":" + str(spec["carrier_port"]),
                 "-allow", spec["target"], "-cert", home + "/server.crt", "-key", home + "/server.key"]
    if check:
        args += ["-check-spoof", "-probe-timeout", "15s"]
    else:
        args += ["-stats", "30s"]
    return args


def launcher(spec, role, pin, check=False):
    note = ("Origin check sends real GRE and temporarily creates its own TUN/routes; start egress first."
            if check and role == "origin" else
            "Egress check validates JSON only; it creates no interfaces and sends no packets."
            if check else "Manual activation only. The configured addresses require authorization on this host.")
    return ("#!/bin/sh\n# " + note + "\nset -eu\numask 077\nexec " +
            " ".join(shlex.quote(x) for x in command_args(spec, role, pin, check)) + "\n").encode("utf-8")


def service(spec, role):
    # Paths are a strict shell/systemd-safe ASCII subset: no %, $, quotes or whitespace.
    return ("[Unit]\nDescription=UNUNKNOWNTUN native GRE pair " + spec["pair_id"] + "\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n"
            "ExecStart=/bin/sh " + shlex.quote(spec["install_dir"] + "/" + role + "/run.sh") + "\n"
            "Restart=on-failure\nRestartSec=5s\nTimeoutStopSec=15s\n"
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n"
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\nNoNewPrivileges=yes\n"
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK\n"
            "PrivateDevices=no\nDevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n"
            "ProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\n"
            "ProtectControlGroups=yes\nProtectKernelModules=yes\nRestrictSUIDSGID=yes\n"
            "LockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def readme(spec):
    return ("PRIVATE PAIRED CONFIGURATION — DO NOT PUBLISH OR SHARE THE WHOLE BUNDLE\n\n"
            "Generation and --check-pair are offline: nothing is installed or activated.\n"
            "Send only origin/ to the origin host and only egress/ to the egress host, privately.\n"
            "Do not send the egress private TLS key to origin. Both endpoint tokens are secret.\n"
            "On each host, install a trusted matching Linux binary at:\n  " + spec["binary_path"] + "\n"
            "Manually copy only that host's endpoint directory, without merging or overwriting an existing\n"
            "deployment, beneath: " + spec["install_dir"] + "\n"
            "Origin destination: " + spec["install_dir"] + "/origin\n"
            "Egress destination: " + spec["install_dir"] + "/egress\n"
            "Keep parent/endpoint directories root-owned 0700 and files 0600. Scripts are not executable.\n"
            "Check actual interface/IP ownership, free TUN name, unused inner /32 pair and carrier port.\n"
            "Linux, iproute2, /dev/net/tun, NET_ADMIN and NET_RAW permissions are required.\n"
            "Do not blindly disable rp_filter or change firewall/routing rules. Check provider authorization.\n"
            "This is raw IPv4/GRE with TLS, not uTLS/CDN camouflage or destination-IP rewriting.\n"
            "Outer destination remains the real peer; the other peer's claimed source is checked exactly.\n\n"
            "Manual foreground order (requires the necessary Linux privileges):\n"
            "  Egress first: /bin/sh " + spec["install_dir"] + "/egress/check.sh  # JSON-only check\n"
            "  Egress:       /bin/sh " + spec["install_dir"] + "/egress/run.sh\n"
            "  Origin:       /bin/sh " + spec["install_dir"] + "/origin/check.sh  # real GRE/TLS/auth check\n"
            "  Origin:       /bin/sh " + spec["install_dir"] + "/origin/run.sh\n"
            "Do not run a check while this endpoint is already active: the TUN name is exclusive.\n"
            "The target application must already be listening at " + spec["target"] + " on egress.\n"
            "Origin client listener: " + spec["client_listen"] + " (protect non-loopback listeners).\n"
            "The optional .service file is a TEMPLATE ONLY. Review and manually install it only after\n"
            "foreground testing; this helper never calls systemctl. The unit grants only NET_ADMIN/NET_RAW,\n"
            "uses the host network, and explicitly permits /dev/net/tun. Do not set PrivateDevices=yes.\n"
            "Run --check-pair against the original complete private bundle before copying it.\n"
            "An offline PASS does not prove GRE reachability, provider source permission or payload flow.\n"
            "The freshly pinned certificate expires after 365 days; regenerate/redeploy a coordinated pair\n"
            "before expiry. Never replace only one side's token or pin.\n").encode("utf-8")


def openssl_binary():
    value = shutil.which("openssl")
    require(value is not None, "OpenSSL is required locally; nothing was installed.")
    return os.path.abspath(value)


def openssl_run(executable, args, data=None, pass_fds=()):
    try:
        # Do not load a user-supplied OpenSSL config/provider or update a home
        # random-seed file. All key/certificate material travels through pipes.
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                       "OPENSSL_CONF": "/dev/null", "RANDFILE": "/dev/null"}
        result = subprocess.run([executable] + args, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=45, check=False, env=environment, pass_fds=pass_fds)
    except (OSError, subprocess.TimeoutExpired):
        raise PairError("Local OpenSSL operation failed or timed out; diagnostic output suppressed.") from None
    require(result.returncode == 0 and len(result.stdout) <= MAX_FILE,
            "Local OpenSSL operation failed; diagnostic output suppressed.")
    return result.stdout


def make_certificate(spec, executable):
    key = openssl_run(executable, ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
    name = "ununknowntun-gre-" + spec["pair_id"] + ".invalid"
    # LibreSSL also needs a distinguished_name config section with -subj.
    # Pass a fixed minimal config through an inherited pipe, never a disk file.
    config_read, config_write = os.pipe()
    try:
        os.write(config_write, b"[req]\ndistinguished_name=dn\n[dn]\n")
        os.close(config_write)
        config_write = -1
        cert = openssl_run(executable, ["req", "-new", "-x509", "-key", "/dev/stdin", "-sha256",
                                       "-config", "/dev/fd/" + str(config_read), "-days", "365", "-subj", "/CN=" + name,
                                       "-addext", "subjectAltName=DNS:" + name], key, (config_read,))
    finally:
        os.close(config_read)
        if config_write >= 0:
            os.close(config_write)
    der = openssl_run(executable, ["x509", "-outform", "DER"], cert)
    return key, cert, hashlib.sha256(der).hexdigest()


def normalize_local_path(value, label):
    require(type(value) is str and value != "", label + " is required.")
    # Do not resolve symlinks or silently normalize traversal before checking.
    path = value if value.startswith("/") else str(Path.cwd()) + "/" + value
    return absolute_path(path, label)


@contextlib.contextmanager
def directory(path, private=False):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute_path(path, "directory").split("/")[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            info = os.fstat(fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "Bundle directories must be owned by the current user and mode 0700.")
        yield fd
    finally:
        os.close(fd)


def create_directory(parent, name):
    # The standalone helper is single-threaded. Restore even an unusually
    # restrictive caller mask after ensuring the new directory is traversable.
    previous = os.umask(0o077)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    finally:
        os.umask(previous)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    os.fchmod(fd, 0o700)
    return fd


def write_private(parent, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(fd)


def read_file(parent, name, private=True, limit=MAX_FILE):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                "Input must be a bounded regular file, not a link or special file.")
        if private:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "Bundle files must be owned by the current user and mode 0600.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, "Input file exceeds its size limit.")
        return data
    finally:
        os.close(fd)


def read_spec(path):
    path = Path(normalize_local_path(path, "spec path"))
    with directory(str(path.parent)) as parent:
        return validate_spec(strict_json(read_file(parent, path.name, private=False, limit=MAX_JSON)))


def generate(value, output):
    spec = validate_spec(value)
    path = Path(normalize_local_path(output, "output path"))
    with directory(str(path.parent)) as parent:
        # Fail before generating credentials if anything already occupies this name.
        require(path.name not in os.listdir(parent), "Output already exists; nothing will be overwritten.")
        executable = openssl_binary()
        key, cert, pin = make_certificate(spec, executable)
        token = (secrets.token_hex(32) + "\n").encode("ascii")
        root = create_directory(parent, path.name)
        try:
            write_private(root, "pair.json", json_bytes(spec))
            write_private(root, "README.txt", readme(spec))
            for role in ("origin", "egress"):
                peer = create_directory(root, role)
                try:
                    entries = {"gre.json": json_bytes(gre_config(spec, role)), "token": token,
                               "server.crt": cert, "pin.sha256": (pin + "\n").encode("ascii"),
                               "run.sh": launcher(spec, role, pin), "check.sh": launcher(spec, role, pin, True),
                               "ununknowntun-gre-" + spec["pair_id"] + ".service": service(spec, role)}
                    if role == "egress":
                        entries["server.key"] = key
                    for name, data in entries.items():
                        write_private(peer, name, data)
                finally:
                    os.close(peer)
        finally:
            os.close(root)
    # Never start generated scripts or invoke the UNUNKNOWNTUN binary here.
    return spec


def check_pair(output):
    path = normalize_local_path(output, "bundle path")
    with directory(path, private=True) as root:
        require(set(os.listdir(root)) == {"pair.json", "README.txt", "origin", "egress"},
                "Unexpected or missing bundle entries.")
        spec = validate_spec(strict_json(read_file(root, "pair.json", limit=MAX_JSON)))
        require(read_file(root, "README.txt") == readme(spec), "Bundle instructions do not match the spec.")
        peers = {}
        for role in ("origin", "egress"):
            with directory(path + "/" + role, private=True) as peer:
                names = {"gre.json", "token", "server.crt", "pin.sha256", "run.sh", "check.sh",
                         "ununknowntun-gre-" + spec["pair_id"] + ".service"}
                if role == "egress":
                    names.add("server.key")
                require(set(os.listdir(peer)) == names, role + " has unexpected or missing files.")
                data = {name: read_file(peer, name) for name in names}
                # Python considers True == 1 == 1.0; Go's strict JSON decoder
                # does not. Canonical JSON retains these distinct value types.
                require(json_bytes(strict_json(data["gre.json"])) == json_bytes(gre_config(spec, role)),
                        role + " GRE fields or JSON value types do not match the paired spec.")
                require(re.fullmatch(rb"[0-9a-f]{64}\n", data["token"]) is not None,
                        role + " token format is invalid.")
                require(re.fullmatch(rb"[0-9a-f]{64}\n", data["pin.sha256"]) is not None,
                        role + " pin format is invalid.")
                pin = data["pin.sha256"].decode("ascii").strip()
                require(data["run.sh"] == launcher(spec, role, pin) and
                        data["check.sh"] == launcher(spec, role, pin, True),
                        role + " launcher content does not match the paired spec.")
                require(data["ununknowntun-gre-" + spec["pair_id"] + ".service"] == service(spec, role),
                        role + " service template does not match the paired spec.")
                peers[role] = data
        origin, egress = peers["origin"], peers["egress"]
        for key in ("token", "server.crt", "pin.sha256"):
            require(secrets.compare_digest(origin[key], egress[key]), "Peer " + key + " files do not match.")
        executable = openssl_binary()
        der = openssl_run(executable, ["x509", "-outform", "DER"], origin["server.crt"])
        require(secrets.compare_digest(hashlib.sha256(der).hexdigest().encode() + b"\n", origin["pin.sha256"]),
                "Certificate fingerprint does not match the pin.")
        openssl_run(executable, ["x509", "-checkend", "0", "-noout"], origin["server.crt"])
        cert_public = openssl_run(executable, ["x509", "-pubkey", "-noout"], origin["server.crt"])
        key_public = openssl_run(executable, ["pkey", "-pubout"], egress["server.key"])
        require(secrets.compare_digest(cert_public, key_public), "Certificate and egress private key do not match.")
    return spec


def prompt(label, default=None):
    answer = input(label + (" [" + str(default) + "]" if default is not None else "") + ": ").strip()
    return answer if answer or default is None else default


def wizard():
    print("Native IPv4/GRE pair preparation — no installation or activation.")
    print("Outer destination stays the real peer. Each peer can claim an authorized source IP.")
    print("A matching source/real IP is an ordinary GRE baseline, not a spoofing test.")
    require(input("Type AUTHORIZED if you control both endpoints and may use both source IPs: ").strip() == "AUTHORIZED",
            "Explicit authorization was not given; no files were created.")
    value = {"authorized": True, "pair_id": prompt("Pair name (lowercase letters/digits/dashes)")}
    value["binary_path"] = prompt("Absolute installed Linux UNUNKNOWNTUN binary path")
    value["install_dir"] = prompt("Private parent for origin/egress config directory", "/etc/ununknowntun-gre/" + value["pair_id"])
    for role, default_inner in (("origin", "10.77.0.1"), ("egress", "10.77.0.2")):
        print("\n" + role.upper() + " host")
        peer = {"interface": prompt("Physical interface", "eth0"), "real_ip": prompt("Real assigned IPv4")}
        peer["source_ip"] = prompt("Authorized outgoing source IPv4 (real IP = baseline)", peer["real_ip"])
        peer["inner_ip"] = prompt("Unused private inner IPv4", default_inner)
        value[role] = peer
    value["client_listen"] = prompt("Origin client listener IPv4:port", "127.0.0.1:12055")
    value["target"] = prompt("Egress application target IPv4:port", "127.0.0.1:18082")
    for key, label, default in (("carrier_port", "Inner TLS carrier port", "18443"), ("mtu", "Inner MTU", "1280")):
        raw = prompt(label, default)
        require(re.fullmatch(r"[0-9]{1,5}", raw) is not None, label + " must be an integer.")
        value[key] = int(raw)
    value["mux"] = prompt("MUX on/off", "on")
    return validate_spec(value)


def summary(spec, output, checked=False):
    print(("OFFLINE PAIR CHECK PASSED" if checked else "PRIVATE PAIR PREPARED") + ": " + spec["pair_id"])
    print("Bundle: " + normalize_local_path(output, "bundle path"))
    for role in ("origin", "egress"):
        peer = spec[role]
        mode = "authorized source override configured" if peer["source_ip"] != peer["real_ip"] else "ordinary GRE baseline"
        print(role + ": " + mode)
    print("No service, route, interface or host setting was changed. No network test was performed.")
    print("Keep the complete bundle private. Read README.txt; copy only each host's endpoint directory.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--spec", help="strict JSON input; omit for interactive wizard")
    action.add_argument("--check-pair", metavar="DIRECTORY", help="offline integrity check of a complete private pair")
    parser.add_argument("--output", help="new output directory; parent must already exist; never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.check_pair:
            require(args.output is None, "--output cannot be used with --check-pair.")
            spec = check_pair(args.check_pair)
            summary(spec, args.check_pair, checked=True)
        else:
            require(args.output is not None, "--output is required; its parent must already exist.")
            spec = read_spec(args.spec) if args.spec else wizard()
            spec = generate(spec, args.output)
            summary(spec, args.output)
        return 0
    except (PairError, OSError, EOFError) as error:
        print("PAIR ERROR: " + str(error) + " No existing deployment was changed. A partial private output, if present, must not be activated.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled. Nothing was activated. Any partial private output must not be used.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
