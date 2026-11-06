#!/usr/bin/env python3
"""Discover and explicitly manage existing private Direct ICMP endpoint bundles.

Opening this console only reads local metadata. It does not migrate endpoints,
install software, probe the network or change services. Python standard library.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unicodedata
from dataclasses import dataclass

CONFIG_ROOT = Path("/etc/ununknowntun-direct-icmp")
BINARY_ROOT = Path("/opt/ununknowntun-direct-icmp")
PYTHON = "/usr/bin/python3"
MAX_ENTRIES = 256
FILE_LIMIT = 262144
ACTIONS = {"info", "status", "start", "stop", "restart", "logs", "doctor", "uninstall"}
MUTATING = {"start", "stop", "restart", "uninstall"}
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,23}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z][a-z0-9.-]{0,31})?\Z")


class ConsoleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConsoleError(message)


def clean(value):
    return "".join(c if not unicodedata.category(c).startswith("C") else " "
                   for c in str(value))[:256]


def trusted(path, directory=False, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "Non-canonical path refused.")
    for component in (path, *path.parents):
        entry = component.lstat()
        require(not stat.S_ISLNK(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022,
                "Ownership, permissions or symlink check failed.")
        if component != path:
            require(stat.S_ISDIR(entry.st_mode), "Invalid parent directory.")
    entry = path.lstat()
    require(stat.S_ISDIR(entry.st_mode) if directory else stat.S_ISREG(entry.st_mode), "Unexpected file type.")
    if private:
        require(stat.S_IMODE(entry.st_mode) == (0o700 if directory else 0o600), "Endpoint must use private permissions.")


def read_file(path, check_trust=True):
    if check_trust:
        trusted(path, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        entry = os.fstat(fd)
        require(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1 and entry.st_size <= FILE_LIMIT,
                "Expected a bounded, single-link regular endpoint file.")
        if check_trust:
            require(entry.st_uid == 0 and stat.S_IMODE(entry.st_mode) == 0o600, "Unsafe endpoint file.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(FILE_LIMIT + 1)
        require(len(result) <= FILE_LIMIT, "Endpoint file exceeds the size limit.")
        return result
    finally:
        os.close(fd)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON field.")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ConsoleError("Malformed endpoint JSON.") from None


def bounded_children(folder, limit=MAX_ENTRIES):
    result = []
    with os.scandir(folder) as entries:
        for entry in entries:
            require(len(result) < limit, "Directory exceeds the discovery limit; inspect it manually.")
            result.append(Path(entry.path))
    return sorted(result)


@dataclass(frozen=True)
class Endpoint:
    pair: str
    role: str
    version: str
    folder: Path
    unit: str
    signature: str
    summary: tuple

    @property
    def identity(self):
        return self.pair + "/" + self.role


def ip_label(value, network=False):
    try:
        require(type(value) is str, "Invalid address.")
        return str(ipaddress.ip_network(value, strict=True) if network else ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return "not configured / invalid"


def socket_label(value):
    try:
        require(type(value) is str and len(value) <= 80, "Invalid socket address.")
        host, port = value.rsplit(":", 1)
        host = str(ipaddress.ip_address(host.strip("[]")))
        require(port.isascii() and port.isdigit() and 1 <= int(port) <= 65535, "Invalid port.")
        return ("[" + host + "]" if ":" in host else host) + ":" + str(int(port))
    except (ValueError, TypeError):
        return "invalid mapping (details hidden)"


def describe(config):
    lines = []
    for label, key, network in (("Local address", "local_ip", False), ("Peer address", "peer_ip", False),
                                ("Local private address", "inner_local_ip", False), ("Peer private address", "inner_peer_ip", False),
                                ("Local pool", "local_pool_cidr", True), ("Peer pool", "peer_pool_cidr", True)):
        if key in config:
            lines.append(label + ": " + ip_label(config[key], network))
    forwards = config.get("port_forwards", [])
    require(type(forwards) is list and len(forwards) <= 128, "Invalid forwarding inventory.")
    for mapping in forwards:
        require(type(mapping) is dict and mapping.get("protocol") in ("tcp", "udp"), "Invalid forwarding entry.")
        lines.append(mapping["protocol"].upper() + " " + socket_label(mapping.get("listen")) + " -> " + socket_label(mapping.get("target")))
    if not forwards:
        lines.append("Port forwarding: none recorded in this endpoint")
    return tuple(lines)


def inspect_endpoint(folder, check_trust=True):
    folder = Path(folder)
    require(folder.is_absolute() and folder.parent.parent == CONFIG_ROOT, "Endpoint is outside the fixed registry.")
    pair, role = folder.parent.name, folder.name
    require(NAME_RE.fullmatch(pair) and role in ("origin", "egress"), "Invalid endpoint identity.")
    if check_trust:
        trusted(folder, directory=True, private=True)
    else:
        require(not folder.is_symlink(), "Endpoint symlink refused.")
    raw = read_file(folder / "endpoint.json", check_trust)
    metadata = strict_json(raw)
    expected_keys = {"format", "version", "pair_id", "role", "install_dir", "binary_path", "unit_name", "binary_sha256", "files"}
    require(type(metadata) is dict and set(metadata) == expected_keys and type(metadata["format"]) is int and metadata["format"] == 1,
            "Unsupported endpoint manifest.")
    version = metadata["version"]
    require(type(version) is str and VERSION_RE.fullmatch(version), "Invalid endpoint version.")
    unit = "ununknowntun-direct-icmp-" + pair + "-" + role + ".service"
    require(metadata["pair_id"] == pair and metadata["role"] == role and metadata["install_dir"] == str(folder) and
            metadata["unit_name"] == unit and metadata["binary_path"] == str(BINARY_ROOT / version / "ununknowntun"),
            "Endpoint identity or fixed paths do not match.")
    binaries = metadata["binary_sha256"]
    require(type(binaries) is dict and set(binaries) == {"amd64", "arm64"} and
            all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in binaries.values()), "Invalid binary inventory.")
    files = metadata["files"]
    require(type(files) is dict and set(files) == {"direct-icmp.json", "icmp.key", "manage.py", "doctor.py", unit}, "Unsupported endpoint inventory.")
    require({path.name for path in bounded_children(folder, 8)} == set(files) | {"endpoint.json"}, "Unexpected or missing endpoint file.")
    contents = {}
    for name, digest in files.items():
        require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "Invalid integrity digest.")
        contents[name] = read_file(folder / name, check_trust)
        require(hashlib.sha256(contents[name]).hexdigest() == digest, "Endpoint file integrity check failed.")
    require(re.fullmatch(rb"[0-9a-f]{64}\n", contents["icmp.key"]), "Invalid private key file format.")
    config = strict_json(contents["direct-icmp.json"])
    require(type(config) is dict and config.get("role") == role and config.get("key_file") == str(folder / "icmp.key"), "Configuration identity mismatch.")
    return Endpoint(pair, role, version, folder, unit, hashlib.sha256(raw).hexdigest(), describe(config))


def discover(check_trust=True):
    if not CONFIG_ROOT.exists() and not CONFIG_ROOT.is_symlink():
        return [], []
    if check_trust:
        trusted(CONFIG_ROOT, directory=True)
    endpoints, rejected = [], []
    for pair in bounded_children(CONFIG_ROOT):
        try:
            require(NAME_RE.fullmatch(pair.name), "Invalid pair name.")
            if check_trust:
                trusted(pair, directory=True)
            else:
                require(pair.is_dir() and not pair.is_symlink(), "Unsafe pair folder.")
            for folder in bounded_children(pair, 2):
                try:
                    require(len(endpoints) < MAX_ENTRIES, "Endpoint discovery limit exceeded.")
                    endpoints.append(inspect_endpoint(folder, check_trust))
                except (OSError, ConsoleError):
                    rejected.append(clean(pair.name + "/" + folder.name) + ": unsafe or incompatible bundle; no actions available")
        except (OSError, ConsoleError):
            rejected.append(clean(pair.name) + ": unsafe or incompatible pair; no actions available")
    return endpoints, rejected


def child_env():
    # Deliberately do not inherit Python loaders, shell startup files or secrets.
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C.UTF-8", "SYSTEMD_PAGER": "cat", "PAGER": "cat",
            "TERM": os.environ.get("TERM", "dumb")}


def invoke(endpoint, action):
    require(action in ACTIONS, "Unsupported action.")
    require(inspect_endpoint(endpoint.folder) == endpoint, "Endpoint changed; refresh the list before acting.")
    command = [PYTHON, "-I", str(endpoint.folder / "manage.py")]
    try:
        help_result = subprocess.run(command + ["--help"], capture_output=True, text=True, timeout=5, env=child_env())
        require(help_result.returncode == 0 and len(help_result.stdout) + len(help_result.stderr) <= FILE_LIMIT,
                "Installed endpoint manager capabilities could not be read.")
        choices = set()
        for group in re.findall(r"\{([a-z,-]+)\}", help_result.stdout):
            choices.update(group.split(","))
        require(action in choices, "This installed endpoint manager does not support " + action + "; no upgrade or substitute action was attempted.")
        require(inspect_endpoint(endpoint.folder) == endpoint, "Endpoint changed; refresh the list before acting.")
        return subprocess.run(command + [action], env=child_env()).returncode
    except (OSError, subprocess.TimeoutExpired):
        raise ConsoleError("Endpoint manager could not start or its capability check timed out.") from None


def show_inventory(endpoints, rejected):
    print("\nUNUNKNOWNTUN / Direct ICMP manager")
    print("Existing endpoints only. Opening this menu does not change services.")
    if not endpoints:
        print("No trusted Direct ICMP endpoint found. Use ICMP L3 setup to create one.")
    for number, endpoint in enumerate(endpoints, 1):
        print("\n" + str(number) + ") " + endpoint.identity + "  [" + endpoint.version + "]")
        print("   Service: " + endpoint.unit)
        for line in endpoint.summary:
            print("   " + line)
    for error in rejected:
        print("[SKIPPED] " + error)


def interactive(input_fn=input):
    while True:
        endpoints, rejected = discover()
        show_inventory(endpoints, rejected)
        choice = input_fn("\nEndpoint number, r refresh, q back > ").strip()
        if choice in ("q", "0", "exit"):
            return 0
        if choice == "r":
            continue
        if not choice.isascii() or not choice.isdigit() or len(choice) > 4 or not 1 <= int(choice) <= len(endpoints):
            print("Choose an endpoint number from the list.")
            continue
        endpoint = endpoints[int(choice) - 1]
        print("\nSelected: " + endpoint.identity)
        print("1 Status   2 Start   3 Stop   4 Restart   5 Logs   6 Doctor   7 Info   8 Remove   0 Back")
        action = {"1": "status", "2": "start", "3": "stop", "4": "restart", "5": "logs", "6": "doctor", "7": "info", "8": "uninstall"}.get(input_fn("Action > ").strip())
        if action is None:
            continue
        if action in MUTATING:
            print("This changes only " + endpoint.identity + ". Stop/restart/remove may interrupt its clients.")
            if action == "uninstall":
                print("Removal deletes this endpoint configuration, key and service. The peer is unchanged.")
            if input_fn("Type " + endpoint.identity + " to " + action + " (Enter cancels): ").strip() != endpoint.identity:
                print("Cancelled; nothing executed.")
                continue
        try:
            code = invoke(endpoint, action)
            print("Manager exit=" + str(code) + ". This alone does not establish client connectivity.")
        except ConsoleError as error:
            print("[STOP] " + str(error))
        input_fn("Press Enter to return to the endpoint list. ")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="read-only inventory; no manager or service commands")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run on the Linux server as root; no installation is performed.")
    try:
        if args.list:
            endpoints, rejected = discover()
            show_inventory(endpoints, rejected)
            return 1 if rejected else 0
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            parser.error("Interactive management requires a terminal. Use --list for read-only inventory.")
        return interactive()
    except (ConsoleError, OSError):
        print("[STOP] Registry is unavailable, unsafe or incompatible. No automatic repair was attempted.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nDirect ICMP manager closed. No automatic stop or restart requested.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
