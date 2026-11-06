#!/usr/bin/env python3
"""Manage only the named Direct ICMP endpoint beside this private helper."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True

VERSION = "3.7.0-preview.11"
CONFIG_ROOT = Path("/etc/ununknowntun-direct-icmp")
BINARY_ROOT = Path("/opt/ununknowntun-direct-icmp")
UNITS_DIR = Path("/etc/systemd/system")
LOCK_FILE = Path("/run/ununknowntun-direct-icmp.lock")


class ManageError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ManageError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key.")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ManageError("Invalid JSON.") from None


def check_ancestors(path, private=False, owned=True):
    require(path.is_absolute() and all(p not in (".", "..") for p in path.parts), "Absolute non-traversing path required.")
    for parent in reversed([path, *path.parents]):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "Directory symlink or non-directory refused.")
        # The source may live under /tmp, but the endpoint itself must be private.
        if owned:
            require(info.st_uid == 0 and (not info.st_mode & 0o022 or parent == Path("/tmp") or parent == Path("/private/tmp")),
                    "Installation ancestors must be root-owned and not writable by other users.")
    if private:
        info = path.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "Endpoint directory must be current-user-owned mode0700.")


def read_file(path, private=True, limit=131072):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, "Expected bounded single-link regular file.")
        if private:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, "Endpoint files must be current-user-owned mode0600.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, "File exceeds size limit.")
        return data
    finally:
        os.close(fd)


def canonical_unit(metadata):
    return ("[Unit]\nDescription=UNUNKNOWNTUN Direct ICMP L3 " + metadata["pair_id"] + " " + metadata["role"] + "\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\n"
            "UMask=0077\nExecStart=" + metadata["binary_path"] + " -direct-icmp-config " + metadata["install_dir"] + "/direct-icmp.json\n"
            "Restart=on-failure\nRestartSec=3s\nTimeoutStopSec=15s\n"
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n"
            "NoNewPrivileges=yes\nRestrictAddressFamilies=AF_INET AF_NETLINK\nPrivateDevices=no\n"
            "DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\nProtectSystem=strict\nProtectHome=yes\n"
            "RuntimeDirectory=ununknowntun-icmp-rr\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n"
            "ReadWritePaths=/run/ununknowntun-icmp-rr\n"
            "ProtectKernelTunables=yes\nProtectControlGroups=yes\nProtectKernelModules=yes\n"
            "RestrictSUIDSGID=yes\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n").encode()


def load_bundle(folder):
    folder = Path(os.path.abspath(folder))
    check_ancestors(folder, private=True, owned=False)
    metadata = strict_json(read_file(folder / "endpoint.json"))
    keys = {"format", "version", "pair_id", "role", "install_dir", "binary_path", "unit_name", "binary_sha256", "files"}
    require(type(metadata) is dict and set(metadata) == keys and type(metadata["format"]) is int and metadata["format"] == 1 and metadata["version"] == VERSION,
            "Endpoint metadata version/fields mismatch.")
    name, role = metadata["pair_id"], metadata["role"]
    require(type(name) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,23}", name) and role in ("origin", "egress"), "Invalid endpoint identity.")
    unit = "ununknowntun-direct-icmp-" + name + "-" + role + ".service"
    require(metadata["install_dir"] == str(CONFIG_ROOT / name / role) and
            metadata["binary_path"] == str(BINARY_ROOT / VERSION / "ununknowntun") and metadata["unit_name"] == unit,
            "Endpoint paths differ from its fixed private identity.")
    hashes = metadata["binary_sha256"]
    require(type(hashes) is dict and set(hashes) == {"amd64", "arm64"} and
            all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in hashes.values()), "Missing release binary hashes.")
    expected = metadata["files"]
    require(type(expected) is dict and set(expected) == {"direct-icmp.json", "icmp.key", "manage.py", "doctor.py", unit}, "Invalid endpoint inventory.")
    require(set(p.name for p in folder.iterdir()) == set(expected) | {"endpoint.json"}, "Unexpected/missing endpoint files.")
    contents = {name: read_file(folder / name) for name in expected}
    for filename, digest in expected.items():
        require(type(digest) is str and hashlib.sha256(contents[filename]).hexdigest() == digest, "Endpoint integrity failure: " + filename)
    require(re.fullmatch(rb"[0-9a-f]{64}\n", contents["icmp.key"]), "Invalid key format.")
    config = strict_json(contents["direct-icmp.json"])
    require(type(config) is dict and config.get("role") == role and config.get("key_file") == metadata["install_dir"] + "/icmp.key", "Endpoint config identity mismatch.")
    # systemd sections and ordering are semantic. Require the complete canonical
    # unit bytes, not an unordered inventory of otherwise allowed directives.
    require(contents[unit] == canonical_unit(metadata), "Unexpected service directives, sections or ordering.")
    return metadata, contents


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def ensure_root_directory(path):
    if not path.exists():
        ensure_root_directory(path.parent)
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
    check_ancestors(path)


def systemctl(*args, check=True):
    return subprocess.run(["/usr/bin/systemctl", *args], check=check, timeout=45)


@contextlib.contextmanager
def lock():
    check_ancestors(LOCK_FILE.parent)
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, "Unsafe lock file.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def binary_bytes(path, metadata):
    path = Path(os.path.abspath(path))
    check_ancestors(path.parent, owned=False)
    data = read_file(path, private=False, limit=128 * 1024 * 1024)
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    require(arch is not None, "Only Linux amd64/arm64 is supported.")
    require(len(data) > 64 and data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == {"amd64": 62, "arm64": 183}[arch], "Wrong ELF architecture.")
    require(hashlib.sha256(data).hexdigest() == metadata["binary_sha256"][arch], "Release binary SHA256 mismatch; no executable was run.")
    return data


def verify_installed(metadata, contents):
    destination = Path(metadata["install_dir"])
    current, current_files = load_bundle(destination)
    require(current == metadata and current_files == contents, "Installed endpoint differs; use its own installed manager.")
    check_ancestors(destination)
    info = (UNITS_DIR / metadata["unit_name"]).lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, "Installed unit is writable by another user.")
    require(read_file(UNITS_DIR / metadata["unit_name"], private=False) == contents[metadata["unit_name"]], "Unit mismatch; refusing to manage another service.")
    binary = Path(metadata["binary_path"])
    check_ancestors(binary.parent)
    info = binary.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, "Installed binary is writable by another user.")
    binary_bytes(binary, metadata)


def install(folder, metadata, contents, binary_path):
    data = binary_bytes(binary_path, metadata)
    destination = Path(metadata["install_dir"])
    unit_path = UNITS_DIR / metadata["unit_name"]
    check_ancestors(UNITS_DIR)
    require(not destination.exists() and not destination.is_symlink() and not unit_path.exists() and not unit_path.is_symlink(), "Endpoint or unit already exists; never overwritten.")
    state = subprocess.check_output(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", metadata["unit_name"]],
                                    text=True, timeout=15).strip()
    require(state == "not-found", "A service with this identity is already known to systemd; refusing replacement.")
    # Reject aliases/drop-ins that could redirect the newly installed service.
    require(not Path(str(unit_path) + ".d").exists() and not Path(str(unit_path) + ".d").is_symlink(), "Existing unit drop-in directory refused.")
    binary = Path(metadata["binary_path"])
    ensure_root_directory(binary.parent)
    if binary.exists() or binary.is_symlink():
        info = binary.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "Existing versioned binary is writable by another user.")
        require(binary_bytes(binary, metadata) == data, "Existing versioned binary differs.")
    else:
        write_new(binary, data, 0o755)
    observed = subprocess.check_output([str(binary), "-version"], timeout=10, text=True).strip()
    require(observed == "ununknowntun " + VERSION, "Binary version mismatch.")
    ensure_root_directory(destination.parent)
    os.mkdir(destination, 0o700)
    os.chmod(destination, 0o700)
    created_unit = False
    try:
        for filename, content in contents.items():
            write_new(destination / filename, content)
        write_new(destination / "endpoint.json", read_file(folder / "endpoint.json"))
        subprocess.run([str(binary), "-check-direct-icmp-config", str(destination / "direct-icmp.json")], check=True, timeout=15)
        write_new(unit_path, contents[metadata["unit_name"]], 0o644)
        created_unit = True
        systemctl("daemon-reload")
    except BaseException:
        if created_unit:
            unit_path.unlink()
            systemctl("daemon-reload", check=False)
        for child in destination.iterdir():
            child.unlink()
        destination.rmdir()
        raise
    print("INSTALLED, NOT STARTED: " + metadata["unit_name"])
    print("Start outside first, then Iran: sudo python3 -I " + str(destination / "manage.py") + " start")


def execute(action, folder, metadata, contents, binary_path=None):
    require(action in ("check-bundle", "info", "install", "start", "restart", "stop", "status", "logs", "doctor", "uninstall"),
            "Unsupported lifecycle action.")
    if action == "check-bundle":
        print("PASS: endpoint files and matching release hashes verified offline. No network test.")
        return
    if action == "info":
        config = strict_json(contents["direct-icmp.json"])
        # Keep this explicit allowlist: never print the key, arbitrary config fields,
        # or the full private bundle when the menu requests a readable summary.
        fields = ("interface", "tun_name", "local_ip", "peer_ip", "inner_local_ip", "inner_peer_ip",
                  "local_pool_cidr", "peer_pool_cidr", "source_rotation", "mtu", "poll_ms", "timeout_seconds",
                  "rekey_seconds", "fec_mode", "fec_percent", "fec_max_percent", "fec_block_ms")
        summary = {key: metadata[key] for key in ("version", "pair_id", "role", "unit_name")}
        summary["config"] = {key: config[key] for key in fields if key in config}
        summary["config"]["port_forwards"] = [
            {key: rule[key] for key in ("protocol", "listen", "target") if key in rule}
            for rule in config.get("port_forwards", [])]
        summary["config"]["forward_idle_seconds"] = config.get("forward_idle_seconds", 180)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    require(platform.system() == "Linux" and os.geteuid() == 0, "Run this lifecycle action as root on Linux.")
    with lock():
        if action == "install":
            require(binary_path is not None, "install requires --binary from the matching trusted release.")
            install(folder, metadata, contents, binary_path)
            return
        verify_installed(metadata, contents)
        unit = metadata["unit_name"]
        if action == "start":
            systemctl("enable", "--now", unit)
        elif action == "restart":
            systemctl("restart", unit)
        elif action == "stop":
            systemctl("disable", "--now", unit)
        elif action == "status":
            return systemctl("status", "--no-pager", "--full", unit, check=False).returncode
        elif action == "logs":
            subprocess.run(["/usr/bin/journalctl", "-u", unit, "-n", "80", "--no-pager"], check=True, timeout=15)
        elif action == "doctor":
            path = Path(metadata["install_dir"]) / "doctor.py"
            loader = importlib.util.spec_from_file_location("gdt_installed_icmp_doctor", path)
            doctor = importlib.util.module_from_spec(loader)
            loader.loader.exec_module(doctor)
            config = strict_json(contents["direct-icmp.json"])
            doctor.display(doctor.collect(config["peer_ip"], config["interface"], unit, tun_name=config.get("tun_name")))
        elif action == "uninstall":
            systemctl("disable", "--now", unit)
            (UNITS_DIR / unit).unlink()
            systemctl("daemon-reload")
            destination = Path(metadata["install_dir"])
            for filename in [*contents, "endpoint.json"]:
                (destination / filename).unlink()
            destination.rmdir()
            try:
                destination.parent.rmdir()
            except OSError:
                pass
            print("REMOVED: " + unit + "; shared versioned binary retained.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check-bundle", "info", "install", "start", "restart", "stop", "status", "logs", "doctor", "uninstall"))
    parser.add_argument("--endpoint", help="private endpoint folder; defaults beside this helper")
    parser.add_argument("--binary", help="trusted matching release ELF; verified before execution")
    args = parser.parse_args(argv)
    try:
        require(args.action == "install" or args.binary is None, "--binary is only valid with install.")
        folder = Path(os.path.abspath(args.endpoint)) if args.endpoint else Path(__file__).absolute().parent
        metadata, contents = load_bundle(folder)
        return execute(args.action, folder, metadata, contents, args.binary) or 0
    except (ManageError, OSError, subprocess.SubprocessError) as error:
        print("DIRECT ICMP MANAGER ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
