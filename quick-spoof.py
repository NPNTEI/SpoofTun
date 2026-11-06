#!/usr/bin/env python3
"""UnUnknownTun quick spoof tunnel helper (writes private endpoint files only).

foreign: creates the egress endpoint, certificate and token, and prints a short link.
iran:    reads that link and creates the matching origin endpoint.
Reuses the validated GRE pair logic from spoof-pair.py. Never starts services.
"""
import argparse, base64, importlib.util, json, os, re, secrets, shutil, sys
from pathlib import Path

INNER = {"origin": "10.77.0.1", "egress": "10.77.0.2"}


def load_pair_module(path):
    spec = importlib.util.spec_from_file_location("spoof_pair", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_spec(M, a, role_info):
    pair = a.pair
    spec = {
        "authorized": True, "pair_id": pair, "binary_path": a.binary,
        "install_dir": "/etc/ununknowntun-gre/" + pair,
        "carrier_port": 18443, "mtu": 1280, "mux": "on",
        "client_listen": role_info["client_listen"], "target": "127.0.0.1:%d" % role_info["target_port"],
        "origin": {"interface": role_info["origin_iface"], "real_ip": role_info["origin_ip"], "inner_ip": INNER["origin"]},
        "egress": {"interface": role_info["egress_iface"], "real_ip": role_info["egress_ip"], "inner_ip": INNER["egress"]},
    }
    forger = role_info["forger"]
    spoof = role_info["spoof_ip"]
    spec["origin" if forger == "iran" else "egress"]["source_ip"] = spoof
    return M.validate_spec(spec)


def write_endpoint(M, spec, role, token, pin, cert=None, key=None):
    root = Path(spec["install_dir"])
    if root.exists():
        sys.exit("The folder %s already exists; choose another tunnel name." % root)
    os.umask(0o077)
    os.makedirs(root / role, mode=0o700)
    os.chmod(root, 0o700)
    os.chmod(root / role, 0o700)
    files = {
        "gre.json": M.json_bytes(M.gre_config(spec, role)),
        "token": (token + "\n").encode(),
        "pin.sha256": (pin + "\n").encode(),
        "run.sh": M.launcher(spec, role, pin),
        "check.sh": M.launcher(spec, role, pin, True),
        "ununknowntun-gre-%s.service" % spec["pair_id"]: M.service(spec, role),
    }
    if cert:
        files["server.crt"] = cert
    if key:
        files["server.key"] = key
    for name, data in files.items():
        fd = os.open(root / role / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)


def encode_link(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return "uutspoof://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_link(link):
    link = "".join(link.split())
    if not link.startswith("uutspoof://"):
        sys.exit("Invalid link: it must start with uutspoof://")
    body = link[len("uutspoof://"):]
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        for key, kind in (("v", int), ("n", str), ("f", str), ("i", str), ("fg", str), ("sp", str), ("tp", int), ("t", str), ("p", str)):
            if not isinstance(payload[key], kind):
                raise ValueError(key)
        if payload["v"] != 1 or payload["fg"] not in ("iran", "foreign"):
            raise ValueError("version")
        if not re.fullmatch(r"[0-9a-f]{64}", payload["t"]) or not re.fullmatch(r"[0-9a-f]{64}", payload["p"]):
            raise ValueError("secret")
    except Exception:
        sys.exit("Invalid link: copy the whole line exactly from the foreign server.")
    return payload


def cmd_foreign(M, a):
    info = {"origin_iface": "eth0", "origin_ip": a.iran_ip, "egress_iface": a.iface, "egress_ip": a.foreign_ip,
            "client_listen": "0.0.0.0:12055", "target_port": a.target_port, "forger": a.forger, "spoof_ip": a.spoof_ip}
    spec = build_spec(M, a, info)
    exe = M.openssl_binary()
    key, cert, pin = M.make_certificate(spec, exe)
    token = secrets.token_hex(32)
    write_endpoint(M, spec, "egress", token, pin, cert=cert, key=key)
    print(encode_link({"v": 1, "n": a.pair, "f": a.foreign_ip, "i": a.iran_ip, "fg": a.forger, "sp": a.spoof_ip,
                       "tp": a.target_port, "t": token, "p": pin}))


def cmd_iran(M, a):
    p = decode_link(a.link)
    a.pair = p["n"]
    info = {"origin_iface": a.iface, "origin_ip": p["i"], "egress_iface": "eth0", "egress_ip": p["f"],
            "client_listen": "0.0.0.0:%d" % a.listen_port, "target_port": p["tp"], "forger": p["fg"], "spoof_ip": p["sp"]}
    spec = build_spec(M, a, info)
    write_endpoint(M, spec, "origin", p["t"], p["p"])
    print("PAIR=%s IRAN_IP=%s FOREIGN_IP=%s FORGER=%s SPOOF=%s TARGET=%d" % (p["n"], p["i"], p["f"], p["fg"], p["sp"], p["tp"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spair", required=True, help="path to spoof-pair.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("foreign")
    f.add_argument("--pair", required=True)
    f.add_argument("--binary", required=True)
    f.add_argument("--foreign-ip", required=True)
    f.add_argument("--iface", required=True)
    f.add_argument("--iran-ip", required=True)
    f.add_argument("--forger", choices=("iran", "foreign"), default="iran")
    f.add_argument("--spoof-ip", required=True)
    f.add_argument("--target-port", type=int, required=True)
    i = sub.add_parser("iran")
    i.add_argument("--link", required=True)
    i.add_argument("--binary", required=True)
    i.add_argument("--iface", required=True)
    i.add_argument("--listen-port", type=int, required=True)
    n = sub.add_parser("info")
    n.add_argument("--link", required=True)
    a = ap.parse_args()
    if a.cmd == "info":
        p = decode_link(a.link)
        print("%s %s %s %s %s %d" % (p["n"], p["f"], p["i"], p["fg"], p["sp"], p["tp"]))
        return 0
    M = load_pair_module(a.spair)
    try:
        (cmd_foreign if a.cmd == "foreign" else cmd_iran)(M, a)
    except M.PairError as exc:
        sys.exit("Error: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
