#!/usr/bin/env python3
"""UnUnknownTun web panel (stdlib only). Manages quick tunnels and runs path tests.

Runs as root behind HTTPS (self-signed) with a random password, login rate limiting,
CSRF protection and strict input validation. All actions use fixed argument lists;
no shell is ever invoked. Tunnel creation reuses the installer non-interactively.
"""
import argparse, collections, hashlib, hmac, http.server, json, os, re, secrets, shutil, signal, socket, ssl, subprocess, sys, tempfile, threading, time
from pathlib import Path
from urllib.parse import urlparse

QUICK_DIR = Path("/etc/ununknowntun/quick")
SPOOF_ROOT = Path("/etc/ununknowntun-gre")
INSTALLER = "/opt/ununknowntun/installer.sh"
CONNTEST = "/opt/ununknowntun/panel/connection-test.py"
WEB_DIR = Path("/opt/ununknowntun/panel/web")
SESSION_SECONDS = 12 * 3600
MAX_BODY = 65536

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,23}\Z")
IPV4 = re.compile(r"((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)\Z")
IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
LINK_TLS = re.compile(r"uutun://[0-9a-f]{64}@[0-9.]+:\d{1,5}\?fp=[0-9a-f]{64}&sni=[A-Za-z0-9.-]+#[a-z0-9-]{1,24}\Z")
LINK_SPOOF = re.compile(r"uutspoof://[A-Za-z0-9_-]{100,900}\Z")
LINK_TEST = re.compile(r"uut://[^:/\s]{1,253}:\d{4,5}/[0-9a-f]{24}\Z")
LINK_SPOOF_TEST = re.compile(r"uuts://[^:/\s]{1,253}:\d{4,5}/[0-9a-f]{24}\Z")
PORTS = re.compile(r"\d{1,5}(=\d{1,5})?(,\d{1,5}(=\d{1,5})?){0,15}\Z")
SNI = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}\Z")
CIDRS = re.compile(r"[0-9./,]{0,200}\Z")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

STATE_DIR = Path("/etc/ununknowntun/panel")
SESSIONS = {}
HISTORY = 22
METRICS = {"cpu": collections.deque(maxlen=HISTORY), "rx": collections.deque(maxlen=HISTORY), "tx": collections.deque(maxlen=HISTORY),
           "cpu_now": 0.0, "rx_total": 0, "tx_total": 0}
PING = {}
PANEL_VERSION = "3.7.0-preview.11"
SESSION_LOCK = threading.Lock()
FAILS = {}
TEST_PROC = {"proc": None, "kind": "", "link": "", "started": 0.0, "log": None}
TEST_LOCK = threading.Lock()


def clean(text):
    return ANSI.sub("", text).replace("\r", "")


def run(argv, timeout=60, env=None, stdin=None):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, input=stdin)
        return done.returncode, clean(done.stdout + done.stderr)
    except subprocess.TimeoutExpired as exc:
        return 124, clean((exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")) + "\n[timed out]"
    except OSError as exc:
        return 127, str(exc)


# ------------------------------------------------------------------ auth
def auth_path():
    return STATE_DIR / "auth.json"


def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def set_password_value(password):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    salt = secrets.token_bytes(16)
    data = {"salt": salt.hex(), "hash": hash_password(password, salt).hex()}
    fd = os.open(auth_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle)


def set_password():
    password = secrets.token_urlsafe(15)
    set_password_value(password)
    return password


def check_password(password):
    try:
        data = json.loads(auth_path().read_text())
        expected = bytes.fromhex(data["hash"])
        return hmac.compare_digest(hash_password(password, bytes.fromhex(data["salt"])), expected)
    except (OSError, ValueError, KeyError):
        return False


# ------------------------------------------------------------------ tunnels
def parse_env(path):
    values = {}
    try:
        for line in path.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def uptime_seconds():
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        return 0.0


def unit_stats(unit):
    code, out = run(["systemctl", "show", unit, "-p", "ActiveEnterTimestampMonotonic", "-p", "IPIngressBytes", "-p", "IPEgressBytes", "-p", "ActiveState"], 10)
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    active = values.get("ActiveState") == "active"
    up = 0
    try:
        up = max(0, int(uptime_seconds() - int(values.get("ActiveEnterTimestampMonotonic", "0")) / 1e6)) if active else 0
    except ValueError:
        pass

    def num(key):
        v = values.get(key, "")
        return int(v) if v.isdigit() and int(v) < 2 ** 63 else None
    return {"active": active, "up": up, "rx": num("IPIngressBytes"), "tx": num("IPEgressBytes")}


def list_tunnels():
    items = []
    if QUICK_DIR.is_dir():
        for directory in sorted(QUICK_DIR.iterdir()):
            info = parse_env(directory / "info.env")
            if not info or not NAME.fullmatch(directory.name):
                continue
            prefix = info.get("PREFIX") or "ununknowntun-quick-"
            stats = [unit_stats(f"{prefix}{unit}.service") for unit in info.get("UNITS", "").split()]
            rx = [x["rx"] for x in stats if x["rx"] is not None]
            tx = [x["tx"] for x in stats if x["tx"] is not None]
            hist = list(PING.get(directory.name, []))
            items.append({"name": directory.name, "role": info.get("ROLE", "?"),
                          "type": "spoof" if info.get("TYPE") == "spoof" else "tls",
                          "detail": (info.get("MAP") or info.get("PORT") or "").replace("=", " → "),
                          "remote": info.get("FOREIGN", ""), "running": bool(stats) and all(x["active"] for x in stats),
                          "up": min((x["up"] for x in stats), default=0), "rx": sum(rx) if rx else None, "tx": sum(tx) if tx else None,
                          "ping": hist, "has_link": (directory / "link.txt").is_file()})
    return items


def read_cpu():
    try:
        fields = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        return fields[3] + fields[4], sum(fields)
    except (OSError, ValueError, IndexError):
        return 0, 0


def read_net():
    rx = tx = 0
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            name, data = line.split(":", 1)
            if name.strip() == "lo":
                continue
            parts = data.split()
            rx += int(parts[0])
            tx += int(parts[8])
    except (OSError, ValueError, IndexError):
        pass
    return rx, tx


def tcp_ping(host, port):
    began = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=2):
            return round((time.monotonic() - began) * 1000)
    except OSError:
        return None


def sampler():
    last_idle, last_total = read_cpu()
    last_rx, last_tx = read_net()
    last_time = time.monotonic()
    tick = 0
    while True:
        time.sleep(3)
        tick += 1
        idle, total = read_cpu()
        if total > last_total:
            METRICS["cpu_now"] = 100.0 * (1 - (idle - last_idle) / (total - last_total))
        last_idle, last_total = idle, total
        METRICS["cpu"].append(round(METRICS["cpu_now"], 1))
        rx, tx = read_net()
        now = time.monotonic()
        dt = max(0.1, now - last_time)
        METRICS["rx"].append(round(max(0, rx - last_rx) * 8 / dt / 1e6, 2))
        METRICS["tx"].append(round(max(0, tx - last_tx) * 8 / dt / 1e6, 2))
        METRICS["rx_total"], METRICS["tx_total"] = rx, tx
        last_rx, last_tx, last_time = rx, tx, now
        if tick % 2 == 0:
            try:
                for item in list_tunnel_targets():
                    name, host, port = item
                    ms = tcp_ping(host, port)
                    PING.setdefault(name, collections.deque(maxlen=HISTORY)).append(ms)
            except Exception:
                pass


def list_tunnel_targets():
    targets = []
    if QUICK_DIR.is_dir():
        for directory in QUICK_DIR.iterdir():
            info = parse_env(directory / "info.env")
            remote = info.get("FOREIGN", "")
            m = re.fullmatch(r"([0-9.]+):(\d{1,5})", remote)
            if m and NAME.fullmatch(directory.name):
                targets.append((directory.name, m.group(1), int(m.group(2))))
    return targets


def system_info():
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            mem[key] = int(value.split()[0]) * 1024
    except (OSError, ValueError):
        pass
    total = mem.get("MemTotal", 0)
    used = total - mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_used = swap_total - mem.get("SwapFree", 0)
    disk = shutil.disk_usage("/")
    os_name = parse_env(Path("/etc/os-release")).get("PRETTY_NAME", "Linux").strip('"')
    try:
        load = os.getloadavg()
    except OSError:
        load = (0, 0, 0)
    return {"host": socket.gethostname(), "os": os_name, "version": PANEL_VERSION, "cores": os.cpu_count() or 1,
            "load": [round(x, 2) for x in load], "uptime": int(uptime_seconds()),
            "cpu": {"now": round(METRICS["cpu_now"], 1), "hist": list(METRICS["cpu"])},
            "mem": {"used": used, "total": total, "pct": round(100 * used / total, 1) if total else 0},
            "swap": {"used": swap_used, "total": swap_total, "pct": round(100 * swap_used / swap_total, 1) if swap_total else 0},
            "disk": {"used": disk.used, "total": disk.total, "pct": round(100 * disk.used / disk.total, 1)},
            "net": {"rx": list(METRICS["rx"]), "tx": list(METRICS["tx"]), "rx_total": METRICS["rx_total"], "tx_total": METRICS["tx_total"]}}


def tunnel_units(name):
    if not NAME.fullmatch(name):
        raise ValueError("bad name")
    info = parse_env(QUICK_DIR / name / "info.env")
    if not info:
        raise ValueError("unknown tunnel")
    prefix = info.get("PREFIX") or "ununknowntun-quick-"
    return info, [f"{prefix}{unit}.service" for unit in info.get("UNITS", "").split() if NAME.fullmatch(unit) or re.fullmatch(r"[a-z0-9-]+", unit)]


def tunnel_action(name, action):
    info, units = tunnel_units(name)
    out = []
    if action in ("start", "stop", "restart"):
        for unit in units:
            out.append(run(["systemctl", action, unit], 30)[1])
        return "OK: " + action
    if action == "remove":
        for unit in units:
            run(["systemctl", "disable", "--now", unit], 30)
            try:
                os.unlink(f"/etc/systemd/system/{unit}")
            except OSError:
                pass
        run(["systemctl", "daemon-reload"], 30)
        extra = info.get("EXTRA_DIR", "")
        if extra.startswith(str(SPOOF_ROOT) + "/") and ".." not in extra:
            shutil.rmtree(extra, ignore_errors=True)
        shutil.rmtree(QUICK_DIR / name, ignore_errors=True)
        return "Removed " + name
    raise ValueError("bad action")


def defaults():
    ip, iface = "", ""
    code, out = run(["ip", "-4", "route", "get", "1.1.1.1"], 5)
    if code == 0:
        m = re.search(r" src (\d+\.\d+\.\d+\.\d+)", out)
        d = re.search(r" dev (\S+)", out)
        ip, iface = (m.group(1) if m else ""), (d.group(1) if d else "")
    return {"ip": ip, "iface": iface}


# ------------------------------------------------------------------ installer-driven creation
def run_installer(command, answers, timeout=150):
    handle = tempfile.NamedTemporaryFile("w", delete=False, prefix="uut-answers-", dir="/run" if os.path.isdir("/run") else None)
    try:
        os.chmod(handle.name, 0o600)
        for key, value in answers.items():
            if "\t" in key or "\n" in key or "\t" in value or "\n" in value:
                raise ValueError("bad characters")
            handle.write(f"{key}\t{value}\n")
        handle.close()
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "UUT_ANSWERS": handle.name, "LC_ALL": "C.UTF-8", "TERM": "dumb"}
        return run(["bash", INSTALLER, command], timeout, env, stdin="")
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def need(body, key, pattern, label):
    value = str(body.get(key, "")).strip()
    if not pattern.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value


def port_of(body, key, label, low=1):
    value = str(body.get(key, "")).strip()
    if not value.isdigit() or not low <= int(value) <= 65535:
        raise ValueError(f"Invalid {label}")
    return value


def create(kind, body):
    if kind == "quick-foreign":
        a = {"Tunnel name": need(body, "name", NAME, "name"),
             "This foreign server's public IPv4": need(body, "ip", IPV4, "IP"),
             "Tunnel port (Iran connects to this port)": port_of(body, "port", "port")}
        sni = str(body.get("sni", "")).strip()
        if sni:
            if not SNI.fullmatch(sni):
                raise ValueError("Invalid TLS name")
            a["Change the TLS name (SNI) shown to the network? Default: www.speedtest.net (y/n)"] = "y"
            a["TLS name (SNI)"] = sni
        else:
            a["Change the TLS name (SNI) shown to the network? Default: www.speedtest.net (y/n)"] = "n"
        return run_installer("quick-foreign", a)
    if kind == "quick-iran":
        ports = need(body, "ports", PORTS, "ports").replace(" ", "")
        a = {"Paste the link from the foreign server (uutun://...)": need(body, "link", LINK_TLS, "link"), "Ports to forward": ports,
             "Install anyway (it will keep retrying)? (y/n)": "n"}
        if body.get("advanced"):
            prof = str(body.get("fingerprint", "1"))
            if prof not in ("1", "2", "3"):
                raise ValueError("Invalid fingerprint")
            a["Change advanced options (browser fingerprint, TLS fragment, sessions)? (y/n)"] = "y"
            a["Fingerprint"] = prof
            a["Enable TLS ClientHello fragmentation (helps against some DPI)? (y/n)"] = "y" if body.get("fragment") else "n"
            sessions = str(body.get("sessions", "8"))
            if not sessions.isdigit() or not 2 <= int(sessions) <= 32:
                raise ValueError("Invalid sessions")
            a["Parallel tunnel sessions (2-32)"] = sessions
        return run_installer("quick-iran", a)
    if kind == "spoof-foreign":
        a = {"Tunnel name": need(body, "name", NAME, "name"),
             "Iran server public IPv4": need(body, "iran_ip", IPV4, "Iran IP"),
             "This foreign server's real IPv4 (assigned on the interface)": need(body, "ip", IPV4, "IP"),
             "Network interface": need(body, "iface", IFACE, "interface"),
             "Select": "1" if body.get("forger", "iran") == "iran" else "2",
             "Forged source IP (an IP inside a range that PASSED the Spoof test)": need(body, "spoof_ip", IPV4, "forged IP"),
             "Port of the service on THIS server to forward to (e.g. your Xray inbound)": port_of(body, "target", "target port")}
        return run_installer("quick-spoof-foreign", a)
    if kind == "spoof-iran":
        a = {"Paste the link from the foreign server (uutspoof://...)": need(body, "link", LINK_SPOOF, "link"),
             "Network interface": need(body, "iface", IFACE, "interface"),
             "Port users connect to on THIS Iran server (1024-65535)": port_of(body, "port", "port", 1024),
             "Install and start anyway (it keeps retrying)? (y/n)": "n"}
        return run_installer("quick-spoof-iran", a)
    raise ValueError("unknown kind")


# ------------------------------------------------------------------ tests
def stop_listener():
    with TEST_LOCK:
        proc = TEST_PROC["proc"]
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        TEST_PROC.update(proc=None, kind="", link="")


def start_listener(kind, host, port):
    stop_listener()
    token = secrets.token_hex(12)
    role = "server" if kind == "conn" else "spoof-server"
    log = tempfile.TemporaryFile("w+")
    proc = subprocess.Popen(["python3", "-I", CONNTEST, role, "--port", str(port), "--token", token],
                            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    scheme = "uut" if kind == "conn" else "uuts"
    link = f"{scheme}://{host}:{port}/{token}"
    with TEST_LOCK:
        TEST_PROC.update(proc=proc, kind=kind, link=link, started=time.time(), log=log)
    threading.Timer(1200, lambda: stop_listener() if TEST_PROC["proc"] is proc else None).start()
    return link


def listener_status():
    with TEST_LOCK:
        proc = TEST_PROC["proc"]
        running = bool(proc and proc.poll() is None)
        log = ""
        if TEST_PROC["log"] is not None:
            TEST_PROC["log"].flush()
            TEST_PROC["log"].seek(0)
            log = clean(TEST_PROC["log"].read())[-3000:]
        return {"running": running, "kind": TEST_PROC["kind"], "link": TEST_PROC["link"] if running else "", "log": log}


def run_test(body):
    kind = body.get("kind")
    link = str(body.get("link", "")).strip()
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
    if kind == "conn":
        if not LINK_TEST.fullmatch(link):
            raise ValueError("Invalid link")
        host, rest = link[len("uut://"):].split(":", 1)
        port, token = rest.split("/", 1)
        return run(["python3", "-I", CONNTEST, "client", "--host", host, "--port", port, "--token", token], 240, env)
    if kind == "spoof":
        if not LINK_SPOOF_TEST.fullmatch(link):
            raise ValueError("Invalid link")
        host, rest = link[len("uuts://"):].split(":", 1)
        port, token = rest.split("/", 1)
        argv = ["python3", "-I", CONNTEST, "spoof-client", "--host", host, "--port", port, "--token", token]
        if body.get("mode") == "scan":
            ranges = str(body.get("ranges", "")).strip()
            if not CIDRS.fullmatch(ranges):
                raise ValueError("Invalid ranges")
            argv += ["--scan", "--my-ip", need(body, "my_ip", IPV4, "own IP")]
            if ranges:
                argv += ["--ranges", ranges]
        else:
            argv += ["--spoof-ip", need(body, "spoof_ip", IPV4, "forged IP")]
        return run(argv, 240, env)
    raise ValueError("unknown test")


# ------------------------------------------------------------------ HTTP
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "UUTPanel"
    sys_version = ""
    timeout = 30

    def log_message(self, *args):
        pass

    def send_json(self, data, code=200, cookie=None):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.security_headers()
        self.end_headers()
        self.wfile.write(raw)

    def security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

    def session(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"uut_session=([A-Za-z0-9_-]{20,64})", cookie)
        if not m:
            return None
        with SESSION_LOCK:
            item = SESSIONS.get(m.group(1))
            if item and item["expires"] > time.time():
                return item
            SESSIONS.pop(m.group(1), None)
        return None

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("too large")
        if length == 0:
            return {}
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("bad body")
        return data

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/app.js", "/app.css"):
            name = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/app.css": "app.css"}[path]
            raw = (WEB_DIR / name).read_bytes()
            ctype = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8"}[name]
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.security_headers()
            self.end_headers()
            self.wfile.write(raw)
            return
        sess = self.session()
        if path == "/api/session":
            return self.send_json({"auth": bool(sess), "csrf": sess["csrf"] if sess else ""})
        if not sess:
            return self.send_json({"error": "login required"}, 401)
        try:
            if path == "/api/tunnels":
                return self.send_json({"tunnels": list_tunnels()})
            if path == "/api/defaults":
                return self.send_json(defaults())
            if path == "/api/system":
                return self.send_json(system_info())
            if path == "/api/test/status":
                return self.send_json(listener_status())
            m = re.fullmatch(r"/api/tunnel/([a-z0-9-]{1,24})/(logs|link)", path)
            if m:
                info, units = tunnel_units(m.group(1))
                if m.group(2) == "link":
                    link = QUICK_DIR / m.group(1) / "link.txt"
                    return self.send_json({"text": link.read_text().strip() if link.is_file() else "No link on this server (links exist on the foreign side)."})
                out = "\n".join(run(["journalctl", "-u", unit, "-n", "60", "--no-pager"], 20)[1] for unit in units)
                return self.send_json({"text": out[-6000:]})
        except (ValueError, OSError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        ip = self.client_address[0]
        try:
            body = self.body()
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "bad request"}, 400)
        if path == "/api/login":
            now = time.time()
            fails = [t for t in FAILS.get(ip, []) if now - t < 300]
            if len(fails) >= 5:
                return self.send_json({"error": "Too many attempts. Wait 5 minutes."}, 429)
            password = str(body.get("password", ""))
            if len(password) <= 128 and check_password(password):
                FAILS.pop(ip, None)
                token = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(24)
                with SESSION_LOCK:
                    SESSIONS[token] = {"expires": now + SESSION_SECONDS, "csrf": csrf}
                return self.send_json({"ok": True, "csrf": csrf}, cookie=f"uut_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}")
            fails.append(now)
            FAILS[ip] = fails
            time.sleep(1)
            return self.send_json({"error": "Wrong password."}, 401)
        sess = self.session()
        if not sess or not hmac.compare_digest(self.headers.get("X-CSRF", ""), sess["csrf"]):
            return self.send_json({"error": "login required"}, 401)
        try:
            if path == "/api/logout":
                m = re.search(r"uut_session=([A-Za-z0-9_-]+)", self.headers.get("Cookie", ""))
                with SESSION_LOCK:
                    SESSIONS.pop(m.group(1), None) if m else None
                return self.send_json({"ok": True}, cookie="uut_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
            if path == "/api/restart-all":
                names = [t["name"] for t in list_tunnels()]
                for name in names:
                    tunnel_action(name, "restart")
                return self.send_json({"text": f"Restarted {len(names)} tunnel(s)."})
            if path == "/api/password":
                current, new = str(body.get("current", "")), str(body.get("new", ""))
                if not check_password(current):
                    raise ValueError("Current password is wrong.")
                if not 10 <= len(new) <= 128:
                    raise ValueError("New password must be 10 to 128 characters.")
                set_password_value(new)
                with SESSION_LOCK:
                    SESSIONS.clear()
                return self.send_json({"text": "Password changed. Please sign in again."})
            m = re.fullmatch(r"/api/tunnel/([a-z0-9-]{1,24})/(start|stop|restart|remove)", path)
            if m:
                return self.send_json({"text": tunnel_action(m.group(1), m.group(2))})
            m = re.fullmatch(r"/api/create/(quick-foreign|quick-iran|spoof-foreign|spoof-iran)", path)
            if m:
                code, out = create(m.group(1), body)
                link = re.search(r"(uutun://\S+|uutspoof://\S+)", out)
                return self.send_json({"ok": code == 0, "text": out[-5000:], "link": link.group(1) if (link and code == 0 and m.group(1).endswith("foreign")) else ""})
            if path == "/api/test/listen":
                kind = body.get("kind")
                if kind not in ("conn", "spoof"):
                    raise ValueError("bad kind")
                host = need(body, "host", IPV4, "IP")
                return self.send_json({"link": start_listener(kind, host, int(port_of(body, "port", "port", 1024)))})
            if path == "/api/test/stop":
                stop_listener()
                return self.send_json({"ok": True})
            if path == "/api/test/run":
                code, out = run_test(body)
                return self.send_json({"ok": code == 0, "text": out[-8000:]})
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, 400)
        self.send_json({"error": "not found"}, 404)


def serve(args):
    global STATE_DIR
    STATE_DIR = Path(args.state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(STATE_DIR / "cert.pem", STATE_DIR / "key.pem")
    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    signal.signal(signal.SIGTERM, lambda *_: (stop_listener(), os._exit(0)))
    threading.Thread(target=sampler, daemon=True).start()
    print(f"panel listening on https://{args.bind}:{args.port}", flush=True)
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="/etc/ununknowntun/panel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--bind", default="0.0.0.0")
    sub.add_parser("set-password")
    args = ap.parse_args()
    if args.cmd == "set-password":
        global STATE_DIR
        STATE_DIR = Path(args.state)
        print(set_password())
        return 0
    serve(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
