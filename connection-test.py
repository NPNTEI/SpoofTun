#!/usr/bin/env python3
"""UnUnknownTun connection test between two servers (stdlib only).

  server role: python3 connection-test.py server --port 4500 --token SECRET
  client role: python3 connection-test.py client --host SERVER_IP --port 4500 --token SECRET

Ports used on the server: P (TCP+UDP), P+1 (TLS + WebSocket over TLS), P+2 (plain HTTP).
ICMP is tested with the system ping command and needs no listener.
It does not touch any tunnel, service or firewall configuration.
"""
import argparse, base64, hashlib, os, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CHUNK = 64 * 1024


def recv_line(conn, limit=512):
    data = b""
    while not data.endswith(b"\n") and len(data) < limit:
        piece = conn.recv(1)
        if not piece:
            break
        data += piece
    return data.decode("latin-1").strip()


def recv_exact(conn, count):
    buf = b""
    while len(buf) < count:
        piece = conn.recv(min(CHUNK, count - len(buf)))
        if not piece:
            raise ConnectionError("peer closed")
        buf += piece
    return buf


def ws_read(conn):
    head = recv_exact(conn, 2)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(conn, 8))[0]
    mask = recv_exact(conn, 4) if head[1] & 0x80 else b""
    payload = recv_exact(conn, length)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return head[0] & 0x0F, payload


def ws_write(conn, payload, mask=False):
    head = bytes([0x82])
    if len(payload) < 126:
        head += bytes([len(payload) | (0x80 if mask else 0)])
    else:
        head += bytes([126 | (0x80 if mask else 0)]) + struct.pack(">H", len(payload))
    if mask:
        key = os.urandom(4)
        payload = key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    conn.sendall(head + payload)


# ---------------------------------------------------------------- server
def handle_stream(conn, token, allow_ws):
    conn.settimeout(20)
    first = recv_line(conn)
    if allow_ws and first.startswith("GET "):
        key = ""
        while True:
            line = recv_line(conn)
            if not line:
                break
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        opcode, payload = ws_read(conn)
        ws_write(conn, payload)
        return
    if first != f"TOKEN {token}":
        conn.sendall(b"DENIED\n")
        return
    conn.sendall(b"OK\n")
    while True:
        cmd = recv_line(conn)
        if not cmd:
            return
        parts = cmd.split()
        if parts[0] == "ECHO" and len(parts) == 2:
            conn.sendall(recv_exact(conn, int(parts[1])))
        elif parts[0] == "SINK" and len(parts) == 2:
            recv_exact(conn, min(int(parts[1]), 256 << 20))
            conn.sendall(b"DONE\n")
        elif parts[0] == "BLAST" and len(parts) == 2:
            left = min(int(parts[1]), 256 << 20)
            block = b"\0" * CHUNK
            while left > 0:
                conn.sendall(block[:min(CHUNK, left)])
                left -= CHUNK
        else:
            return


def serve_tcp(port, token, ctx=None, allow_ws=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)

    def one(raw):
        try:
            conn = ctx.wrap_socket(raw, server_side=True) if ctx else raw
            handle_stream(conn, token, allow_ws)
        except Exception:
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass

    while True:
        raw, _ = sock.accept()
        threading.Thread(target=one, args=(raw,), daemon=True).start()


def serve_udp(port, token):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    prefix = f"TOKEN {token} ".encode()
    while True:
        data, addr = sock.recvfrom(2048)
        if data.startswith(prefix):
            sock.sendto(data, addr)


def serve_http(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(32)

    def one(conn):
        try:
            conn.settimeout(10)
            conn.recv(2048)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass
        finally:
            conn.close()

    while True:
        conn, _ = sock.accept()
        threading.Thread(target=one, args=(conn,), daemon=True).start()


def run_server(args):
    workdir = tempfile.mkdtemp(prefix="uut-conntest-")
    cert, key = os.path.join(workdir, "c.pem"), os.path.join(workdir, "k.pem")
    ctx = None
    if shutil.which("openssl"):
        made = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                               "-days", "1", "-subj", "/CN=uut-connection-test"], capture_output=True)
        if made.returncode == 0:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
    shutil.rmtree(workdir, ignore_errors=True)
    p = args.port
    jobs = [(serve_tcp, (p, args.token)), (serve_udp, (p, args.token)), (serve_http, (p + 2,))]
    if ctx:
        jobs.append((serve_tcp, (p + 1, args.token, ctx, True)))
    for fn, a in jobs:
        threading.Thread(target=fn, args=a, daemon=True).start()
    print(f"Listening: TCP+UDP {p}, HTTP {p + 2}" + (f", TLS/WebSocket {p + 1}" if ctx else ", (TLS/WebSocket disabled: openssl not found)"))
    print("Open these ports in the firewall if needed. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nStopped.")


# ---------------------------------------------------------------- client
COLOR = sys.stdout.isatty() or os.environ.get("UUT_COLOR") == "1"
def c(code, text):
    return f"\033[{code}m{text}\033[0m" if COLOR else text
GREEN, RED, YELLOW, CYAN, DIM, BOLD = "32", "31", "33", "36", "2", "1"

RESULTS = {}
SPEEDS = []


def section(title):
    line = "─" * (58 - len(title))
    print(f"\n  {c(CYAN, '┌─ ' + title + ' ' + line)}")


def report(key, name, ok, detail, warn=False):
    RESULTS[key] = ok
    icon = c(GREEN, "✔ PASS") if ok and not warn else (c(YELLOW, "▲ WEAK") if ok else c(RED, "✘ FAIL"))
    print(f"  {c(CYAN, '│')} {icon}  {c(BOLD, f'{name:<24}')} {c(DIM, detail)}")


def bar(value, top, width=16):
    filled = 0 if top <= 0 else max(1 if value > 0 else 0, round(width * value / top))
    return c(GREEN, "█" * filled) + c(DIM, "░" * (width - filled))


def connect(host, port, timeout, ctx=None):
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=None) if ctx else raw


def open_session(host, port, token, ctx, timeout):
    conn = connect(host, port, timeout, ctx)
    conn.settimeout(timeout)
    conn.sendall(f"TOKEN {token}\n".encode())
    if recv_line(conn) != "OK":
        raise PermissionError("listener rejected the token (link mismatch)")
    return conn


def transfer(conn, direction, size):
    if direction == "down":
        conn.sendall(f"BLAST {size}\n".encode())
        recv_exact(conn, size)
    else:
        conn.sendall(f"SINK {size}\n".encode())
        block = b"\0" * CHUNK
        sent = 0
        while sent < size:
            conn.sendall(block[:min(CHUNK, size - sent)])
            sent += CHUNK
        recv_line(conn)


def test_icmp(host, count=6):
    if not shutil.which("ping"):
        report("icmp", "ICMP ping", False, "ping is not installed (apt install iputils-ping)")
        return
    out = subprocess.run(["ping", "-c", str(count), "-i", "0.3", "-W", "2", host], capture_output=True, text=True).stdout
    loss, avg = None, None
    for line in out.splitlines():
        if "packet loss" in line:
            loss = float([t for t in line.split(",") if "loss" in t][0].strip().split("%")[0])
        if line.startswith(("rtt", "round-trip")):
            avg = float(line.split("=")[1].split("/")[1])
    if loss is None or loss >= 100:
        report("icmp", "ICMP ping", False, "no reply: ICMP is blocked on this path")
    else:
        report("icmp", "ICMP ping", True, f"{avg:.0f} ms, loss {loss:.0f}%", warn=loss > 10)


def test_stream(key, label, host, port, token, ctx, timeout):
    try:
        began = time.monotonic()
        conn = open_session(host, port, token, ctx, timeout)
        setup = (time.monotonic() - began) * 1000
        sample = os.urandom(1024)
        began = time.monotonic()
        conn.sendall(b"ECHO 1024\n" + sample)
        good = recv_exact(conn, 1024) == sample
        rtt = (time.monotonic() - began) * 1000
        version = f", {conn.version()}" if ctx else ""
        report(key, label, good, f"handshake {setup:.0f} ms, rtt {rtt:.0f} ms{version}")
        rates = []
        for direction in ("down", "up"):
            began = time.monotonic()
            transfer(conn, direction, 8 << 20)
            rates.append((8 << 20) * 8 / (time.monotonic() - began) / 1e6)
        SPEEDS.append((f"{label} x1", *rates))
        conn.close()
    except Exception as exc:
        report(key, label, False, f"{type(exc).__name__}: {exc}")


def test_parallel(label, host, port, token, ctx, timeout, streams=4, size=4 << 20):
    rates = []
    for direction in ("down", "up"):
        done = []

        def worker():
            try:
                conn = open_session(host, port, token, ctx, timeout)
                transfer(conn, direction, size)
                done.append(size)
                conn.close()
            except Exception:
                pass

        threads = [threading.Thread(target=worker) for _ in range(streams)]
        began = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        rates.append(sum(done) * 8 / (time.monotonic() - began) / 1e6)
    if rates[0] or rates[1]:
        SPEEDS.append((f"{label} x{streams}", *rates))


def test_websocket(host, port, ctx, timeout):
    try:
        conn = connect(host, port, timeout, ctx)
        conn.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        conn.sendall((f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        status = recv_line(conn)
        while recv_line(conn):
            pass
        if "101" not in status:
            report("wss", "WebSocket over TLS", False, status or "no response")
            return
        payload = os.urandom(512)
        began = time.monotonic()
        ws_write(conn, payload, mask=True)
        _, echoed = ws_read(conn)
        report("wss", "WebSocket over TLS", echoed == payload, f"upgrade ok, frame rtt {(time.monotonic() - began) * 1000:.0f} ms")
        conn.close()
    except Exception as exc:
        report("wss", "WebSocket over TLS", False, f"{type(exc).__name__}: {exc}")


def test_http(host, port, timeout):
    try:
        conn = connect(host, port, timeout)
        conn.settimeout(timeout)
        began = time.monotonic()
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        body = b""
        while True:
            piece = conn.recv(4096)
            if not piece:
                break
            body += piece
        report("http", "Plain HTTP", body.endswith(b"ok"), f"response in {(time.monotonic() - began) * 1000:.0f} ms")
    except Exception as exc:
        report("http", "Plain HTTP", False, f"{type(exc).__name__}: {exc}")


def test_udp(host, port, token, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.settimeout(2)
    got, rtts = 0, []
    total = 30
    for i in range(total):
        packet = f"TOKEN {token} e{i} ".encode() + os.urandom(200)
        began = time.monotonic()
        sock.sendto(packet, (host, port))
        try:
            while True:
                data, _ = sock.recvfrom(2048)
                if data == packet:
                    got += 1
                    rtts.append((time.monotonic() - began) * 1000)
                    break
        except socket.timeout:
            pass
    loss = (total - got) * 100 / total
    if not got:
        report("udp", "UDP echo", False, "no reply: UDP is blocked on this path")
        return
    report("udp", "UDP echo", True, f"{sum(rtts) / len(rtts):.0f} ms, loss {loss:.0f}%", warn=loss > 10)
    # Paced stream: 1000 x 1 KB at ~4 Mbit/s, received concurrently.
    received = [0]
    stop = threading.Event()

    def reader():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                sock.recvfrom(2048)
                received[0] += 1
            except socket.timeout:
                continue
            except OSError:
                return

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    count = 1000
    began = time.monotonic()
    for i in range(count):
        sock.sendto(f"TOKEN {token} s{i} ".encode() + b"x" * 1000, (host, port))
        time.sleep(0.002)
    elapsed = time.monotonic() - began
    time.sleep(2)
    stop.set()
    thread.join()
    ratio = received[0] * 100 / count
    rate = received[0] * 1000 * 8 / elapsed / 1e6
    report("udpstream", "UDP stream (1000 x 1 KB)", ratio >= 50, f"{ratio:.0f}% delivered, ~{rate:.1f} Mbit/s paced", warn=ratio < 90)


def recommendations():
    r = RESULTS
    tips = []
    if r.get("tls"):
        tips.append(("Quick tunnel (TLS 1.3 direct)", "works: menu 2 on Foreign → link → menu 1 on Iran", True))
    elif r.get("tcp"):
        tips.append(("Quick tunnel (TLS 1.3 direct)", "TCP works but TLS is filtered: try other port or CDN (WSS)", False))
    else:
        tips.append(("Quick tunnel (TLS 1.3 direct)", "TCP is blocked on this port: pick another port", False))
    tips.append(("WSS / XHTTP via CDN", "WebSocket passes directly" if r.get("wss") else "direct WebSocket blocked: use CDN profile", bool(r.get("wss"))))
    tips.append(("ICMP L3 (menu 8)", "ICMP passes, usable as a fallback" if r.get("icmp") else "ICMP is blocked", bool(r.get("icmp"))))
    tips.append(("UDP traffic (calls, games)", "UDP passes" if r.get("udpstream") else "UDP is blocked or lossy", bool(r.get("udpstream"))))
    for name, text, ok in tips:
        icon = c(GREEN, "●") if ok else c(RED, "○")
        print(f"  {c(CYAN, '│')} {icon} {c(BOLD, f'{name:<30}')} {c(DIM, text)}")


def run_client(args):
    host, p, t = args.host, args.port, args.token
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    print(c(BOLD, f"\n  UnUnknownTun connection test  →  {host}  (ports {p}-{p + 2})"))
    section("Reachability")
    test_icmp(host)
    test_stream("tcp", "TCP", host, p, t, None, args.timeout)
    test_stream("tls", "TLS 1.3", host, p + 1, t, ctx, args.timeout)
    test_websocket(host, p + 1, ctx, args.timeout)
    test_http(host, p + 2, args.timeout)
    test_udp(host, p, t, args.timeout)
    if RESULTS.get("tcp"):
        test_parallel("TCP", host, p, t, None, args.timeout)
    if RESULTS.get("tls"):
        test_parallel("TLS 1.3", host, p + 1, t, ctx, args.timeout)
    if SPEEDS:
        section("Speed  (Mbit/s, download ↓ / upload ↑)")
        top = max(max(d, u) for _, d, u in SPEEDS)
        for name, down, up in SPEEDS:
            print(f"  {c(CYAN, '│')} {c(BOLD, f'{name:<12}')} ↓ {down:7.1f} {bar(down, top)}  ↑ {up:7.1f} {bar(up, top)}")
    section("Which tunnel to use")
    recommendations()
    passed = sum(1 for ok in RESULTS.values() if ok)
    print(f"  {c(CYAN, '└' + '─' * 61)}")
    print(f"  {c(BOLD, f'{passed}/{len(RESULTS)} checks passed')}  {c(DIM, '(path test only; no tunnel was changed)')}\n")
    return 0 if passed else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    s = sub.add_parser("server")
    s.add_argument("--port", type=int, default=4500)
    s.add_argument("--token", required=True)
    cl = sub.add_parser("client")
    cl.add_argument("--host", required=True)
    cl.add_argument("--port", type=int, default=4500)
    cl.add_argument("--token", required=True)
    cl.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()
    if not 1024 <= args.port <= 65533:
        sys.exit("Port must be 1024..65533.")
    if args.role == "server":
        run_server(args)
        return 0
    return run_client(args)


if __name__ == "__main__":
    sys.exit(main())
