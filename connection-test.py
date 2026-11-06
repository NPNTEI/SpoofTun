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
RESULTS = []


def report(name, ok, detail):
    RESULTS.append((name, ok))
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name:<28} {detail}")


def connect(host, port, timeout, ctx=None):
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=None) if ctx else raw


def test_icmp(host, count=5):
    if not shutil.which("ping"):
        report("ICMP echo", False, "ping command not installed")
        return
    out = subprocess.run(["ping", "-c", str(count), "-W", "2", host], capture_output=True, text=True).stdout
    loss = None
    avg = None
    for line in out.splitlines():
        if "packet loss" in line:
            for tok in line.split(","):
                if "loss" in tok:
                    loss = tok.strip().split("%")[0]
        if line.startswith(("rtt", "round-trip")):
            avg = line.split("=")[1].split("/")[1]
    ok = loss is not None and float(loss) < 100
    report("ICMP echo (ping)", ok, f"loss {loss}%  avg {avg} ms" if ok else "no reply (ICMP blocked or host down)")


def stream_checks(label, host, port, token, ctx, timeout):
    try:
        began = time.monotonic()
        conn = connect(host, port, timeout, ctx)
        setup_ms = (time.monotonic() - began) * 1000
        conn.settimeout(timeout)
        conn.sendall(f"TOKEN {token}\n".encode())
        if recv_line(conn) != "OK":
            report(f"{label} connect", False, "server rejected token")
            return
        extra = f" ({conn.version()})" if ctx else ""
        sample = os.urandom(512)
        began = time.monotonic()
        conn.sendall(b"ECHO 512\n" + sample)
        good = recv_exact(conn, 512) == sample
        rtt = (time.monotonic() - began) * 1000
        report(f"{label} connect + echo", good, f"setup {setup_ms:.0f} ms, echo {rtt:.0f} ms{extra}")
        size = 8 << 20
        began = time.monotonic()
        conn.sendall(f"BLAST {size}\n".encode())
        recv_exact(conn, size)
        down = size * 8 / (time.monotonic() - began) / 1e6
        began = time.monotonic()
        conn.sendall(f"SINK {size}\n".encode())
        block = b"\0" * CHUNK
        sent = 0
        while sent < size:
            conn.sendall(block[:min(CHUNK, size - sent)])
            sent += CHUNK
        recv_line(conn)
        up = size * 8 / (time.monotonic() - began) / 1e6
        report(f"{label} throughput", True, f"download {down:.1f} Mbit/s, upload {up:.1f} Mbit/s (8 MiB)")
        conn.close()
    except Exception as exc:
        report(f"{label} connect + echo", False, f"{type(exc).__name__}: {exc}")


def test_websocket(host, port, ctx, timeout):
    try:
        conn = connect(host, port, timeout, ctx)
        conn.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        conn.sendall((f"GET /uut HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        status = recv_line(conn)
        while recv_line(conn):
            pass
        if "101" not in status:
            report("WSS WebSocket upgrade", False, status or "no response")
            return
        began = time.monotonic()
        payload = os.urandom(300)
        ws_write(conn, payload, mask=True)
        _, echoed = ws_read(conn)
        report("WSS WebSocket upgrade", echoed == payload, f"frame echo {(time.monotonic() - began) * 1000:.0f} ms")
        conn.close()
    except Exception as exc:
        report("WSS WebSocket upgrade", False, f"{type(exc).__name__}: {exc}")


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
        report("HTTP plain", body.endswith(b"ok"), f"{(time.monotonic() - began) * 1000:.0f} ms")
    except Exception as exc:
        report("HTTP plain", False, f"{type(exc).__name__}: {exc}")


def test_udp(host, port, token, timeout, total=40):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout / 3)
    got, rtts = 0, []
    for i in range(total):
        packet = f"TOKEN {token} {i} ".encode() + os.urandom(200)
        began = time.monotonic()
        sock.sendto(packet, (host, port))
        try:
            data, _ = sock.recvfrom(2048)
            if data == packet:
                got += 1
                rtts.append((time.monotonic() - began) * 1000)
        except socket.timeout:
            pass
    loss = (total - got) * 100 / total
    detail = f"loss {loss:.0f}%" + (f", avg {sum(rtts) / len(rtts):.0f} ms" if rtts else "")
    report("UDP echo", got > 0 and loss <= 50, detail if got else "no reply (UDP blocked or server not listening)")
    burst = 200
    for i in range(burst):
        sock.sendto(f"TOKEN {token} b{i} ".encode() + b"x" * 1000, (host, port))
    sock.settimeout(1.5)
    back = 0
    try:
        while back < burst:
            sock.recvfrom(2048)
            back += 1
    except socket.timeout:
        pass
    report("UDP burst (200 x 1 KB)", back > 0, f"{back}/{burst} returned")


def run_client(args):
    host, p, t = args.host, args.port, args.token
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    print(f"Testing {host} (ports {p}, {p + 1}, {p + 2}) ...\n")
    test_icmp(host)
    stream_checks("TCP", host, p, t, None, args.timeout)
    stream_checks("TLS", host, p + 1, t, ctx, args.timeout)
    test_websocket(host, p + 1, ctx, args.timeout)
    test_http(host, p + 2, args.timeout)
    test_udp(host, p, t, args.timeout)
    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\nSummary: {passed}/{len(RESULTS)} checks passed.")
    print("A blocked protocol here shows what the path between these two servers allows; it does not test a live tunnel.")
    return 0 if passed else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    s = sub.add_parser("server")
    s.add_argument("--port", type=int, default=4500)
    s.add_argument("--token", required=True)
    c = sub.add_parser("client")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, default=4500)
    c.add_argument("--token", required=True)
    c.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()
    if not 1024 <= args.port <= 65533:
        sys.exit("Port must be 1024..65533.")
    if args.role == "server":
        run_server(args)
        return 0
    return run_client(args)


if __name__ == "__main__":
    sys.exit(main())
