#!/usr/bin/env python3
"""UnUnknownTun connection test between two servers (stdlib only).

  server role: python3 connection-test.py server --port 4500 --token SECRET
  client role: python3 connection-test.py client --host SERVER_IP --port 4500 --token SECRET

Ports used on the server: P (TCP+UDP), P+1 (TLS + WebSocket over TLS), P+2 (plain HTTP).
ICMP is tested with the system ping command and needs no listener.
It does not touch any tunnel, service or firewall configuration.
"""
import argparse, base64, hashlib, ipaddress, os, random, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time

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

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(streams)]
        began = time.monotonic()
        for t in threads:
            t.start()
        deadline = began + 45
        for t in threads:
            t.join(max(0.1, deadline - time.monotonic()))
        rates.append(sum(done) * 8 / max(0.001, time.monotonic() - began) / 1e6)
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


# ---------------------------------------------------------------- spoof test
def ip_checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_ip(src, dst, proto, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), os.getpid() & 0xFFFF, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", ip_checksum(header)) + header[12:]
    return header + payload


def build_udp(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data  # checksum 0 is valid for IPv4 UDP


def build_icmp(ident, seq, data):
    body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + data
    return body[:2] + struct.pack("!H", ip_checksum(body)) + body[4:]


def run_spoof_server(args):
    seen = {}
    lock = threading.Lock()
    prefix = f"UUTSPOOF {args.token} ".encode()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", args.port))

    def note(kind, nonce, src):
        with lock:
            seen.setdefault(nonce, {})[kind] = src
        print(f"  received spoof-test {kind} packet, source address seen: {src}", flush=True)

    def icmp_listener():
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError as exc:
            print(f"  ICMP spoof listening unavailable ({exc}); UDP only.")
            return
        while True:
            data, _ = raw.recvfrom(2048)
            ihl = (data[0] & 0x0F) * 4
            if len(data) > ihl + 8 and data[ihl] == 8 and data[ihl + 8:].startswith(prefix):
                nonce = data[ihl + 8 + len(prefix):].split(b" ")[0].decode("latin-1")
                note("ICMP", nonce, socket.inet_ntoa(data[12:16]))

    threading.Thread(target=icmp_listener, daemon=True).start()
    print(f"Spoof listener ready on UDP {args.port} (and raw ICMP). Press Ctrl+C to stop.")
    try:
        while True:
            data, addr = udp.recvfrom(2048)
            if data.startswith(prefix):
                nonce = data[len(prefix):].split(b" ")[0].decode("latin-1")
                note("UDP", nonce, addr[0])
            elif data.startswith(f"UUTREPORT {args.token} ".encode()):
                run = data.split(b" ")[2].decode("latin-1")
                with lock:
                    lines = [f"{n}|{k}|{v}" for n, kinds in seen.items() if n.startswith(run) for k, v in kinds.items()]
                udp.sendto(("\n".join(lines) or "NONE").encode(), addr)
    except KeyboardInterrupt:
        print("\nStopped.")


def run_spoof_client(args):
    print(c(BOLD, f"\n  UnUnknownTun spoof test  →  {args.host}:{args.port}   spoofed source: {args.spoof_ip}"))
    section("This server")
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        report("raw", "Raw socket (root)", True, "can craft IP packets")
    except OSError as exc:
        report("raw", "Raw socket (root)", False, f"{exc} (run as root)")
        print(f"  {c(CYAN, '└' + '─' * 61)}\n")
        return 1
    try:
        with open("/proc/sys/net/ipv4/conf/all/rp_filter") as handle:
            rp = handle.read().strip()
        report("rp", "rp_filter (this server)", True, {"0": "off", "1": "strict (affects replies only)", "2": "loose"}.get(rp, rp), warn=False)
    except OSError:
        pass
    run = os.urandom(4).hex()
    section("Sending spoofed packets")
    for i in range(args.count):
        nonce = f"{run}{i:02d}"
        payload = f"UUTSPOOF {args.token} {nonce} ".encode() + b"x" * 40
        raw.sendto(build_ip(args.spoof_ip, args.host, socket.IPPROTO_UDP, build_udp(40000 + i, args.port, payload)), (args.host, 0))
        raw.sendto(build_ip(args.spoof_ip, args.host, socket.IPPROTO_ICMP, build_icmp(os.getpid() & 0xFFFF, i, payload)), (args.host, 0))
        time.sleep(0.05)
    print(f"  {c(CYAN, '│')} sent {args.count} UDP + {args.count} ICMP packets with source {args.spoof_ip}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    reply = ""
    for _ in range(3):
        sock.sendto(f"UUTREPORT {args.token} {run}".encode(), (args.host, args.port))
        try:
            reply = sock.recvfrom(4096)[0].decode("latin-1")
            break
        except socket.timeout:
            continue
    section("Result")
    got = {"UDP": [], "ICMP": []}
    if reply and reply != "NONE":
        for line in reply.splitlines():
            _, kind, src = line.split("|")
            got[kind].append(src)
    if not reply:
        report("rep", "Listener report", False, "no answer: check the link/port and that UDP is open on the listener")
        print(f"  {c(CYAN, '└' + '─' * 61)}\n")
        return 1
    for kind in ("UDP", "ICMP"):
        sources = got[kind]
        if not sources:
            report(kind, f"Spoofed {kind}", False, f"0/{args.count} arrived: provider filters forged sources (or ICMP not listened)")
        elif all(s == args.spoof_ip for s in sources):
            report(kind, f"Spoofed {kind}", True, f"{len(sources)}/{args.count} arrived with source {args.spoof_ip}  → spoofing WORKS")
        else:
            report(kind, f"Spoofed {kind}", False, f"arrived but source was rewritten to {sorted(set(sources))[0]} (NAT)")
    ok = any(got[k] and all(s == args.spoof_ip for s in got[k]) for k in got)
    verdict = c(GREEN, "IP source spoofing works on this path: spoof/GRE tunnels can be used.") if ok else \
        c(RED, "Spoofing is blocked on this path. Do not use spoof/GRE; use Quick tunnel (TLS) or CDN.")
    print(f"  {c(CYAN, '│')} {verdict}")
    print(f"  {c(CYAN, '└' + '─' * 61)}\n")
    return 0 if ok else 1


def sample_range(cidr, count):
    net = ipaddress.ip_network(cidr, strict=False)
    size = net.num_addresses
    if size <= 2:
        return [str(net.network_address)]
    picks, seen = [], set()
    tries = 0
    while len(picks) < min(count, size - 2) and tries < count * 20:
        tries += 1
        offset = random.randrange(1, size - 1) if size > 256 else random.randrange(1, size - 1)
        ip = str(net.network_address + offset)
        if ip not in seen:
            seen.add(ip)
            picks.append(ip)
    return picks


def local_ip_for(host):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def run_spoof_scan(args):
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except OSError as exc:
        print(f"Raw socket unavailable ({exc}). Run as root.")
        return 1
    mine = args.my_ip or local_ip_for(args.host)
    ranges = [(f"{mine} (real IP)", f"{mine}/32", "baseline: NOT forged")]
    for bits in (24, 20, 16, 12, 8):
        ranges.append((f"{mine}/{bits}", str(ipaddress.ip_network(f"{mine}/{bits}", strict=False)), "this server's own range"))
    target_net = str(ipaddress.ip_network(f"{args.host}/24", strict=False))
    ranges.append((f"{args.host}/24", target_net, "receiver's /24"))
    for extra in [x.strip() for x in (args.ranges or "").split(",") if x.strip()]:
        try:
            ranges.append((extra, str(ipaddress.ip_network(extra, strict=False)), "custom"))
        except ValueError:
            print(f"Ignoring invalid range: {extra}")
    print(c(BOLD, f"\n  UnUnknownTun spoof RANGE scan  →  {args.host}:{args.port}   own IP: {mine}"))
    plan, index = [], 0
    for label, cidr, note in ranges:
        ips = sample_range(cidr, args.samples)
        plan.append((label, cidr, note, [(index + i, ip) for i, ip in enumerate(ips)]))
        index += len(ips)
    if index > 200:
        print("Too many sample addresses (max 200). Reduce ranges.")
        return 1
    run = os.urandom(4).hex()
    section("Sending")
    for _, _, _, items in plan:
        for idx, ip in items:
            payload = f"UUTSPOOF {args.token} {run}{idx:03d} ".encode() + b"x" * 32
            for _ in range(2):
                raw.sendto(build_ip(ip, args.host, socket.IPPROTO_UDP, build_udp(41000 + idx, args.port, payload)), (args.host, 0))
            time.sleep(0.01)
    print(f"  {c(CYAN, '│')} sent {index} forged source addresses from {len(plan)} ranges")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    reply = ""
    for _ in range(3):
        sock.sendto(f"UUTREPORT {args.token} {run}".encode(), (args.host, args.port))
        try:
            reply = sock.recvfrom(65000)[0].decode("latin-1")
            break
        except socket.timeout:
            continue
    if not reply:
        print(c(RED, "  No answer from the receiver: check the link, port and UDP firewall."))
        return 1
    arrived = {}
    if reply != "NONE":
        for line in reply.splitlines():
            nonce, kind, src = line.split("|")
            if kind == "UDP":
                arrived[int(nonce[8:])] = src
    section("Which source ranges are allowed")
    passing = []
    for label, cidr, note, items in plan:
        ok = sum(1 for idx, ip in items if arrived.get(idx) == ip)
        total = len(items)
        status = "✔ PASS" if ok == total else ("▲ PART" if ok else "✘ FAIL")
        col = GREEN if ok == total else (YELLOW if ok else RED)
        if ok:
            passing.append((label, cidr))
        print(f"  {c(CYAN, '│')} {c(col, status)}  {c(BOLD, f'{label:<20}')} {ok}/{total} passed  {c(DIM, note)}")
    print(f"  {c(CYAN, '│')}")
    baseline_ok = arrived.get(plan[0][3][0][0]) == plan[0][3][0][1]
    if not baseline_ok:
        print(f"  {c(CYAN, '│')} {c(YELLOW, 'Baseline FAILED: even a packet with your real IP did not arrive.')}")
        print(f"  {c(CYAN, '│')} {c(YELLOW, 'Result is inconclusive: check the UDP firewall/port on the receiver and that this IP is the real outgoing IP.')}")
    elif not passing[1:]:
        print(f"  {c(CYAN, '│')} {c(RED, 'Baseline passed but every forged source failed: this path really filters spoofed sources.')}")
    else:
        names = ", ".join(str(ipaddress.ip_network(cidr)) for _, cidr in passing[1:] or passing)
        print(f"  {c(CYAN, '│')} {c(GREEN, 'Forged sources are accepted from: ' + names)}")
        print(f"  {c(CYAN, '│')} {c(DIM, 'Use a source IP inside a passing range for spoof/GRE tunnels. FAIL ranges are filtered.')}")
    print(f"  {c(CYAN, '└' + '─' * 61)}\n")
    return 0


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
    ss = sub.add_parser("spoof-server")
    ss.add_argument("--port", type=int, default=4510)
    ss.add_argument("--token", required=True)
    sc = sub.add_parser("spoof-client")
    sc.add_argument("--host", required=True)
    sc.add_argument("--port", type=int, default=4510)
    sc.add_argument("--token", required=True)
    sc.add_argument("--spoof-ip", default="")
    sc.add_argument("--count", type=int, default=5)
    sc.add_argument("--scan", action="store_true")
    sc.add_argument("--ranges", default="")
    sc.add_argument("--samples", type=int, default=4)
    sc.add_argument("--my-ip", default="")
    args = ap.parse_args()
    if args.role == "spoof-server":
        run_spoof_server(args)
        return 0
    if args.role == "spoof-client":
        if args.scan:
            return run_spoof_scan(args)
        if not args.spoof_ip:
            sys.exit("--spoof-ip is required unless --scan is used.")
        return run_spoof_client(args)
    if not 1024 <= args.port <= 65533:
        sys.exit("Port must be 1024..65533.")
    if args.role == "server":
        run_server(args)
        return 0
    return run_client(args)


if __name__ == "__main__":
    sys.exit(main())
