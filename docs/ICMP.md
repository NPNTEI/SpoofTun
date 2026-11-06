# ICMP modes — 3.7.0-preview.8 experimental

Two different capabilities, not interchangeable transports:

| Mode | Outer network | Implemented payload |
|---|---|---|
| Native ICMP | IPv4 Echo request/reply between exact real peers | Existing UNUNKNOWNTUN TCP forwarding, through authenticated ICMP plus inner TLS/token |
| ICMP Echo inside WSS | Existing verified/authenticated UNUNKNOWNTUN WSS | Dedicated bounded ping client; egress emits real ICMP Echo to one configured IPv4 target |

The WSS adapter is **not system ping, a TUN, arbitrary ICMP messages or general IP forwarding**. Native ICMP is also not a general host VPN, destination/source spoofing, IPv6 or NAT traversal. Use only authorized peers and targets. No production server/CDN was changed to prepare the release.

## Pair generation and activation boundary

Choosing Foreign/Iran in the installer first asks for the tunnel type: existing managed WSS/XHTTP, native ICMP, ICMP Echo inside WSS, or existing native GRE. The two ICMP branches generate private paired files only; they do not install services or alter existing tunnels. Generate once and copy only each role's directory to that host. Never publish the pair bundle.

Alternatively keep both Python helpers together and run:

```sh
python3 -I icmp-pair.py --output /absolute/new-private-pair
python3 -I icmp-pair.py --check-pair /absolute/new-private-pair
```

The parent directory must exist; output must not. `--mode native-icmp` or `--mode icmp-wss` preselects the interactive choice. `--spec PRIVATE_JSON` is an alternative strict input, not combinable with `--mode`. The generated README includes exact paths and commands. Directories are0700/files0600, owner-only, no symlink paths. Checks do not send traffic or prove reachability.

The commands above are for the ready/install archive. In the source archive use `python3 -I packaging/icmp-pair.py ...`; binary-only install-preview.py is included only in the ready bundles.

The optional `install-preview.py --dry-run` then explicit `--install` puts only the verified executable at `/opt/ununknowntun-gre-preview/3.7.0-preview.8/ununknowntun`; the historical directory name does not restrict it to GRE. Unit files are templates, never activated by pair generation. Start a separate lab pair, not a replacement for a live tunnel.

## Native ICMP

Requires Linux, iproute2, /dev/net/tun and NET_ADMIN+NET_RAW. Fixed locally assigned outer IPv4 addresses are mandatory. An exclusive nonpersistent TUN and exact inner-peer /32 route are owned/cleaned by the process. No default route, host firewall, sysctl, forwarding or echo-response policy change. Physical MTU must cover configured inner MTU+96 bytes; default inner1200. Default polling20ms means modest throughput; this is not a high-throughput release claim.

Generated role launchers use `-icmp-config FILE -transport tls`. Egress first, origin second. Offline check: `-mode ROLE -icmp-config FILE -check-icmp-config`. Explicit origin `-check-tunnel -icmp-config FILE` with all ordinary generated TLS/token flags temporarily sets up the owned underlay, probes TLS/UNUNKNOWNTUN authentication, then closes it; this is not a payload or provider-spoofing test. It must run separately from a service owning the same TUN.

Envelope: exact real peer addresses, direction/type-bound HMAC-SHA256, fresh session/challenge proof, sequence/replay window and one-use bounded polling credits. Inner traffic is restricted to the configured exact TCP pair/port and TLS certificate/token remain required. Kernel automatic Echo reflections are ignored, not disabled; rejection counters can therefore rise on a healthy link. This is neither arbitrary source spoofing nor a reflector. The generated pinned TLS certificate expires after365days; coordinated renewal is manual. Ordinary ping success does not prove this carrier works on a provider.

Native ICMP has no HTTP path, ECH or ordinary CDN proxy. Existing GRE flags are mutually exclusive. Internal session settings apply to the inner TCP carrier, not generation of a new public IP. No claim of seamless loss recovery, WAN performance or DPI resistance.

For explicit native check with `-ca`, use an owned regular0600 CA copy with no symlink components and size at most1MiB; the check snapshots it privately and removes the snapshot afterwards. Generated pairs use certificate pinning and need no CA copy. `-system-ca` uses the system store. This does not promise a deadline on arbitrary filesystem I/O latency.

## ICMP Echo through existing WSS

The generator outputs an egress loopback raw-Echo adapter and an origin unprivileged command. It does not create or change WSS/CDN configuration. Default mapping:

```text
origin -icmp-ping → 127.0.0.1:12056 → existing authenticated GDT WSS
    → egress target/allow 127.0.0.1:18083 → -icmp-relay → fixed authorized target
```

Start the egress generated run.sh with NET_RAW only. Configure a **separate, manually reviewed WSS pair** with that exact mapping and a loopback-only origin listener. The current managed wizard takes port numbers and binds its direct Iran entry to0.0.0.0; it cannot select this private mapping. Do not use that public-entry default for the ping adapter. Start/check the separate WSS pair, then run the origin generated run.sh. Origin needs no raw capability but must own/read its private key/config. `-check-icmp-relay-config FILE` validates either role offline. Adapter CLI rejects unrelated tunnel flags; transport settings belong to the separate WSS service.

Example carrier flags (replace every example path/domain and create a **new** shared private UNUNKNOWNTUN token; do not change a live tunnel):

```sh
# Egress backend behind a separately configured Nginx WSS/TLS endpoint:
ununknowntun -mode egress -transport wss \
  -listen 127.0.0.1:18080 -allow 127.0.0.1:18083 \
  -ws-host tunnel.example.com -ws-path /REPLACE_WITH_NEW_SHARED_RANDOM_PATH \
  -token-file /absolute/private/wss-token

# Origin connects to that verified HTTPS endpoint, exposing ONLY loopback:
ununknowntun -mode origin -transport wss \
  -listen 127.0.0.1:12056 -target 127.0.0.1:18083 \
  -connect tunnel.example.com:443 -ws-host tunnel.example.com \
  -sni tunnel.example.com -system-ca -ech-mode off \
  -ws-path /REPLACE_WITH_NEW_SHARED_RANDOM_PATH \
  -token-file /absolute/private/wss-token
```

These are examples, not turnkey deployment scripts. Nginx must present the matching valid certificate and forward WebSocket Upgrade at the exact shared path to127.0.0.1:18080. Configure/test that TLS endpoint separately; do not expose the backend directly. Shared path, token and optional rotation settings must match both peers. No Iran public HTTPS entry is used. Review resulting listeners before connecting the ping client.

Compatible **interserver** WSS core features remain available: CDN/Cloudflare, verified TLS, optional ECH, path rotation/recovery, MUX and padding. They need matching settings in this separate carrier; the adapter generator does not configure them. The loopback ping entry is not an Iran public HTTPS/Xray entry. WSS services gain no raw privileges. Encapsulating Echo does not bypass a blocked WSS or ECH handshake; use the permitted working TLS configuration, not disabled certificate verification.

Each relay is restricted to one literal authorized IPv4 target, four clients, globally one actual Echo/sec, ten requests per connection, a120s connection cap,16..256 configurable payload bytes and250..10000ms probe timeout. Authentication is a separate shared32byte key, fresh mutual challenge and per-message MAC/session/sequence/nonces. Actual Echo replies must match source, checksum, ID, sequence and complete nonce/payload. Standard ICMP does not provide cryptographic target authentication against on-path actors.

JSON `round_trip_ms` measures the whole adapter/tunnel exchange; `icmp_rtt_ms` measures egress-target Echo time. `sent` counts adapter submissions. Partial failure returns nonzero status and partial results. No silent retries or duplicate resends; carrier loss/rotation can interrupt a pending command. Re-run after recovery. A target timeout does not establish interserver failure or a filtering cause and does not trigger global path rotation.

## Evidence and limits

See the final packaged validation reports for fresh test results and binary hashes. Opt-in local-VM fixtures are `tests/icmp-netns-lab.py` (protocol1 capture, authenticated-pair32KiB each direction, wrong-key rejection) and `tests/icmp-wss-lab.py` (real Nginx TLS/WSS, raw Echo, bad-key/no-reply negatives). Both require isolated disposable Linux testing and have bounded cleanup. Offline self-tests never prove network success. Actual Cloudflare, Iran WAN, generated unit sandbox runtime, sustained load, NAT and system-ping/TUN support are not established by these fixtures.
