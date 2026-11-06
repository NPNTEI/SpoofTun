# UNUNKNOWNTUN Direct ICMP IPv4 L3

Direct ICMP is an independent UNUNKNOWNTUN mode in `3.7.0-preview.11`. It transports complete permitted IPv4 packets, including TCP, UDP and ICMP, through encrypted ICMP Echo. Origin (normally Iran) initiates; egress responds. This is not the old TCP-only native ICMP underlay or the bounded Echo-over-WSS adapter. It is not Backpack wire-compatible.

No TLS certificate, WebSocket, ECH or domain is required. Ordinary Cloudflare DNS proxy does not carry this mode. Outer real peer IPs remain visible; no source spoofing or IPv6 is implemented. Linux, iproute2, systemd, Python 3, `/dev/net/tun`, `CAP_NET_RAW` and `CAP_NET_ADMIN` are required. Real outer IPv4 must be locally assigned. NAT-traversal and dynamic peer discovery are not supported.

## Easy setup (recommended)

Run the same complete installer on each server. Choose **8 — Direct ICMP L3 setup**.
Start on the foreign server and choose Foreign. Give the Iran public IPv4, a pair
name, separate unused private pools and the requested MTU/FEC settings. The wizard
detects the local public address and interface, checks the host, and starts a
separately named service. It prints a **private pairing code**.

On Iran choose the same menu and Iran, then paste that code into the hidden input.
The wizard verifies the local address, exact release and hashes, installs the
matching endpoint and starts it. No manual transfer of endpoint files, keys or
certificates is needed. The installer must still be present on both servers.

The code contains the shared secret. Keep it private; it expires after 24 hours.
Its checksum detects copy errors, not who sent it. It is not a single-use signed
invitation. Existing endpoint identities cannot be overwritten by replaying it.

A separate CLI is available:

```bash
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh direct-icmp-setup foreign
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh direct-icmp-setup iran
```

The installer installs missing host prerequisites. It does not disable the
firewall, unban IPs, flush rules, change the default route or enable forwarding.
A running service still needs actual ICMP delivery between the two providers.

## Built-in port forwarding

From preview.11, foreign-first setup offers port forwarding and asks:

1. Iran client entry port (default 12055).
2. Foreign application port (default 18082).
3. TCP, UDP or both; additional mappings are optional.

The foreign application must already listen on 127.0.0.1 or a wildcard address.
For example, a Shadowsocks inbound on 0.0.0.0:18082 is reachable at the Iran
public address and port 12055 after both paired services are running. Application
credentials and protocol do not change. This wizard does not install a panel or
create client credentials, and does not add public firewall rules.

The path is `Iran entry → ICMP private path → foreign private relay → loopback application`.
The private relay uses a separate high port so an application bound to 0.0.0.0
does not collide with the relay. The foreign wizard checks local availability;
the final runtime bind is authoritative and fails with cleanup on a collision.
All relays run inside the Go core; no socat service is created.

TCP preserves half-close and UDP keeps separate bounded client associations.
The shared flow cap is 1024 per endpoint; default idle timeout is 180 seconds
(advanced field `forward_idle_seconds`, range 10..3600). An idle UDP association
is recreated on the next packet; an expired TCP connection must reconnect.
At most 32 runtime protocol rules are allowed; `both` expands to two rules.
Ports in this preview are 1024..65535. New connections keep their private pool
source for their lifetime, using the existing round-robin mechanism.

Advanced pair specs accept `forwards` entries such as
`{"iran_port":12055,"foreign_port":18082,"protocol":"both"}`. The normalized
spec also contains the chosen `relay_port`. Omitting `forwards` preserves the
previous L3-only behavior. Do not hand-edit installed JSON: its integrity
manifest intentionally rejects changed files. Existing pairs are not silently
migrated to port forwarding; create a new matched pair with nonconflicting
ports, names and private ranges when testing this release.

## Manage Direct ICMP

Choose main-menu 3, then **Direct ICMP tunnels and port forwards**, or open the
Control Room and press **i**. This dedicated console supports status, start,
stop, restart, logs, doctor, safe information and confirmed removal.

```bash
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh direct-icmp-manage
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh direct-icmp-manage --list
```

After a normal manager installation/upgrade, `sudo ununknowntunctl direct-icmp-manage`
also works. The console calls each endpoint's own verified manager, so listing
does not migrate old bundles. Unsupported actions on older bundles are refused
explicitly. Opening/listing does not change services. The standard WSS/XHTTP
editor remains separate. Removal requires the exact selected pair/role identity.

## Private pools and round robin

Defaults are `10.79.1.0/28` on Iran and `10.79.2.0/28` outside. Choose separate,
nonoverlapping RFC1918 ranges from /26 through /30 that are unused locally.
The first usable address is the peer's anchor, and every usable pool address is
assigned to its tunnel interface. The other pool is routed through that interface.

New inner TCP/UDP conntrack flows use source addresses in round-robin order.
The address stays fixed for the life of each tracked flow, including an existing
UDP flow. This avoids changing the identity of an active TCP connection.
The outer public IPs do not rotate. Private rotation is not a cure for provider
ICMP filtering or a source-IP-spoof feature.

The runtime creates only its own uniquely named nftables SNAT table. It records
a private ownership lease so a crash can be recovered on restart; an unrelated
same-name table is refused. Normal shutdown removes the owned table and TUN.
The shared `/run/ununknowntun-icmp-rr` lease directory is retained across service stops.

Advanced runtime fields are `local_pool_cidr`, `peer_pool_cidr` and
`source_rotation: "round-robin"`. Existing configurations without these fields
retain single-address behavior. Use the paired generator to avoid mismatched
settings and integrity manifests.

## Advanced file-based setup

The original `direct-icmp-pair /root/new-pair` and `direct-icmp-install /root/endpoint`
installer commands remain available for operators who want separately reviewed
endpoint bundles. Generation alone does not install or start a service. Install
checks the matching release hashes, ELF architecture and version. Each installed
endpoint has `manage.py` with start, stop, restart, status, info, logs, doctor and uninstall.
Services and versioned binaries are separate from normal managed WSS/XHTTP tunnels.
The versioned binary is `/opt/ununknowntun-direct-icmp/3.7.0-preview.11/ununknowntun`.

## Check and lifecycle

```bash
ping -c 4 10.79.2.1
sudo python3 -I /etc/ununknowntun-direct-icmp/icmp1/origin/manage.py status
sudo python3 -I /etc/ununknowntun-direct-icmp/icmp1/origin/manage.py logs
sudo python3 -I /etc/ununknowntun-direct-icmp/icmp1/origin/manage.py stop
```

Use `egress` on outside and ping `10.79.1.1` for the reverse test. An active process is not proof of a connected data path. For actual TCP/UDP tests, outside can run `iperf3 -s -B 10.79.2.1 -p 15201`; Iran can run `iperf3 -c 10.79.2.1 -p 15201 -t 10`, and `iperf3 -c 10.79.2.1 -p 15201 -u -b 1M -t 10`. `-R` tests reverse TCP. These require independently installed iperf3.

`uninstall` stops/disables and removes only the selected endpoint; the shared versioned binary is retained. Config and unit integrity are checked before lifecycle actions. Generate new paired settings for changes instead of editing installed files blindly. Multiple pairs need distinct names and inner address ranges.

MTU is explicitly configured; TCP MSS clamping helps fit TCP packets, but this is not automatic path-MTU discovery.

Outer IPv4 overhead is130 bytes with FEC, versus80 bytes in off mode. With a1500-byte physical interface MTU, the FEC inner MTU must therefore be at most1370; the default1200 produces a1330-byte outer packet. The runtime rejects a configured packet size exceeding the physical interface MTU. The actual network path may have a smaller MTU.

## Timeout diagnosis

Run `python3 -I /etc/ununknowntun-direct-icmp/icmp1/origin/manage.py doctor` on Iran,
or replace `origin` with `egress` outside. The installed doctor works after the
installer staging files are removed. It checks interface/route state, iptables,
ip6tables, nftables, UFW/firewalld, Fail2ban bans, reverse-path filtering, ICMP
settings and bounded service counters. Missing tools and unreadable data are
reported as unknown, never as proof that traffic is allowed.

The doctor makes no rule or ban changes. Temporary route/link send errors now
keep the process and TUN alive while normal authenticated recovery retries.
Recovery cannot make a continuously blocked path deliver packets. Correlate
both peers' counters and an actual TCP/UDP transfer before diagnosing the provider.

## FEC modes and budget

FEC sends repair packets that can recover some missing data. Original data is forwarded immediately without waiting for a repair block to fill. Repair packets consume bandwidth; downlink repairs also require origin polling credit. They cannot recover a completely blocked ICMP path.

| Mode | Behavior |
| --- | --- |
| `off` | No repair; preserves the preview.7 non-FEC wire format |
| `fixed` | Fixed repair target, default20%, bounded by the configured cap |
| `adaptive` | Authenticated receiver feedback adjusts each direction independently; new pair default |

Adaptive repair may be zero on a healthy path. The default cap is **25 repair packets per100 source packets**, and the block deadline is20ms. This is not a promise that total network traffic or billing increases by only25%: headers, control traffic, polling and packet sizes also contribute. Allowed cap5..50%, fixed target0..cap, block deadline5..100ms. Excess repair can worsen congestion, so increasing the cap is not automatically an improvement.

Upgrade **both peers to preview.8 or a compatible implementation before enabling FEC**. Enabled FEC uses a versioned format that rejects mismatched peers instead of silently downgrading. Existing runtime JSON with omitted FEC fields defaults to off. The new pair generator explicitly writes adaptive to both endpoints.

Advanced pair specifications accept top-level `fec_mode`, `fec_percent`, `fec_max_percent` and `fec_block_ms`, for example `"fec_mode":"adaptive", "fec_percent":20, "fec_max_percent":25, "fec_block_ms":20`. `fec_percent` is the fixed-mode target, not a fixed setting for the adaptive controller. Generate a new matched pair for changes rather than editing one installed endpoint and invalidating its integrity manifest.

Compare pre-repair loss, recovered packets, remaining loss and repair traffic with actual TCP/UDP delivery. Successful recovery does not prove that the network stopped losing packets. Observe both directions; their loss and repair ratios may differ.

This mode creates an exclusive nonpersistent TUN and explicit private peer routes. Pool rotation adds only the owned nftables SNAT table described above; default routes, unrelated firewall rules, kernel forwarding and host sysctl are unchanged. A listener bound to the outside private tunnel address can be reached from Iran. Optional built-in public client-port forwarding is configured during paired setup as described above.

Advanced JSON generation accepts per-endpoint private `cidrs` mapped to mirrored `local_cidrs`/`peer_cidrs`. No default/public ranges or opposing-range overlap. Routing and forwarding for hosts behind either peer must be explicitly configured by their administrator; the helper does not silently enable them.

The authenticated session recovers after path loss and initiates coordinated new keys periodically. Recovery cannot bypass a continuously blocked ICMP path and does not guarantee all existing TCP sessions survive. Ordinary ping success is not a throughput, WAN or DPI-resistance test. See the release validation reports for actual local checks; public WAN, provider filtering and long-term stability need separate tests.

## Maintainer: disposable Linux VM service test

The generated pair and exact systemd sandbox have an opt-in lifecycle harness. Run it only inside a disposable local Linux VM. It creates two randomly named network namespaces, a veth pair, private matched settings and independently named generated units. Namespace binding and a runtime watchdog are added through temporary `/run` drop-ins; the generated unit files remain unchanged. It verifies bilateral private ping, process namespace, exact capabilities, manager status/stop/uninstall and resource cleanup. It does not test WAN quality.

```bash
sudo python3 -I tests/direct-icmp-systemd-lab.py --run-local-lab --binary /absolute/path/to/final/ununknowntun --output /absolute/new-direct-icmp-systemd-report.json
```

Add `--installer /absolute/UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh` to exercise the actual standalone wizard and embedded binary installation for both endpoints, followed by the same namespace, service and cleanup checks. The supplied `--binary` must be the exact matching release binary; both its hash and the installer hash are recorded.

`--helper` may point to the matching `packaging/direct-icmp-pair.py` when running the harness separately from its source tree. `--self-test` performs only the offline harness checks. The report is mode0600 and contains no private key or configuration dump. Normal cleanup removes only resources created by the run. SIGKILL or a kernel failure may leave the named lab resources; the service runtime/start limit bounds the processes even then.
