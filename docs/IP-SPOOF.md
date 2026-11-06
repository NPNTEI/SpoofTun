# Native IP source spoof / GRE — preview.4

This mode changes the actual outer IPv4 source, not the TLS/browser fingerprint.
Both endpoints must run UNUNKNOWNTUN; it is not Backhaul wire-compatible.

The supplied Backhaul artifact was statically inspected, not executed: outgoing
source selects `spoof_src_ip`, outgoing destination remains real `dst_ip`, and
`spoof_dst_ip` selects the expected incoming peer **source**. UNUNKNOWNTUN uses the
unambiguous names `source_ip` and `expected_peer_source_ip` for that behavior.
The implementation remains independent RFC 2784 GRE with UNUNKNOWNTUN TLS/token
authentication, not copied proprietary transport/control logic.

## Prepare a pair without deployment

Use only owned/authorized endpoints and source addresses. On a trusted device
with Python 3 and OpenSSL, run the bundled helper:

```sh
python3 -I spoof-pair.py --output /YOUR/PRIVATE/NEW-PAIR
python3 -I spoof-pair.py --check-pair /YOUR/PRIVATE/NEW-PAIR
```

Replace the path with a new directory under an existing parent. Menu **6** in
the Linux installer runs the same wizard, without installing or activating.
It asks for both assigned real IPs, physical interfaces, permitted claimed
source IPs, unused private inner IPs, the origin client listener and egress
application target. A source equal to its real address is a normal GRE baseline.
It produces matched configurations, a fresh token, pinned certificate/key,
role-specific run/check scripts and separate systemd templates. Secrets are
never printed. Directories are 0700 and files 0600; nothing is overwritten.

For automation use `--spec /absolute/private-spec.json --output NEW_DIRECTORY`.
The generated `pair.json` documents the accepted schema. It is private, not an
artifact to share publicly. Changing it does not regenerate the endpoint files;
make a new complete pair instead.

## Install and test separately from existing tunnels

On each Linux test host use the bundle's binary-only installer:

```sh
python3 -I install-preview.py --dry-run
sudo python3 -I install-preview.py --install
```

Use `/opt/ununknowntun-gre-preview/3.7.0-preview.8/ununknowntun` as the wizard's binary path.
It does not replace the shared managed executable or restart existing services.
Copy only the correct role's directory privately to the generated destination,
for example `/etc/ununknowntun-gre/my-pair/egress` on egress and the sibling `origin`
path on origin. Preserve root ownership and 0700/0600 permissions; never merge
with an existing deployment. The egress private key stays on egress.

1. On egress run its `check.sh` with `sudo /bin/sh` (JSON-only), then `run.sh`.
2. Leave egress running. On origin run its `check.sh`: bounded 15s real GRE/TLS/auth
   check with temporary TUN cleanup, not an application payload test.
3. Start origin `run.sh`, then test a real connection to the configured client
   listener and target application. The default client listener is loopback-only.
4. Stop foreground processes before installing the reviewed per-role systemd
   template. The generated unit uses a separate `ununknowntun-gre-PAIR.service` name.
   The helper itself never invokes systemctl or edits the host.

Do not run a check alongside the same endpoint's active service; TUN creation
is exclusive. Ordinary WSS/XHTTP service permissions do not support this mode;
use the separate template, not additional privileges for unrelated services.

## Boundaries and troubleshooting

Linux, IPv4, direct TLS, iproute2, /dev/net/tun, NET_ADMIN and NET_RAW are required.
GRE is IP protocol 47, not TCP/UDP port 47. The real IP must be assigned to the
physical interface; a public NAT address is not an assigned local address.
Only the selected UNUNKNOWNTUN TCP/TLS carrier is transported, not arbitrary host
traffic. No CDN, WSS/XHTTP, HTTP-path rotation or destination-IP redirection.

`configuration_only=true` logs describe intended tuples, not packet evidence.
Rejection counters distinguish TX-invalid, RX-invalid, wrong peer identity and
truncated RX. AF_INET raw receive can lose traffic to kernel firewall/rp_filter
before counters; zero receive counts do not locate an ISP/DPI fault. Inspect
reverse routes and filtering instead of disabling protections blindly.
There is no silent fallback to a public non-GRE transport.

Fresh certificates expire after 365 days; replace token/certificate/pin as a
coordinated pair, not on one peer only. GRE itself is unauthenticated; pinned
TLS and the private UNUNKNOWNTUN token remain mandatory.

See the packaged fresh validation evidence for executed tests and limitations.
No provider reachability, anti-DPI effectiveness, zero-bug or production
deployment guarantee is made. No reference executable or production server was
used to run the local tests.
