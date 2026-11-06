# UNUNKNOWNTUN 3.7 preview: coordinated paths, renewal, scanner and Iran Nginx

## Coordinated path rotation

Opt in during the paired installer or Manage → Edit → Coordinated paths. The
wizard asks interval (1–168 hours), candidate paths per set (2–8), and overlap
(0–60 minutes). The core also accepts duration syntax. Both peers must share
the same token, HTTP Host, transport/base path, interval, count and overlap. Clock drift
beyond overlap can disconnect the pair: use working time synchronization.

Each time window has deterministic authenticated candidate routes. A failed
connection can try another candidate; new carrier connections use the new set
after rotation. Previous/current overlap supports a controlled handover.
Existing authenticated traffic is not deliberately terminated at the boundary.
Schedules use UTC epoch boundaries, not an independent timer started at each
server's installation time. New connections use the current set; gradual
carrier renewal checks the actual route epoch, not just connection age. It is
gradual and can lag a boundary during bounded draining of previous carriers.
An actually broken network connection cannot be preserved by merely changing a
path. Multiple failed paths also do not prove path-specific censorship: ordinary
TLS encrypts the HTTP path from intermediate observers, whereas a TLS-terminating
CDN can see it.

The static base route is rejected while rotation is enabled unless the explicit
`legacy=true` migration setting is selected. Keep that exception temporary.
For changing a live pair, schedule maintenance, upgrade both peers first, then
apply the exact signed profile on both ends. The initial manual enable/disable
change can interrupt the pair; subsequent scheduled sets do not require manual
sync. Token/base-path changes still require the normal paired update procedure.

This feature applies to WSS/XHTTP, not to GRE spoof transport or independent
customer WS/XHTTP entry paths. No customer UUID, public IP, or customer URL is
rotated by this feature. Nginx prefix configuration avoids a reload every epoch.

## Adaptive carriers and graceful renewal

The existing `sessions-min` / `sessions` bounds remain the adaptive pool limits.
`session-renewal=0` disables periodic renewal; values such as `2h` enable it for
MUX ON. Path rotation also triggers gradual carrier replacement. Replacement
uses a new carrier before retiring the old one, with bounded spare capacity.
An old carrier drains existing streams for at most two minutes after an
authenticated, payload-tested replacement is installed. Remaining old streams
are then closed, so an indefinitely open stream cannot block all future renewal.
There is one spare globally; replacement remains serial, not simultaneous for
all slots. A selection lease can delay installation for at most 30 seconds;
failed/stale candidates are discarded and slots receive fair retry turns.
MUX OFF already uses separate per-client carriers. Configuring
renewal does not generate public IPs, randomize a live stream's ID, or promise
uninterrupted traffic through an actual blocked/disconnected socket.

## Scanner and Nginx operations

Run `ununknowntunctl cdn-preview TUNNEL_ID` to measure without applying; run
`ununknowntunctl cdn-scan TUNNEL_ID` only when endpoint changes and a possible selected
service reconnect are acceptable. Missing scanner settings use conservative
defaults with automatic updates OFF. Actual bounded carrier/token/TLS probes
are not throughput or customer-payload certification. Automatic replacement
remains opt-in. The terminal UI exposes preview with `p`.
Each scanner probe has a strict deadline and starts a fresh core process. A
short timeout can expire before all backup paths are tried; it does not prove
every candidate path is broken. Increase the bounded probe timeout if needed.

Iran `nginx` entry means direct DNS to Iran and HTTPS terminated by its local
Nginx, forwarding WS/XHTTP to the loopback tunnel listener. Raw TCP clients must
remain on direct mode unless explicitly migrated and reconfigured. Existing
entry migration preserves customer identity, quota and usage and exports the
updated endpoint, but cannot update clients already installed on devices.
Only managed site files are edited. Nginx configuration validation precedes
graceful reload; existing transactional rollback is retained. Unrelated panel
ports, sites and certificates are not intentionally replaced.

## Validation boundary

Read this package's fresh validation report. Unit tests, fixture tests and local
loopback processes are distinct from Linux systemd/Nginx runtime, an actual CDN,
Iran ISP behavior, Xray payload compatibility and sustained throughput. No live
server is modified by building the package, and this preview is not a claim of
production certification or a guaranteed censorship fix.

## Authenticated payload watchdog and recovery routes

Supporting preview.3 peers negotiate and echo 1 KiB of random data through the
same application data queues before publishing a new carrier and periodically
afterwards. Runtime probes wait 10 seconds and retry after 15 seconds; three
consecutive misses close a failed carrier, even if outgoing writes/control
frames continue. Only exact timely echoes, or bounded fresh consumed-once late
proofs of payload progress, reset failures. Client idleness and target silence
are not failures. Old peers fall back explicitly to an 8-byte control heartbeat,
which does not certify payload delivery. These checks are not Internet, Xray,
phone-to-origin or arbitrary destination probes.

Failed rotating routes are quarantined for 120 seconds with at most 64 records.
A fresh 128-bit random nonce and 128-bit HMAC produce a 64-hex recovery path;
generation is limited to once per 30 seconds. The MAC binds the shared settings
and accepted epoch. The egress validates it statelessly, still requiring normal
tunnel authentication. Fixed 32-hex routes remain available for rolling-upgrade
fallback, but both peers must be upgraded for full recovery/payload guarantees.
Managed Nginx accepts only the supported 32/64-hex route shapes and valid XHTTP
suffixes. Backend authorization remains mandatory. No per-recovery Nginx reload
is needed. A failed whole network still cannot be repaired by changing a path;
backoff and rate limits bound retries rather than promising connectivity.
