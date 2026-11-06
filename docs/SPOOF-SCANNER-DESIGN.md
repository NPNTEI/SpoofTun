# Spoof candidate scanner — proposed design

Status: design only. Not implemented by 3.7.0-preview.11. The existing
`-check-spoof` tests a preconfigured pair; the Cloudflare/SNI scanner does not
discover usable forged-source addresses. This design targets the existing
native GRE carrier, independently of Direct ICMP port forwarding.

## What can be established

A single foreign-side UI can coordinate the entire scan. A foreign server alone
cannot prove a forged-source packet reached Iran or that the tunnel carried
application data. An authenticated receiver in Iran is required. Local send
success, a healthy foreign IP, or an ordinary ping from a third party is not
delivery evidence. CAIDA Spoofer likewise uses cooperating clients and receivers
to measure source-address validation: https://www.caida.org/projects/spoofer/.

Candidate addresses change the outer **source** only. The outer destinations
remain the real two paired servers. A candidate is not an endpoint to scan or
contact. Only explicitly permitted source addresses/ranges are accepted, with
a bounded sample count and per-job packet/byte/time budgets. The scanner must
not send replies to the forged source or create a reflection service.

The useful reserve record is a tested pair `(foreign_source, iran_source)`, not
an IP universally labelled "spoof-capable". Filtering can differ by direction,
protocol, provider, destination, packet size and time. A single candidate may
be tried on both sides as requested; that is the diagonal of the pair matrix,
not proof that independently passing addresses can be freely combined.

## Operator flow

1. Select the installed paired tunnel and real peer addresses. Reuse no secret
   in logs. Establish a pinned, authenticated control session with the Iran agent.
2. Enter permitted source ranges or a list, sample count, trial duration,
   maximum RTT/stall, repetitions, transfer-byte cap and required reserve count.
   Default one active candidate trial at a time.
3. Choose "same source on both sides" or separate approved source pools. For
   separate pools, prefilter each direction, then validate complete pairs; never
   silently expand a large Cartesian product.
4. Show candidate, pair, phase, direction, elapsed time, receiver-confirmed
   bytes, RTT and categorized failure live. Pause/stop keeps completed results.
5. Sort by complete success, timeout rate and transfer quality. Offer unlimited
   Top-N refinement with fresh limits. Export private JSON/CSV including failures
   and unknowns, not only attractive winners.
6. Before using a reserve, run a fresh full check. Selection and activation are
   separate actions. The initial implementation should not switch production
   automatically merely because an IP scored higher.

## Preserve the working path

Use an isolated probe instance on each server, with unique tunnel interface,
private addresses, carrier port and fresh pinned credentials. Production source
addresses, routes and services stay unchanged while candidates are tested.
The existing GRE runtime has no source-range hot-reload interface; implementing
this requires either managed probe instances or a new reviewed runtime API.

The control channel must not depend solely on the candidate being tested. A
working data tunnel is therefore not a prerequisite if a separate management
channel exists. If control is unavailable, a bounded, signed/authorized trial
plan can be preloaded on both peers and evidence reconciled later. Without a
peer report, the result is **unknown**, not a successful or failed source.
No design guarantees remote coordination when all communication is blocked.

Jobs require unique nonces, expiry, sequence numbers, anti-replay checks,
idempotent commands and a watchdog that removes only job-owned probe resources.
After a crash or timeout, keep the last known working production configuration.
Any later automatic activation needs prepare/ack/commit, an independent control
path and timed rollback when either peer fails to acknowledge the new pair.

## Each trial must test data and stalls

| Phase | Required observation |
| --- | --- |
| Preflight | Peer identity, routes, permissions, free probe resources, matching config |
| Wire delivery | Receiver observes expected forged source, job nonce and sequence in each direction |
| Session | Real GRE carrier, certificate pin, UNUNKNOWNTUN token and session negotiation succeed |
| Tunnel RTT | Small authenticated request/reply over the actual carrier; report p50/p95 |
| Upload | Iran-to-foreign byte count and payload hash match at the receiver |
| Download | Foreign-to-Iran byte count and payload hash match at the receiver |
| Idle/resume | Pause within the configured trial policy, then transfer successfully again |
| Reconnect | Fresh session and bidirectional transfer succeed after deliberate probe reconnect |
| Repeat | The configured number of complete trials pass before reserve admission |

Current native GRE admits inner TCP, not ordinary inner ICMP ping. Label the
echo measurement **Tunnel RTT**. Do not show unsupported system ping as a failed
candidate or substitute Internet ping for application delivery.

Use monotonic clocks and explicit deadlines for connection, authentication,
first byte, read progress, write progress and the whole trial. Detect lack of
new application bytes; do not rely on matching the literal text `i/o timeout`.
Classify connect timeout, handshake timeout, first-byte timeout, read stall,
write stall, reset, authentication failure, integrity mismatch, peer unavailable
and control unavailable separately. Background keepalive packets must not reset
an application progress deadline. Stop and clean up when the job budget expires.

A successful short transfer can miss buffering, congestion or long-lived stream
failure. Include bounded sustained transfer and idle/resume; longer soak checks
are optional and report their actual duration. Tests certify only what was
observed, never future availability or a promise of zero timeouts.

## Reserve records

Persist source pair, real destinations, protocol, MTU, release/build identity,
job IDs, both receiver reports, completed phases, payload sizes/hashes, per-phase
timings, upload/download rate, stall count, first/last verification and expiry.
Do not persist private tokens or raw client data in scan reports.

States: `untested`, `testing`, `one-way`, `failed`, `unknown`, `passed`, `expired`.
Only complete bidirectional repeated success enters `passed`. Interrupted,
one-way, control-lost or stale results cannot be selected as a ready reserve.
Use separate direction counters; socket reject counts can include unrelated
traffic and must not be advertised as measured packet loss.

## Acceptance tests before implementation can ship

- Matching and mismatched source pairs, one-way delivery and source rewriting.
- Silent blackhole after authentication, one-direction stall, reset, slow reads
  and writes, first-byte stall and a transfer larger than buffering capacity.
- Control loss during each phase, concurrent/duplicate commands, expired plan,
  clock jumps, cancellation, process crash and restart cleanup.
- No production route/service changes, no secret leaks, bounded traffic and
  candidate counts, no reflected replies, no forged success from stale reports.
- Reserve expiry/revalidation, Top-N refinement, partial export and two-phase
  activation rollback if automatic activation is implemented later.
- Isolated Linux fault tests first; separately authorized two-VPS/WAN tests are
  required before claiming an address pair works on a real Iran path.
