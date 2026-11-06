# UNUNKNOWNTUN XHTTP profiles (3.6 preview)

This is a new HTTP transport for the existing authenticated UNUNKNOWNTUN byte
stream. It is not the older H2/gRPC-shaped transport with a different name.
It is not a VLESS server and cannot be configured as a stock Xray proxy peer.

## Wire reference and deliberately supported subset

The independent implementation follows the **PACKET-UP** section of the Xray
maintainer's [XHTTP: Beyond REALITY specification, discussion 4113](https://github.com/XTLS/Xray-core/discussions/4113#packet-up),
published December 5, 2024 and reviewed September 28, 2026. The accepted wire
subset is pinned here, rather than implicitly promising compatibility with
future upstream modes or defaults. The modes are real transports, not menu aliases:

* `auto` selects `packet-up` on the connecting peer and accepts all three
  implemented profiles on the listening peer. This deliberately differs from
  Xray's automatic TLS/H2 preference for streaming: UNUNKNOWNTUN does not send
  gRPC headers and cannot assume a CDN allows streaming requests.
* `packet-up` is the backward-compatible finite-upload profile described below.
* `stream-up` opens a GET download and a continuous POST upload at the same
  `/configured-path/UUID` route. Exactly one upload attaches to each UUID.
* `stream-one` uses one full-duplex POST to `/configured-path/`; the response
  carries download data. Both streaming profiles require 3.6 peers. A server
  configured with a specific mode accepts only that mode, not silent fallback.

## Packet-up

* A fresh random UUID v4 associates one upload/download carrier.
* `GET /configured-path/UUID` opens the streamed download. Its response is
  `200`, `Content-Type: text/event-stream`, `Cache-Control: no-store`, and
  `X-Accel-Buffering: no`. HTTP/1.1 backends use HTTP chunked transfer encoding.
* `POST /configured-path/UUID/0`, then `/1`, etc., carry finite upload bodies
  without a gRPC envelope or gRPC content type. Each body is at most 65,536
  bytes. POST success is an empty `200` response.
* Up to eight finite POSTs can be awaiting replies simultaneously. The next
  request starts after the preceding body has been written, not after its
  response. This also pipelines small consecutive UNUNKNOWNTUN frame writes.
  An eight-sequence receive window buffers intermediary-induced reordering,
  delivers bytes in sequence, and only then acknowledges the corresponding
  POST. Duplicates and sequences outside that window are rejected. A missing
  sequence/body closes the carrier after ten seconds without ordered progress.
  The former artificial one-POST-per-RTT limit is removed; this is not a WAN
  throughput guarantee or an implementation of every Xray optimization.
* GET must be opened first. POST-first session association,
  H3, browser dialer, separately routed upload/download, and Xray
  XMUX rotation controls are not implemented.
* The user-selected UNUNKNOWNTUN MUX
  setting concerns client streams inside a UNUNKNOWNTUN carrier, not Xray XMUX or
  the HTTP/2 protocol itself. A carrier owns its own HTTP/2 connection.

## Header padding

`-xhttp-padding-bytes 0`, `100`, or `100-1000` controls HTTP-header padding.
The inclusive range must be between 0 and 4096; zero disables it and preserves
legacy behavior. Each request chooses a cryptographically random length and
uses `Referer: https://host/?x_padding=XXX...`; responses use `X-Padding`.
The setting applies only to the sender's outgoing headers. A receiver accepts
absent padding or syntactically valid padding up to 4096 bytes, irrespective of
its own outgoing range. Padding is not authentication, a throughput improvement,
or a guarantee of indistinguishability from ordinary browsing. It is distinct
from UNUNKNOWNTUN payload-frame padding and does not change application bytes.

## Streaming response records and delivery guarantees

Stream-up and stream-one use UNUNKNOWNTUN's `gdt-stream-ack-v1` HTTP profile, selected
explicitly in request/response headers. The upload body is the unchanged
UNUNKNOWNTUN byte stream. The download body carries bounded records: a one-byte
kind, a four-byte big-endian length, and either at most 32768 data bytes (kind
1) or an eight-byte delivered-upload counter (kind 2). Record headers and ACKs
are removed before handing data to the UNUNKNOWNTUN parser. Only one serialized
writer touches each HTTP response.

ACKs are emitted after upload bytes reach the application-facing pipe. FIN and
Close delivery barriers wait for the corresponding counter, avoiding loss when
an exclusive MUX-off carrier closes immediately after its last write. This is
a UNUNKNOWNTUN extension, not a stock Xray transport compatibility claim. It does
not claim remote target delivery before the existing UNUNKNOWNTUN stream protocol
has processed a frame.

The client uses bounded pipes/backpressure, 32 KiB receive buffers and the
existing bounded HTTP/2 windows. Request-header setup is timed out; after valid
transport authentication the backend clears its finite request-body timeout
for continuous uploads. Application authentication, tunnel idle checks,
adjustable read/write/delivery deadlines, and cancellation remain active.
Both ends close all pipes when either direction fails; uncertain uploads are
never retransmitted. HTTP/1 backends explicitly enable full duplex.

## Authentication and replay protection

Every request includes the existing time-bound HMAC Authorization mechanism,
bound to the host and **complete request path**, including UUID and sequence.
This is a UNUNKNOWNTUN extension, not a standard Xray HTTP authentication field.
GET additionally uses the bounded transport nonce replay cache. Each streaming
POST also requires an unused transport nonce, and duplicate stream-up POSTs
are rejected. Packet-up POST replay
is rejected by the per-session sequence number; placing every POST nonce in
the global cache would exhaust it during normal bulk traffic. Neither rejected
nor oversized uploads advance the sequence. The authenticated UNUNKNOWNTUN
challenge-response handshake is still mandatory inside this HTTP transport.

A POST that fails or times out closes the carrier. The client does not retry
an uncertain upload, because its bytes may already have been delivered before
the error. Reconnection uses a new UUID and a new UNUNKNOWNTUN session.

The 3.5 parallel sender requires the 3.5 receive window. Streaming profiles
require 3.6 on both peers. Upgrade **both XHTTP peers together** when changing
mode: old servers do not understand the new streaming profile.

Unauthorized requests intentionally receive a generic `404`, not a token or
signature error that identifies a hidden endpoint. Client errors identify the
failing stage and HTTP status without printing the Authorization header or
response body. A `404` therefore means route/host/authentication must be checked;
it is not proof of a particular cause.

## Resource limits and lifecycle

The server allows at most 64 active download sessions and 576 backend HTTP
connections (one GET plus eight POSTs per carrier). Per-carrier queued plus
in-flight client bodies are limited to eight, each at most 64 KiB. Server
reservations count toward the same eight-sequence limit **before** their bodies
are read, bounding queued payload to 512 KiB per carrier on each side, plus
allocator/HTTP metadata overhead. Download copy buffers are 32 KiB. The client HTTP/2 receive stream
window is 128 KiB and connection window is 256 KiB; response headers are capped
at approximately 16 KiB. These transport allocations are separate overhead
from the existing queued-stream memory budget, not a promised process RSS cap.

The backend has a five-second header deadline, an authentication-timeout body
deadline (including implicit draining of rejected request bodies), and a
30-second idle-connection timeout. Upload bodies have that read deadline, and
forwarding/flushes have the existing tunnel write timeout. Existing UNUNKNOWNTUN
authentication deadlines prevent abandoned unauthenticated GETs from keeping
their session indefinitely. Request cancellation closes both directions of the
paired stream. Graceful shutdown refuses new download carriers while allowing
POST uploads for existing UUIDs until active UNUNKNOWNTUN streams drain or the
existing shutdown deadline expires; only then are their connections closed.
Client read deadlines are real pipe deadlines. Writes copy bytes into the
bounded transport buffer, as with a socket send buffer; they do not promise
remote acknowledgement. A full buffer applies backpressure. Adjustable write
deadlines cancel blocked enqueueing, pending POSTs and delivery barriers;
each actual POST also has the existing tunnel write timeout even if a caller
clears its deadline after enqueueing. Asynchronous upload failures close both
directions and are reported on subsequent reads/writes, without retransmission.
FIN/Close frame batches flush all pending uploads before the frame writer
reports completion, preventing MUX-off carrier cleanup from dropping final data.

## Deployment and test scope

The origin verifies TLS certificates and requires HTTP/2 ALPN. Existing uTLS,
strict ECH, and optional ClientHello-fragment settings are applied by the same
TLS setup as the other browser-profile transports. ECH acceptance still depends
on the public TLS endpoint/CDN, not the plaintext backend.

The backend listens on loopback behind a TLS reverse proxy. Route the complete
configured path prefix with HTTP `proxy_pass`, **not** `grpc_pass`, preserve Host
and Authorization, disable response caching/buffering/compression for the
tunnel route, and permit the selected POST/GET patterns. Stream modes require
request streaming and (for stream-one) end-to-end full duplex; many CDNs buffer
uploads despite otherwise supporting HTTP/2. These modes use no gRPC content
type or envelope, and there is no automatic substitution with gRPC. Keep a
normal website on separate paths. Existing idle UNUNKNOWNTUN Ping/Pong traffic
provides application-level activity; HTTP/2 pings alone do not ensure that a
CDN will keep an idle HTTP download alive.

Local tests cover all four mode choices over an HTTP/1 backend, padding,
streaming upload delivery acknowledgements/deadlines, HTTP/2 + uTLS + UNUNKNOWNTUN
authentication, and raw HTTP packet-up byte integrity, ordered body emission,
out-of-order reassembly, bounded receive windows, missing-sequence timeout,
bounded concurrent small writes under simulated response delay, asynchronous
failure/cancellation with no retries, HMAC
rejection, GET/POST replay rejection, oversized upload rejection, capacity,
deadline changes and cancellation, and TLS + authenticated UNUNKNOWNTUN + TCP target
round trips including half-close. Local success does **not** establish Fastly,
Cloudflare, Arvan, ECH, or Iran WAN reachability in a particular deployment.
