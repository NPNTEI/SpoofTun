# ECH configuration and DNS: distinct features

## Manual and automatic ECH discovery

`-ech-mode strict` requires accepted ECH on the actual TLS handshake. Successful
DNS retrieval alone is not proof of ECH support. An unsuccessful ECH handshake
never silently falls back to unencrypted ClientHello.

`-ech-config` accepts:

- `auto` (or empty): query the tunnel's TLS SNI using the configured `-ech-doh`
  endpoints, retaining the existing automatic discovery behavior.
- A Base64-encoded ECHConfigList (optional `base64:` prefix).
- `udp://9.9.9.9`, `tcp://9.9.9.9`, or an HTTPS DoH URL: query the TLS SNI.
- `cloudflare-ech.com+udp://9.9.9.9`: query HTTPS records for
  `cloudflare-ech.com` through this resolver. This string is a discovery
  descriptor, **not** an ECHConfigList itself. Other domain/resolver pairs work
  when the selected TLS endpoint possesses the corresponding ECH private key.

An explicit port is allowed. UDP/TCP resolvers require a literal IPv4/IPv6
address and default to port 53. HTTPS resolver certificates are verified; HTTP,
h2c, URL credentials and fragments are rejected. UDP queries are plaintext and
can reveal the ECH lookup domain to the network/resolver; choose authenticated
DoH when that disclosure is undesirable. DNSSEC validation is not implemented.

Manual discovery has one eight-second deadline covering aliases and any UDP
truncation-to-TCP retry. Responses must match the requested question and answer
owner; unrelated additional records cannot supply a key. Config framing and
supported algorithms are checked before the strict TLS handshake.

This release does **not** cache or periodically refresh ECH by DNS TTL. Configs
are fetched at transport initialization and refreshed when the existing strict
ECH rejection path requests another attempt. A fixed Base64 config remains fixed;
it must be edited when the server rotates keys. Manual discovery does not replace
the dial address, TLS inner SNI, or HTTP Host.

ECH runs on whichever side **initiates the TLS connection**, regardless of its
country. For example, an Iran-side UNUNKNOWNTUN origin dialing a foreign domain
behind Cloudflare sends ECH to the Cloudflare TLS edge. The foreign origin server
does not obtain Cloudflare's ECH private key. Reversing geography alone does not
reverse the implementation's origin/egress roles.

## Why “TLS Hello = DNS” is not an ordinary TLS option

The former mode 4 has been **removed** from current menus. DNS ECH
lookup above retrieves public configuration; it does not send ClientHello via DNS.

A standard HTTPS/CDN socket expects its TLS handshake on the same ordered
transport stream as the subsequent TLS records. Sending ClientHello to a DNS
resolver and the remaining records to an unrelated CDN TCP connection cannot
construct that stream. Ordinary Cloudflare/Fastly/Arvan endpoints do not offer
this proposed DNS-to-TLS-stream rendezvous protocol.

A real implementation would require a cooperating relay plus an authenticated
session-binding and ordered reassembly protocol, or a complete DNS-tunnel
transport. That changes deployment requirements and performance characteristics.
A complete DNS tunnel is also not equivalent to moving only ClientHello through
DNS. No menu success, fallback to plain TLS, or DNS lookup is presented as this
unimplemented feature. The current wizard offers only the three supported TLS modes.

## Primary references

- [Project X TLS configuration](https://xtls.github.io/en/config/transports/tls.html):
  `echConfigList` Base64 and domain-plus-resolver formats.
- [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html): ECHConfigList in the DNS
  HTTPS/SVCB `ech` parameter, bootstrap before the TLS handshake, deployment keys.
- [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html): encrypted inner and
  outer ClientHello and ECH acceptance.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html): TLS uses a reliable,
  ordered underlying stream; the handshake authenticates its transcript.

No public resolver, CDN, live tunnel or user's server was probed by the local
unit tests. Local fixtures do not establish WAN reachability or censorship
resistance.
