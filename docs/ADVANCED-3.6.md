# UNUNKNOWNTUN 3.6 preview: connection profiles

Historical 3.6 notes. For current behavior read [3.7 changes and limits](ADVANCED-3.7.md). The old fourth ClientHello-over-DNS menu option has been removed in 3.7; DNS-based ECH discovery remains. Scanner preview, rotating routes, carrier renewal and standalone Iran Nginx are described in the 3.7 guide.

This is an experimental release, not a production certification. Upgrade both
peers before selecting streaming XHTTP. The separate GRE spoof underlay remains
Linux-only, direct-TLS-only and opt-in. It is not combined with CDN modes.

## Three independent names

| Setting | Meaning | Example |
|---|---|---|
| Connect host | Network address used to dial the CDN | A validated CDN IP or clean domain |
| TLS SNI | Certificate identity and TLS service name | `tunnel.example.org` |
| HTTP Host | Application route the CDN and UNUNKNOWNTUN expect | `tunnel.example.org` |

The default uses the same domain for Host/SNI. A clean connection address does
not disable certificate verification. Different Host/SNI values require the
provider to support that route. Setting an arbitrary SNI is not sufficient to
make domain fronting work. Host edits are paired changes; synchronize the signed
editor update on the egress and configure its CDN/Nginx routing yourself.

Installation asks for original domain, manual IP/domain, or Cloudflare scanning.
`ununknowntunctl edit ID` can change `connect_host`, `tls_sni`, `http_host`,
`ech_source`, `xhttp_mode`, `padding_bytes`, and `xhttp_padding`. Enter `auto` in
connect_host to restore the normal domain/direct-IP choice. IP/port/domain edits
retain explicit overrides; SNI/Host defaults follow a domain rename.

## ECH / fragmentation / DNS

The wizard shows four requested choices:

1. ECH OFF: ordinary verified TLS.
2. ECH ON: strict ECH acceptance required; automatic discovery or manual source.
3. ECH OFF + ClientHello fragmentation: editable byte/delay ranges.
4. ClientHello over DNS: **unavailable**, with an explanation and reprompt. It
   never silently starts ordinary TLS and reports DNS tunneling as successful.

Manual ECH can be a Base64 ECHConfigList or a discovery descriptor such as
`cloudflare-ech.com+udp://9.9.9.9`. This descriptor queries DNS HTTPS records;
it is not the ClientHello itself. UDP/TCP DNS is not encrypted. Verified DoH is
also supported. Automatic discovery uses the inner SNI and configured DoH.
See [ECH details and architectural limitation](ECH-AND-DNS.md).

ECH is configured on the side **initiating** the TLS connection. In the managed
Iran-origin arrangement that is Iran; a separately designed foreign-origin
arrangement would put the client setting abroad. Being behind Cloudflare alone
does not make an egress process a TLS client or enable ECH on stock Nginx.

## XHTTP modes and padding

`packet-up` uses bounded upload POSTs and a streaming download GET. `stream-up`
uses separate continuous upload/download requests. `stream-one` uses one
full-duplex POST. `auto` deliberately resolves to packet-up; it is not Xray's
adaptive mode selection. Streaming modes use UNUNKNOWNTUN framing, require both
peers, and are not stock Xray/VLESS wire-compatible.

The UNUNKNOWNTUN carrier does not add gRPC. Long streaming requests may be rejected,
buffered or timed out by a CDN or its plan. No provider compatibility claim is
made without testing its actual path. Fastly remains an experimental XHTTP-only
profile. WSS or packet-up is the conservative choice.

`padding-bytes` adds a random bounded byte count to each nonempty data frame;
range 0–1024, e.g. `100-1000`. Control frames are not padded. WSS/XHTTP receivers
remove padding before forwarding user data. This is sender-local. Padding
traffic is included in wire statistics, not represented as useful payload.

`xhttp-padding-bytes` separately pads XHTTP HTTP headers (0–4096, N or MIN-MAX).
Both settings default to 0 and can be edited later. Padding consumes bandwidth
and does not prove browser equivalence or censorship resistance. Legacy `-pad`
remains ignored, so old installations do not unexpectedly emit extra traffic.

## Cloudflare scanner and automatic updates

`ununknowntunctl cdn ID` opens scanner settings; `cdn-scan ID` runs a bounded scan
and may update this tunnel; `cdn-status ID` is read-only. Defaults: 300 seconds,
64 candidate IPs, two authenticated samples, six seconds per probe, 15% minimum
latency improvement. Maximum duration 600 seconds; maximum 128 candidates.
Duration is an upper limit, not a forced wait. IPs/CIDRs can be supplied instead
of the official Cloudflare IPv4 range snapshot. Other CDNs support manual
addresses, not automatic range scanning.

Every success uses the **real core**, its TLS certificate/ECH policy, Host,
path and token. Ping or an HTTPS website alone is not sufficient. Ranking uses
authentication latency, not download speed. Target payload is not tested by
the scanner. Tokens remain in the tunnel's private token file.

Scheduling is off by default. If enabled, a per-tunnel systemd timer scans at
the chosen interval (default eight hours). Configuration edits invalidate stale
results. No replacement is applied without authenticated improvement. A failed
post-change authentication rolls back the selected tunnel's files. Applying a
new endpoint restarts that tunnel and **can interrupt its existing sessions**;
this is not a zero-downtime hot switch. Other tunnels are not restarted.

Stopped services stay stopped. Deletion disables the selected tunnel's timer;
recoverable deletion backups include its previous timer state. Scan settings
and last report are private local files in the managed tunnel directory.

## Limits of validation

Local tests check bytes, authentication, ECH, timeouts, races and fake-service
rollback. They do not certify your ISP, CDN configuration, real client, public
reachability, bandwidth, sustained stability or spoofing support. The previous
GRE namespace lab result belongs to 3.5.0-gre-preview.1; this release does not
claim a new privileged GRE runtime test. Use the delivered validation report.
