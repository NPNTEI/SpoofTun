# ArvanCloud and UNUNKNOWNTUN

This is configuration guidance, not a live account or deployment test.
TLS has two independent legs: the client/tunnel to the CDN edge, and the CDN to
the Nginx origin. Enabling edge HTTPS does not install an origin certificate.
Use a valid matching certificate and full chain on the origin; keep certificate
verification enabled. Existing certificate files can be selected in the installer.

Configure each proxied domain independently: its origin is the public address
of the server hosting that entry. Keep Host/SNI aligned with the service. The
installer's Arvan profile uses HTTPS port 443. DNS/CDN account settings and
certificate renewal remain the operator's responsibility.

For the tunnel route, avoid caching, redirects, browser challenges, compression
and rewriting Host/Authorization. WSS needs WebSocket Upgrade. XHTTP needs
long-lived GET and POST delivery to a stable backend; its download response is
200, not a WebSocket 101. Do not distribute one session across independent
backends. Automatic POST retries may conflict with replay protection.

HTTP-01 issuance/renewal needs the correct HTTP/80 ACME challenge route.
Certificate errors should be diagnosed separately from wrong IP/port, broken
routes, WAF responses and origin connectivity. A valid certificate alone cannot
make a blocked transport work.

## Diagnose the failed stage

| Stage | Inspect |
| --- | --- |
| DNS/TCP | Record, destination, listener, firewall and route |
| TLS/x509 | Hostname, time, full chain and trust for that TLS leg |
| HTTP 301/302 | Route redirects |
| HTTP 403/429 | Security policy or rate limits |
| HTTP 404 | Path, Host, authentication and clock; not conclusive alone |
| HTTP 502/503/504 | CDN-to-origin/backend connectivity |
| UNUNKNOWNTUN authentication | Matching settings and actual payload arrival |

`sudo ununknowntunctl doctor TUNNEL_ID` separates local origin and CDN probes.
Reports redact credentials but still contain endpoint addresses; review them
before sharing. Successful tunnel authentication is not a customer payload or
throughput test. The interserver transport and Iran client entry are separate;
configure the corresponding Xray inbound explicitly. ECH support must be
verified at the actual TLS endpoint, never inferred from a menu option.

Provider documentation: [HTTPS settings](https://docs.arvancloud.ir/fa/cdn/https-settings/),
[origin certificates](https://docs.arvancloud.ir/fa/cdn/https-settings/server-certificate/),
[page rules](https://docs.arvancloud.ir/fa/cdn/page-rules/),
[advanced settings](https://docs.arvancloud.ir/fa/cdn/advanced-settings/).
