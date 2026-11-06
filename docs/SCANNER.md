# Full SIKDPI scanner in UNUNKNOWNTUN 3.7.0-preview.11

The full headless SIKDPI scanner is an independent tool for IP, TLS/SNI and authenticated REALITY testing, selected-result retests, download/upload measurement and private exports. It has a English terminal wizard and a scriptable command line. It does not require Tkinter, a display server, a web listener or an existing UNUNKNOWNTUN tunnel.

## Guided range rounds

For a managed Cloudflare tunnel, run `sudo ununknowntunctl cdn-rounds TUNNEL_ID`.
The manager takes the port and TLS SNI from that tunnel. Give a range and how many
IPs to sample. Every round asks for probes per IP, parallel workers and maximum
latency. Slower probes count as timeouts. Active IPs and completed results are
shown during scanning, then ranked by successful probes and latency.

Choose another round to select the Top N candidates and enter fresh probe,
worker and latency settings. Repeat as many rounds as needed. Ctrl+C stops the
current round, retains completed results and lets you select a successful IP.
When finished, enter the IP you want. Each round and the session history are saved.
The manager authenticates the selected address using the actual tunnel before
transactional application; failure keeps the previous endpoint. Application may
restart the selected tunnel. Generic probe success alone is not tunnel success.
The existing automatic scanner uses its unchanged all-samples-authenticated,
loss/latency/jitter ranking and minimum-improvement policy.

The standalone scanner's `rounds` command does not change a tunnel. Its port
can be supplied with `--port`; otherwise it defaults to 443. The original full
scanner, exports, REALITY tests and detailed results remain available.

## Open the scanner

After installing or upgrading this release:

```bash
sudo ununknowntunctl scanner
sudo ununknowntunctl scanner --help
sudo ununknowntunctl scanner ip --help
```

No tunnel ID follows `scanner`. The installer main menu offers **7 — Full SIKDPI scanner**, its management menu offers **23 — Full SIKDPI scanner**, and the terminal dashboard uses **k**. The dashboard's existing **s** remains the authenticated CDN scan/apply action. Demo dashboard mode never starts the scanner.

The standalone installer can also run its embedded scanner without installing a core or service:

```bash
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh scanner
```

This route extracts only the two scanner helpers into a private directory under `/run`, runs them, and removes that directory on exit. Opening a menu does not start a network scan or install optional dependencies. Normal installation/upgrade embeds the current helpers at `/opt/ununknowntun/share/scanner-console.py` and `scanner-engine.py`, with root ownership and modes `0755` and `0700`; existing upgrade rollback covers them.

## Keep the evidence levels separate

| Tool or method | What its result establishes |
| --- | --- |
| `scanner ip --method tcp` | A TCP connection to the selected address and port. |
| `scanner ip --method tls` | A generic Python/OpenSSL TLS handshake with the chosen SNI. |
| Browser TLS or generic `scanner sni` | A TLS handshake using the selected supported browser fingerprint. |
| REALITY mode | A probe through a temporary local Xray/SOCKS session using your actual REALITY link; TCP evidence remains separately visible. |
| `ununknowntunctl doctor TUNNEL_ID` / `scan` | Existing bounded diagnostics for that configured UNUNKNOWNTUN tunnel. |
| `ununknowntunctl cdn-preview TUNNEL_ID` | Existing authenticated UNUNKNOWNTUN CDN candidate comparison without applying it. |
| `ununknowntunctl cdn-scan TUNNEL_ID` | Existing authenticated CDN selection that can change an endpoint and restart the selected tunnel. |

Generic scanner TLS/browser probes deliberately disable certificate verification to measure SNI reachability. Their `Online` result does **not** certify the certificate, hostname, server identity, REALITY authentication, or UNUNKNOWNTUN authentication. Authenticated REALITY probes verify the HTTPS probe inside the tunnel. A REALITY result still does not test UNUNKNOWNTUN's own token/protocol. The full scanner never edits tunnel settings, enables a timer, changes firewall rules, installs a service, or applies an IP automatically.

## Inputs, controls and results

The wizard exposes manual IP/CIDR entry or files; TCP/TLS/browser choice; port and SNI; optional initial TCP port filtering; browser fingerprints; target/server override; manual, file, common-list or crt.sh SNI candidates; REALITY credentials; concurrency, attempts and timeout; Top N retesting; transfer sizes; result selection and exports.

The browser provides pagination, all-row display, details, sorting and text filtering. `--rows 1,3-5` selects rows **after** filtering/sorting, with one-based numbering. `--online` filters the displayed status; it does not upgrade weak evidence into an authentication claim. Retest and speed commands additionally accept `--top N`. Reports preserve all completed rows; displayed page size does not discard results.

Result fields include target, pinned connection address, port, method, SNI/fingerprint, status/verdict, successes/attempts, failure percentage, average/minimum/maximum latency, jitter, standard deviation, individual latencies, TLS version/ALPN where available, TCP sub-results, classified failure reasons, per-attempt diagnostics and transfer statistics. The legacy names `avg_ping` and `packet_loss` mean **probe latency** and **failed-probe percentage**, not ICMP ping or independently measured network packet loss. Latency statistics use successful attempts. A missing value is unavailable, not zero. Speed results include download/upload Mbps, success, bytes and elapsed seconds separately.

## Command examples

The reserved addresses and example domains below are placeholders. Replace them with destinations you own or are authorized to test; the scanner rejects reserved example address ranges. Network commands require `--authorized`. For an authorized private/loopback lab, also use `--allow-private`; metadata and link-local destinations remain forbidden. No tests in this guide have been run against a public server.

```bash
sudo ununknowntunctl scanner ip 192.0.2.10 --method tcp --count 4 --timeout 4000 --workers 8 --authorized
sudo ununknowntunctl scanner ip --input-file /root/candidates.txt --method tls --sni edge.example --port-filter --authorized
sudo ununknowntunctl scanner ip 192.0.2.10 --method browser --sni edge.example --fingerprint chrome --authorized
sudo ununknowntunctl scanner sni 192.0.2.10:443 edge.example --authorized
sudo ununknowntunctl scanner sni 192.0.2.10:443 --sni-file /root/sni.txt --server 192.0.2.20:443 --authorized
sudo ununknowntunctl scanner discover example.com --candidates-output /root/discovered-new.txt --authorized
```

Use a private `0600` file containing one REALITY VLESS/Trojan link, or `--secret-prompt` for hidden entry in a terminal. Do not put credential-bearing links into command arguments or shell history. Xray must have an explicit trusted absolute path; the scanner does not search the root user's current directory or `PATH` for it.

```bash
sudo ununknowntunctl scanner sni 192.0.2.10:443 edge.example --reality-config /root/reality-link.txt --xray /root/.cache/ununknowntun/scanner/xray --authorized
sudo ununknowntunctl scanner results
sudo ununknowntunctl scanner results /root/REPORT.json --sort avg_ping --online
sudo ununknowntunctl scanner results /root/REPORT.json --detail 1
sudo ununknowntunctl scanner retest /root/REPORT.json --top 20 --count 10 --timeout 4000 --authorized
sudo ununknowntunctl scanner retest /root/IP-REPORT.json --top 10 --method browser --sni edge.example --port 8443 --fingerprint chrome --authorized
sudo ununknowntunctl scanner speed /root/REPORT.json --top 2 --download-mb 20 --upload-mb 10 --traffic-consent --reality-config /root/reality-link.txt --xray /root/.cache/ununknowntun/scanner/xray --authorized
```

Use the actual trusted Xray path printed by dependency setup instead of the illustrative path above. REALITY retests require the REALITY file/prompt and explicit `--xray` again. Speed tests use `speed.cloudflare.com` through the temporary REALITY connection. Payload plus protocol overhead consumes bandwidth and quota; the wizard displays the planned amount, and CLI speed testing requires separate `--traffic-consent`.

Retesting preserves each selected row's method and pinned address unless you explicitly override supported settings. For IP reports, `--method tcp|tls|browser` changes the probe method and `--sni` changes its SNI. `--port` and `--fingerprint` can override those settings for retests of any supported scan report. For REALITY, the default fingerprint comes from the supplied secret link; an explicit fingerprint override also changes the temporary Xray configuration. The English retest wizard offers these choices. Each retest writes a new report and preserves the original.

```bash
sudo ununknowntunctl scanner export /root/REPORT.json --rows 1,3-5 --format csv --output /root/selected-new.csv
sudo ununknowntunctl scanner export /root/REPORT.json --format json --output /root/full-new.json
sudo ununknowntunctl scanner export /root/REPORT.json --format txt --output /root/full-new.txt
sudo ununknowntunctl scanner sni-json edge.example:443 --report /root/REPORT.json --rows 1,3 --output /root/reality-settings-new.json
sudo ununknowntunctl scanner configs /root/IP-REPORT.json --config-file /root/client-link.txt --rows 1,3-5 --output /root/client-links-new.txt
```

`sni-json` produces a REALITY `target`/`serverNames` snippet; it does not install a complete server configuration. `configs` rewrites only the destination IP in supported VLESS, VMess, Trojan or Shadowsocks links selected from an IP report. Its output contains credentials and stays private. JSON, CSV and TXT exports include the available selected fields and attempt details; existing output files are never overwritten.

## Optional dependencies

TCP and generic TLS need only the standard library. Browser fingerprints, generic SNI and REALITY probe/speed modes need `curl-cffi`; REALITY also needs Xray. Status is safe to inspect without starting Xray:

```bash
sudo ununknowntunctl scanner dependencies status
sudo ununknowntunctl scanner dependencies check --xray /absolute/trusted/path/to/xray
sudo ununknowntunctl scanner dependencies install --authorized
```

`xray` is an alias for `dependencies`. Only the explicit `install --authorized` action downloads Xray. It uses the engine's pinned release and verifies SHA-256 metadata before installing a private executable. HTTPS release metadata plus a matching hash is integrity evidence; it is not a separate publisher signature or a general security audit. Existing Xray services/configurations are not adopted or changed.

Install `curl-cffi` explicitly into the scanner's **private virtual environment**, never into system Python:

```bash
sudo install -d -o root -g root -m 0755 /opt/ununknowntun
sudo /usr/bin/python3 -m venv /opt/ununknowntun/scanner-venv
sudo /opt/ununknowntun/scanner-venv/bin/python3 -I -m pip install curl-cffi==0.13.0
sudo ununknowntunctl scanner dependencies status
```

If Python's `venv` support is absent, install the matching distribution package deliberately before these commands. No pip/package command runs automatically. The launcher selects this fixed virtual environment when present and otherwise uses system Python. It checks root ownership and non-writability by other users for helpers, environment files/directories and the interpreter's resolved target, then launches Python with `-I`. Unsafe environments are refused, not silently repaired or bypassed. A fingerprint unsupported by the installed `curl-cffi` version is an error, not a successful fallback.

Optional curl-cffi execution or skips are recorded in the fresh validation logs. Standard-library and mocked tests do not establish actual browser-library behavior. Its upload fallback is limited to **16 MiB per upload** because this binding does not provide the streaming read callback. Larger uploads return `DEPENDENCY_ERROR`; they require a binding with working streaming `READFUNCTION` support. The default 10 MiB upload stays within the verified fallback limit. This local validation does not establish public WAN throughput.

## Privacy, limits and cancellation

Reports default to `~/.local/state/ununknowntun/scanner-reports` for the executing account; with `sudo`, normally `/root/.local/state/ununknowntun/scanner-reports`. Use `--report-dir` for another private directory. Report directories are `0700`; files and secret exports are `0600`. Credentials are excluded from scan reports, and raw sensitive diagnostics are replaced with classified errors. Targets, IPs and SNI names can still be operationally sensitive; share exports deliberately.

Input is bounded to 4096 explicit IP candidates or target/SNI combinations, up to 32 workers for generic probes, 100 attempts and a 100–120000 ms timeout. **REALITY scans, REALITY retests and speed tests run one job at a time**; `--workers` and the compatibility option `--reality-workers` do not increase their actual concurrency. For REALITY, `--timeout` applies independently to TCP checks, Xray startup and the tunneled probe; it is not a total attempt or batch deadline. Oversized CIDRs/combinations fail rather than silently truncate. Discovery allows up to 32 base domains and a configured per-domain limit. Speed inputs allow up to 256 MiB per direction and 4096 MiB aggregate requested payload, subject to the dependency's upload capability described above. Lower attempt/target counts to reduce load and elapsed time.

Ctrl+C cancels queued work, signals running probes and closes scanner-owned temporary Xray processes. Scan reports retain completed rows with `cancelled=true`; a partial report is not a complete scan. DNS/TLS/network errors are evidence of the attempted operation, not a conclusive diagnosis of censorship or server failure. Discovery queries crt.sh and must not be treated as proof that discovered names are usable or authorized targets.

Offline packaging, mocked routing, local fixtures and loopback tests provide local evidence only. Real Iran-to-foreign paths, provider/DPI behavior, public WAN throughput and long-term stability require separate authorized validation. Installing this release or viewing an `Online` row does not establish those properties.
