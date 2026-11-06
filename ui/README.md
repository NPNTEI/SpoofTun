# UNUNKNOWNTUN Terminal UI

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

A terminal companion for an existing UNUNKNOWNTUN installation, organized into **Tunnels**, **Tuning** and **Doctor**. This is UI **3.7.0-preview.11**, retaining the **3.5** manager layout with optional **3.7** actions. The UI itself is **not UNUNKNOWNTUN V1**, a new tunnel core, an upgrade installer or a web control panel.

No live-server validation has been performed. Opening the interface does not install, migrate, restart or remotely probe anything. The three guides cover the same behavior; application menus and command names remain in English.

## 3.7 quick guide: endpoints, ECH and padding

The Tuning page separates the actual **Dial endpoint**, **TLS SNI** and **HTTP Host**. A clean IP/domain changes the connection destination; it does not automatically replace the TLS name or Host. Use `e` to open the selected tunnel's editor. Manual endpoints may be IPv4, IPv6 or domains; automated range scanning is Cloudflare IPv4 only, not Fastly/Arvan scanning.

- `n` opens CDN settings (`cdn`): choose candidates, maximum scan duration, improvement threshold and optional periodic updates. Automatic updates default to **off**; the default interval is **8 hours**, and the default scan budget is **300 seconds**, capped at **600 seconds**.
- `s` delegates scan/application (`cdn-scan`) to the matching manager. This can change the selected tunnel's destination and restart it; entering its exact ID is required. Authentication is not proof of client payload or bandwidth.
- `v` displays CDN status (`cdn-status`) without enabling updates or starting a scan. Simply opening or refreshing the UI never scans or changes settings.

ECH source is shown as automatic DNS discovery, a manual DNS/resolver descriptor, or a manual ECHConfigList. Resolver URLs/queries and raw configuration bytes are hidden from the dashboard. ECH acts on the connection-initiating TLS client; it is not inherently tied to Iran. The TLS terminator must actually support it. **“TLS Hello over DNS” has been removed from menus**; DNS-based ECH discovery remains and is not a DNS tunnel.

In 3.7, `p` runs `cdn-preview` with progress but does not change the endpoint or restart a tunnel. Tuning shows path rotation/count and carrier renewal. Use `e` for the atomic paired path profile, carrier-renewal interval, or Iran entry migration to `nginx` (standalone HTTPS, no CDN). Both peers need 3.7 for rotation, synchronized clocks and identical signed settings. Nginx HTTP entry requires matching WS/XHTTP clients; raw TCP is not converted automatically.

XHTTP modes `auto`, `packet-up`, `stream-up` and `stream-one` and both padding values are visible. **Frame padding bytes** and **XHTTP HTTP padding** are separate settings. Streaming-mode compatibility through real CDNs has not been certified; test the selected provider and mode with real client traffic. These actions require the matching 3.7 helpers; unsupported older managers are refused, never silently upgraded.

## Verify the package

Extract the complete release ZIP and open a terminal at the release root containing `SHA256SUMS`, not inside `ui/`. If a source-only archive has no manifest, use the published archive checksum instead. Verify files from the same trusted release before running them:

```bash
sha256sum -c SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS`. Checksums detect changed files; they do not establish trust when an attacker controls both the files and manifest.

## Preview without accessing a server

Inside the `ui/` directory, on macOS or Linux with Python 3.8 or newer:

```bash
python3 ununknowntun-ui.py --demo
```

Demo mode needs no root access. All data is illustrative, and every live action is disabled. Type a key or command and press Enter. For a single sample screen without an interactive terminal:

```bash
python3 ununknowntun-ui.py --preview doctor
```

The complete release may include `ui/preview.html`. A source-only archive does not require generated preview files. To create a fresh local preview, choose a filename that does not already exist:

```bash
python3 ununknowntun-ui.py --export-html ui-preview.html
```

Open `ui-preview.html` in your browser to inspect all three sample pages. It is a static local preview, not a working web dashboard or a diagnostic result; it contacts no server.

## Run on an existing server

Live mode requires Linux, root, Python 3.8 or newer, systemd and an existing UNUNKNOWNTUN manager. The UI has no third-party Python dependencies and installs or downloads nothing.

The installer now includes this UI: choose **9) Control Room UI** in its main menu. After a normal install or upgrade, open it directly:

```bash
sudo ununknowntunctl ui
```

To open the embedded UI without installing or upgrading anything, run:

```bash
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh ui
```

Guided rounds (`b` / `cdn-rounds`) use the selected tunnel's port and SNI, ask for range/count and per-round probes/workers/maximum latency, show live results, and allow repeated Top-N refinement. Ctrl+C retains completed results. Choosing an endpoint runs the existing authentication and transactional apply checks; automatic scanning policy is unchanged. Direct ICMP endpoints remain isolated from standard tunnel actions. Press **i** to open their dedicated manager, available even when no standard tunnel is registered; use the installer's **8) ICMP L3** for setup.

The initial view only reads local configuration and service state. It does not replace `/usr/local/bin/ununknowntunctl`, the core executable, Nginx, X-UI, firewall rules, certificates, ports or peer files. The installed editor and Doctor helpers are needed for their respective actions; unsupported manager commands are refused rather than treated as successful.

## Controls

Enter one of these commands, then press Enter:

| Command | Action |
|---|---|
| `1` | Tunnels page |
| `2` | Tuning page |
| `3` | Doctor page |
| `t 2` | Select the second tunnel in the list |
| `e` | Open the existing full editor for the selected tunnel |
| `a` | Open the existing paired-server update-code workflow |
| `c` | Open existing customer, port and quota management |
| `u` | Show usage through the installed manager |
| `o` | Start, stop, restart or remove the selected tunnel |
| `n` | After exact-ID confirmation, open CDN endpoint and periodic-scan settings |
| `b` | Guided Cloudflare scan rounds, refine Top-N and select an authenticated endpoint; exact tunnel ID required |
| `p` | Preview the authenticated CDN scan without changing the endpoint |
| `s` | After exact-ID confirmation, scan/apply an endpoint; may restart this tunnel |
| `v` | Show CDN settings/status without starting a scan |
| `k` | Open the full SIKDPI scanner: IP, SNI, REALITY, speed and exports; no tunnel selection required |
| `i` | Open Direct ICMP management: endpoint list, forwarding information, status, start/stop/restart, logs, doctor and removal |
| `f` | Check configuration offline with the installed Doctor |
| `d` | After confirmation, probe this tunnel's configured endpoints |
| `r` | Refresh local state and discard previous on-screen reports |
| `q` | Exit the UI |

The full scanner opens an English wizard through `ununknowntunctl scanner`. Opening it performs no network scan or dependency installation. It asks for targets and authorization before scanning, saves private reports, and never applies results to a UNUNKNOWNTUN tunnel. Generic TLS/SNI reachability, authenticated REALITY and UNUNKNOWNTUN authentication are separate evidence levels. The existing `s` action still performs the authenticated CDN scan/apply workflow; `k` does not enable it. Demo mode blocks `k` as well as other live actions.

Before opening a change-capable operation, type the exact selected tunnel ID. An empty confirmation cancels it. The existing editor still previews and confirms individual changes, handles locking and rollback, and produces paired updates where needed. Removal also retains the existing manager's confirmation and backup workflow.

Editing, stopping or restarting may interrupt the selected tunnel. Read the operation's output; exit code zero alone does not prove client connectivity. Customer and editing forms still use the existing interfaces and have not received a complete visual redesign.

## Managed and read-only services

Standard tunnels registered under `/etc/ununknowntun/tunnels` can be selected for management when their configuration is readable and trusted. Legacy or separately installed services, including `ununknowntun.service`, `ununknowntun-germany.service` and `ununknowntun35-turkey-yta.service`, are shown **read-only**. The UI never automatically adopts or upgrades them.

Creating new tunnels and upgrading the core remain tasks for the existing installer; this preview does not launch it. Do not mix UNUNKNOWNTUN V1 and 3.x files or pairing information. This UI does not make V1 compatible with the 3.5 manager layout.

Settings shown are saved configuration, not proof that ECH, MUX or a connection was negotiated successfully. Unsafe or unreadable configuration blocks actions. If configuration changes after selection, refresh and review it before continuing.

## Understand diagnostics

- `active/running` describes the service process, not a working tunnel or Internet connection.
- `WAIT` means a check has not run. `PASS` comes from the actual Doctor report, not an illustrative success label.
- TLS or tunnel-authentication success does not prove VLESS, Shadowsocks or real website traffic works. **Real client payload** remains `TODO` and requires a separate client test.

Doctor uses the matching installed helper and tests configured endpoints only. It does not scan port ranges, disable TLS verification or rewrite configuration. The UI allows **55 seconds total**, with **3 seconds per stage**. Slow paths or many candidates may exceed that limit; an incomplete run is not a success and does not establish the cause of failure. Use the existing CLI for a longer diagnostic run. Offline mode performs no network checks.

Reports are timestamped snapshots, not continuous monitoring. Endpoint errors identify the failed stage; the interface does not guess that a token, certificate or firewall must be responsible.

## Display and secrets

Termius or your terminal controls the background and font. The exact white appearance of the concept image is not guaranteed. A window of at least 80 columns and about 40 rows is easier to read; scroll upward in a short window. Use `--ascii` for limited fonts or `--no-color` for plain output. `NO_COLOR` is also respected.

The dashboard and static preview do not display tokens, `peer.env`, private keys or private tunnel routes. Diagnostic details come from the installed Doctor's sanitized report. The existing editor may display a confidential synchronization code after a change: do not publish that code or screenshots containing secrets.

## Validation and exit

Run the bundled offline UI tests:

```bash
python3 test_terminal_ui.py
```

Tests use fixtures and mocked service calls, not real servers or network connections. For the complete suite, run `python3 run-tests.py` from `source/ui/` (or `ui/` in the GitHub source archive), with the matching `packaging/` directory beside it. A standalone UI copy cannot run compatibility integration. The complete release's root `VALIDATION.md` and `validation/` record build-time checks and limits; its root `SHA256SUMS` covers delivered files. These generated reports are not required in a source-only archive. Local tests do not replace a live Linux acceptance test. Test on a non-production server first.

Press `q` to exit. The UI has no daemon or boot entry; closing it does not stop tunnels. After exiting, removing this companion file does not remove the tunnel core or its configuration. **Do not copy it over `ununknowntunctl`.**

## GitHub publication

Keep these three UI guides (`README.md`, `README.ru.md`, `README.zh-CN.md`) together inside `ui/`; do not overwrite the core release's root README with a UI-only guide. Their only required relative links are the three guides themselves. These translations are equivalent guides, not three different implementations.

This companion was prepared locally and has **not been uploaded to GitHub**. Do not include real server configuration, pairing files, credentials or private keys when publishing. The UI directory alone is not a complete UNUNKNOWNTUN core release.

## Direct ICMP management

Use `--icmp-manage --list` for a read-only inventory without an interactive terminal. The **i** shortcut and `--icmp-manage` open the trusted `direct-icmp-console.py` staged beside the UI. The matching installer and installed `ununknowntunctl ui` stage both files. Source-only `--preview` and `--demo` do not need this helper; live management requires the installed/staged pair. Opening the console only reads `/etc/ununknowntun-direct-icmp`; it performs no migration, scan, installation or service change. Configured local and remote forwarding ports appear in the endpoint list.

Each action uses the selected endpoint's own verified manager. Older valid endpoints remain on their existing version; unsupported actions are refused without upgrading or substituting a restart. Start, stop, restart and removal require the exact `pair/role` identity. Removal affects only that local endpoint, not its peer. Demo mode blocks **i**. Service status is not proof of payload delivery; Doctor and real-client checks remain separate.
