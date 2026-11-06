# 3.7.0-preview.11

- Add optional lifecycle-managed TCP/UDP relays to Direct ICMP, with bounded idle time, flow count, startup rollback and shutdown cleanup.
- Ask the Iran entry port and foreign application port during foreign-first setup; allocate a separate private relay port and include the matched mappings in the pairing code. No external socat process is required.
- Add dedicated Direct ICMP management to menu3 and Control Room key i, retaining exact installed-bundle trust and legacy version identity without automatic migration.
- Add manager restart and redacted info; preserve the actual service-status exit code.
- Document the proposed two-peer spoof candidate scanner separately; source-range discovery and automatic reserve activation are not implemented in this release.

Executed validation and remaining network limits are recorded in the fresh release report.

# 3.7.0-preview.10

- Restore the Control Room terminal UI in the standalone installer: main-menu option 9 and the `ui` command.
- Install the UI with the normal manager installation/upgrade and reopen it using `ununknowntunctl ui`.
- Preserve the Tunnels, Tuning and Doctor layout, English interface and read-only opening behavior.
- Connect the UI to guided Cloudflare refinement rounds while retaining the independent full scanner.
- No tunnel wire format or runtime behavior change from preview.9; existing ICMP pools, pairing, recovery and scanner policies are retained.

Validation is recorded in this release's own report; earlier runtime results are not represented as fresh WAN testing.

# 3.7.0-preview.9

- Guided foreign-first Direct ICMP L3 setup using a private matching code on Iran; no manual endpoint-file transfer.
- Separate private IPv4 pools and per-new-flow round-robin source NAT, preserving established TCP/UDP mappings.
- Scoped nftables ownership leases and safe recovery after process crashes.
- Keep the runtime/TUN alive on transient route/interface send failures; authenticated recovery continues.
- Installed read-only doctor for route, firewall, Fail2ban, kernel and runtime evidence.
- English installer/scanner/diagnostics, with Persian documentation copies removed.
- Unlimited manual scanner refinement rounds with inherited tunnel port, per-round controls, live progress, early stop, full reports and final IP choice.
- Authenticate manually selected Cloudflare endpoints before transactional application; automatic scanner policy retained.

Validation is recorded separately in the fresh release report. Local tests do not certify public WAN or provider behavior.

# Changelog

## 3.7.0-preview.8 — bounded adaptive FEC for Direct ICMP

- Add `off`, `fixed` and `adaptive` repair modes to Direct ICMP, with a bounded systematic Reed-Solomon codec and authenticated per-direction receiver feedback. Forward original data without waiting for the repair block to fill.
- Bound repair overhead and block lifetime; adapt repair and sending pressure to measured path conditions. FEC cannot repair a fully blocked ICMP path or guarantee delivery under arbitrary loss.
- Extend paired setup with repair mode, cap, fixed target and block deadline. New generated pairs select adaptive by default; existing runtime JSON without FEC fields remains off. Both peers must support the enabled FEC wire format.
- Keep the previous non-FEC wire format for off mode and preserve independent services, exact-release binary verification, private pair files and explicit private routes. Existing WSS, XHTTP, scanner and other modes remain separate.
- Add codec, feedback, configuration and generator regressions plus local Linux fault tests. Executed test evidence belongs to this release's validation report; WAN, operator filtering and long-term performance are not established by local testing.

## 3.7.0-preview.7 — independent Direct ICMP IPv4 tunnel

- Require Go 1.26.10 or newer for packaged binaries, including the crypto/x509 security fix for GO-2026-6809; reject older build metadata before rendering a release installer.
- Add an independent authenticated, encrypted IPv4 L3 tunnel over native ICMP Echo, carrying permitted TCP, UDP and ICMP packets between private tunnel addresses. Include replay protection, bounded queues, session rekey and recovery after path loss.
- Add one-time matched pair generation, private keys/configuration, independently named systemd services, and hash/version/architecture-checked install, start, status, stop and uninstall. Integrate installer menu8, tunnel-type choice5 and `ununknowntunctl direct-icmp-pair`; preserve the existing scanner and transports.
- Create only an exclusive TUN and explicit private peer routes; use configurable MTU and TCP MSS clamping. Do not alter default routes, NAT, forwarding, firewall or host sysctl.
- Add protocol, configuration, generator and lifecycle regression coverage plus opt-in local Linux namespace/systemd harnesses. Consult this release's validation reports for executed results; WAN performance, provider filtering and long-term stability remain separate checks.
- This mode requires no TLS certificate, WS or ECH. It is not Backpack wire-compatible, IPv6, NAT traversal, source-IP spoofing or a Cloudflare proxy transport. A continuously blocked ICMP path cannot be repaired by session recovery.

## 3.7.0-preview.6 — full SIKDPI scanner

- Add the original scanner's IP/CIDR, SNI, TCP/TLS/browser and TCP/raw REALITY workflows through a Persian terminal wizard and scriptable CLI, independent of tunnel configuration.
- Add complete result history, sorting, selection, detailed attempt metrics, method-aware retests, download/upload tests, JSON/CSV/TXT exports, SNI JSON and client-link rewriting.
- Integrate installer menu7, management menu23, dashboard key k and ununknowntunctl scanner. The standalone installer can open the scanner without installing a tunnel.
- Bound inputs, worker counts, DNS workers and timeouts; support IPv6 and cancellation, preserve partial reports, and use private report/secret files. Xray selection/download is explicit; authenticated tests force SOCKS even when NO_PROXY is set.
- Keep the existing authenticated CDN apply workflow separate. Generic TLS reachability does not prove REALITY or UNUNKNOWNTUN authentication. REALITY requires an explicitly configured Xray and optional curl-cffi; only TCP/raw link transport is supported.

## 3.7.0-preview.4 — native IP-spoof pair setup and wire evidence

- Add a generation-only native GRE wizard (installer menu6 / spoof-pair) with matched two-peer IP configuration, fresh pinned TLS/token, private role-specific launchers and separate minimum-capability systemd templates. It does not upgrade or activate existing tunnels.
- Distinguish actual outer source override from TLS/browser fingerprint profiles; real outer destination remains the peer. The separately inspected reference's spoof_dst_ip is an incoming-source filter, not an arbitrary destination override. No reference executable is redistributed or required.
- Expose configuration-only outer/inner address plans and categorized TX/RX identity/truncation rejects, with explicit kernel/rp_filter-before-counters guidance. GRE packet semantics and fail-closed transport remain unchanged.
- Add independent bounded AF_PACKET capture/parser tests alongside generated-launcher integration, authentication and mismatched-peer negatives. Consult fresh validation for executed results; synthetic namespaces do not certify Internet/provider behavior.
- Reject type-confused GRE JSON in pair integrity checks; preserve temporary-file cleanup on failed/cancelled wizard invocation. Do not claim bug-free, Backhaul wire compatibility or DPI resistance.

## 3.7.0-preview.3 — payload stall detection and bounded path recovery

- Negotiate a real 1 KiB data-queue roundtrip before publishing a carrier; repeat with bounded timeouts and three-miss recovery independent of outgoing traffic. Legacy peers explicitly retain control-heartbeat-only coverage.
- Accept bounded consumed-once late proofs so slow but progressing FIFO traffic does not look like a blackhole. Do not claim Internet/Xray/phone-path coverage.
- Quarantine failed rotating paths and generate bounded random HMAC-authenticated recovery routes without relying on the failed control channel. Preserve fixed-route fallback and endpoint isolation for pre-HTTP failures.
- Align renewal with actual route epochs; cap old-carrier draining at two minutes and pending leases at 30 seconds, with fair retries and one spare. Long streams may be interrupted; no zero-disruption guarantee.
- Restrict managed Nginx to supported 32/64-hex routes and valid XHTTP suffixes; migrate old generated prefix routes without changing unrelated locations.

## 3.7.0-preview.2 — audit fixes

- Suppress degradation-triggered extra carrier creation under high memory pressure; preserve scheduled renewal and bounded draining.
- Harden coordinated-path profile validation, Nginx managed-block validation, MUX/session capacity checks, and interrupted editor rollback. Failed rollback leaves the affected tunnel stopped instead of activating mixed files.
- Serialize scanner scheduling/deletion with tunnel edits. Fail closed on local configuration errors, late/invalid probe samples, and incomplete scheduler rollback; terminate cancelled probe children.
- Expand parser fuzzing, randomized clock-boundary tests, concurrent renewal/cancellation regressions, actual Nginx configuration checks and timed path-rotation/failover tests. See fresh validation evidence for executed results and limitations.
- Update the build toolchain and linked dependencies to security-patched versions recorded in the build metadata and dependency audit.

## 3.7.0-preview.1 — coordinated paths and resilient sessions

- Added opt-in shared UTC/HMAC path rotation for WSS/XHTTP, multiple authenticated fallback routes and bounded old/new overlap. Both peers need matching settings and synchronized clocks. Existing authenticated XHTTP uploads retain their original route while draining.
- Added optional make-before-break session renewal alongside adaptive pool sizing. Replacement authentication precedes retirement, active streams retain their IDs, and long-lived streams can postpone further renewal. This does not generate public IPs.
- Removed the unsupported ClientHello-over-DNS menu choice; strict ECH and ECH DNS discovery remain.
- Improved Cloudflare scanner preflight, progress, classified errors and preview-only mode. A local configuration error is no longer reported as repeated candidate network failure. Live ISP/CDN behavior still needs deployment-specific validation.
- Added explicit standalone Nginx entry on Iran, independent of CDN selection, with matching WS/XHTTP customer-entry requirements. Added paired path-profile editing and updated installer/UI documentation.
- Fixed authenticated XHTTP path fallback when download works but upload fails, fair fallback across all overlapping paths, and premature carrier retirement while a slow peer is still receiving an upload.

Experimental preview: see the bundled fresh VALIDATION.md and docs/ADVANCED-3.7.md. Local tests are not a production Linux/Nginx, live CDN, bandwidth, or filtering-resistance certification. No running server was changed by release preparation.

## 3.6.0-preview.1 — editable CDN endpoints and transport profiles

- Added independent dial IP/domain, verified TLS SNI and HTTP Host settings to installation, transactional editing and terminal UI.
- Added bounded Cloudflare IPv4 scanning using actual core certificate/ECH/transport/token authentication, optional per-tunnel timers, stale-result rejection and post-change rollback. Automatic changes can interrupt this tunnel's sessions; no speed or filtering-resistance guarantee is made.
- Added manual Base64 ECHConfigList and domain-plus-UDP/TCP/DoH resolver sources alongside automatic strict ECH discovery. ECH failures do not silently disable ECH.
- Implemented UNUNKNOWNTUN-specific XHTTP stream-up/stream-one alongside packet-up; auto deliberately selects packet-up. Both peers must be updated. This is not stock Xray wire compatibility.
- Added opt-in byte-count data padding for WSS/XHTTP and independent XHTTP header padding. Legacy ratio padding remains ignored.
- Extended the terminal UI and four-language guides, isolated scheduler deletion/rollback, installation repair prompts and package validation. Existing Linux/direct-TLS GRE support remains separate from CDN modes.
- TLS menu choice 4 (ClientHello over DNS) is explicitly unavailable, not a working feature. It needs a cooperating relay/transport design; fetching ECH configuration over DNS is not DNS tunneling.

This is an experimental preview. Consult the fresh VALIDATION.md supplied with the reviewed download; source build/assembly alone is not evidence of a live CDN or production Linux deployment. Historical release reports mentioned below are not this release's test evidence.

## 3.5.0-rc1 — completed carrier cleanup, entry migrations and diagnostics

- Removed gRPC/H2 carrier implementation and outbound frame-padding generation. Legacy CLI aliases log migration to WSS; old padded frames remain decodable. Managed upgrades retire only selected gRPC routes, retain certificates/quotas/usage and set pad to zero.
- Replaced serial XHTTP uploads with an eight-request bounded pipeline, ordered receive window, gap deadlines, asynchronous error propagation and FIN/Close delivery barriers. Both XHTTP peers require 3.5; new pairing exports are V5.
- Fixed an early-peer-FIN truncation race in MUX OFF by waiting for remote stream-completion acknowledgement before releasing the exclusive carrier.
- Added signed provider edits and transactional Iran direct/proxy and WebSocket/XHTTP entry migrations, including customer listeners/routes/exports. Existing usage is never refunded during rollback. Xray inbound and external CDN changes remain explicit manual preparation.
- Removed the ECH provider-name allowlist; strict acceptance and real DNS ECH configuration remain mandatory. No provider support is inferred from the menu.
- Added bounded real-core authentication-only probes and a read-only explicit-candidate scanner, stage-specific reports, secret redaction, private report creation and no automatic endpoint switching.
- Separated local-origin CA verification from public CDN-edge trust. Added Arvan edge/origin certificate guidance and support for existing downloaded origin certificate/key files.
- Added migration rollback, disabled-account, trust-selection, scanner, pipeline/reordering and transport-retirement regressions. See RELEASE-VALIDATION.md for the actual run and its limits.

This is a release candidate, not a promise of defect-free software or live CDN compatibility. Current gRPC/padding removal supersedes the historical retention statements below.

## 3.4.0-rc1 — experimental XHTTP, selectable MUX and TLS profiles

- Added an independently implemented XHTTP packet-up carrier: sequenced finite POST uploads, streaming GET downloads, per-request HMAC and existing UNUNKNOWNTUN authentication. No gRPC envelope; website fallback remains on other paths.
- Added experimental Fastly profiles and independent client-entry protocol metadata. Inter-server XHTTP does not silently change existing Xray WebSocket entries. Iran Fastly requires explicitly configured XHTTP entry/inbound.
- Added real MUX OFF: one exclusive carrier per user TCP connection, bounded concurrent handshakes/connections, 15-second capacity queue and existing quota/global-stream limits. Both peers must be synchronized.
- Added ECH OFF / strict ECH ON / ECH OFF with experimental initial ClientHello TCP-write fragmentation. Editable default 100–200 bytes, 1–3ms; fragments may be coalesced. Strict ECH remains certificate-verified TLS 1.3 and never silently downgrades.
- New normal installs use WSS and zero legacy frame padding. Upgrades preserve old auto/H2/WSS, TLS minimums, Nginx TLS settings, padding, quotas and usage.
- Editor synchronizes carrier/path/MUX settings, validates TLS profiles and rebuilds selected routes transactionally. Customer XHTTP routes preserve session/sequence suffixes and export their actual entry protocol.
- New V4 pairing exports reject old installers safely; legacy V3 pairing codes remain importable. Signed edit codes remain a separate format.
- Added transport/authentication stage diagnostics without misclassifying malformed responses or timeouts as proven token failures. Frame authentication timeouts retain their exact waiting stage and underlying cause.
- Expanded tests for XHTTP TLS/data/half-close, HMAC/replay/resource limits, deadlines/cancellation, MUX exclusivity, fragmentation byte integrity and new install/edit profiles.

### Explicit RC limitations

- Initial XHTTP upload is serial: at most one 64-KiB POST per RTT, often less for small frames. It is not an optimized stock Xray implementation, VLESS endpoint, H3 transport or Xray XMUX.
- ECH depends on the TLS terminator accepting it; the installer offers strict ECH only for Cloudflare foreign profiles. No customer-endpoint ECH claim is made for Fastly or Arvan.
- Live CDN accounts, ECH deployment, systemd/Nginx installation, WAN throughput and resistance to filtering require separate validation. No server was changed for this release build. See RELEASE-VALIDATION.md for actual local results.

## 3.3.0-rc1 — edit existing tunnels

### Added

- A unified per-tunnel editor: `ununknowntunctl edit`, read-only settings through `edit-show`, and paired-server editor updates through `edit-apply`.
- Editable display names, domain/certificate settings, shared connection token, transport paths, padding and stream/resource options; IP and port editing remain available from the same menu.
- Preview and confirmation, targeted input correction, managed configuration backups and rollback. Existing accounting state is not restored from an older backup or reset during an edit.
- Confidential V3 synchronization codes for paired settings, bound to the tunnel pair and previous field values. Pasted updates are parsed as data, never executed as shell commands.
- Private per-change `edit-update-HASH.txt` archives and a replaceable `last-edit-update.txt` copy. Codes expire after seven days and must be applied in order while their previous values/token remain current.
- Certificate/key checks before activation and embedded editor helpers in the complete offline installer.
- Separate full-editor and editor-TLS regression suites in the Linux release pipeline.

### Fixed

- Preserve numbered metadata names such as `H2_BACKEND_PORT` when reading and rewriting deployment settings.
- Reject transport/infrastructure ports and other tunnels' reserved ports as the foreign Xray target before probing it.
- Invalid synchronization codes re-prompt only for the code; unchanged settings return without creating a transaction.

### Compatibility and operational limits

- Upgrade each tunnel on both servers before using the new editor. The friendly name is editable; the immutable service ID, pairing identity and customer IDs remain stable.
- Server role, direct/proxy topology and CDN provider conversion are outside the editor. Certificate edits select an already-issued matching certificate/key; issuance and automatic renewal are not provided by this UI.
- `edit-ip` and `edit-ports` use the new transactional editor. `apply-update` and `edit-apply` both accept V3 editor codes; older V2 codes must be regenerated with the new release.
- Paired token/domain/path changes may disconnect the selected tunnel until applied on both sides. No remote SSH, DNS/CDN account update or Xray-panel mutation is implied.
- Certificates and their private keys are not exported in synchronization codes. Token-rotation codes contain the new token and must stay confidential.
- Live CDN compatibility, replacement-domain DNS propagation and production Linux service behavior still require deployment-specific validation. Local regressions are not a live-server success claim.

## 3.2.0-rc1 — customer quotas and recoverable setup

### Added

- Per-customer entry ports or proxied WebSocket routes, enable/disable controls, usage status and customer endpoint exports.
- Combined upload/download accounting, independent customer quotas and a total tunnel quota. Zero means unlimited; GB uses decimal units.
- Persistent accounting with durable reservations, corruption checks and fail-closed behavior. Any restart can conservatively charge at most 64 KiB of unused allowance per active account, including after an orderly shutdown.
- An initial total-quota question on Iran and a customer-management menu. The original entry is retained as the `default` account.
- An explicit `upgrade` workflow for existing instances: preserves settings and consumption, initializes accounting once for older installations, and restarts only the selected instance if it was active. Managed-file rollback never refunds an existing traffic ledger.
- Verified WebSocket upgrade probes for local and CDN endpoints. Foreign transport probes include HMAC pre-authentication and validate the WebSocket accept response.
- GitHub Linux CI and a tag workflow that builds checked release assets into a draft GitHub release.

### Fixed

- Invalid input, occupied ports, DNS/proxy mismatches and certificate problems now offer a targeted retry while retaining prior answers.
- Foreign ArvanCloud routes use a WSS compatibility profile with certificate-verified TLS 1.2 or newer. Nginx accepts TLS 1.2 and 1.3 on both sides.
- WebSocket routes bypass Nginx caching; foreign pre-authentication headers are forwarded explicitly.
- A cached or decoy HTTP 200 page can no longer pass as a successful WebSocket route.
- ACME firewall rule ownership is recorded only after creating the tunnel configuration directory.
- Automatic backend selection excludes configured public and target ports.
- Origin port ownership records contain local listeners, not remote foreign ports.
- Failed legacy-service migration restores prior service state and keeps the failed import available for recovery.

### Compatibility and validation

- Direct/direct, proxy/direct, direct/proxy and proxy/proxy remain available, including mixed Cloudflare/ArvanCloud providers.
- Direct and Cloudflare foreign routes retain HTTP/2-first automatic WSS fallback. ArvanCloud's own documentation describes TLS 1.3 support; this release does not assume that every account's gRPC or origin settings are ready.
- Customer exports do not include server or tunnel-pairing secrets. Xray credentials are supplied separately; a port/path is not authentication.
- Upgrade is repeated per tunnel on both servers. Executables and management tools are shared, but individual launch configuration is updated only for the selected tunnel. Upgrade checks fresh accounting acknowledgment and a stable service invocation before committing an active origin.
- Usage is lifetime accounting, retained when quotas change. It is not a payment system or automatic monthly subscription renewal.
- Isolated upgrade regressions cover repeated patches, missing state, selected-service restarts, stopped instances, stale status rejection and rollback without usage refunds. The Linux Nginx gate parses foreign and Iran sites plus generated customer routes.
- Local tests are not evidence of a successful live ArvanCloud/Cloudflare deployment or measured Iran–foreign throughput. See the accompanying test report for checks actually executed.

## 3.1.0-rc1

- Introduced named `ununknowntun@TUNNEL_ID` instances, independent Iran/foreign proxy choices, shared Nginx public ports, pairing codes, IP synchronization and per-tunnel removal with recovery backups.

## 3.0.9-rc1

- Base transport and protected standalone installation workflow used by the later multi-tunnel releases.
