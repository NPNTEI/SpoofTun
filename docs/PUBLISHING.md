# Publishing UNUNKNOWNTUN 3.7.0-preview.5

The source folder is ready to become a repository. It does not contain a chosen license, a repository URL, deployment credentials, or a preconfigured GitHub owner.

## Repository contents

Upload the contents of the source folder to the repository root, including hidden `.github` and `.gitignore` files. Do not upload server configuration from `/etc/ununknowntun`, accounting state, pairing codes, customer exports, SSH keys or certificate private keys. Build output belongs in release assets rather than source commits.

Select the project's license deliberately before describing the repository as open source. The package has not assigned one on the owner's behalf.

## Linux verification

The complete build uses a security-patched Go toolchain (minimum 1.26.10; the workflow selects the newest Go 1.26 patch), Python 3.9 or newer, OpenSSL, a C compiler for the Go race detector, and Nginx for generated-configuration parsing. On an Ubuntu build host:

```bash
sudo apt-get update
sudo apt-get install -y build-essential nginx openssl python3 util-linux zip
export UNUNKNOWNTUN_TEST_NGINX=/usr/sbin/nginx
bash packaging/build-complete.sh
```

Install Go from its official distribution or use the GitHub Actions workflow. `build-complete.sh` runs module verification, Go unit tests, vet, race tests, the installer/editor/diagnostic/CDN Python suites and all terminal UI tests, then builds Linux amd64/arm64 executables and renders the full installer. Its output defaults to `release/`. Keep `ui/`, `tests/` and `packaging/` together in the source tree: the build validates their compatibility. The source archive contains all seven embedded helpers, including profile validation and CDN scanner/controller helpers.

The renderer checks source/version agreement, ELF architecture, Go build metadata, embedded payload equality, Python helper syntax, complete helper-marker expansion, checksums and shell syntax. Helpers are embedded in the standalone installer; target servers do not download them separately. Tests use temporary data and mocked system administration commands; optional Nginx parser tests check foreign and Iran configurations with generated customer routes on private high ports without launching a daemon. WebSocket/ECH tests use temporary loopback TLS endpoints. Upgrade/editor/scheduler tests exercise state-preserving rollback, not a real host upgrade, live CDN address change or live domain switch. No test result should be described as a successful live CDN or Iran–foreign deployment.

The renderer also retains the Go runtime and linked-module license notices under `THIRD_PARTY_LICENSES/`. Keep this directory with redistributed runtime bundles. These notices do not select a license for the project itself.

When UNUNKNOWNTUN_TEST_NGINX is set, the pipeline also runs tests/nginx_integration.py after building the host-native Linux binary. Unlike parser-only checks, this starts a temporary Nginx process on loopback high ports and terminates only its own test processes; it does not change the installed service.

To assemble a new local distributable after a successful build:

```bash
python3 packaging/package-release.py release release-assets
```

Choose a new output directory; the assembler refuses to overwrite an existing one. It copies four-language guides, the UI, required source/tests/workflows, binaries and dependency notices. Each ZIP has its own `SHA256SUMS` for the files inside that archive. This command checks assembly integrity only and writes an explicitly limited `VALIDATION.md`; it does not assert that build tests passed and does not require or reuse an old release report. Keep the current build/CI logs as the test evidence. The separately delivered reviewed preview uses `package-preview.py` to include its fresh validation logs and twenty-profile integration report; these are not automatically recreated by the generic assembler.

## GitHub workflows

`.github/workflows/ci.yml` runs on pushes and pull requests. It enables the Linux-only checks and retains the built files as a workflow artifact. The workflow requests read-only repository access.

`.github/workflows/release.yml` runs on pushed `v*` tags. It requires the tag to equal `v` followed by the content of `VERSION`; the build renderer also checks the Go version constant. The workflow runs the checks again, verifies tracked source did not change during the build, invokes the assembler, calculates downloadable asset checksums, and creates a **draft** GitHub release. Versions containing a prerelease suffix, including `-preview.1` and `-rc1`, are marked prereleases. It does not read historical `RELEASE-VALIDATION.md` files.

For this version, after committing the reviewed source:

```bash
git tag v3.7.0-preview.5
git push origin v3.7.0-preview.5
```

Pushing the tag triggers the workflow; these commands have not been run as part of preparing this package. Inspect the successful workflow and draft release, add the deployment test results, and publish the draft when ready. The workflow does not overwrite an existing release. If a release already exists for the tag, review it and use a new version/tag for changed artifacts.

GitHub documents the [Go build/test workflow](https://docs.github.com/en/actions/tutorials/build-and-test-code/go), [workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions), and [draft release creation](https://cli.github.com/manual/gh_release_create).

## Release files and verification

The tag workflow attaches:

- `UNUNKNOWNTUN-V3-INSTALLER-VERSION.sh`: standalone server installer, including both architectures.
- `UNUNKNOWNTUN-VERSION-github-source.zip`: selected source from the tagged checkout, including the UI, tests, docs and workflows; generated caches and historical release reports are excluded.
- `UNUNKNOWNTUN-VERSION-linux-bundle.zip`: installer and Linux binaries with their relative paths.
- `SHA256SUMS`: checksums for the three downloadable assets.

Download all three assets and the outer checksum file into one directory, then run:

```bash
sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS`. After extraction, verify each archive's own manifest from its extraction root. It contains only that archive's files. The build output's separate checksum file refers to `bin/`; preserve that folder structure when verifying a raw build artifact. Hashes detect changed bytes; they do not authenticate the publisher if the files and checksum manifest come from an untrusted source.

## Deployment and upgrade release checklist

This is an experimental preview, not a bug-free or production-certified release. Document the actual server OS, proxy combination and successful client test before making deployment claims. For an existing managed installation, distribute the new complete installer to both servers and use its `upgrade` command, selecting each existing tunnel in turn. Do not use it to adopt separately installed/isolated services. No uninstall or recreation is required for supported managed upgrades.

Back up each tunnel's configuration and its matching accounting state before deployment. Existing quotas and usage are retained; older tunnels without accounting start metering at upgrade. Missing usage state blocks upgrade, and corrupted state remains fail-closed at runtime. Do not advertise reconstruction of traffic that predates accounting.

The upgrade snapshots managed configuration and executables under `/opt/ununknowntun/backups`, validates Nginx, restarts only the selected active instance, and requires fresh accounting acknowledgment for an active origin. Stopped instances stay stopped. Rollback preserves an existing live ledger rather than restoring older consumption. The binary and helpers are shared; repeat the upgrade per tunnel on both sides so their individual launch settings are updated too.

The 3.7 preview retains the 3.5 migration rules: TLS minimum, Nginx TLS versions, certificates, domain, MUX and customer accounting are preserved; legacy carrier `auto/h2` becomes WSS, managed gRPC routes are removed and the old ratio flag becomes `pad 0`. New `padding-bytes` and `xhttp-padding-bytes` are independent, explicit settings; their existing values, clean endpoint, SNI, HTTP Host, ECH source and selected XHTTP mode are preserved during upgrade. Existing unused legacy backend reservations may remain conservatively reserved. Upgrade does not automatically switch WSS to XHTTP. Both peers must use this preview before using the new streaming modes. Coordinate a maintenance window. Read [the XHTTP profile and limitations](../xhttp-profile.md) and [advanced 3.7 settings](ADVANCED-3.7.md), then coordinate transport/Host/mode changes and their signed peer updates. New install pairing codes use V5; legacy V3/V4 codes import with an explicit paired-upgrade warning. Signed edit codes still use the separate V3 edit format. Keep the XHTTP profile document in both source and runtime packages.

ClientHello-over-DNS has been removed from current menus. DNS discovery of ECH configuration is not DNS tunneling. Strict ECH requires the real TLS terminator to accept ECH; there is no silent non-ECH fallback. Streaming is UNUNKNOWNTUN's transport, not stock Xray wire compatibility. The built-in Cloudflare scanner authenticates the configured carrier/token, not target payload, bandwidth or a real customer's client. Preview scans do not apply endpoints or restart services. Scan-and-apply and periodic replacement can restart only the selected tunnel and may interrupt sessions; verify on a test deployment before opting in.

Rotation is opt-in and requires both upgraded peers, identical interval/count/grace/base path/token/HTTP Host, synchronized clocks and the `/gdt-r/` Nginx route. Existing installs remain rotation-off. Initial signed paired edits still require an operator and may interrupt connectivity; recurring route derivation afterwards is automatic. Carrier renewal is make-before-drain, bounded by one spare carrier and a two-minute old-carrier drain grace; streams still using it at the deadline are interrupted. Pending installation leases expire after thirty seconds. Preview.3 adds authenticated payload health probes and signed random recovery routes; upgrade both peers and their generated Nginx routes for full coverage. This checks the interserver carrier, not every Internet destination. Standalone Iran Nginx is explicitly WS/XHTTP entry, not automatic conversion of existing raw TCP clients. Preserve other sites and verify the generated configuration before a graceful reload. Local mocked rollback tests are not live Nginx or ISP validation.

Test direct↔proxy entry migrations and independent WS↔XHTTP entry changes with multiple enabled/disabled customers, including a disabled default customer. Confirm previewed listeners are free, no account or usage disappears, existing certificate paths remain, exports no longer advertise old TLS/path fields after return to direct, and failed Nginx validation restores all selected files without refunding traffic. The editor neither issues certificates nor changes a CDN account or Xray inbound. Provider changes require compatible public ports and explicit paired synchronization. Private origin trust uses `LOCAL_TLS_CA_PATH`; public CDN/client trust is independent (`CA_PATH`).

Afterwards, check `ununknowntunctl test TUNNEL_ID`, establish a real client session through the chosen CDN/direct route, verify upload plus download consumption, then verify quota exhaustion and recovery after an increase. Confirm unrelated tunnels remain connected and a customer export contains no server/pairing secrets. These are deployment checks for the owner; preparing this source package does not perform them on any external server.

For the full editor, also exercise the [domain-change checklist](EDITING.md) with a test tunnel. Verify a token/path update on both servers, preserved client usage, a stopped instance remaining stopped, and rollback after a rejected Nginx configuration. Editor update codes are private operational data and must never be added to the source repository or release notes.

## Accounting integration reference

The installer maintains a root-owned account configuration, for example:

```json
{
  "version": 1,
  "total_quota_bytes": 500000000000,
  "accounts": [
    {"id": "default", "name": "Default access", "listen": "0.0.0.0:2053", "quota_bytes": 0, "enabled": true},
    {"id": "customer-1", "name": "Customer 1", "listen": "0.0.0.0:21000", "quota_bytes": 100000000000, "enabled": true}
  ]
}
```

With `-access-config`, these account listeners replace the normal `-listen` entries in origin mode. `-access-state` names the durable accounting file. `-access-init-state` initializes a new state once and exits; it refuses to overwrite existing consumption. The installer performs initial setup with the service account's ownership. Runtime `SIGHUP` reloads account configuration without resetting consumption; use the manager so route/port checks and backups accompany configuration changes.

Never include accounting initialization in each service start, delete state to repair a quota error, or distribute pairing credentials as customer credentials. Customer exports contain endpoint information; Xray authentication is supplied separately.
