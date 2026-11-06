# Fresh validation — 3.7.0-preview.11

45 validation groups passed. Python: 958 passed,
8 optional skips (966 discovered). Individual logs identify the
skips and any retained initial failure; they are not claimed as executed passes.

- Full Linux Go tests, race detector, vet and resilience: PASS.
- Installer, rollback, paired setup, scanner, editor, doctor and UI tests: PASS.
- Actual two-peer Linux namespace forwarding: simultaneous TCP half-close and
  UDP payload hashes through the encrypted ICMP path, multiple Iran ports,
  private source-pool rotation, distinct private relay beside a wildcard-bound
  application, listener cleanup, and restart with payload: PASS, with FEC off
  and adaptive separately.
- Actual generated systemd services through the dedicated console: list/info,
  start/status, cancelled and confirmed restart, stop/start, peer preservation,
  removal and standalone installer listing: PASS.
- Existing Control Room Linux launch/terminal smoke: PASS. Protected inventory
  and existing service identities remained unchanged.
- Standalone embedded advanced ICMP pairing wizard and binary installation,
  followed by exact sandbox/capability, connectivity and cleanup checks: PASS.
- Actual local Nginx transport integration: PASS; see nginx.log.
- Go1.26.10 Linux amd64/arm64 binaries: ELF/build metadata/version, embedded bytes
  and SHA256 checked. arm64 executed; amd64 cross-built and inspected only.
- Source/runtime/complete archive contents and SHA256 manifests verified.

The original full Go run exposed a UDP test failure. Diagnosis and exact rerun
evidence are retained in validation/; the final summary references the passing
evidence after correction. A 480KB simultaneous datagram burst overflowed a
212KB kernel receive queue; nine reproduced client timeouts matched nine new
kernel buffer drops. Concurrent-client and single large-datagram integrity
tests were separated, without retries; eight repeats passed with zero new
buffer drops. Runtime code did not change for this test correction.
The first runtime-lab preflight refused group-writable build binaries created
by the VM umask; their file modes were corrected to0755 without changing bytes.
No initial failure is represented as a pass.

This is local Linux, namespace, loopback and disposable-systemd evidence.
Production servers were not changed. No real Iran/provider/Cloudflare path,
real client streaming quality, prolonged WAN soak or future timeout-free
operation is certified. The spoof candidate scanner is a documented DESIGN,
not implemented or tested as a scanning feature in this release.

Installer SHA256: `de3466721e3039f53bd88a9a7b16c0608ce171c0d43ce9054a1363c1b00e44f5`.
