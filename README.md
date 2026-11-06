# UnUnknownTun — نصب سریع / Quick install

روی هر سرور (با root) فقط این یک دستور را اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NPNTEI/SpoofTun/main/install.sh)
```

یا بدون process substitution:

```bash
curl -fsSLO https://raw.githubusercontent.com/NPNTEI/SpoofTun/main/UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh && sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh
```

## تونل سریع (Quick tunnel) — خارج فقط لینک می‌دهد، همه تنظیمات در ایران

1. **سرور خارج**: منو `2) Setup Foreign` → `1) Quick tunnel`. فقط IP و پورت تونل را تأیید می‌کنید؛ یک لینک `uutun://...` تحویل می‌گیرید.
2. **سرور ایران**: منو `1) Setup Iran` → `1) Quick tunnel`. لینک را paste کنید، پورت‌ها را انتخاب کنید (مثلاً `443` یا `8080=2083` یعنی پورت 8080 ایران به پورت 2083 خارج). اتصال قبل از نصب تست می‌شود.
3. مدیریت (وضعیت، لاگ، ری‌استارت، نمایش دوباره لینک، حذف): منو `3) Manage` → `1) Quick tunnels`.

- نوع تونل: TLS 1.3 مستقیم با گواهی pin شده (بدون دامنه، CDN یا Nginx)، با fingerprint مرورگر (Chrome/Firefox/iOS)، fragment اختیاری و چند session موازی.
- روی خارج باید سرویس مقصد (مثلاً inbound ایکس‌ری) روی پورت انتخاب‌شده روشن باشد.
- دستورهای مستقیم: `quick-foreign`، `quick-iran`، `quick-manage`.
- حالت پیشرفته (WSS / XHTTP / CDN / ICMP / GRE) هنوز از گزینه `2) Advanced` در همان منوها در دسترس است.

## دستور باز کردن منو + تست Spoof

- بعد از اولین اجرا، منو با یک دستور باز می‌شود: `ununknowntun` (کوتاه: `uut`). دستورهای مستقیم: `ununknowntun quick-manage`، `ununknowntun spoof-test`، `ununknowntun connection-test`.
- منوی `Setup Iran` و `Setup Foreign` حالا مستقیم می‌پرسد چه تونلی می‌خواهید: Quick tunnel، CDN (WSS/XHTTP)، ICMP L3، IP spoof/GRE یا سایر.
- منوی `0) Test` دو بخش دارد: Connection test و **Spoof test** (فقط بررسی می‌کند بسته با IP مبدأ جعلی بین دو سرور عبور می‌کند یا نه؛ UDP و ICMP). گیرنده لینک `uuts://...` می‌دهد، فرستنده لینک و IP جعلی را وارد می‌کند. نیاز به root دارد.
- پیش‌فرض پوشه فایل‌های spoof/ICMP خودکار `/root/ununknowntun-...` است.

## سایر نکات

- بعد از نصب حالت پیشرفته: `sudo ununknowntunctl list` و `sudo ununknowntunctl ui`
- مسیرها: `/opt/ununknowntun`، `/etc/ununknowntun`، `/usr/local/bin/ununknowntun`، `/usr/local/bin/ununknowntunctl`، سرویس `ununknowntun@.service`.
- هر دو باینری amd64 و arm64 داخل نصاب هستند؛ یکپارچگی با `SHA256SUMS` بررسی می‌شود.
- منوی اصلی در چهار بخش: TEST (`0`)، IRAN SERVER (`1`)، FOREIGN SERVER (`2`)، TOOLS (`3`–`10`).
- تست اتصال: روی سرور **ایران** `0` → گزینه 1 (لینک `uut://IP:PORT/TOKEN`)، روی سرور **خارج** `0` → گزینه 2 و لینک را paste کنید. خروجی: دسترسی (ICMP، TCP، TLS 1.3، WebSocket، HTTP، UDP)، نمودار سرعت تک‌جریانه و ۴ جریانه، و پیشنهاد اینکه کدام نوع تونل روی این مسیر کار می‌کند. دستور مستقیم: `sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh connection-test`. پورت‌های `P` تا `P+2` (TCP/UDP) روی ایران باید باز باشند. به تونل‌ها دست نمی‌زند.
- نسخه preview است؛ قبل از استفاده روی سرور واقعی بکاپ بگیرید.

---

# UNUNKNOWNTUN 3.7.0-preview.11

preview.11 adds **built-in Direct ICMP TCP/UDP port forwarding**. Foreign-first
setup asks for the public Iran port, the foreign application's port and TCP/UDP.
The private pairing code carries both matching relay configurations; no socat is
needed. An authenticated application must still listen on the foreign server.

**Manage tunnels → Direct ICMP** and Control Room key **i** now manage these
independent pairs: safe information, status, start, stop, restart, logs, doctor
and confirmed removal. Existing ICMP bundles remain unchanged when listed.

The requested range-based spoof scanner is a **design, not an implemented
scanner in this release**. Its two-peer measurement and reserve-pair requirements
are documented in [the scanner design](docs/SPOOF-SCANNER-DESIGN.md).

The restored **Control Room terminal UI** is embedded in this release's standalone installer. Choose main-menu **9**, or run `sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh ui`. After a normal install or upgrade, reopen it with `sudo ununknowntunctl ui`. Opening the UI only reads local state; no core upgrade or service restart is performed.

preview.9 added **guided Direct ICMP L3 setup, private address pools and staged scanning**.
Start on the foreign server, answer the setup questions, then paste the private pairing code on Iran using the same release. No endpoint files need manual transfer. Menu **8** opens setup; the advanced file generator remains available.

Each peer can use a separate private IPv4 pool. New TCP/UDP flows rotate through the pool while existing flows keep their source address. A read-only doctor checks routing, firewall rules, Fail2ban and runtime counters. Temporary network send errors no longer tear down the ICMP process. See the [ICMP guide](docs/DIRECT-ICMP.md).

The English scanner now supports range sampling, live results, unlimited Top-N refinement rounds and final IP selection. Use `sudo ununknowntunctl cdn-rounds TUNNEL_ID` for a managed Cloudflare tunnel: it inherits the tunnel port and authenticates the selected endpoint before applying it. Existing automatic selection policy is retained. The full independent scanner remains available through menu **7** and `sudo ununknowntunctl scanner`. See the [scanner guide](docs/SCANNER.md).

Fixed/adaptive ICMP FEC from preview.8 remains available. It consumes bandwidth and cannot repair complete path blocking.

preview.5 adds **native ICMP TCP transport** and **real ICMP Echo inside WSS**,
with a protocol choice before tunnel creation and private paired configuration.
The WSS feature is a dedicated ping adapter, not system ping/TUN/general IP.
See [ICMP guide and boundaries](docs/ICMP.md).

preview.4 adds matched two-server **native IP source spoof / GRE** setup,
explicit wire-address diagnostics, rejection categories, and an independent
captured-packet lab. This is separate from browser/TLS fingerprint camouflage.
See [IP spoof setup and limits](docs/IP-SPOOF.md).

preview.3 adds an authenticated 1 KiB interserver payload watchdog, bounded
random signed-path recovery, and epoch-aware renewal with a two-minute maximum
old-carrier drain. Long old streams can be interrupted at that deadline. Upgrade
both peers; enable matching Coordinated paths separately for automatic path
changes. See [behavior, coverage limits and migration](docs/ADVANCED-3.7.md). · [English](README.md) · [Русский](README.ru.md) · [中文](README.zh-CN.md)

Experimental preview. Back up both peers before changing a live installation.
No production server was modified while preparing this release; Linux testing used a separate local VM.

## Included

- Coordinated rotating path sets and backup paths on both peers (opt-in).
- Adaptive session pool plus gradual, new-before-old carrier renewal.
- Standalone Nginx HTTPS entry on Iran, independently of CDN selection.
- Scanner preflight, progress, categorized failures and preview-only scan.
- Separate clean IP/domain, TLS SNI and HTTP Host, editable per tunnel.
- Manual or automatic ECH discovery; strict certificate/ECH verification.
- ClientHello fragmentation with editable size/delay.
- WSS and XHTTP data padding; separate XHTTP header padding.
- XHTTP auto, packet-up, stream-up and stream-one; MUX on/off.
- Bounded authenticated Cloudflare scanning; opt-in periodic updates with rollback.
- Terminal UI, customer quotas, paired edits, diagnostics, and retained native GRE code.

**The ClientHello-over-DNS menu option has been removed.** TLS choices are
ordinary TLS, strict ECH, or ClientHello fragmentation. ECH DNS discovery remains.
Streaming modes require both peers on this release and an actual CDN test.
UNUNKNOWNTUN XHTTP is not stock Xray/VLESS wire-compatible. See [3.7 changes and rollout](docs/ADVANCED-3.7.md).

## Install on Linux

The ready-to-install archive contains the standalone installer with both Linux
amd64/arm64 binaries. Review SHA256SUMS against your trusted download. Checksums
detect corruption, not publisher identity. Run on a test server first:

```sh
sha256sum -c SHA256SUMS
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh
```

For managed WSS/XHTTP, choose foreign/egress first and import its private pairing code on Iran/origin.
Never publish token files, peer codes, customer exports or server configuration.
For an existing **managed** tunnel, the installer offers Upgrade; it can replace
the shared core, so coordinate both peers and use a maintenance window.
Do not use it to adopt separately installed/isolated services.

When included in a reviewed preview download, the binary-only option is `python3 -I install-preview.py --dry-run`, then
`sudo python3 -I install-preview.py --install`. This optional helper is not generated by the generic source build. It installs a versioned binary
without starting services or changing the shared core. Native GRE remains a
separate, authorized Linux-only direct-TLS configuration; it is not CDN spoofing.
Menu **6** generates matching GRE endpoint files without installing or starting
anything. Use the IP-spoof guide for the separate versioned binary and service;
ordinary managed WSS/XHTTP services do not receive extra raw-socket privileges.

## Operate

```sh
sudo ununknowntunctl list
sudo ununknowntunctl edit TUNNEL_ID
sudo ununknowntunctl cdn TUNNEL_ID
sudo ununknowntunctl cdn-scan TUNNEL_ID
sudo ununknowntunctl cdn-preview TUNNEL_ID
sudo ununknowntunctl cdn-status TUNNEL_ID
sudo ununknowntunctl scanner
sudo ununknowntunctl ui
```

The UI opens read-only. Mutating actions require selecting/confirming a tunnel.
Automatic scanning is off by default. A successful IP replacement restarts only
that tunnel and may interrupt sessions; it is not zero downtime. CDN scanner success
means certificate/carrier/token authentication, not a target-payload/speed test.
Manual addresses work with all three CDN profiles; range scanning is Cloudflare
IPv4 only. [Terminal UI guides](ui/README.md).

## Build, test, publish

On a Linux build host with security-patched Go 1.26.10 or newer, Python 3.9+, OpenSSL and optional Nginx:

```sh
bash packaging/build-complete.sh
```

This builds artifacts; it does not install a tunnel on the build host.
The source archive includes tests and GitHub CI/release workflows.
Current validation is in the delivered `validation/` directory, not historical
3.5 reports. No GitHub upload/publication is performed automatically.
Local loopback/mock tests do not certify real ISP/CDN paths or long-term stability.

## Independent encrypted Direct ICMP

Preview.7 adds **Direct ICMP L3**, a private IPv4 link for TCP, UDP and ICMP without WebSocket or TLS certificates. One paired generator supplies matched settings and independently named endpoint services. See [setup and lifecycle](docs/DIRECT-ICMP.md) and the. IPv6, ordinary Cloudflare DNS proxy and Backpack wire interoperability are not supported.
