# 3.7.0-preview.11 — Direct ICMP forwarding and management

Run the same installer on each Linux peer:

```sh
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh
```

Choose **8 (ICMP L3)**, foreign first. Enter real peer addresses and unused
private ranges, then the Iran client entry port, foreign application/inbound
port and TCP/UDP/both. Copy the private pairing code into option8 on Iran.
No socat or manual endpoint-file transfer is required. The target application
must already exist; this does not install a panel or create client accounts.
Ports in this preview are1024..65535. Public firewall rules are not changed.

Choose **3 → Direct ICMP** to manage installed pairs, or **9 → i** from the
Control Room. A direct command also works without a normal manager install:

```sh
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh direct-icmp-manage
```

Opening the console reads only. Start/stop/restart/removal require the selected
pair/role confirmation. Existing bundles keep their own verified manager;
unsupported old actions are refused. Existing ICMP pairs are not automatically
migrated to built-in forwarding. Test a new pair with unused name/ports/ranges;
do not run conflicting old and new listeners simultaneously.

The requested spoof range scanner is specified in docs/SPOOF-SCANNER-DESIGN.md,
not an implemented menu in this release. It requires observations from both
peers even when all control is performed from the foreign server.

Read docs/DIRECT-ICMP.md and VALIDATION.md. Verify the extracted archive with
`sha256sum -c SHA256SUMS`. The included UI HTML is only a static sample preview.
