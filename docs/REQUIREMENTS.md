# Requirements and implementation scope — 3.7.0-preview.11

| Request | Implementation | Boundary |
| --- | --- | --- |
| ICMP timeouts | Retain runtime on temporary send errors; authenticated recovery; read-only doctor | Continuous ICMP blocking still prevents delivery |
| Check iptables and Fail2ban | Bounded rules, jail bans, route, ICMP/kernel and runtime checks | Does not flush rules, unban addresses or disable protections |
| Private range on each peer | Separate /26–/30 pools, aliases and peer routes | Inner private addresses only; public addresses unchanged |
| Round-robin source addresses | New TCP/UDP flows distributed across pool with conntrack pinning | Existing flows keep their address |
| Easy foreign-first setup | Guided questions, detected interface, private pairing code for Iran | Same release installer needed on both hosts |
| No manual endpoint file transfer | Code carries matching settings and shared secret | Keep the code private; it expires after 24 hours |
| English tools | English installer, scanner and diagnostics | Historical Persian guide copies removed from this release |
| Guided scanner | Range, sample size, probes, workers, latency threshold, live IP progress | Probe latency is not ICMP ping or a bandwidth measurement |
| Repeated refinement | Unlimited Top-N rounds, new settings each time, sorted reports | Limits per round bound resource use |
| Stop and select early | Ctrl+C retains completed results and allows selection | Incomplete probes are not successful results |
| Select IP for tunnel | Inherit tunnel port/SNI; authenticate final choice before transactional apply | Managed Cloudflare mode only; applying may interrupt sessions |
| Automatic scanner | Existing authenticated selection and improvement policy preserved | Manual-round rankings do not replace automatic policy |

Existing WSS/XHTTP, coordinated paths, adaptive carriers, Nginx entry, native
ICMP, Echo-over-WSS, GRE and customer-management features remain separate modes.
Direct ICMP L3 has no TLS certificate or WebSocket dependency and cannot pass
through an ordinary Cloudflare DNS proxy. It is not Backpack wire-compatible.

Fresh test logs in the delivered validation directory describe what ran.
Source code, a successful build, an Online row or a local test is not proof of
WAN throughput, provider reachability or a bug-free deployment. No production
server is changed by building or packaging this release.
