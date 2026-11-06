# UNUNKNOWNTUN 3.7.0-preview.8 · [English](README.md) · [Русский](README.ru.md) · [中文](README.zh-CN.md)

**Control Room UI (preview.10):** installer menu **9**, or `sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh ui`. It is embedded; no separate UI transfer is required. Opening it does not upgrade or restart tunnels.

这是实验预览版。请备份两端配置，先在测试服务器验证。没有修改生产服务器；Linux 测试使用独立的本地虚拟机。

preview.8 为 Direct ICMP 增加 `off / fixed / adaptive` FEC。新建配对默认使用 adaptive；未包含 FEC 字段的旧配置仍为 off。启用 FEC 前须升级两端。修复包会增加流量，不能解决 ICMP 被完全阻断的问题。[设置说明](docs/DIRECT-ICMP.md)。

新增功能：独立的连接 IP/域名、TLS SNI 与 HTTP Host；手动或自动获取 ECH；
可调 ClientHello 分片；WS/XHTTP 数据填充和独立的 XHTTP 标头填充；
auto、packet-up、stream-up、stream-one 模式；经过认证的 Cloudflare 扫描及可选定时更新。

3.7 新增两端同步路径轮换与备用路径、渐进式会话更新、扫描预览，以及不依赖 CDN 的伊朗端 Nginx HTTPS 入口。
[设置与限制](docs/ADVANCED-3.7.md)。

**通过 DNS 传送 ClientHello 的菜单项已删除。** 通过 DNS 获取 ECH 配置仍然保留，但不等于 DNS 隧道。
ECH 应配置在发起 TLS 连接的一侧，而不是由所在国家决定。

## 安装

安装包包含 Linux amd64/arm64 程序与独立安装脚本：

```sh
sha256sum -c SHA256SUMS
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.8.sh
```

先设置境外 egress，再在 origin 导入其保密配对代码。升级现有托管隧道时，请安排维护时间并同步升级两端。
Upgrade 会替换共享核心；不要用它自动接管独立安装的服务。不要发布令牌、配对代码或真实服务器配置。

在已验证的预览下载包中，可只安装独立版本的二进制文件、不启动服务。
普通源码构建不会生成此可选安装器：

```sh
python3 -I install-preview.py --dry-run
sudo python3 -I install-preview.py --install
```

保留的 GRE 功能仅用于 Linux、直接 TLS 和已授权的双端配置，不与 CDN 组合。

## 管理

```sh
sudo ununknowntunctl list
sudo ununknowntunctl edit TUNNEL_ID
sudo ununknowntunctl cdn TUNNEL_ID
sudo ununknowntunctl cdn-scan TUNNEL_ID
sudo ununknowntunctl cdn-preview TUNNEL_ID
sudo ununknowntunctl cdn-status TUNNEL_ID
sudo ununknowntunctl ui
```

将 TUNNEL_ID 替换为所选隧道 ID。connect_host 控制网络地址，tls_sni 控制证书名称，
http_host 控制 HTTP 路由。修改 Host 必须与对端及 CDN 配置一致；编辑器提供签名同步代码。
将 connect_host 设为 auto 可恢复默认地址。

定时扫描默认关闭。可设置最长时间、候选数量、Cloudflare IPv4/CIDR 列表及更新间隔。
Arvan/Fastly 支持手动地址，内置范围扫描仅适用于 Cloudflare。
成功替换 IP 会重启所选隧道，可能中断现有连接；其他隧道不重启。
扫描成功只表示证书、传输及令牌验证成功，不代表客户端有效负载或带宽测试通过。

auto 当前选择 packet-up。流式模式需要两端升级并测试实际 CDN。
UNUNKNOWNTUN XHTTP 并非普通 Xray/VLESS 的线协议。填充会增加流量，不保证规避检测。
源代码、测试与最新验证报告随包提供；没有自动发布到 GitHub。

[界面指南](ui/README.zh-CN.md) · [技术说明](docs/ADVANCED-3.7.md)
