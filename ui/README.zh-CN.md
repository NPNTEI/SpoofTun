# UNUNKNOWNTUN 终端界面

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

这是现有 UNUNKNOWNTUN 安装的配套终端界面，分为 **Tunnels**、**Tuning** 和 **Doctor** 三个页面。UI **3.7.0-preview.11** 保留 **3.5** 管理器的目录布局，并增加可选的 **3.7** 操作。界面本身**不是 UNUNKNOWNTUN V1**，也不是新的隧道核心、升级安装程序或网页控制面板。

尚未在实际服务器上进行验证。打开界面不会执行安装、迁移、重启或远程探测。四种语言的指南描述相同的行为；应用菜单和命令名称均保留英文。

## 3.7 快速指南：连接地址、ECH 与填充

Tuning 页面分别显示实际的 **Dial endpoint**、**TLS SNI** 和 **HTTP Host**。设置可用 IP/域名只改变连接目标，不会自动替换 SNI 或 Host。按 `e` 打开所选隧道的编辑器。手动地址支持 IPv4、IPv6 和域名；自动地址段扫描仅支持 Cloudflare IPv4，不扫描 Fastly/Arvan。

- `n` 打开 CDN 设置（`cdn`）：候选地址、扫描最长时间、改善阈值和可选的定期更新。自动更新默认**关闭**；默认间隔为 **8 小时**，默认扫描预算为 **300 秒**，上限为 **600 秒**。
- `s` 将扫描和应用结果（`cdn-scan`）交给匹配版本的管理器。此操作可能更改地址并重启所选隧道，必须准确输入该隧道 ID。身份验证成功不代表客户端流量或带宽已通过测试。
- `v` 显示 CDN 状态（`cdn-status`），不会启用更新或启动扫描。仅打开或刷新界面不会进行扫描或更改设置。

ECH 来源显示为自动 DNS 发现、手动 DNS/解析器描述符或手动 ECHConfigList。解析器 URL/查询参数和原始配置字节不会显示在仪表板中。ECH 作用于发起连接的 TLS 客户端，并不限定在伊朗一侧；TLS 终止端必须实际支持它。**“TLS Hello over DNS”菜单项已删除**；DNS ECH 配置发现仍然保留，并非 DNS 隧道。

3.7 中按 `p` 运行 `cdn-preview`，显示扫描进度但不修改地址或重启。Tuning 显示路径轮换和会话更新；按 `e` 编辑两端共享配置、更新间隔或无 CDN 的独立 `nginx` 入口。轮换要求两端 3.7、时钟同步和相同的已签名配置。Nginx HTTP 入口需要匹配的 WS/XHTTP 客户端，不会自动转换原始 TCP。

界面显示 XHTTP 的 `auto`、`packet-up`、`stream-up`、`stream-one` 模式及两种填充值。**Frame padding bytes** 与 **XHTTP HTTP padding** 是不同设置。流式模式与实际 CDN 的兼容性尚未认证；需要用真实客户端流量测试所选提供商和模式。新操作需要匹配的 3.7 辅助工具；不支持这些操作的旧管理器会被拒绝，不会被自动升级。

## 校验软件包

解压完整发行 ZIP 文件，在包含 `SHA256SUMS` 的发行包根目录打开终端，而不是在 `ui/` 内。如果仅源码归档不含清单，请使用已公布的归档校验和。运行前，请使用同一可信发行包中的文件进行校验：

```bash
sha256sum -c SHA256SUMS
```

在 macOS 上，使用 `shasum -a 256 -c SHA256SUMS`。校验和可以检测文件是否被改动；如果攻击者同时控制文件和校验清单，则校验和无法证明这些文件可信。

## 无需访问服务器即可预览

进入 `ui/` 目录，在安装了 Python 3.8 或更高版本的 macOS 或 Linux 上运行：

```bash
python3 ununknowntun-ui.py --demo
```

演示模式无需 root 权限。所有数据均为示例，所有实际操作均已禁用。输入按键或命令后按 Enter。如果没有交互式终端，也可以输出单个示例页面：

```bash
python3 ununknowntun-ui.py --preview doctor
```

完整发行包可能包含 `ui/preview.html`。仅源码归档不依赖已生成的预览文件。要创建新的本地预览，请选择一个尚不存在的文件名：

```bash
python3 ununknowntun-ui.py --export-html ui-preview.html
```

在浏览器中打开 `ui-preview.html`，即可查看三个示例页面。这是静态本地预览，不是可操作的网页控制面板或诊断结果，也不会连接任何服务器。

## 在现有服务器上运行

实际运行模式需要 Linux、root 权限、Python 3.8 或更高版本、systemd，以及已安装的 UNUNKNOWNTUN 管理器。该界面没有第三方 Python 依赖，也不会安装或下载任何内容。

The installer now includes this UI: choose **9) Control Room UI** in its main menu. After a normal install or upgrade, open it directly:

```bash
sudo ununknowntunctl ui
```

To open the embedded UI without installing or upgrading anything, run:

```bash
sudo bash UNUNKNOWNTUN-V3-INSTALLER-3.7.0-preview.11.sh ui
```

Guided rounds (`b` / `cdn-rounds`) use the selected tunnel's port and SNI, ask for range/count and per-round probes/workers/maximum latency, show live results, and allow repeated Top-N refinement. Ctrl+C retains completed results. Choosing an endpoint runs the existing authentication and transactional apply checks; automatic scanning policy is unchanged. Direct ICMP endpoints remain isolated from standard tunnel actions. Press **i** to open their dedicated manager, available even when no standard tunnel is registered; use the installer's **8) ICMP L3** for setup.

初始页面仅仅读取本地配置和服务状态。它不会替换 `/usr/local/bin/ununknowntunctl`、核心可执行文件、Nginx、X-UI、防火墙规则、证书、端口或对端文件。相关操作需要已安装的编辑器和 Doctor 辅助工具；对于管理器不支持的命令，界面会拒绝执行，不会将其视为成功。

## 操作方式

输入以下任一命令，然后按 Enter：

| 命令 | 操作 |
|---|---|
| `1` | Tunnels 页面 |
| `2` | Tuning 页面 |
| `3` | Doctor 页面 |
| `t 2` | 选择列表中的第二条隧道 |
| `e` | 打开现有的完整编辑器，编辑所选隧道 |
| `a` | 打开现有的配对服务器更新码流程 |
| `c` | 打开现有的客户、端口和配额管理界面 |
| `u` | 通过已安装的管理器显示使用量 |
| `o` | 启动、停止、重启或移除所选隧道 |
| `n` | 准确输入 ID 后，打开 CDN 地址和定期扫描设置 |
| `b` | Guided Cloudflare scan rounds, refine Top-N and select an authenticated endpoint; exact tunnel ID required |
| `p` | Preview the authenticated CDN scan without changing the endpoint |
| `s` | 准确输入 ID 后，扫描并应用地址；可能重启该隧道 |
| `v` | 显示 CDN 设置/状态，不启动扫描 |
| `k` | 打开完整 SIKDPI 扫描器：IP、SNI、REALITY、速度和导出；无需选择隧道 |
| `i` | Open Direct ICMP management: endpoint list, forwarding information, status, start/stop/restart, logs, doctor and removal |
| `f` | 使用已安装的 Doctor 离线检查配置 |
| `d` | 确认后，探测该隧道配置的端点 |
| `r` | 刷新本地状态，并清除之前显示在屏幕上的报告 |
| `q` | 退出界面 |

完整扫描器通过 `ununknowntunctl scanner` 打开英语交互向导。仅打开向导不会启动网络扫描或安装依赖。扫描前需要指定目标并确认授权；报告以私密方式保存，结果不会应用到 UNUNKNOWNTUN 隧道。普通 TLS/SNI 可达性、经过身份验证的 REALITY 连接和 UNUNKNOWNTUN 身份验证属于不同证据层级。原有 `s` 命令仍负责经过身份验证的 CDN 扫描及应用；`k` 不会启用它。演示模式同样禁止 `k` 和其他实际操作。

在进入可能更改配置或状态的操作之前，必须准确输入所选隧道的 ID。确认输入留空则取消操作。现有编辑器仍会预览并确认每项更改，处理锁定和回滚，并在需要时生成配对更新。移除操作也会保留现有管理器的确认和备份流程。

编辑、停止或重启操作可能中断所选隧道。请阅读操作输出；仅凭退出码为零并不能证明客户端可以连接。客户管理和编辑表单仍使用现有界面，尚未进行完整的视觉改版。

## 可管理服务与只读服务

注册在 `/etc/ununknowntun/tunnels` 下的标准隧道，只要配置可读且可信，就可以选择并管理。旧版或单独安装的服务（包括 `ununknowntun.service`、`ununknowntun-germany.service` 和 `ununknowntun35-turkey-yta.service`）会以**只读**方式显示。界面绝不会自动接管或升级这些服务。

创建新隧道和升级核心仍需使用现有安装程序；此预览版不会启动该程序。不要混用 UNUNKNOWNTUN V1 和 3.x 的文件或配对信息。该界面不会使 V1 兼容 3.5 管理器的目录和文件布局。

界面显示的是已保存的配置，不能证明 ECH、MUX 或连接已成功协商。不安全或不可读的配置会阻止操作。如果选中隧道后配置发生变化，请刷新并检查配置后再继续。

## 理解诊断结果

- `active/running` 描述的是服务进程状态，并不表示隧道或互联网连接可用。
- `WAIT` 表示检查尚未运行。`PASS` 来自实际的 Doctor 报告，不是用于演示的成功标签。
- TLS 或隧道身份验证成功，不能证明 VLESS、Shadowsocks 或实际网站流量能够正常工作。**Real client payload** 仍标记为 `TODO`，需要单独进行客户端测试。

Doctor 使用匹配版本的已安装辅助工具，仅测试已配置的端点。它不会扫描端口范围、禁用 TLS 验证或改写配置。界面允许的诊断**总时长为 55 秒**，**每个阶段为 3 秒**。较慢的网络路径或较多的候选端点可能导致超时；未完成的检查不算成功，也不能确定失败原因。如需运行更长时间的诊断，请使用现有命令行工具。离线模式不会执行任何网络检查。

报告是带时间戳的状态快照，并非持续监控。端点错误会标明失败发生在哪个阶段；界面不会猜测问题一定出在令牌、证书或防火墙上。

## 显示与敏感信息

背景和字体由 Termius 或您使用的终端控制。无法保证与概念图中的白色外观完全一致。至少 80 列、约 40 行的窗口更便于阅读；窗口较矮时请向上滚动。如果字体支持有限，请使用 `--ascii`；如需无颜色输出，请使用 `--no-color`。界面也遵循 `NO_COLOR` 设置。

概览界面和静态预览不会显示令牌、`peer.env`、私钥或私有隧道路由。诊断详情来自已安装的 Doctor 所生成的脱敏报告。现有编辑器在完成更改后可能显示保密的同步码：请勿公开该同步码，也不要发布包含敏感信息的截图。

## 验证与退出

运行软件包附带的离线界面测试：

```bash
python3 test_terminal_ui.py
```

测试使用固定数据和模拟服务，不使用真实服务器或网络。在 `source/ui/`（GitHub 源码归档中为 `ui/`）运行 `python3 run-tests.py` 可执行完整测试；旁边必须有匹配版本的 `packaging/` 目录。独立界面副本无法执行兼容性集成测试。完整发行包根目录的 `VALIDATION.md` 和 `validation/` 记录构建检查及局限，根目录的 `SHA256SUMS` 涵盖交付文件。仅源码归档不必包含这些生成的报告。本地测试不能替代真实 Linux 验收测试，请先使用非生产服务器。

按 `q` 退出。该界面没有守护进程或开机启动项；关闭它不会停止隧道。退出后，删除这个配套文件不会移除隧道核心或其配置。**不要用它覆盖 `ununknowntunctl`。**

## 发布到 GitHub

将三份界面指南（`README.md`、`README.ru.md`、`README.zh-CN.md`）保留在 `ui/` 中；不要用界面指南覆盖核心发行包根目录的 README。必需的相对链接仅指向这三份指南。这些译文内容等效，并非三种不同的实现。

此界面在本地准备，**尚未上传到 GitHub**。发布时不要包含真实服务器配置、配对文件、凭据或私钥。仅界面目录不是完整的 UNUNKNOWNTUN 核心发行版。

## Direct ICMP management

Use `--icmp-manage --list` for a read-only inventory without an interactive terminal. The **i** shortcut and `--icmp-manage` open the trusted `direct-icmp-console.py` staged beside the UI. The matching installer and installed `ununknowntunctl ui` stage both files. Source-only `--preview` and `--demo` do not need this helper; live management requires the installed/staged pair. Opening the console only reads `/etc/ununknowntun-direct-icmp`; it performs no migration, scan, installation or service change. Configured local and remote forwarding ports appear in the endpoint list.

Each action uses the selected endpoint's own verified manager. Older valid endpoints remain on their existing version; unsupported actions are refused without upgrading or substituting a restart. Start, stop, restart and removal require the exact `pair/role` identity. Removal affects only that local endpoint, not its peer. Demo mode blocks **i**. Service status is not proof of payload delivery; Doctor and real-client checks remain separate.
