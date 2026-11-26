# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **WebAuthn / Passkey 与分级二次认证**：新增 Passkey（ES256/Ed25519）注册与无密码登录、有界 CBOR 解析及克隆计数器检测，支持纯 Passkey 无密码配置；新增 `ReauthModal` 与强因子（MFA）分级 Reauth 令牌体系。
- **反代门禁、通知收件箱与签名更新管理**：新增独立反向代理 Auth-Gate 门户（`proxy_gate`）、持久化通知收件箱（`NotificationInboxPanel`）、纯 Rust Ed25519 验签自更新与前端 `SystemUpdatePanel`、以及完整 PWA 图标/离线清单与可复用 UI 基础组件库（`EditorDialog`、`FacetFilter`、`CronSchedulePicker`、`TerminalPane` 等）。
- **跨机全量加密备份 (`.vane.bak`)**：完整纳入 ACME 账户（导出解密、导入自动用目标机 Vault 主密钥重封）、未完成清理的 `acme-challenges` 日志、有效代际证书 (`bundle.json` 验签并即时热加载) 及管理端 TLS 证书/私钥 (`certs/admin.{crt,key}`)，升级至 `VANEBAK2`（600k PBKDF2 + 40B 完整头 AAD + 强口令校验，兼容读取 `VANEBAK1`），并在 UI 中展示备份范围清单、安全降级确认与恢复汇总。
- **反代请求头 Vault 全链路加密**：`reverse_proxy[].rules[].request_headers_set` 纳入字段级 `ChaCha20-Poly1305` 信封加密、API 掩码、脱敏配置剔除与运行时解密，配套前端结构化 `HeaderRowsEditor` 编辑器（同样复用于 DDNS Custom HTTP、Cron HTTP 与通知渠道自定义请求头）。
- **反代门禁 WebSocket 取票 UI**：在反向代理规则卡片中为 `auth_gate + websocket` 规则新增一键取票弹窗（调用 `POST /api/proxy/ticket`，展示 30 秒倒计时与完整 `wss://...?vane_ticket=...` 地址）。
- **Web UI 与终端体验升级**：新增全局 WAN 封锁警示横幅与防火墙降级告警、按作用域展示/解封 Fail2Ban、增量日志轮询 (`after_seq`)、接口快速选择 Chips、`secret_path` 随机生成与已生效/草稿双预览、终端 `ResizeObserver` 自适应行列 + ANSI 256/TrueColor 配色 + `\r`/`\x08`/清屏支持 + 智能滚屏、备份魔数与大小预校验以及全量中英双语和 WCAG AA 深色对比度优化。

### Security
- **全面白盒安全审计修复（37 项已核验问题全部闭环）**：
  - **本机受保护端口与 SSRF 硬防线**：`23456` 纳入受保护端口清单，校验合并活态 + 配置管理监听与本机全网卡地址并封禁链路本地/云元数据/NAT64，收紧 `open_wan_firewall = false` 条件；反向代理拨号前执行单次 DNS 解析 + 全量解析 IP 校验 + `connect_candidates`；出站 `HttpClient` 补全 `0.0.0.0/8`、`240/4`、`fec0::/10`、NAT64 解包阻断，云 DNS/DDNS/STUN Cloudflare/内置公共 ACME CA 默认切换 `PublicOnly`；STUN 严格校验公网映射 IP 与服务器解析地址。
  - **反向代理路径与数据面防 DoS**：拦截 `;`/`%3b`/`..;` 路径参数并统一 `match_rule` 与 `rewrite_request_path` 百分号规范化及受保护规则大小写匹配；修复 `/{{path}}` 协议相对 `//` 重定向；反代与端口转发新增基于 `BanKey` 的单源并发配额与 `Fail2Ban` 接入拦截、H2 请求活跃度空闲超时、`403`/`421` 断链、UDP 有界缓冲池与驱逐取消，以及按 STUN 绑定按需开启 `SO_REUSEPORT`。
  - **认证、Fail2Ban 与 Step-Up MFA 边界**：按信任域拆分管理面与反代门户 `ScopedFail2Ban`（杜绝低权限门户登录清零管理封禁，前后端支持 `?scope=` 精准解封），修正 `secret_path` 封禁判定顺序，表满且未卸载内核时 Fail-Closed；为备份导出/导入、TOTP 启用/恢复码重置、Passkey 注册/双向开关、模块二次认证关闭、`dns_providers` 及 8 项管理面敏感字段补齐 MFA 级 Reauth 与跨 `HashGate` 配置变更复核；恢复码 PBKDF2 移出 `config_lock` 持锁区间，`vane auth-reset` 新增 `--clear-mfa`。
  - **高权限执行、防火墙与模块生命周期回收**：新增配置文件只读门禁 `admin.allow_manual_update_upload`、`admin.update_signing_public_key`、`admin.allow_cron_exec` 与只读 `admin.docker_socket`（含 `symlink_metadata`/`is_socket` 校验）；手动更新与纯 Rust `vane update`（彻底移除 `curl | sh`）强制 Ed25519 验签且探测子进程降权至 `nobody`，修复 Tar PAX 解析 Panic 与 `gzip` 僵尸回收；`fw3` 改用 `iptables-restore --noflush` 原子更新并支持失败回滚与 `degraded` 状态上报；CLI/守护进程共享持久化 `.lockdown`（每 2 秒同步停/启 WAN 监听且不清空 Fail2Ban 封禁）；完整回收禁用后的 Cron 任务与进程组（`JoinSet` + `CancellationToken` + `waitid`）、容器/宿主 PTY（含 `module_reauth.docker` 与 I/O 超时撤销）、`proxy_gate` 会话、在途 DDNS 与 `cert_table`。
  - **Vault、持久化、日志与供应链硬化**：引入 `enc:v2:` 无歧义 AAD 消除跨字段碰撞（兼容升级 `enc:v1:`），`acme-accounts` 改用强制验签 `vault.open`，备份恢复改为全量预校验 + 原子提交与证书匹配过滤，管理 TLS 证书采用世代目录原子切换；强化系统目录前缀黑名单与 ACME 多级域名校验、密钥/配置/自定义 TLS 符号链接与权限检查及内存零化；日志与外部通知统一脱敏清洗（含 PEM/Telegram/URL 凭据与 `totp_secret` 掩码），收件箱落盘异步化，限制 `secret_path` 仅首次启动打印；固定 `Dockerfile`/`docker-compose.example.yml`/CI `cross` 版本，默认注释 `docker.sock` 挂载并补全 `.dockerignore` 与 `install.sh`/`release.sh` 安全加固。
- 修复 `HashGate` 异步取消泄漏导致的永久 `429` 认证锁死，新增防用户名枚举的虚拟 PBKDF2 路径与 Fail2Ban 活跃封禁防驱逐。
- 修复反向代理 `auth_gate` 在 `static`/`redirect` 规则上的 `Upgrade: websocket` 绕过、未认证慢速连接/HTTP2 配额耗尽、路径规范化与前缀匹配绕过、`redirect` 模板二次展开注入以及 `vane_entry` Cookie 透传与 `Set-Cookie` 空格绕过。
- 修复 Vault `_renames` 跨字段 AAD 绕过与删除条目时的重命名优先级缺陷，修复保存前先加密导致字段校验被绕过的系统性问题，修复 TOTP 密钥损坏/过短时的 fail-open 退化。
- 修复 Linux UDP 端口转发 `PKTINFO` 缓冲区未对齐 UB 与 `MSG_CTRUNC` 缺失校验、UDP 伪造源洪峰耗尽共享配额与双向活跃保活缺陷。
- 修复 OpenWrt `fw4` 封禁规则未限定 WAN `iifname` 导致误伤 LAN/Loopback、删规则/解封失败未回滚、IPv6 `conntrack` 清理缺失、`KernelDnat` `FORWARD` 规则缺 `ct status dnat` 约束及管理端口/IPv4 映射地址目标绕过。
- 加固管理端 HTTPS 服务：新增单源并发上限、认证接口 8 KiB / 备份接口 8 MiB 请求体上限、60 秒请求超时、全响应 CSP/HSTS/Permissions-Policy 安全头、改密 Fail2Ban 限流、凭据/密钥变更全量会话轮换、子进程剥离 `VANE_MASTER_KEY*` 环境变量、共享 HTTP 客户端默认 SSRF 防护以及日志多键脱敏与注入清洗。

## [0.1.0] - 2026-11-10

### Added
- 全栈 IPv4/IPv6 双栈路由器网关守护进程与 Svelte 5 (Runes) 响应式 PWA 控制台（默认端口 `23456`）。
- 单管理员三合一认证（PBKDF2-SHA256 + 单调水位 TOTP + OpenSSH Ed25519）与首次登录强制修改默认密码 (`admin321`) 硬门禁。
- `ChaCha20-Poly1305` + `HKDF-SHA256` 字段级信封加密 (`Vault`) 与 `.vane.bak` 跨设备加密备份。
- 适配 OpenWrt `fw4` (`nftables`) 与 `fw3` (`iptables`) 的隔离防火墙引擎、`conntrack` 状态表清理、一键 `Lockdown` 与 IPv4 `/32` + IPv6 `/64` 自适应 `Fail2Ban`。
- 可插拔子功能模块（反向代理、4x4 端口转发、动态 DDNS、ACME 证书、STUN 穿透、默认关闭的受控 Web 终端、轻量 Cron 计划任务、Docker 容器管理）与 `ModuleSupervisor` 舱壁隔离。
- 一键安装与持久化无损更新脚本 `scripts/install.sh` 及自动化 CI/Release 工作流。
