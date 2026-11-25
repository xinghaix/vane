# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **跨机全量加密备份 (`.vane.bak`)**：完整纳入 ACME 账户（导出解密、导入自动用目标机 Vault 主密钥重封）、未完成清理的 `acme-challenges` 日志、有效代际证书 (`bundle.json` 验签并即时热加载) 及管理端 TLS 证书/私钥 (`certs/admin.{crt,key}`)，并在 UI 中展示备份范围清单与恢复汇总。
- **反代请求头 Vault 全链路加密**：`reverse_proxy[].rules[].request_headers_set` 纳入字段级 `ChaCha20-Poly1305` 信封加密、API 掩码、脱敏配置剔除与运行时解密，配套前端结构化 `HeaderRowsEditor` 编辑器（同样复用于 DDNS Custom HTTP、Cron HTTP 与通知渠道自定义请求头）。
- **反代门禁 WebSocket 取票 UI**：在反向代理规则卡片中为 `auth_gate + websocket` 规则新增一键取票弹窗（调用 `POST /api/proxy/ticket`，展示 30 秒倒计时与完整 `wss://...?vane_ticket=...` 地址）。
- **Web UI 与终端体验升级**：新增全局 WAN 封锁警示横幅、增量日志轮询 (`after_seq`)、接口快速选择 Chips、`secret_path` 随机生成与已生效/草稿双预览、终端 `ResizeObserver` 自适应行列 + ANSI 256/TrueColor 配色 + `\r`/`\x08`/清屏支持 + 智能滚屏、备份魔数与大小预校验以及全量中英双语和 WCAG AA 深色对比度优化。

### Security
- 修复 `HashGate` 异步取消泄漏导致的永久 `429` 认证锁死，新增防用户名枚举的虚拟 PBKDF2 路径与 Fail2Ban 活跃封禁防驱逐。
- 修复反向代理 `auth_gate` 在 `static`/`redirect` 规则上的 `Upgrade: websocket` 绕过、未认证慢速连接/HTTP2 配额耗尽、路径规范化与前缀匹配绕过、`redirect` 模板二次展开注入以及 `vane_entry` Cookie 透传与 `Set-Cookie` 空格绕过。
- 修复 Vault `_renames` 跨字段 AAD 绕过与删除条目时的重命名优先级缺陷，修复保存前先加密导致字段校验被绕过的系统性问题，修复 TOTP 密钥损坏/过短时的 fail-open 退化。
- 修复 Linux UDP 端口转发 `PKTINFO` 缓冲区未对齐 UB 与 `MSG_CTRUNC` 缺失校验、UDP 伪造源洪峰耗尽共享配额与双向活跃保活缺陷。
- 修复 OpenWrt `fw4` 封禁规则未限定 WAN `iifname` 导致误伤 LAN/Loopback、删规则/解封失败未回滚、IPv6 `conntrack` 清理缺失、`KernelDnat` `FORWARD` 规则缺 `ct status dnat` 约束及管理端口/IPv4 映射地址目标绕过。
- 加固管理端 HTTPS 服务：新增单源并发上限、认证接口 8 KiB / 备份接口 24 MiB 请求体上限、60 秒请求超时、全响应 CSP/HSTS/Permissions-Policy 安全头、改密 Fail2Ban 限流、凭据/密钥变更全量会话轮换、子进程剥离 `VANE_MASTER_KEY*` 环境变量、共享 HTTP 客户端默认 SSRF 防护以及日志多键脱敏与注入清洗。

## [0.1.0] - 2026-11-10

### Added
- 全栈 IPv4/IPv6 双栈路由器网关守护进程与 Svelte 5 (Runes) 响应式 PWA 控制台（默认端口 `23456`）。
- 单管理员三合一认证（PBKDF2-SHA256 + 单调水位 TOTP + OpenSSH Ed25519）与首次登录强制修改默认密码 (`admin321`) 硬门禁。
- `ChaCha20-Poly1305` + `HKDF-SHA256` 字段级信封加密 (`Vault`) 与 `.vane.bak` 跨设备加密备份。
- 适配 OpenWrt `fw4` (`nftables`) 与 `fw3` (`iptables`) 的隔离防火墙引擎、`conntrack` 状态表清理、一键 `Lockdown` 与 IPv4 `/32` + IPv6 `/64` 自适应 `Fail2Ban`。
- 可插拔子功能模块（反向代理、4x4 端口转发、动态 DDNS、ACME 证书、STUN 穿透、默认关闭的受控 Web 终端、轻量 Cron 计划任务、Docker 容器管理）与 `ModuleSupervisor` 舱壁隔离。
- 一键安装与持久化无损更新脚本 `scripts/install.sh` 及自动化 CI/Release 工作流。
