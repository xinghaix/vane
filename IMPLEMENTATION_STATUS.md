# 实现与验收清单

以 [架构规范](<rust.md>) 与实际代码、可重复测试共同判断完成度。中英文为唯一语言范围，WOL 不在范围内。本文记录实现进度，不代表生产认证。

| 子系统 | 当前已实现与安全加固内容 | 完成门槛与剩余边界 |
| --- | --- | --- |
| 管理安全 | TOTP 一次性恢复码核销与水位线落盘、无效/过短 Base32 TOTP 密钥 fail-closed、取消安全 `HashGate`、防用户名枚举虚拟 PBKDF2、改密 Fail2Ban 限流、删除公钥/改用户名/改入口自动轮换全量会话、`secret_path` 门禁 + Fail2Ban 记账、全响应安全头（CSP / HSTS / Permissions-Policy / `no-store`）、配置保存先解密 Vault 校验再原子落盘、敏感环境变量剥离 | 重放/并发/取消/越权/入口门禁/安全头回归测试全部通过 |
| Vault 与备份 | 字段级 `ChaCha20-Poly1305` + `HKDF-SHA256` 信封加密（含反代 `request_headers_set`）、`_renames` 结构化路径白名单防跨字段 AAD 绕过、脱敏导出覆盖 `eab_kid` 与反代请求头；`.vane.bak` 跨机全量加密备份已纳入配置、Vault 字段、ACME 账户（导入时以目标机主密钥自动重封）、挑战日志、有效代际证书 (`bundle.json`) 与管理端 `certs/admin.{crt,key}`，支持 600k 迭代/16 MiB/256 文件上限与内存零化 | 跨机全量备份导出/导入/证书表热加载端到端测试通过；实机跨设备整机迁移待演练 |
| HTTP 底座 | 双栈成功优先竞速、严格 TLS、有界请求响应、全程超时与取消、默认 `SsrfPolicy::BlockLoopbackAndLinkLocal` SSRF 防护 | 本地 HTTP/TLS、分块正文、SSRF 拦截、上限与失败回退测试通过 |
| 通知 | 八种渠道报文、真实投递、业务错误检查、Telegram Token 字符校验、Vault 解密、订阅/级别过滤与全局后台告警广播（DDNS/ACME/STUN/Fail2Ban/Cron/高温低内存/模块熔断） | 本地 Webhook 实际投递、冷却节流及签名向量测试通过；真实渠道待凭据验收 |
| DNS/DDNS | 服务商调度、Custom HTTP、外部地址源、地址族独立、缺 IP 策略、NDP 后缀缓存、Linux 地址事件、Split-DNS (`0644` 权限兼容非 root `dnsmasq`) 与状态变更通知 | 本地 HTTP 对账、删除报文、双栈部分成功、凭据解密、邻居解析、地址标志及 hosts 输出测试通过；真实服务和 Linux/OpenWrt 验收待完成 |
| ACME | 真实 RFC 8555 订单、DNS-01/EAB、账户持久化与恢复、传播/轮询/清理、续期、代际安全落盘（符号链接防护）、多目录 `CopyToDir`、`Webhook` 部署钩子、X.509 验证、管理证书热加载与重载证书表清理 | 本地 CA 校验真实 JWS/nonce/EAB/CSR 与实际 UDP DNS 传播测试通过；真实 CA/DNS 及掉电测试未执行 |
| 反向代理 | Hyper HTTP/1.1 & HTTP/2 ALPN 直连流式反代（含 H2 保活与 16 并发流上限）、中性降级默认证书、`request_headers_set` 全链路 Vault 加封、路径规范化与前缀防绕过、`redirect` 模板防注入、`vane_session`/`vane_entry` Cookie 清洗、上游禁指管理端口/环回地址、门禁 WS 一次性票据与前端取票 UI | 真实 TCP/TLS 协议与安全回归测试全面通过；公网压测与真实第三方应用待验收 |
| 端口转发 | 完整 TCP/UDP 4×4 双栈转发、Linux UDP `PKTINFO` 8 字节对齐 `AlignedCmsgBuf` 与边界校验、UDP 子配额防洪峰与双向活跃续期、`splice` 零字节保护、租约与时间窗、主备轮询、内核 DNAT 模式 | 双栈转发与取消测试通过；内核 DNAT 模式需 Linux 实机验收 |
| STUN | 同端口持久会话 (`run_stun_rule`)、源地址与端口有效性校验、TCP 故障转移、临时错误指数退避、`bind_rule` 端口继承、Webhook、Cloudflare Redirect 同步与通知联动 | 本地 STUN 持久会话及 Cloudflare/Webhook 协议测试通过；公网 NAT 类型需实网验收 |
| 防火墙 | 原子对账、挂链、删除/解封失败自动回滚、`fw4` `iifname` 作用域封禁防误伤 LAN/Loopback、IPv4/IPv6 `conntrack` 清理、`KernelDnat` `ct status dnat` / `--ctstate DNAT` 约束、网卡名与管理员端口防护、`lockdown` 子命令 | 命令生成、安全边界与故障注入测试通过；OpenWrt `fw3`/`fw4` 实机待验收 |
| Cron | 全部五类动作真实执行、32/64 位步长防溢出、防重入互斥、独立进程组超时预回收（防 PID 复用）、`>64 KiB` 输出无 SIGPIPE 截断、早退/取消保证落盘并触发失败通知、剥离主密钥环境变量 | 未来运行时间、HTTP 解密执行、进程组超时强杀回收测试通过 |
| Docker | 有界标准 HTTP、超时取消自动回收连接任务、32 位帧长防溢出、8 位及以上十六进制短 ID 保护匹配、日志多路复用、真实 prune | 模拟 Unix Socket + 回归测试通过 |
| Web 终端 | 原生 `openpty` + `TIOCSWINSZ` + `TIOCSCTTY` 伪终端、64 KiB 帧上限、会话/源网段/目标绑定票据、二次验证、登出/关模块即时断连、`Drop` 与先 `SIGHUP` 再 `SIGKILL(-pgid)` 进程组回收、剥离主密钥环境变量 | 本地真实 PTY 流式透传、票据越权拦截与子孙进程组回收测试通过 |
| 监控与日志 | 按需 CPU 时间片增量、网卡实时吞吐增量、`thermal_path` `/sys/` 白名单与 64B 有界读取、高温/低内存冷却告警；日志统一脱敏（含 `Basic`、Cookie、多键）与换行/ANSI 注入清洗 | 固定 procfs 样本、CPU 多核增量、阈值冷却告警与日志脱敏测试通过 |
| UI/PWA | Svelte 5 Runes 全功能双语控制台：结构化 `HeaderRowsEditor`、WS 门禁取票弹窗、ANSI 256/TrueColor + `ResizeObserver` + 智能滚屏终端、增量日志跟踪、WCAG AA 深色对比度与无障碍、备份包魔数/大小预校验与范围清单、`.rodata` 零拷贝 `.br/.gz` 直出与版本化 SW | 前端 0 警告构建与嵌入式静态资源测试通过 |
| 项目交付 | 完整 GPLv3 文本、标准 Tag 校验、源码归档、GHCR、安装校验/回滚/持久化 | 工作流静态检查、脚本沙箱测试、构建验证 |

## 已确认基线

- 管理 HTTPS、固定目的地明文跳转、Host/Origin 校验、Secure Cookie、可信 TCP 对端、安全响应头与静态资源路径保护均有回归测试覆盖。
- 测试不得修改开发宿主机防火墙、发布 DNS、签发真实证书或发送真实通知。

## 当前进度（2026-11-24）

- **功能缺口补齐**：
  1. `.vane.bak` 跨机全量备份与恢复已完整支持 ACME 账户（导出内存解密、导入自动用目标机 Vault 主密钥重封）、未清理挑战日志、有效代际证书（验签并即时热加载至 `CertTable`）及管理端 TLS 证书/私钥。
  2. 反向代理 `request_headers_set` 已接入全链路 Vault 信封加密、API 掩码、`sanitized_export` 脱敏、运行时解密及前端结构化请求头编辑器。
  3. 反向代理已内置 `auth_gate` 规则 WebSocket 一次性票据生成弹窗（`POST /api/proxy/ticket` + 30s 倒计时 + 一键复制 WSS URL）。
- **深度安全审计与修复**：完成前后端全模块安全审计并修复全部已确认的高/中/低危漏洞（含 `HashGate` 取消泄漏、反代 `auth_gate` 升级绕过与慢速连接 DoS、Vault `_renames` 跨字段 AAD 绕过、反代路径规范化绕过与模板注入、Linux UDP `PKTINFO` 未对齐 UB 与洪峰配额耗尽、Vault 加密字段校验绕过、`fw4` 全局封禁误伤 LAN/Loopback、管理端慢速连接与 TOTP fail-open、子进程环境变量泄漏、Cron/PTY/Docker/Logger 边界缺陷等），并补齐对应回归测试。
- **Web UI 全面完善**：修复 Lockdown 提示反转并增加全局封锁横幅、升级增量日志轮询、完善双语覆盖与移动端适配、重构终端 ANSI 解析与窗口自适应、增强备份校验与交互提示，前端实现零警告编译。
- **自动化验证**：后端 **121+ 项测试**全部通过（0 警告、0 失败），`vane check --config config.example.toml` 校验通过，前端构建与 `.br/.gz` 预压缩零警告通过。
- Split DNS 当前生成 `0644` 权限的专用 hosts 文件供 `dnsmasq` 引用，不自动重启系统 DNS，参见 [DDNS 使用说明](<DDNS_GUIDE.md>)。

### 协议参考

- [飞书自定义机器人签名](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot.md)
- [Cloudflare 创建 DNS 记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)
- [阿里云 AddDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord)
- [DNSPod 修改记录](https://cloud.tencent.com/document/api/1427/56157)

## 外部验收

涉及真实 DNS/CA/消息渠道的测试需要用户专用测试凭据，Linux/OpenWrt `fw3`/`fw4` 防火墙、内核 DNAT、公网 NAT STUN、长时间压测与掉电测试需在目标硬件上执行；缺少实机与外部凭据不影响本地协议与安全回归验证，但正式生产部署前必须完成上述实机验收。
