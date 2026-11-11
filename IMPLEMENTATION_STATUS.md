# 实现与验收清单

以 [架构规范](<rust.md>) 与实际代码、可重复测试共同判断完成度。中英文为唯一语言范围，WOL 不在范围内。本文记录实现进度，不代表生产认证。

| 子系统 | 当前待补齐内容 | 完成门槛 |
| --- | --- | --- |
| 管理安全 | 已完成 TOTP 一次性恢复码核销落盘、水位线落盘、配置并发互斥更新、终端会话/网段/目标三重绑定票据、安全入口路径 (`secret_path`) 与受信额外 Origin | 重放/并发/越权/入口门禁回归测试已通过 |
| HTTP 底座 | 已实现双栈成功优先竞速、严格 TLS、有界请求响应、全程超时与取消；后续按模块扩展流式上游接口 | 已通过本地 HTTP/TLS、分块正文、上限与失败回退测试 |
| 通知 | 已实现八种渠道报文、真实投递、业务错误检查、Vault 解密、订阅/级别过滤与全局后台告警广播（DDNS/ACME/STUN/Fail2Ban/Cron/高温低内存/模块熔断） | 已通过本地 Webhook 实际投递、冷却节流及签名向量测试；真实渠道待凭据验收 |
| DNS/DDNS | 已接入服务商调度、Custom HTTP、外部地址源、地址族独立、缺 IP 策略、NDP 后缀缓存、Linux 地址事件、Split DNS 文件与状态变更通知；系统 DNS 自动重载仍待目标固件集成 | 已通过本地实际 HTTP 对账、删除报文、双栈部分成功、凭据解密、邻居解析、地址标志及 hosts 输出测试；真实服务和 Linux/OpenWrt 运行验收待完成 |
| ACME | 已实现真实 RFC8555 订单、DNS01/EAB、账户恢复、传播/轮询/清理、续期、部署钩子、X509 验证、管理证书热加载与签发/失败通知 | 本地 CA 校验真实 JWS/nonce/EAB/CSR，实际 UDP DNS 传播测试通过；真实 CA/DNS 及掉电测试未执行 |
| 反向代理 | 已替换为 Hyper HTTP1/HTTP2 流式处理，支持真实 HTTPS 上游、三种 TLS 策略、头清洗、上传限额、门禁与绑定票据 WS、取消回收 | 9 项真实 TCP/TLS 协议测试通过，覆盖双栈、分片、分块、H2、升级撤权、配额回收；公网压测与第三方应用待验收 |
| 端口转发 | 完整 TCP/UDP 会话生命周期、租约与时间窗、主备轮询、内核模式 | 双栈转发与取消测试；内核模式需 Linux 验收 |
| STUN | 已在守护编排器与探测接口完整接入同端口持久会话 (`run_stun_rule`)、TCP/UDP 双栈、`bind_rule` 端口继承、Webhook、Cloudflare Redirect 同步与通知联动 | 本地 STUN 持久会话及 Cloudflare/Webhook 协议测试通过；公网 NAT 类型需实网验收 |
| 防火墙 | 原子对账、挂链、幂等撤销、双栈封禁、按所有者全模块重载回收、失败关闭与 CLI `lockdown` 子命令 | 命令生成与故障注入测试通过；OpenWrt fw3/fw4 隔离环境待实机验收 |
| Cron | 已实现全部五类动作真实执行（Docker 镜像清理、容器重启、规则启停、加密 HTTP 请求、独立进程组 Exec）、防重入互斥、秒级防抖调度与失败通知 | 未来运行时间（含半小时时区/月度）、HTTP 解密执行、进程组超时强杀回收测试通过 |
| Docker | 有界标准 HTTP、严格容器名首字符校验、ID/别名双重保护、日志多路复用、真实 prune | 模拟 Unix Socket + 回归测试通过 |
| Web 终端 | 已切换为原生 `openpty` + `TIOCSWINSZ` 伪终端、会话/源网段/目标绑定票据、二次验证选项、登出/关模块即时断连与进程组 `SIGHUP/SIGKILL` 回收 | 本地真实 PTY 无换行提示符流式透传、票据越权拦截与子孙进程组回收测试通过 |
| 监控 | 已移除全部硬编码模拟指标，实现按需 CPU 时间片增量、网卡实时吞吐增量、真实宿主机系统调用回退与高温/低内存冷却告警 | 固定 procfs 样本、CPU 多核增量与阈值冷却告警回归测试通过 |
| UI/PWA | 已重构为模块化 Svelte 5 Runes 全功能控制台（全模块增删改抽屉、快捷预设、TOTP/Ed25519 登录与管理、通知中心、加密备份恢复、终端按需分包、移动端底部导航+全量抽屉、`.rodata` 零拷贝 `.br/.gz` 直出与安全 SW） | 前端零警告构建与嵌入式静态资源测试通过 |
| 项目交付 | 完整 GPL 文本、标准 Tag 校验、源码归档、GHCR、安装校验/回滚/持久化 | 工作流静态检查、脚本沙箱测试、构建验证 |

## 已确认基线

- 管理 HTTPS、固定目的地明文跳转、Host/Origin 校验、Secure Cookie、可信 TCP 对端、静态资源路径保护已有回归测试。
- 本轮开始前后端 50 项测试通过，但大量子功能仍为伪成功路径；不能以此宣称全部功能完成。
- 测试不得修改开发宿主机防火墙、发布 DNS、签发真实证书或发送真实通知。

## 当前进度（2026-11-11）

- 共享 HTTP、DNS 服务商、通知底座和真实 ACME 协议已实现，DDNS 已接入真实对账；后端测试由 50 增至 93 项，全部通过，原生开发构建通过。
- DDNS 不再伪报 synced；IPv4/IPv6 结果分开，源错误不会触发删除，last_sync_unix 仅在完整成功后推进。ACME 的自签冒充签发路径已删除，改为真实订单、证书元数据验证和代际落盘。详见 [ACME 使用与验收说明](<ACME_GUIDE.md>)。
- 监督器同步工厂 panic 和关闭通道忙循环已修复；重载会等待旧监督器退出后启动新任务，所有数据面后代任务及防火墙关闭顺序仍需下一阶段逐项验收。
- Split DNS 当前生成专用 hosts 文件，须在目标设备接入 dnsmasq；没有自动重启系统 DNS。参见 [DDNS 使用说明](<DDNS_GUIDE.md>)。
- Linux ARM64 musl 开发产物已通过 Zig 交叉构建；RTNETLINK 等 Linux 专用分支编译通过，但没有在 Linux 上运行。构建使用与已安装目标匹配的 Rust 工具链，不能把 macOS 原生编译器的目标缺失误判为源码错误。
- 通知测试 API 已返回 sent/skipped 真实结果；后台告警事件分发仍需接入。
- 反代已替换丢失正文的原始解析器；实际协议与剩余兼容边界见 [反向代理说明](<PROXY_GUIDE.md>)。
- 仍保留所有未提交安全补丁；未触发生产 DNS、CA、通知、防火墙或 Release 操作。

### 协议参考

- [飞书自定义机器人签名](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot.md)
- [Cloudflare 创建 DNS 记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)
- [阿里云 AddDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord)
- [DNSPod 修改记录](https://cloud.tencent.com/document/api/1427/56157)

## 外部验收

涉及真实 DNS/CA/消息渠道的测试需要用户专用测试凭据；缺少凭据不影响本地协议实现，但必须明确记录未完成真实服务验证。镜像和发行产物需在远端工作流实际运行后才可宣称已发布。
