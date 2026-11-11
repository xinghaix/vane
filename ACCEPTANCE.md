# Vane 网关功能验收测试准则 (Acceptance Criteria)

为确保 Vane 生产环境的安全性与稳定性，部分子功能模块必须在真实 Linux 嵌入式环境（如 OpenWrt / Debian）下进行集成验证，不可完全依赖单元测试或模拟器。

## 1. 强制需实机/真实依赖验证的功能
以下功能组件必须在目标 SoC (ARM64/x86_64) 环境下使用真实网络与驱动进行验收：

*   **防火墙策略（M2/M3）**：
    *   必须验证 fw4 (nftables) / fw3 (iptables) 规则链挂载的幂等性与原子性。
    *   验证 conntrack 在规则修改/封禁时是否被正确清理。
    *   必须在拨号重拨后的 Netlink 事件中验证 /128 IPv6 子设备防火墙规则的自动原子更新（禁止遗留无效前缀规则）。
*   **网络接口感知（M3/M8）**：
    *   验证在 pppoe-wan 等接口切换、掉线、IPv6 前缀更新时，Netlink 订阅是否能做到零延迟感知并剔除非法地址（CGNAT/Deprecated）。
*   **Docker 运维功能（M9）**：
    *   必须具备真实的 /var/run/docker.sock。
    *   验证容器列表、日志实时流式传输（避免聚合内存炸弹）与 Prune 清理功能。
*   **PTY Web 终端（M6）**：
    *   验证 openpty 的终端字符流是否按 16 KB 窗口正确流式透传，以及进程组 SIGKILL 回收机制的鲁棒性。

## 2. 需凭据/外部依赖的服务验证
以下功能需配置真实服务商 API 或账户凭据：

*   **DDNS 服务商（M3）**：Cloudflare、阿里云、DNSPod 等真实解析记录变更。
*   **ACME 自动化证书（M4）**：域名 DNS 解析权限（DNS-01 挑战）、真实 CA 机构签发环境。
*   **多渠道通知中心（M7）**：Telegram/Bark/Webhook 推送验证。

## 3. 已交付测试集清单
*   [x] 配置加载与原子落盘测试（Atomic IO）
*   [x] 全局连接并发限额测试（Global Quota）
*   [x] 舱壁隔离与半开熔断测试（Supervisor）
*   [x] 双栈协议族独立绑定验证（Net/DualStack）
*   [x] 监控数据按需采样验证（Monitor）
*   [x] Cron 安全任务执行验证（Docker Prune / Exec）
*   [x] 登录与强认证（Fail2Ban/TOTP/Ed25519）
