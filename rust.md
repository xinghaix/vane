# Vane：面向资源受限路由器的高安全双栈全能网关规格书

> **项目定位**：使用纯静态编译 **Rust** 构建一个 **全栈 IPv4/IPv6 原生、子模块故障舱壁隔离、安全默认拒绝（Default-Deny）、低闪存磨损、固件升级自愈** 的嵌入式路由器全能网关单二进制程序（代号 **`vane`**），旨在替代传统高内存占用的网关工具与独立容器管理面板。

---

## 1. 项目背景：嵌入式路由器资源约束与架构痛点

在嵌入式 Linux / OpenWrt 硬路由（ARM64 / x86_64 `musl` 环境）中，受限于无线驱动与硬件网络加速引擎固定占用的大量不可回收内核内存（`Slab SUnreclaim`），用户态可用物理内存极其紧缺；同时板载持久化分区（如 `/data` 或 `/overlay`）剩余空间有限，Docker 引擎通常挂载在外置 USB 存储上。

### 1.1 传统网关与容器管理方案的资源瓶颈

| 传统组件类别 | 典型运行形态与开销构成 | 典型常驻内存 (`VmRSS`) | 核心痛点与架构局限 |
| :--- | :--- | :--- | :--- |
| **传统一体式网关（带 GC 运行时）** | 单体进程 + 重型正则 WAF 规则集 + 高上限内存连接/日志留存 | **`65 MB ~ 80+ MB`** | GC 堆内存难以主动归还内核，重型 WAF 与全功能捆绑导致空载内存极高；旧开源分支停更后缺乏安全维护与按需裁剪能力。 |
| **独立容器管理面板（Web 面板 + Redis）** | 面板后端进程 + `redis-server` + `containerd-shim` + 多个 `docker-proxy` 端口转发进程 | **`12 MB ~ 25 MB`** | 仅为提供基础容器启停与日志查看，额外常驻数据库与多个代理进程，浪费宝贵 RAM 与进程槽位。 |

### 1.2 架构演进目标对比

| 指标维度 | 传统多组件组合方案 | Rust `vane` 设计目标值 | 核心机制与预期收益 |
| :--- | :--- | :--- | :--- |
| **常驻进程数** | `6` 个（网关主进程 + 容器面板 + `redis` + `shim` + `proxy`） | **`1` 个**（原生 `procd`）或 **`2` 个**（Docker `host` 模式含 `shim`） | **减少 4~5 个常驻进程**，消除 Redis 与 `docker-proxy` 开销 |
| **日常用户态内存 (`VmRSS`)** | `88,644 KB`（`~86.6 MB`） | 原生版目标 **`6.0~8.5 MB`** / UPX 版 **`9.0~12.0 MB`** | **预计净释放 `74 ~ 80 MB` 用户态内存**（受全局并发配额硬约束） |
| **空闲 CPU 占用** | 持续背景轮询（1%~3% 周期性毛刺） | **无面板订阅接近 `0.0%`**（按需采样 + Netlink 事件 + 低频对账） | 显著降低路由器 SoC 空载唤醒与发热 |
| **板载持久化空间占用** | `~158 MB`（二进制 + 容器层 + Redis RDB） | 原生版 **`~2.8-3.6 MB`** / UPX 版 **`~1.0-1.3 MB`** / U 盘 Docker 版 **板载 `0 KB`** | **双轨二进制 + 容器镜像，按需适配板载与外置存储** |
| **Flash 闪存保护** | 日志落盘、Redis 快照、状态高频写盘 | **高频运行态纯内存驻留**，仅配置/证书/安全核销状态原子落盘 | 极小化板载 NAND/eMMC 擦写次数，包含父目录 `fsync` 防掉电损坏 |
| **双栈与故障隔离** | 单点异常易波及全局；IPv6 旧前缀识别易错 | **IPv4/IPv6 全栈正交 + 协程 `unwind` 隔离与半开熔断** | 单规则或外部依赖故障独立降级，不影响其余模块 |
| **防火墙与安全底线** | 规则粗放，易泄露证书域名，无 Conntrack 联动清理 | **Default-Deny + `fw3/fw4` 原生链精准挂载 + Conntrack 断流** | 守住家庭公网入口最高安全底线 |

---

## 2. 路由器四大资源约束准则（CPU / 内存 / 磁盘 / 持久化）

### 2.1 CPU 约束：按需唤醒、异步非阻塞与硬件加速协同
1. **监控按需唤醒（On-Demand Sampling）**：无浏览器打开管理面板时，`/proc` 与 `/sys` 采集器完全挂起（0 采样定时器）；仅在 SSE/WebSocket 订阅存活期间按 2s 周期采样，关网页即停。
2. **Netlink 事件驱动 + 低频全量对账**：通过 Linux **Netlink Socket (`RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE`)** 实时捕获拨号接口变化，辅以 15 分钟低频对账，消除高频轮询。
3. **严禁阻塞异步 Worker 线程**：系统仅配置 `2` 个 Tokio I/O 工作线程。所有外部防火墙命令统一采用异步 `tokio::process::Command`（绑定硬超时与 `kill_on_drop(true)`）；`PBKDF2` 密码哈希计算放入受有界信号量（`Semaphore(1)`）与队列上限（最多 4 个等待请求）保护的 `spawn_blocking` 线程（限制 `max_blocking_threads = 2`），彻底杜绝慢锁或算力阻塞导致网关断流。
4. **双引擎端口转发**：
   - **同协议族纯转发（`v4→v4` / `v6→v6`，无需网关层限流/Proxy Protocol/ACL 策略时）**：下发内核 `nftables`/`iptables` `DNAT` 规则，首包建连后可协同系统 Conntrack / Flow Offload 硬件或内核加速。
   - **跨协议族转发（`v6→v4` / `v4→v6`）或带策略转发（连接配额、CIDR 白名单、Proxy Protocol）**：TCP 走用户态 **Linux `splice()`** 零拷贝管道；UDP 走基于 `recvmsg/sendmsg`（保留 `IP_PKTINFO` / `IPV6_PKTINFO` 源地址一致性）的有界会话表代理。

### 2.2 内存约束：全局预算硬水位与内核态缓存限额
1. **全机全局连接与内核管道预算（Global Quota）**：
   - 除每条规则独立限制并发连接数外，全进程设置 **全局最大并发转发/反代连接硬上限（默认 `global_max_conns = 512`）**，并为管理面板独立预留 `16` 个连接槽位（永不被业务流量挤占）。
   - TCP `splice()` 创建匿名管道后立即调用 `libc::fcntl(pipe_fd, libc::F_SETPIPE_SZ, 16384)` 请求收缩单管道缓存并校验返回值，绑定空闲超时回收。
2. **编译期 `Brotli (.br)` / `Gzip (.gz)` 预压缩静态直出**：前端采用编译期无虚拟 DOM 的 **Svelte 5 (Runes)** 构建，离线产出 `.br`（体积较 `.gz` 再缩减 ~25%）与 `.gz` 双静态资产；`rust-embed` **关闭运行时 `compression` 解压缓存**，Release 模式下直接通过 `Bytes::from_static` 零拷贝发送 ELF `.rodata` 切片。
3. **100% 纯流式代理**：反向代理与 Docker API 严禁调用 `.collect().await` 全量聚合 Body，采用固定 `16 KB` 流控窗口逐帧透传，HTTP/2 显式限制 `max_concurrent_streams = 64`。
4. **有界容器与安全线程栈**：环形日志锁死 `300` 条（单条截断 `512 B`）、防爆破 LRU 锁死 `512` 槽位、Rustls 会话缓存缩减至 `64`；工作线程栈设为 **`512 KB`**（兼顾极低内存与深层 TLS/解析调用栈安全，防止栈溢出触发整机 abort）。

### 2.3 磁盘约束：双轨打包（原生 vs UPX）+ 外挂 Docker 与低磨损设计
1. **代码源头裁剪**：全模块共享单一 `hyper + rustls (ring)` 底座；`instant-acme` 通过自定义 `HttpClient` 复用内置客户端；提供原生未压缩版（`~2.8 - 3.6 MB`）、UPX 极限压缩版（`~1.0 - 1.3 MB`，供板载 `/data` 空间充裕但仅剩 `>= 4 MB` 的独立部署场景选用，预留至少 2 倍体积用于原子升级与备份）与外挂 U 盘 Docker 镜像版。
2. **闪存低磨损与安全持久化平衡**：高频运行态（日志、监控、DDNS/STUN 缓存、临时封禁表）100% 驻留内存；**仅在配置修改、ACME 证书签发/续期、或高安全单向状态核销（如一次性恢复码消费）时执行落盘**。

### 2.4 持久化约束：掉电一致性原子写（含父目录 `fsync`）与固件升级自愈
1. **掉电安全的完整原子落盘（Crash-Safe Atomic Write）**：
   任何针对 `config.toml`、安全状态与证书私钥的保存，严格执行：
   `在同目录 (0700) 创建带随机后缀的 0600 临时文件 (O_CREAT|O_EXCL|O_WRONLY) -> 完整写入并 File::sync_all() -> 若存在旧文件则原子更新 .bak -> fs::rename() 原子替换目标文件 -> 打开父目录 FD 执行 dir.sync_all() 刷入目录项元数据`。多文件证书更新采用“先写齐新文件并 fsync，校验公私钥匹配后再原子切换指向”策略；若遇 `ENOSPC` / `EROFS` 立即中止并保留旧有效状态。
2. **OpenWrt / 定制固件 OTA 自愈**：文件统一收敛于 `/data/vane/`，内置 `vane service install` 注册 `/etc/config/firewall` `include` 钩子（并在安装时实机校验固件分区保留属性），开机或防火墙重载时幂等恢复 `procd` 服务与防火墙规则链。

---

## 3. 三大架构底线设计：全栈 IPv4/IPv6、故障舱壁隔离与纵深安全

### 3.1 全方位 IPv4 / IPv6 双栈一等公民架构（Dual-Stack Everywhere）

| 架构层面 | 常见双栈陷阱 | `vane` 正交双栈设计规范 |
| :--- | :--- | :--- |
| **Socket 监听层** | 依赖 `bindv6only=0` 产生 `::ffff:1.2.3.4` 映射地址；或 IPv4 绑定失败直接短路跳过 IPv6 | 统一枚举 `dual` / `ipv4_only` / `ipv6_only`（禁止 `port = 0`）。**`dual` 模式独立尝试绑定原生 IPv4 与强制 `IPV6_V6ONLY = 1` 的原生 IPv6**，分别收集两栈 `Result`：只要任一栈成功即可对外服务，明确区分 `EAFNOSUPPORT`（缺内核栈）与 `EADDRINUSE`（端口冲突），且防火墙**仅开放实际监听成功的协议栈**。 |
| **UDP 源地址一致性** | 在 `0.0.0.0` / `[::]` 多地址接口上直接 `recv_from/send_to` 会导致回包源 IP 漂移，破坏客户端 NAT 状态与 STUN 校验 | UDP 套接字强制启用 `IP_PKTINFO` (IPv4) 与 `IPV6_RECVPKTINFO` (IPv6)，通过 `recvmsg` 记录入站目的 IP 与 `ifindex`，回包时通过 `sendmsg` 辅助数据固定原入站 IP 作为源地址发出。 |
| **转发与反代互通** | 仅支持单向 `6to4`；内网休眠 NAS 的 NDP 邻居表过期后按 MAC 查不到 IPv6 地址 | **支持 `4→4`、`4→6`、`6→4`、`6→6` 全矩阵桥接**。内网子设备 IPv6 定位支持：① 路由器当前有效 PD 前缀 + 配置的固定接口标识符（IID / EUI-64 / DHCPv6 固定后缀）确定性合成；② Netlink `RTM_GETNEIGH` 辅助发现并缓存最近一次已验证后缀（绝不在邻居表过期为空时误删 DNS 或放宽防火墙）。 |
| **公网地址零竞态甄别** | 重拨后残留 `deprecated` (`preferred_lft=0`) 旧前缀或 `tentative` 地址；订阅与快照间丢事件 | **先订阅 Netlink 广播组，再发起 `RTM_GETADDR` / `RTM_GETROUTE` 全量 Dump 按序列号合并**（处理 `NLM_F_DUMP_INTR` 与 `ENOBUFS` 重同步）。IPv4 剔除 RFC1918 与 `100.64.0.0/10` CGNAT；IPv6 仅选取 `2000::/3` 且满足 **`ifa_prefered > 0`、`ifa_valid > 0`、非 `IFA_F_TENTATIVE`、非 `IFA_F_DADFAILED`、非 `IFA_F_TEMPORARY` 且具备有效默认路由** 的地址。 |
| **出站云 API 通信** | 运营商偶发“IPv6 有地址但路由黑洞”导致 DDNS/ACME 死等超时 | 内置符合 **RFC 8305 Happy Eyeballs** 的双栈连接器：A/AAAA 地址交错排序，首选栈连接 `250ms` 未完成即并发尝试备选栈，胜出后立即取消另一路连接（仅在连接建立阶段竞速，严禁对有副作用的 HTTP 请求重复发送）。 |

### 3.2 模块与规则级故障舱壁隔离（Bulkhead Fault Isolation）

1. **协程级 `Panic` 拦截与验证（`panic = "unwind"`）**：
   保留栈展开表，将模块初始化与运行逻辑完整包裹在 `tokio::spawn` 内部（不在 `spawn` 外直接求值工厂闭包），并在 CI 中通过 QEMU / 实机测试用例强制验证子任务 `panic!` 可被 `JoinError::is_panic()` 捕获且不影响主进程。
2. **三层故障隔离与半开熔断（Half-Open Circuit Breaker）**：
   - **配置局部加载**：单条规则语法错误、证书不匹配或端口 `EADDRINUSE` 仅将该条规则标为 `Degraded`，其余规则正常拉起。
   - **滑动窗口退避与半开恢复**：每个模块维护最近 5 次异常时间戳滑动队列。60 秒内连续失败 5 次进入 `CircuitOpen`（熔断保护）；熔断后每 **300 秒执行一次低频半开探测（Half-Open Probe）**，确保像 `/var/run/docker.sock` 这类晚启动或重启恢复的外部服务能自动重连自愈。
   - **结构化取消与子任务树回收**：停止或重载模块时，先触发 `CancellationToken`，限时等待子任务退出，超时后执行 `handle.abort()` 并 `(&mut handle).await` 回收句柄，绝不遗留孤儿协程。

### 3.3 端口防火墙与公网暴露安全底线（Security-First Defense-in-Depth）

1. **Web 管理三合一强认证与全链路 TLS（拒绝明文传输凭据）**：
   - **管理端口默认强制 HTTPS（解决局域网 IP 下 `Secure` Cookie 与防嗅探矛盾）**：
     管理后台默认仅绑定 LAN 接口（如 `192.168.1.1:23456`，同时校验入站接口与 `Host`/`Origin` 防 DNS Rebinding）。首次启动若无证书，自动用 `rcgen` 生成本地 ECDSA 证书（含 `192.168.1.1` / `127.0.0.1` / `::1` SAN，支持面板导出根 CA 或自动复用已签发的 ACME 证书），同端口首字节嗅探将 `http://` 自动 `308` 跳转至 `https://`，确保密码、TOTP、签名与 `HttpOnly; Secure; SameSite=Strict` 会话 Cookie 全程加密传输。
   - **单管理员极简模型与初次登录硬步骤强制改密（Single-Admin & Hard Password-Change Gate）**：
     - **不做多用户管理**：全系统仅设唯一管理员身份（默认登录名 `admin`），不引入多用户表或 RBAC 角色体系，保持最小复杂度与内存占用。
     - **初次部署默认账号密码**：初次部署默认用户名为 `admin`（用户名可保持默认无需强制修改，也支持在设置页按需修改），默认初始密码为 **`admin321`**（配置标记 `must_change_password = true`）。
     - **禁止同初始密码、禁止跳过进入管理页与适度强密码策略**：
       1. **状态判定**：只要 `must_change_password == true`，**或者**后端校验当前 `password_hash` 仍与初始默认密码 `"admin321"` 匹配（防止手动改配置跳过），登录后仅签发受限作用域会话 `SessionScope::MustChangePassword`；
       2. **后端路由中间件硬拦截**：当会话处于 `MustChangePassword` 时，除改密接口 `POST /api/auth/change-password` 与登出接口外，**访问任何管理页面数据、设置保存、容器/防火墙/转发控制 API 一律在后端直接返回 `403 Forbidden (MUST_CHANGE_INITIAL_PASSWORD)`**，前端同步锁定在无“跳过”按钮的强制改密页，彻底封死跳过改密步骤进入管理页面的可能；
       3. **实用型强密码规则（不过度繁琐）**：新密码需满足 **长度 `>= 8` 位 + 必须包含英文字母 + 至少包含数字或特殊字符中的一种**，且严禁与初始默认密码 `"admin321"`、当前旧密码或用户名相同；校验通过并完成掉电安全原子落盘后，将 `must_change_password` 置为 `false` 并签发 `SessionScope::FullAdmin` 正式放行进入管理页面。
   - **防重放 TOTP 双因素认证（单调水位线）**：
     支持 `±1` 时间步长容错，记录全局唯一管理员已接受的最大步长 `last_accepted_step`，**凡 `step <= last_accepted_step` 一律拒绝**（彻底封死 `n -> n+1 -> n` 回退重放漏洞）；校验、步长水位更新与会话签发在同一互斥锁临界区内原子完成。
   - **服务端强绑定 Ed25519 密钥挑战签名登录**：
     支持导入 OpenSSH `ssh-ed25519` 公钥（自动解析 SSH Wire Format 提取 32B 原始公钥）。服务端签发挑战时强制绑定 `(nonce, key_id, client_ban_key)`（挑战池按源 IP 限速且不驱逐未过期挑战）；验签消息固定为 `b"vane-ed25519-auth-v1|" || nonce || b"|" || key_id || b"|" || canonical_server_origin`（`canonical_server_origin` 取自服务端配置而非客户端请求参数），单次原子消费后立即签发会话。
2. **Web 终端默认关闭与高危运维边界管控**：
   - **Web 终端（`modules.web_terminal`）默认关闭（`false`），支持在设置页按需打开**：关闭时完全禁用 WebSocket PTY 路由与前端终端组件加载；打开后支持宿主机 Shell（`openpty`）与容器交互式终端，强制校验 Origin、一次性 WS Ticket、最大并发会话上限（`2`）与空闲超时自动断连，会话登出或断开时立即向进程组发送 `SIGHUP` -> `SIGKILL` 并 `waitpid` 回收。
   - **Docker 与 Cron 安全边界**：Docker 管理模块聚焦**轻量运维白名单接口**（容器列表、状态、已有容器启停/重启、日志流、容器终端、官方 Prune 清理，不提供在线创建挂载宿主机根目录的特权容器接口）；外部 `exec` 计划任务采用无 Shell 结构化参数数组执行。
3. **防火墙 `fw4 (nftables)` 与 `fw3 (iptables/ip6tables)` 真实语义与精确挂载**：
   - **解决 `nftables` 跨表 `ACCEPT` 失效问题**：在 Linux Netfilter 中，独立 `table` 的 `accept` 无法跳过 `table inet fw4` 后续 base chain 的 `drop/reject`（仅 `drop` 跨表立即终局生效）。因此：
     - **黑名单拦截（Drop）**：挂载于高优先级 `prerouting / input` 钩子（`priority filter - 10`）直接静默 `drop`。
     - **端口放行与 DNAT（Accept / DNAT）**：
       - **`fw4` (`nftables`)**：通过专属子链 `vane_input` / `vane_forward` / `vane_dstnat` 挂载进 `table inet fw4` 的官方决策链 `input_wan`、`forward_wan` 与 `dstnat_wan`（在最终 `reject` 之前匹配）。
       - **`fw3` (`iptables` / `ip6tables`)**：自动探测宿主机活跃后端（区分 `iptables-legacy` 与 `iptables-nft`），使用 `-I`（插入链首）将 `VANE_INPUT` 挂入 `zone_wan_input`、`VANE_FORWARD` 挂入 `zone_wan_forward`、`VANE_PREROUTING` 挂入 `nat` 表 `zone_wan_prerouting`。
       - **严格区分本机监听与 DNAT 转发路径**：网关本机监听端口（反代、用户态 `splice`）放行 `INPUT`；内核 `DNAT` 转发放行 `PREROUTING (dnat)` + `FORWARD`（匹配转换后的内网目标 IP 与端口）。
   - **子设备 IPv6 精确 `/128` 放行（废弃宽泛后缀掩码）**：针对内网 NAS 的 IPv6 直连放行，仅匹配当前合成并校验有效的 **完整 `/128` Global IPv6 地址 + 入站 `iifname "pppoe-wan"` + 出站 `oifname "br-lan"` + 指定目标端口**；前缀重拨变化时原子替换集合中的 `/128` 地址，绝不用 `::suffix/64` 掩码误放行其他前缀或 VLAN。
   - **区分本机高危端口与内网转发目标**：硬拦截向 WAN `INPUT` 直接放行路由器本机 `21/22/23/53/67/68/80/139/443/445/1883/2375/2376/6379` 及管理面板端口（转发至内网不同 IP 的 NAS 端口不受本机 `INPUT` 黑名单误伤）。
   - **真实断流（Conntrack 清理）与启动预清扫（Pre-Start Sweep）**：
     - 进程每次启动首轮先清空所有旧残留 `vane` 规则链，再按当前成功监听的规则逐一开门（应对上次 `SIGKILL` / 掉电未执行 `Drop` 的残留）；
     - 规则停用、封禁源 IP 或执行 `vane firewall lockdown` 时，除撤销放行规则并插入前置 `DROP` 外，同步删除匹配的 `conntrack` 状态表项以立即切断已建立的 `ESTABLISHED` 连接（对需即时封禁/限流的规则默认走用户态 `splice` 避免硬件 offload 绕过）。

---

## 4. 完整功能需求矩阵（全栈 IPv4/IPv6 + 故障隔离 + 纵深安全）

| 模块编号 | 模块名称 | 优先级 | 核心需求规格（全栈 IPv4/IPv6 + 故障隔离 + 安全加固） | 编译期可裁剪 |
| :--- | :--- | :---: | :--- | :---: |
| **M1** | **双栈智能网关与反向代理** | **P0** | • **双栈独立监听 + 单端口多协议复用**：支持 `dual / ipv4_only / ipv6_only`；首字节嗅探同端口自适应 HTTP 跳 HTTPS 与 TLS 反代<br>• **严格 SNI 拒连 + 协议安全校验**：未知 SNI 直接断连；严格校验 `Host`/`:authority` 与 SNI 一致性，清洗 `Forwarded`/`X-Forwarded-*` 与逐跳头防请求走私；WebSocket 强制校验 `Origin` 与会话 Ticket | 核心必选 |
| **M2** | **双引擎端口转发与安全防火墙** | **P0** | • 完整支持 **`v6→v4`、`v4→v6`、`v4→v4`、`v6→v6`** 的 TCP（受限 `splice`）与 UDP（`IP_PKTINFO/IPV6_PKTINFO` 源地址一致代理）转发，受全机与单规则双层连接配额保护<br>• 策略自动选路：需限流/ACL/Proxy Protocol 时走用户态引擎；纯同栈高速转发可选内核 DNAT<br>• **`fw3/fw4` 精准防火墙联动**：异步超时受控调用，支持 `conntrack` 即时断流与启动预清扫 | 核心必选 |
| **M3** | **双栈事件驱动 DDNS 与内网回流** | **P0** | • **先订阅后 Dump 零竞态 Netlink** 感知 `pppoe-wan` 等接口地址与路由变更，剔除 CGNAT IPv4 与 `tentative/deprecated/temporary` IPv6<br>• **子设备 IPv6 `/128` 合成与精确放行**：结合当前 PD 前缀与固定后缀/邻居表合成 `/128` 地址，更新 `AAAA` 并原子替换防火墙 `/128` 白名单<br>• **RFC 8305 Happy Eyeballs 云客户端 + Split-DNS 回流** | 核心必选 |
| **M4** | **ACME 证书自动化与热替换** | **P0** | • 通过自定义 `HttpClient` 复用内置双栈客户端，支持同一域名多 TXT 记录并存的 DNS-01 挑战与传播检查，签发 ECDSA P-256 证书<br>• 校验新证书链与私钥匹配后原子落盘（含父目录 `fsync`），再经 `ArcSwap` 无锁热切换内存证书池 | 核心必选 |
| **M5** | **STUN 映射探测与保活（UDP/TCP）** | **P1** | • 支持 RFC 5389/8489 映射探测与可选 RFC 5780 NAT 行为诊断（明确提示 CGNAT/对称 NAT 下无法入站，IPv6 无需 STUN）<br>• 内置 UDP 转发完整校验 20B STUN Header + Magic Cookie + Transaction ID + 服务端源地址分流；Webhook 自动对 IPv6 地址加 `[]` 格式化 | `feature = "stun"` |
| **M6** | **Web 终端（默认关闭，可选打开）** | **P1** | • **默认关闭（`modules.web_terminal = false`）**，可在设置页按需打开；前端终端组件采用异步分包按需加载<br>• 支持宿主机交互式 Shell（`openpty`）与容器交互式终端，内置会话数上限（2）、空闲超时断连、窗口大小同步（`TIOCSWINSZ`），登出或断连立即 `SIGHUP -> SIGKILL` 清理进程组 | `feature = "pty"` |
| **M7** | **受控计划任务（Cron）与通知中心** | **P1** | • 轻量 Cron 调度器，支持内置安全动作（如 `docker_prune`、规则定时启停）与无 Shell 结构化 `program + args` 外部命令<br>• 独立进程组执行 + `timeout_secs` 超时 `SIGKILL` 并 `wait` 回收，配合全局多渠道通知中心告警 | 核心必选 |
| **M8** | **主机与进程级系统监控** | **P1** | • 按需订阅式读取 `/proc` 与 `/sys`（无人查看时 0 采样）：CPU 每核负载、温度、WAN/LAN 双栈吞吐、Slab 不可回收内存拆解<br>• **内置 Top `VmRSS` 进程实时榜** + **各子模块健康状态与防火墙开放规则实时审计** | 核心必选 |
| **M9** | **轻量 Docker 容器管理** | **P2** | • 直连 `/var/run/docker.sock`（支持 Socket 重建自动重连与半开恢复）提供轻量容器管理（容器列表、资源状态、启停/重启、实时日志流、镜像与网络 Prune 清理） | `feature = "docker"` |

### 4.2 各子功能复杂场景深度自定义需求规格（Scenario-Driven Customizations）

为满足复杂家庭与边缘网络拓扑的个性化需求，同时保持零正则引擎、零脚本解释器的极低内存开销，各子模块内置以下结构化自定义能力：

#### 1. 【M1 反向代理与 Web 服务】场景自定义
- **内网自签名 HTTPS 后端对接**：支持 `upstream = "https://..."`，提供三种上游证书校验模式：`"strict"`（默认系统根证书）、`"pinned_sha256"`（绑定内网后端的自签名证书 SHA-256 指纹，兼顾自签证书可用性与防中间人）、`"insecure_skip_verify"`（跳过校验）；支持自定义发往上游的 TLS SNI（`upstream_sni`）与覆写 `Host` 请求头（解决 PVE/路由器后台等强校验 Host 的内网服务）。
- **单域名多路径分流与前缀剥离**：支持在同一域名下按 `path_prefix`（如 `"/qb/"`、`"/ha/"`）分流至不同内网服务，并可选开启 `strip_prefix = true` 自动剥离前缀转发。
- **无后端直接响应与动态重定向（Redirect / Static 模式）**：规则除 `"proxy"` 模式外，支持配置为 `"redirect"`（301/302/307/308 跳转，支持引用 `{{stun.<name>.public_addr}}` 动态跳转至最新穿透地址）或 `"static"`（自定义状态码、Content-Type 与响应体，零后端开销托管 `robots.txt`、维护公告页或验证文件）。
- **请求/响应 Header 增删改与分规则门禁**：支持每条规则独立配置 `request_headers_set`、`request_headers_remove`、`response_headers_set`（如自定义 CORS、HSTS、移除 `X-Frame-Options` 允许内嵌）；支持每条规则独立设置源 CIDR 黑白名单、网关统一前置登录门禁（`auth_gate = true`，直接复用唯一管理员登录会话保护内网无密码服务）、单规则最大上传体积 `max_body_mb` 与长连接读取超时 `read_timeout_secs`。

#### 2. 【M2 4×4 双引擎端口转发】场景自定义
- **多 WAN / 虚拟组网接口定向绑定**：支持指定 `bind_interface`（如仅在异地组网接口 `tailscale0` / `wg0` 或指定 `pppoe-wan2` 上监听）与出站源 IP 绑定。
- **HAProxy Proxy Protocol (`v1` / `v2`) 真实源 IP 透传**：在跨协议栈（如公网 IPv6 转内网 IPv4）使用用户态 `splice()` 转发时，支持开启 `send_proxy_protocol = "v2"`，在首包注入真实公网客户端 IPv4/IPv6 地址后再切入零拷贝管道，使内网 Nginx/游戏服/SSH 审计日志能获取真实访客 IP。
- **多目标主备故障转移与负载均衡**：`targets` 支持配置多个后端地址，可选 `"failover"`（主备自动切换，主节点恢复自动切回）或 `"round_robin"`（轮询分发），内置轻量 TCP/UDP 探测。
- **时间窗开放（Schedule Window）与一键临时开门（Temporary Lease）**：支持按每日时间段（如 `allowed_time_window = "08:00-23:30"`）自动开关端口与防火墙；支持在面板一键开启 **“限时开放 N 分钟”**（例如在外临时开放 SSH 端口 60 分钟，到期自动关闭监听、撤销防火墙规则并清理 `conntrack` 断流）。

#### 3. 【M3 全栈事件驱动 DDNS】场景自定义
- **多源 IP 提取与多前缀精确筛选**：支持在多拨/多前缀环境下通过 `preferred_subnet`（优先匹配指定运营商前缀）或地址索引筛选 IP；子设备 IPv6 支持 `prefix_and_iid`（动态 PD 前缀 + 固定 EUI-64/IID）、`neighbor_mac`（NDP 邻居表 + 持久化历史后缀缓存，防止设备短暂休眠期间丢失解析）及 `custom_http_extract`（从自定义 URL 提取响应中的 IP）。
- **云厂商原生高级参数**：支持 Cloudflare `proxied`（小黄云 CDN 开关）与记录备注；支持阿里云/DNSPod 自定义 `ttl` 与运营商分流线路（`line = "default" | "telecom" | "unicom" | "mobile" | "oversea"`，适配多线多拨路由）。
- **通用自定义 HTTP DDNS 模板（`provider = "custom_http"`）**：支持自定义 HTTP Method、URL 模板、Headers 与 Body 模板（内置 `{{ip}}`, `{{ipv4}}`, `{{ipv6}}`, `{{domain}}`, `{{token}}` 变量替换）及成功响应关键字校验，无需改代码即可对接 Dynv6、DuckDNS、Porkbun 或自建 DNS。

#### 4. 【M4 ACME 证书自动化】场景自定义
- **多 CA 机构切换与 EAB 绑定**：支持切换 Let's Encrypt（生产/Staging 测试环境）、ZeroSSL、Buypass、Google Trust Services 或自定义 ACME Directory URL，支持配置加密保存的 `eab_kid` 与 `eab_hmac_key`。
- **DNS-01 CNAME 挑战别名委派（`challenge_alias_domain`）**：允许将主域名的 `_acme-challenge` CNAME 委派至专用次级域名，路由器仅需持有该专用次级域名的受限 DNS Token 即可安全签发主域名证书，遵循最小权限原则。
- **证书续期后自动部署钩子（Deploy Hooks）**：新证书签发并校验通过后，支持自动将标准 PEM/KEY 同步导出至指定共享目录（供其他容器挂载读取），或调用加密 Webhook 将新证书推送至内网存储/虚拟化主机。

#### 5. 【M5 STUN 穿透】场景自定义
- **免记端口动态重定向联动（Cloudflare Redirect / SRV 同步）**：解决 NAT1 穿透后公网端口随重拨变化的痛点——当探测到穿透 `IP:Port` 变动时，除触发通知外，支持**自动调用 Cloudflare Ruleset API 更新单页重定向规则**（用户访问固定不变的 `https://go.home.example.com` 即可自动 `302/307` 跳转至最新穿透端口），或自动更新 DNS `SRV` / `TXT` 记录。
- **多 STUN 节点容灾与规则直绑**：支持配置多个备选 STUN 服务器自动故障切换；支持直接关联网关内的反向代理或端口转发规则名，自动对齐本地监听端口与防火墙放行策略。

#### 6. 【M6 Web 终端（默认关闭，可选打开）】场景自定义
- **默认关闭与按需动态启用**：`modules.web_terminal` 默认为 `false`（关闭状态下后端零 PTY 句柄分配、前端隐藏菜单且不加载终端 JS 分包）；管理员可在「系统设置 -> 功能模块管理」中按需打开。
- **宿主机与容器多目标切换及安全自定义**：支持选择进入宿主机默认 Shell（自动探测 `/bin/ash` 或 `/bin/sh`）或直接进入指定运行中 Docker 容器的交互式终端；支持自定义默认工作目录 `default_cwd`、最大并发终端会话数 `max_sessions`（默认 `2`）、空闲无操作自动断开时间 `idle_timeout_secs`（默认 `900` 秒即 15 分钟）以及打开终端前是否要求二次验证密码/TOTP（`require_reauth`，默认 `false`）。

#### 7. 【M7 统一通知中心（`[[notifications]]`）与计划任务】场景自定义
- **全局可复用多渠道通知中心**：抽离独立的 `[[notifications]]` 渠道池，原生支持 Bark、Telegram Bot、企业微信/飞书/钉钉群机器人（含 HMAC 加签）、Ntfy/Gotify 及全自定义 HTTP Webhook 模板（自定义 Method、Headers 与 JSON Body 模板变量 `{{event}}`, `{{title}}`, `{{message}}`, `{{severity}}`, `{{timestamp}}`）。支持按事件订阅（DDNS 变更/失败、证书续期、STUN 端口变化、源 IP 封禁、子模块熔断、路由器高内存/高温告警）。
- **Cron 参数化安全动作库**：内置丰富免 Shell 安全动作：① `docker_prune_images`（清理悬空镜像）；② `docker_restart_container`（定时重启指定容器）；③ `rule_toggle`（定时启停指定转发/反代规则）；④ `http_request`（定时触发 Webhook）；⑤ 无 Shell 注入风险的结构化外部程序调用 `exec`（`program` + `args` 数组）。

#### 8. 【M8 系统监控与 M9 Docker 管理】场景自定义
- **M8 监控自定义**：支持自定义重点监控的网卡列表、自定义 SoC 温度传感器 `/sys/class/thermal` 路径、自定义可用内存低水位（如 `MemAvailable < 32 MB`）与高温告警阈值（如 `> 85°C`）及告警冷却时间。
- **M9 Docker 自定义**：支持配置受保护容器名单（默认 `protected_containers = ["vane"]`，禁止在 Web 面板误点停止或删除网关自身容器），支持自定义日志流默认尾行数与时间戳开关。

### 4.3 前端架构（Svelte 5 Runes）、子模块按需关闭、双端响应式与 PWA 支持

前端采用 **Svelte 5 (Runes 细粒度响应式，无 Virtual DOM 开销) + TailwindCSS v4 + 原生 `<svg>` 折线图/雪碧图标 + 构建期 `Brotli (.br)` 预压缩**，核心主包仅 **`~28 KB` (`.br`)**，交互式终端组件拆分为异步按需分包，路由器运行期前端内存分配为 **`0 Byte`**：

1. **子功能模块一键关闭与界面动态收敛（Modular On/Off Switch）**：
   - **三大常驻核心视图**：「概览看板（Dashboard）」、「运行日志（Logs）」、「系统设置（Settings）」作为基础管理底座常驻显示。
   - **八大业务子功能自由启停**：除上述 3 项外，其余所有子功能模块（`reverse_proxy` 反向代理、`port_forward` 端口转发、`ddns` 动态域名、`acme` 自动证书、`stun` 穿透映射、`web_terminal` Web 终端、`cron` 计划任务、`docker` 容器管理）均可在「系统设置 -> 功能模块管理」中一键独立开启或关闭（直接不使用该功能）。
   - **前后端联动真卸载**：当某个子功能被关闭时，① **后端真停用**：`ModuleSupervisor` 立即终止该模块的所有后台协程、关闭监听 Socket、释放内存缓存并同步撤销其关联的防火墙放行规则（历史规则配置保留在 `config.toml` 中不丢失，随时重开即用）；② **前端真清爽**：电脑端左侧导航栏、手机端底部导航栏与概览看板自动隐藏已关闭模块的菜单与状态卡片，零视觉干扰。
2. **现代美观视觉与零门槛操作体验**：
   - **视觉体系**：采用现代高对比度 Bento Grid 卡片布局与微毛玻璃质感，支持 **浅色模式（Light）/ 深色模式（OLED Dark）/ 跟随系统（Auto）** 无闪烁切换；网速、内存水位、IPv4/IPv6 地址与端口号全部启用 `tabular-nums` 等宽数字特性，消除实时刷新时的排版抖动。
   - **操作友好性**：
     - **场景化快捷模板**：新增反代、端口转发、DDNS 时提供“一键场景预设”（如一键配置内网存储 HTTPS 反代、IPv6 子设备直连等），将低频高级参数收纳于折叠抽屉，兼顾新手开箱即用与高玩深度定制；
     - **即时反馈与防呆校验**：支持 CIDR/域名/端口冲突实时预检、Cron 表达式未来 3 次运行时间实时预览、公网 IP/端口一键复制、以及顶部全局状态栏“防火墙一键紧急闭锁”与“未改初始密码强拦截”引导。
3. **电脑端与手机端双端原生级自适应（Desktop & Mobile Responsive）**：
   - **桌面端（`>= 1024px`）**：采用左侧可折叠导航栏 + 顶部双栈/资源状态胶囊栏 + 多列网格视图 + 右侧滑出式配置抽屉。
   - **手机端（`< 768px`）**：自动切换为 **底部单手拇指区悬浮导航栏（Bottom Tab Bar）+ 纵向自适应卡片流（彻底告别移动端表格横向拖拽）+ 底部上滑抽屉式表单（Bottom Sheet）**；所有开关与操作按钮触控热区强制 `>= 44×44px`，并完整适配移动端安全区（`viewport-fit=cover` 与 `env(safe-area-inset-*)`）。
4. **全功能 PWA（Progressive Web App）支持**：
   - **主屏幕独立窗口运行**：支持在 iOS / Android 及桌面浏览器一键“添加到主屏幕 / 安装应用”，以 `display: "standalone"` 隐藏浏览器地址栏独立全屏运行，内嵌极简矢量 SVG 应用图标（`< 8 KB`）。
   - **动态绑定安全路径的 Manifest**：后端根据当前配置的 `secret_path` 动态渲染 `manifest.webmanifest` 的 `start_url` 与 `scope`，确保启用随机安全入口路径后 PWA 快捷方式依然准确直达。
   - **安全优先的 Service Worker (`sw.js`)**：仅对带构建 Hash 的静态 UI 外壳资源（`.js` / `.css` / `.svg`）启用 `Cache-First` 秒开缓存；**所有 `/api/*` 管理接口、认证挑战、配置数据与 SSE/WS 监控流强制执行 `Network-Only`（严禁将任何敏感配置或状态写入浏览器 Cache Storage）**，会话过期（`401`）或登出时立即清空前端状态并跳转登录视图。

---

## 5. 系统架构图与工程目录规划

### 5.1 总体架构与安全舱壁视图

```text
                          公网 IPv4 / IPv6 流量 (WAN: pppoe-wan)
                                            |
+-------------------------------------------v-------------------------------------------+
| [内核层防线] fw4 (table inet fw4 钩子链) / fw3 (iptables-legacy & ip6tables-legacy)   |
|  1. Prerouting/Input 前置黑名单集合 (IPv4 /32 + IPv6 /64 带超时直接 DROP + 删 Conntrack)|
|  2. 仅对已成功监听的协议栈与完整 /128 子设备地址精准放行 (启动预清扫 + 停止自动清表)    |
+-------------------------------------------+-------------------------------------------+
                                            |
+-------------------------------------------v-------------------------------------------+
| [接入护盾层] 双栈独立监听器 (0.0.0.0 + [::] V6ONLY) + 全局并发连接配额 (Global Quota)  |
|  • 5s 握手超时  • 严格 SNI 拒连  • Host/:authority 校验与 Header 清洗  • 全程 HTTPS    |
+-------------------------------------------+-------------------------------------------+
                                            |
+-------------------------------------------v-------------------------------------------+
| [舱壁监督层] ModuleSupervisor (panic="unwind" + 滑动窗口退避 + 300s 半开探测自愈)      |
+-------+---------------+---------------+---------------+---------------+---------------+
        |               |               |               |               |
        v               v               v               v               v
  [M1.流式反代]    [M2.双引擎转发]  [M3/M4.DDNS+ACME] [M5/M7.STUN/Cron] [M6/M8/M9.终端/监控/Docker]
  4<->6 全互通     TCP: 受限 splice  先订阅后 Dump     完整报文头校验    默认内置 HTTPS 面板
  16KB 零缓冲窗口  UDP: PKTINFO代理  剔除无效/旧前缀v6  NAT 类型探测      Web终端默认关闭按需打开
  单规则连接配额   同栈可选内核DNAT  RFC8305 双栈竞速  进程组超时回收    Ed25519/TOTP 强认证
```

### 5.2 工程目录结构 (`vane`)

```text
vane/
├── Cargo.toml                 # 严控依赖树、panic="unwind" 舱壁保障与 LTO 体积优化
├── Cargo.lock                 # 锁定精确依赖版本确保可复现构建
├── build.rs                   # 校验前端预压缩产物 (.br / .gz) 与完整性
├── Dockerfile                 # 多阶段镜像构建 (内置未压缩二进制 + legacy/nft 双栈工具链)
├── docker-compose.example.yml # 外挂 U 盘 Docker 命名卷 + cap_drop:[ALL] 最小权限模板
├── config.example.toml        # 双栈、安全基线与全模块配置模板 (100% 语法合规)
├── web-ui/                    # 响应式前端工程 (Svelte 5 Runes + Tailwind v4 + 原生 SVG + PWA)
└── src/
    ├── main.rs                # CLI (run / service install / firewall lockdown / auth reset / check)
    ├── supervisor.rs          # 模块监督器 (spawn 内包裹 factory、&mut handle 等待回收、半开熔断)
    ├── config.rs              # 配置校验、0600 原子落盘 (含父目录 fsync) 与特权锁守卫
    ├── logger.rs              # 定长 300 条环形内存日志 (严禁写入明文敏感凭据)
    ├── firewall/
    │   ├── mod.rs             # 后端自动探测器、异步超时命令执行器、Conntrack 断流与启动预清扫
    │   ├── nftables.rs        # OpenWrt fw4 (input_wan / forward_wan / dstnat_wan) 规则链驱动
    │   └── iptables.rs        # OpenWrt fw3 (legacy/nft 自动适配) 双栈独立子链驱动
    ├── security/
    │   ├── auth.rs            # PBKDF2(spawn_blocking)、单调水位 TOTP、SSH-Ed25519 绑定挑战验签
    │   └── fail2ban.rs        # IPv4 /32 与 IPv6 /64 归一化定长 LRU 封禁表 + 内核封禁联动
    ├── net/
    │   ├── dual_stack.rs      # 双栈独立容错绑定器、PKTINFO UDP 套接字与 RFC8305 Happy Eyeballs
    │   ├── listener.rs        # 全局配额守卫、握手超时 + 单端口 HTTP->HTTPS 首字节嗅探器
    │   ├── tls_resolver.rs    # Rustls 严格 SNI 证书池 + 管理端自签/ACME 证书管理 + ArcSwap
    │   ├── reverse_proxy.rs   # 4x4 双栈流式反代、Forwarded/Host 严格校验、WebSocket Ticket 守卫
    │   ├── port_forward.rs    # 内核 DNAT 调度 + TCP 受限 splice() + UDP PKTINFO 会话代理
    │   └── stun.rs            # RFC5389/5780 UDP/TCP 映射探测状态机
    ├── daemon/
    │   ├── netlink_ip.rs      # 先订阅后 Dump 零竞态地址/路由/邻居监听与有效 IPv6 筛选
    │   ├── dns_provider.rs    # 复用 hyper+rustls 的双栈 DNS 接口与 TXT 记录事务管理
    │   ├── ddns.rs            # 子设备 /128 IPv6 合成 + 防火墙 /128 集合原子同步
    │   ├── acme.rs            # 自定义 HttpClient 桥接 instant-acme 与证书链校验落盘
    │   └── cron.rs            # 内置安全任务与结构化外部命令执行器 (进程组超时 SIGKILL + wait)
    ├── monitor/
    │   └── procfs.rs          # 按需采样系统指标与 Top VmRSS 进程榜
    ├── docker/
    │   └── unix_client.rs     # 运维白名单过滤、Socket inode 重建自愈式 /var/run/docker.sock 客户端
    └── web/
        ├── mod.rs             # 全程 HTTPS、Host/Origin 校验、.rodata 静态 .br/.gz 零拷贝分发
        └── ws_pty.rs          # Web 终端开关守卫 (默认关闭) + openpty 进程组生命周期与超时回收
```

---

## 6. `Cargo.toml` 依赖裁剪与高可用编译配置

```toml
[package]
name = "vane"
version = "0.1.0"
edition = "2021"

[features]
default = ["docker", "pty", "stun", "mimalloc-alloc"]
docker = []
pty = []
stun = []
mimalloc-alloc = ["dep:mimalloc"]

[dependencies]
tokio = { version = "1.43", features = ["rt-multi-thread", "net", "io-util", "time", "process", "sync", "macros", "signal", "fs"] }

# 全模块共享单一流式 HTTP 底座
axum = { version = "0.8", default-features = false, features = ["http1", "http2", "json", "ws", "tokio", "query"] }
hyper = { version = "1.6", features = ["client", "server", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["tokio", "client-legacy", "server-auto"] }
http-body-util = "0.1"
bytes = "1.9"

# 纯 Rust TLS、ACME 与密码学原语
# 注：instant-acme 仅启用 ring，通过实现其 HttpClient trait 直接复用上方 hyper + tokio-rustls 双栈客户端
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12"] }
rustls-pemfile = "2.2"
rustls-native-certs = "0.8"
webpki-roots = "0.26"          # 当固件缺失 /etc/ssl/certs 时作为可信根证书兜底，杜绝空根或跳过验证
ring = "0.17"
instant-acme = { version = "0.7", default-features = false, features = ["ring"] }
rcgen = { version = "0.13", default-features = false, features = ["ring", "pem"] }

# 底层系统调用与双栈 Socket 精细控制 (IPV6_V6ONLY, IP_PKTINFO, Netlink, splice, F_SETPIPE_SZ, openpty)
libc = "0.2"
socket2 = { version = "0.5", features = ["all"] }

# 静态前端嵌入与无锁原子状态替换
rust-embed = { version = "8.5", default-features = false }
arc-swap = "1.7"
mimalloc = { version = "0.1", default-features = false, optional = true }

serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

[profile.release]
opt-level = "z"          # 极限代码体积优化
lto = "fat"              # 跨库全局死代码消除
codegen-units = 1        # 单编译单元最大化优化
# 保留 unwind 表确保单个子任务意外 panic 被 tokio::spawn 捕获隔离，并在 CI 中执行真机/QEMU panic 回归测试
panic = "unwind"
strip = "symbols"        # 剥离符号表与调试段
```

---

## 7. 核心架构底线代码实现蓝图（已通过编译借用与安全边界核验）

### 7.1 子模块故障舱壁监督器：修复 `JoinHandle` 借用与半开熔断 (`src/supervisor.rs`)
- **修复 P0-01**：使用 `let mut handle = tokio::spawn(...)` 并在 `tokio::select!` 中通过 `res = &mut handle` 轮询，取消分支执行 `handle.abort(); let _ = (&mut handle).await;` 确保完整回收；
- **修复 P1-02 / P1-03**：将工厂调用放入 `tokio::spawn` 内部捕获同步 Panic，采用 60 秒滑动时间窗计数，并在 `CircuitOpen` 后支持 300 秒周期的半开探测自愈：

```rust
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub enum ModuleHealth {
    Running,
    Degraded { reason: String, retry_in_secs: u64 },
    CircuitOpen { last_error: String, probe_in_secs: u64 },
    Stopped,
}

pub async fn supervise_module<F, Fut>(
    module_name: &'static str,
    mut shutdown_rx: watch::Receiver<bool>,
    health_tx: watch::Sender<ModuleHealth>,
    task_factory: Arc<F>,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let mut failure_times: VecDeque<Instant> = VecDeque::with_capacity(6);

    loop {
        if *shutdown_rx.borrow() {
            let _ = health_tx.send(ModuleHealth::Stopped);
            break;
        }

        let _ = health_tx.send(ModuleHealth::Running);
        let factory = Arc::clone(&task_factory);
        // 在 spawn 内部调用 factory()，确保初始化阶段的同步 panic 同样被 Tokio 捕获边界拦截
        let mut handle = tokio::spawn(async move { factory().await });

        let outcome = tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    handle.abort();
                    let _ = (&mut handle).await; // 等待任务取消落定并释放资源
                    let _ = health_tx.send(ModuleHealth::Stopped);
                    break;
                }
                continue;
            }
            res = &mut handle => res,
        };

        let err_msg = match outcome {
            Ok(Ok(())) => {
                let _ = health_tx.send(ModuleHealth::Stopped);
                break;
            }
            Ok(Err(e)) => format!("[{}] 模块运行异常: {}", module_name, e),
            Err(join_err) if join_err.is_panic() => {
                format!("[{}] 捕获子任务 Panic (已隔离，未影响其他模块)", module_name)
            }
            Err(_) => {
                let _ = health_tx.send(ModuleHealth::Stopped);
                break;
            }
        };

        // 维护 60 秒滑动时间窗内的失败时间戳
        let now = Instant::now();
        while failure_times.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) {
            failure_times.pop_front();
        }
        failure_times.push_back(now);

        // 60 秒内连续异常满 5 次进入半开熔断（每 300s 探测一次，兼顾防死循环与外部依赖自愈）
        let wait_secs = if failure_times.len() >= 5 {
            let _ = health_tx.send(ModuleHealth::CircuitOpen {
                last_error: err_msg,
                probe_in_secs: 300,
            });
            300
        } else {
            let backoff = match failure_times.len() {
                1 => 1,
                2 => 2,
                3 => 5,
                _ => 30,
            };
            let _ = health_tx.send(ModuleHealth::Degraded {
                reason: err_msg,
                retry_in_secs: backoff,
            });
            backoff
        };

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = health_tx.send(ModuleHealth::Stopped);
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
        }
    }
}
```

### 7.2 双向容错双栈绑定器与双栈源地址归一化封禁 (`src/net/dual_stack.rs` & `src/security/fail2ban.rs`)
- **修复 P1-04 / P1-05**：分别独立尝试 IPv4 与 IPv6 绑定（IPv4 失败不短路 IPv6），禁止 `port == 0`，返回实际成功的协议栈供防火墙精确开门；支持显式绑定指定局域网 IP（用于管理后台隔离）：

```rust
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackMode {
    Dual,
    Ipv4Only,
    Ipv6Only,
}

pub struct BoundListeners {
    pub v4: Option<TcpListener>,
    pub v6: Option<TcpListener>,
}

/// 在已激活的 Tokio Runtime 中绑定双栈独立监听器（互不短路，至少一栈成功即可工作）
pub fn bind_dual_stack_tcp(port: u16, mode: StackMode) -> io::Result<BoundListeners> {
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "禁止使用动态 0 端口"));
    }

    let v4_res = if mode == StackMode::Dual || mode == StackMode::Ipv4Only {
        Some(bind_one(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), false))
    } else {
        None
    };

    let v6_res = if mode == StackMode::Dual || mode == StackMode::Ipv6Only {
        Some(bind_one(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port), true))
    } else {
        None
    };

    let v4 = match v4_res {
        Some(Ok(l)) => Some(l),
        Some(Err(e)) if mode == StackMode::Ipv4Only => return Err(e),
        Some(Err(_)) => None,
        None => None,
    };

    let v6 = match v6_res {
        Some(Ok(l)) => Some(l),
        Some(Err(e)) if mode == StackMode::Ipv6Only => return Err(e),
        Some(Err(_)) => None,
        None => None,
    };

    if v4.is_none() && v6.is_none() {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 与 IPv6 监听均绑定失败"));
    }
    Ok(BoundListeners { v4, v6 })
}

fn bind_one(addr: SocketAddr, only_v6: bool) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if only_v6 {
        sock.set_only_v6(true)?; // 强制 IPV6_V6ONLY，彻底剥离 v4-mapped 地址歧义
    }
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(512)?;
    TcpListener::from_std(sock.into())
}

/// 防爆破限流键：还原 IPv4-mapped 地址，并对公网 IPv6 聚合至 /64 子网前缀
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BanKey {
    V4(Ipv4Addr),
    V6Prefix64(u64),
}

impl BanKey {
    pub fn from_peer(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    Self::V4(mapped_v4)
                } else {
                    let octets = v6.octets();
                    let prefix64 = u64::from_be_bytes([
                        octets[0], octets[1], octets[2], octets[3],
                        octets[4], octets[5], octets[6], octets[7],
                    ]);
                    Self::V6Prefix64(prefix64)
                }
            }
        }
    }
}
```

### 7.3 异步非阻塞防火墙执行器与本机高危端口守卫 (`src/firewall/mod.rs`)
- **修复 P1-01**：使用异步 `tokio::process::Command` + `kill_on_drop(true)` + 5 秒硬超时，绝不阻塞 Tokio 工作线程；
- **修复 P2-06**：明确 `PROTECTED_LOCAL_INPUT_PORTS` 仅拦截直接暴露路由器本机 `INPUT` 的操作，不影响 `FORWARD` 到内网独立 NAS IP 的规则：

```rust
use std::time::Duration;
use tokio::process::Command;

/// 严禁向公网 WAN INPUT 直接暴露的路由器本机系统端口硬黑名单
pub const PROTECTED_LOCAL_INPUT_PORTS: &[u16] = &[
    21, 22, 23, 53, 67, 68, 80, 139, 443, 445, 1883, 2375, 2376, 4000, 6379,
];

pub fn validate_wan_input_port(port: u16, admin_port: u16, wan_iface: &str) -> Result<(), String> {
    if port == admin_port || PROTECTED_LOCAL_INPUT_PORTS.contains(&port) {
        return Err(format!("安全底线拦截：禁止向 WAN INPUT 直接开放路由器本机受保护端口 {}", port));
    }
    validate_iface_name(wan_iface)
}

pub fn validate_iface_name(iface: &str) -> Result<(), String> {
    if iface.is_empty()
        || iface.len() > 15
        || !iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err("非法网卡接口名称，拒绝执行防火墙操作".into());
    }
    Ok(())
}

/// 异步零 Shell 注入执行器：带 5s 硬超时与 kill_on_drop，绝不卡死异步运行时
pub async fn run_fw_cmd_async(bin: &str, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args).kill_on_drop(true);

    let status = tokio::time::timeout(Duration::from_secs(5), cmd.status())
        .await
        .map_err(|_| format!("执行 {} 超时 (5s)，已中止子进程", bin))?
        .map_err(|e| format!("启动 {} 失败: {}", bin, e))?;

    if status.success() {
        Ok(())
    } else {
### 7.4 单管理员多模态强认证：初始密码硬拦截 + 防重放 TOTP + Ed25519 挑战验签 (`src/security/auth.rs`)
- **单管理员模型与强制改密硬门禁**：内置 `DEFAULT_INITIAL_PASSWORD = b"admin321"` 检测，若当前密码仍为初始密码则强制锁定会话为 `SessionScope::MustChangePassword`（后端路由中间件拦截除改密外的一切管理接口），改密时校验实用型强密码规则（`>= 8` 位 + 必含英文字母 + 含数字或特殊符号之一）且拒绝与初始密码相同；
- **修复 P0-03 / P0-05 / P1-20**：TOTP 采用单调递增步长水位线 `step <= last_accepted`；Ed25519 挑战绑定 `(nonce, key_id, client_ban_key)` 与服务端 `canonical_origin`：

```rust
use crate::net::dual_stack::BanKey;
use ring::{constant_time, hmac, pbkdf2, rand::SecureRandom, signature};
use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

pub const DEFAULT_INITIAL_PASSWORD: &[u8] = b"admin321";
const CHALLENGE_POOL_CAP: usize = 64;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// 登录会话权限作用域：未修改初始密码前强制锁死在 MustChangePassword，禁止进入任何管理页面 API
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionScope {
    MustChangePassword,
    FullAdmin,
}

pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub key_id: String,
    pub client_key: BanKey,
    pub issued_at: Instant,
}

pub struct AuthEngine {
    challenges: VecDeque<PendingChallenge>,
    last_totp_step: Option<u64>, // 严格单调递增水位线：拒绝任何 <= last_totp_step 的动态码
    canonical_origin: String,    // 服务端固定受信 Origin，绝不采信客户端自报 Host
}

impl AuthEngine {
    pub fn new(canonical_origin: String) -> Self {
        Self {
            challenges: VecDeque::with_capacity(CHALLENGE_POOL_CAP),
            last_totp_step: None,
            canonical_origin,
        }
    }

    /// 1. 恒定时间 PBKDF2-HMAC-SHA256 校验（调用方置于受 Semaphore(1) 保护的 spawn_blocking 中执行）
    pub fn verify_password(password: &[u8], salt: &[u8], expected_hash: &[u8], iters: u32) -> bool {
        if password.is_empty() || password.len() > 256 || salt.len() < 16 || iters < 100_000 {
            return false;
        }
        let Some(n) = NonZeroU32::new(iters) else { return false };
        pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, password, expected_hash).is_ok()
    }

    /// 判定当前密码是否仍为初始默认密码，决定签发受限改密会话还是完整管理会话
    pub fn resolve_session_scope(
        must_change_flag: bool,
        current_salt: &[u8],
        current_hash: &[u8],
        iters: u32,
    ) -> SessionScope {
        if must_change_flag
            || Self::verify_password(DEFAULT_INITIAL_PASSWORD, current_salt, current_hash, iters)
        {
            SessionScope::MustChangePassword
        } else {
            SessionScope::FullAdmin
        }
    }

    /// 强制改密校验：最少 8 位 + 必须含英文字母 + 至少含数字或特殊字符之一，且严禁与初始密码/旧密码相同
    pub fn validate_new_password(
        new_password: &[u8],
        username: &[u8],
        current_salt: &[u8],
        current_hash: &[u8],
        iters: u32,
    ) -> Result<(), &'static str> {
        if new_password.len() < 8 || new_password.len() > 128 {
            return Err("新密码长度必须在 8 ~ 128 位之间");
        }
        let has_letter = new_password.iter().any(|b| b.is_ascii_alphabetic());
        let has_digit_or_symbol = new_password
            .iter()
            .any(|b| b.is_ascii_digit() || b.is_ascii_punctuation());
        if !has_letter || !has_digit_or_symbol {
            return Err("密码需包含英文字母，且至少包含数字或特殊字符中的一种");
        }
        if constant_time::verify_slices_are_equal(new_password, DEFAULT_INITIAL_PASSWORD).is_ok() {
            return Err("新密码不能与初始默认密码 (admin321) 相同");
        }
        if constant_time::verify_slices_are_equal(new_password, username).is_ok() {
            return Err("新密码不能与用户名相同");
        }
        if Self::verify_password(new_password, current_salt, current_hash, iters) {
            return Err("新密码不能与当前正在使用的密码相同");
        }
        Ok(())
    }

    /// 2. RFC 6238 TOTP 校验（±1 步长容错 + 严格单调递增水位防回退重放）
    pub fn verify_totp(&mut self, secret: &[u8], code: u32, unix_now: u64) -> bool {
        let current_step = unix_now / 30;
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);

        for step in [current_step.saturating_sub(1), current_step, current_step + 1] {
            if self.last_totp_step.is_some_and(|last| step <= last) {
                continue;
            }
            let tag = hmac::sign(&key, &step.to_be_bytes());
            let bytes = tag.as_ref();
            let offset = (bytes[19] & 0x0f) as usize;
            let bin_code = u32::from_be_bytes([
                bytes[offset] & 0x7f,
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) % 1_000_000;

            if constant_time::verify_slices_are_equal(&bin_code.to_be_bytes(), &code.to_be_bytes()).is_ok() {
                self.last_totp_step = Some(step);
                return true;
            }
        }
        false
    }

    /// 3. 签发绑定上下文的一次性挑战（单管理员模型，按源 IP 限速）
    pub fn issue_challenge(
        &mut self,
        rng: &dyn SecureRandom,
        key_id: String,
        client_key: BanKey,
    ) -> Result<[u8; 32], &'static str> {
        while self.challenges.front().is_some_and(|c| c.issued_at.elapsed() > CHALLENGE_TTL) {
            self.challenges.pop_front();
        }
        if self.challenges.len() >= CHALLENGE_POOL_CAP {
            return Err("当前并发挑战过多，请稍后重试");
        }
        if self.challenges.iter().filter(|c| c.client_key == client_key).count() >= 3 {
            return Err("同一网络请求过于频繁");
        }

        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).map_err(|_| "硬件随机源生成失败")?;
        self.challenges.push_back(PendingChallenge {
            nonce,
            key_id,
            client_key,
            issued_at: Instant::now(),
        });
        Ok(nonce)
    }

    /// 4. 原子消费挑战并校验 Ed25519 签名（强制绑定 KeyID、源网络与服务端 Origin）
    pub fn verify_ed25519_challenge(
        &mut self,
        nonce: &[u8; 32],
        key_id: &str,
        client_key: BanKey,
        sig: &[u8],
        raw_ed25519_pubkey: &[u8; 32],
    ) -> bool {
        let Some(pos) = self.challenges.iter().position(|c| {
            c.issued_at.elapsed() <= CHALLENGE_TTL
                && c.client_key == client_key
                && c.key_id == key_id
                && constant_time::verify_slices_are_equal(&c.nonce, nonce).is_ok()
        }) else {
            return false;
        };
        self.challenges.remove(pos);

        // 带域分隔符的签名原文：vane-ed25519-auth-v1|<nonce>|<key_id>|<canonical_origin>
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(b"vane-ed25519-auth-v1|");
        msg.extend_from_slice(nonce);
        msg.push(b'|');
        msg.extend_from_slice(key_id.as_bytes());
        msg.push(b'|');
        msg.extend_from_slice(self.canonical_origin.as_bytes());

        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, raw_ed25519_pubkey);
        pk.verify(&msg, sig).is_ok()
    }
}

/// 从 OpenSSH ssh-ed25519 公钥 Wire Format 解码字节中提取精确的 32B 原始公钥
pub fn extract_ed25519_from_ssh_wire(wire_bytes: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
    if wire_bytes.len() == 51 && wire_bytes.starts_with(PREFIX) {
        let mut out = [0u8; 32];
        out.copy_from_slice(&wire_bytes[19..51]);
        Some(out)
    } else {
        None
    }
}
```
    } else {
        None
    }
}
```

### 7.5 掉电一致性原子落盘（含 `0600` 权限收紧与父目录 `fsync`，`src/config.rs`）
- **修复 P1-15**：临时文件采用 `OpenOptionsExt::mode(0o600)` + `create_new(true)`，在 `rename` 完成后打开父目录执行 `sync_all()`，确保目录项（dentry）在突发断电后 100% 落入闪存：

```rust
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn crash_safe_atomic_write(target: &Path, data: &[u8], pid_nonce: u64) -> std::io::Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target.file_name().and_then(|s| s.to_str()).unwrap_or("config.toml");
    let tmp_path = parent.join(format!(".{}.{}.tmp", file_name, pid_nonce));
    let bak_path = target.with_extension("bak");

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?; // 1. 刷入文件内容与 inode
    }

    if target.exists() {
        let _ = fs::copy(target, &bak_path);
        let _ = fs::set_permissions(&bak_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp_path, target)?; // 2. 原子替换目录项
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;

    // 3. 关键掉电保护：对父目录执行 fsync，确保 rename 后的目录项持久写入 NAND Flash
    if let Ok(dir_fd) = File::open(parent) {
        let _ = dir_fd.sync_all();
    }
    Ok(())
}
```

### 7.6 敏感数据信封加密、脱敏读取与跨机备份恢复 (`src/security/vault.rs`)

针对路由器“既要断电重启无人值守拉起服务，又要防止 `config.toml`、API 接口或备份文件泄露云厂商 Token 与私钥”的核心诉求，全系统复用 `ring`（`aead::CHACHA20_POLY1305` + `hkdf` + `pbkdf2`，**零额外依赖**）实现全生命周期机密管理：

#### 1. 敏感数据四级分类与存储策略
| 敏感数据分级 | 包含字段 | 落盘存储格式 | 安全保障机制 |
| :--- | :--- | :--- | :--- |
| **L1：单向认证哈希 / 公钥** | `password_hash`, `totp_recovery_hashes`, `authorized_ed25519_keys` | `pbkdf2-sha256$100000$<salt>$<hash>` 或原始公钥 | **不可逆**：服务端无需也无法还原明文口令或私钥。 |
| **L2：运行时可逆机密** | DNS `api_token` / `secret_key`, `totp_secret`, `webhook_url` | `enc:v1:<base64(nonce_12B \|\| ciphertext \|\| tag_16B)>` | **字段级 AEAD 信封加密**：使用 `ChaCha20-Poly1305` 加密，并将字段路径（如 `dns_providers.cf_home.api_token`）作为 **AAD（附加认证数据）** 绑定，严防跨字段剪贴替换攻击（例如将 `totp_secret` 密文复制到 `webhook_url` 触发外发泄密）。 |
| **L3：TLS 与 ACME 私钥** | `certs/*.key`, `acme_account.key` | `0700` 目录下 `0600` 文件，支持可选 `enc:v1:` 封装 | 启动或续期时在内存中解密构建 `rustls::sign::CertifiedKey`，运行期无需反复读盘。 |
| **L4：初始默认密码锁** | `must_change_password = true` | 布尔状态 + 初始密码哈希校验 | 初次部署默认账密为 `admin` / `admin321`；未完成改密或密码仍与 `admin321` 相同时，后端路由中间件硬性拦截除改密外的一切管理 API。 |

#### 2. 主密钥派生、自动加封（Auto-Seal）与 API 脱敏读取流程
1. **主密钥（Master Key）分离与派生**：
   - 首次初始化时通过硬件随机源生成 32 字节根密钥存于 `/data/vane/.master.key`（权限 `0400`；Docker 部署支持通过环境变量 `VANE_MASTER_KEY` 或 Docker Secret 注入），经 `HKDF-SHA256` 派生 256-bit 数据加密密钥（DEK）。
   - **手写明文自动加封（Auto-Seal）**：若管理员通过 SSH 手动在 `config.toml` 中填写了明文 `api_token = "cf_live_xxx"`，`vane` 加载时检测到无 `enc:v1:` 前缀，自动在内存中加密为 `enc:v1:...` 并通过掉电安全原子写更新回 `config.toml`，消除磁盘明文残留。
2. **Web 设置页“只进不出”脱敏读写协议（Never Echo Secrets）**：
   - **读取（`GET /api/settings`）**：后端绝不向浏览器返回任何明文或 `enc:v1:` 密文，统一转换为脱敏状态对象 `{ "configured": true, "masked": "cf_****...8f2a" }`。
   - **保存（`PUT /api/settings`）**：前端未改动某敏感输入框时提交占位符 `"__UNCHANGED__"`，后端直接保留原密文；仅当管理员输入新值时才重新执行 AEAD 加密并原子落盘。
   - **内存擦除（Zeroize on Drop）**：解密后的明文 Token 在内存中封装于 `SecretBytes`，用毕销毁时调用 `std::ptr::write_volatile` 逐字节清零，且禁止 `Debug / Display` 打印。

#### 3. 跨设备备份导出与恢复闭环（`.vane.bak` 加密归档）
由于 `config.toml` 内的 `enc:v1:` 密文绑定了原路由器的 `.master.key`，直接拷贝单文件到新路由器无法解密 L2 机密。因此内置标准备份恢复流：
- **导出备份（Web 设置页 / CLI `vane config export`）**：
  - **模式 A（全量加密备份，用于迁移/容灾）**：管理员设置一次性备份密码（`>= 8` 位），后端在内存中用本机 DEK 解密所有 L2/L3 机密，连同全部规则与 `certs/` 证书打包，再用 **备份密码 + 16B 随机 Salt 经 `PBKDF2-HMAC-SHA256` (200,000 次迭代) 派生归档密钥，通过 `ChaCha20-Poly1305` 整包加密** 输出为 `vane-backup-YYYYMMDD.vane.bak`。
  - **模式 B（脱敏排障导出，用于开源社区提 Issue）**：一键剔除所有 Token、哈希与私钥，仅导出纯配置骨架。
- **导入恢复（Web 设置页 / CLI `vane config import`）**：
  - 校验备份密码与 AEAD 完整性标签通过后，自动用**当前目标机器自身的 `.master.key`** 将所有 L2/L3 机密重新加密为新的 `enc:v1:...`，执行掉电安全原子落盘并触发 `ArcSwap` 无缝热重载。

```rust
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;

/// 字段级 ChaCha20-Poly1305 信封加密：绑定字段路径作为 AAD 防止跨字段密文替换攻击
pub fn seal_field(
    dek: &[u8; 32],
    field_path: &str,
    plaintext: &[u8],
    rng: &dyn SecureRandom,
) -> Result<Vec<u8>, &'static str> {
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| "Nonce 生成失败")?;

    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, dek).map_err(|_| "无效密钥")?;
    let key = LessSafeKey::new(unbound);

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(plaintext);

    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(field_path.as_bytes()),
        &mut out[12..],
    )
    .map_err(|_| "AEAD 加密失败")?;
    Ok(out)
}

pub fn open_field(
    dek: &[u8; 32],
    field_path: &str,
    sealed_nonce_and_cipher: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if sealed_nonce_and_cipher.len() < 12 + 16 {
        return Err("密文长度不足");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&sealed_nonce_and_cipher[..12]);
    let mut buf = sealed_nonce_and_cipher[12..].to_vec();

    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, dek).map_err(|_| "无效密钥")?;
    let key = LessSafeKey::new(unbound);

    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(field_path.as_bytes()),
            &mut buf,
        )
        .map_err(|_| "AEAD 解密或 AAD 字段路径校验失败")?;
    let plain_len = plain.len();
    buf.truncate(plain_len);
    Ok(buf)
}
```

---

## 8. 双轨打包矩阵与多形态部署方案（宿主机 `/data` vs 外挂 U 盘 Docker）

### 8.1 产物分类与选型对照表

| 产物名称 / 形态 | 文件 / 镜像体积 | 日常用户态 `VmRSS` 目标 | 核心特性与推荐适用场景 |
| :--- | :--- | :--- | :--- |
| **1. 原生标准版**<br>`vane-aarch64-musl` | `~2.8 - 3.6 MB` | **`6.0 ~ 8.5 MB`**<br>（最低内存） | 保留 Linux ELF 按需分页（Demand Paging），未访问模块不占 RAM 且冷代码页可被内核回收。<br>**适合**：板载 `/data` 剩余 `>= 10 MB`，或直接放入外挂 U 盘由宿主机拉起。 |
| **2. 极限压缩版 (UPX)**<br>`vane-aarch64-musl-upx` | **`~1.0 - 1.3 MB`**<br>（最小单文件） | `9.0 ~ 12.0 MB`<br>（代码段解压至匿名页） | 启动时自解压至匿名内存常驻，换取最小二进制体积。<br>**适合**：板载 `/data` 剩余空间较小（**建议至少预留 `>= 4 MB` 余量**以容纳配置备份与原子更新临时文件），且要求脱离外置 U 盘独立自愈运行。 |
| **3. Docker 全功能镜像**<br>`vane:latest` (Alpine 微底座) | 拉取压缩 `~4.5 MB`<br>展开约 `~14 MB`<br>*(存于 U 盘，**板载 0 KB**)* | `6.5 ~ 8.5 MB`<br>*(+ `shim` ~2.5MB)* | **内嵌原生未压缩二进制**（省 RAM），同时打包 `nftables` + `iptables` + **`iptables-legacy`** + CA 证书。<br>**适合**：已开启外挂 U 盘 Docker，希望**板载零占用**并完整兼容传统内核 `fw3 (legacy)` 与新内核 `fw4 (nft)`。 |
| **4. Docker 极简网关镜像**<br>`vane:slim` (仅含二进制与 CA) | `~3.8 MB`<br>*(存于 U 盘，**板载 0 KB**)* | `6.0 ~ 8.0 MB`<br>*(+ `shim` ~2.5MB)* | 不含外部 Shell 与防火墙 CLI（自动禁用宿主机防火墙代管、自定义 Shell Cron 与宿主机 PTY）。<br>**适合**：仅需反向代理、DDNS、ACME 与用户态端口转发的最小权限场景。 |

### 8.2 宿主机可复现交叉编译与双轨打包脚本

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. 准备固定工具链与输出目录
mkdir -p dist
rustup toolchain install nightly-2025-02-01 --component rust-src
rustup target add aarch64-unknown-linux-musl --toolchain nightly-2025-02-01

# 2. 构建前端并生成 .gz 预压缩静态包（原生版与 UPX 版共用同一套静态资源协议）
cd web-ui && npm ci && npm run build && cd ..

# 3. 编译【类别一：原生标准版】（使用 --locked 锁定依赖，保留默认 panic-unwind 特性）
cargo +nightly-2025-02-01 zigbuild --release --locked \
  -Z build-std=std,panic_unwind \
  --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/vane dist/vane-aarch64-musl

# 4. 打包【类别二：UPX 极限压缩版】并输出 SHA256 校验和
upx --best --lzma -o dist/vane-aarch64-musl-upx dist/vane-aarch64-musl
shasum -a 256 dist/vane-aarch64-musl* > dist/SHA256SUMS
ls -lh dist/
```

### 8.3 部署方式一：板载 `/data` 原生 `procd` 自愈部署（单实例锁与信号闭环）

执行 `/data/vane/vane service install` 生成 `0700` 引导脚本 `/data/vane/boot_hook.sh` 并注册至 `/etc/config/firewall`（避免使用不安全的 `pidof` 多 PID 拼接，统一通过 `procd` 原生接口管理状态与信号）：

```sh
#!/bin/sh
INIT_SCRIPT="/etc/init.d/vane"

# 1. 若系统 OTA 升级清空了 /etc/init.d/vane，自动幂等重建 procd 服务
if [ ! -x "$INIT_SCRIPT" ]; then
    cat << 'EOF' > "$INIT_SCRIPT"
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance "vane"
    procd_set_param command /data/vane/vane run -c /data/vane/config.toml
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="65535 65535"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

reload_service() {
    # 发送 SIGHUP 通知主进程重校验防火墙自定义链与热重载配置（主进程已注册 SIGHUP handler）
    procd_send_signal vane vane HUP 2>/dev/null || true
}

stop_service() {
    # 守护停止后兜底执行防火墙紧急清理与 Conntrack 断流
    /data/vane/vane firewall lockdown 2>/dev/null || true
}
EOF
    chmod 0755 "$INIT_SCRIPT"
    "$INIT_SCRIPT" enable
fi

# 2. 通过 procd 状态判断：未运行则启动，已运行则触发 reload 同步防火墙链
if "$INIT_SCRIPT" running >/dev/null 2>&1; then
    "$INIT_SCRIPT" reload
else
    "$INIT_SCRIPT" start
fi
```

### 8.4 部署方式二：外置存储 Docker 容器化部署（兼容 `fw3 legacy` / `fw4 nft` + 最小权限）

#### 1. 兼容 `legacy` 与 `nft` 双后端的 `Dockerfile`
```dockerfile
FROM --platform=linux/arm64 alpine:3.21 AS runtime
# 关键修复：Alpine 3.21 的 iptables 主包默认为 nft 后端；必须显式安装 iptables-legacy
# 以兼容传统 OpenWrt fw3 (Linux 4.x/5.x legacy xtables) 与 fw4 (nf_tables) 双环境
RUN apk add --no-cache ca-certificates tzdata nftables iptables iptables-legacy ip6tables
COPY dist/vane-aarch64-musl /usr/local/bin/vane
ENTRYPOINT ["/usr/local/bin/vane"]
CMD ["run", "-c", "/data/vane/config.toml"]
```

#### 2. 路由器 `docker-compose.yml` 标准模板（`cap_drop: [ALL]` + 命名卷防漂移）
```yaml
services:
  vane:
    image: ghcr.io/vane-project/vane:latest
    container_name: vane
    restart: unless-stopped
    network_mode: host

    # 安全底线：先剥离 Docker 默认赋予的所有 root Capabilities，再仅添加网关必需的 2 项网络能力！
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN          # 管理宿主机 nftables / iptables-legacy / ip6tables-legacy 与 Conntrack
      - NET_BIND_SERVICE   # 允许绑定 1024 以下端口（如按需转发）
    security_opt:
      - no-new-privileges:true
    read_only: true        # 容器根文件系统设为只读，防运行时篡改二进制
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=4m

    stop_grace_period: 10s
    ulimits:
      nofile:
        soft: 65535
        hard: 65535

    volumes:
      # 1) 核心防坑：使用 Docker 命名卷跟随 dockerd data-root，避免 /mnt/usb-xxxx 挂载名变动引发丢配置
      #    同时 vane 启动时会校验 /data/vane 非 tmpfs 内存盘并写入持久化 Marker 防止空卷误初始化
      - vane_data:/data/vane
      # 2) 挂载宿主机 /run/xtables.lock 所在锁文件（采用 create_host_path: false 防止目标不存在时误建目录）
      - type: bind
        source: /run/xtables.lock
        target: /run/xtables.lock
        bind:
          create_host_path: false
      # 3) 可选挂载 /var/run/docker.sock（vane 内置 Socket inode 变化检测，dockerd 重启后自动重连）
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        bind:
          create_host_path: false

volumes:
  vane_data:
    name: vane_data
```

---

## 9. Web 设置页可配置项全集、默认值说明与配置文件规格

**所有主要配置与子功能模块开关均可在 Web 管理面板的「设置中心」直接可视化配置、校验并原子保存**。

### 9.1 Web 设置页配置项字典（默认值、生效方式与详细说明）

> **生效方式图例**：
> - `Hot-Reload`：点击保存后通过 `ArcSwap` 与模块监督器即时热生效，**无需重启进程、不中断其他模块存量连接**。
> - `Restart`：涉及 Tokio 底层运行时线程池初始化，保存后需重启 `vane` 进程生效。
> - `Local-Lock`：Web 设置页只读展示状态，仅允许通过宿主机/容器本地修改 `config.toml` 开启，防范远程提权。

#### （1）系统、资源预算与子功能模块总开关（`[system]` & `[modules]`）
| 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `timezone_offset` | String | `"UTC"` | `Hot-Reload` | 时区偏移（如 `"+08:00"`）或 `"auto"`（自动解析路由器 `/etc/TZ`），用于 Cron 计划任务与日志时间戳展示。 |
| `worker_threads` | u8 | `2` | `Restart` | Tokio 异步 I/O 工作线程数（范围 `1 ~ 8`）。双核/四核硬路由推荐保持默认 `2`，兼顾多核吞吐与最小线程栈开销。 |
| `log_ring_capacity` | usize | `300` | `Hot-Reload` | 内存环形日志最大保留条数（范围 `50 ~ 1000`，单条上限 `512 Bytes`）。调整后立即动态扩缩容，零磁盘写入。 |
| `global_max_conns` | usize | `512` | `Hot-Reload` | 全机数据面（反向代理 + 用户态端口转发）最大并发连接总预算（范围 `64 ~ 4096`）；管理面板额外独占 16 个保留连接槽位。 |
| `modules.reverse_proxy` | bool | `true` | `Hot-Reload` | **反向代理模块总开关**。设为 `false` 时彻底停用所有反代监听、撤销关联防火墙规则并在导航栏隐藏「反向代理」入口（保留已有规则配置不丢失）。 |
| `modules.port_forward` | bool | `true` | `Hot-Reload` | **端口转发模块总开关**。设为 `false` 时彻底停用所有 TCP/UDP 转发与 DNAT 规则、关闭对应防火墙端口并隐藏导航入口。 |
| `modules.ddns` | bool | `true` | `Hot-Reload` | **DDNS 动态域名模块总开关**。设为 `false` 时停止 Netlink 地址同步与定时对账，隐藏「DDNS」入口。 |
| `modules.acme` | bool | `true` | `Hot-Reload` | **ACME 自动证书模块总开关**。设为 `false` 时停止自动申请/续期任务并隐藏「证书管理」入口。 |
| `modules.stun` | bool | `false` | `Hot-Reload` | **STUN 穿透模块总开关**（默认关闭，按需开启）。设为 `false` 时零后台探测开销并隐藏「STUN 穿透」入口。 |
| `modules.web_terminal` | bool | `false` | `Hot-Reload` | **Web 终端模块总开关（默认关闭，可选打开）**。设为 `false` 时彻底禁用后端 PTY 终端接口、隐藏导航栏「Web 终端」入口且前端不加载终端组件分包。 |
| `modules.cron` | bool | `false` | `Hot-Reload` | **Cron 计划任务模块总开关**（默认关闭，按需开启）。设为 `false` 时停止调度器协程并隐藏「计划任务」入口。 |
| `modules.docker` | bool | `true` | `Hot-Reload` | **Docker 容器管理总开关**。设为 `false` 时断开 `/var/run/docker.sock` 并隐藏「容器管理」入口（仅保留常驻的看板、日志与设置）。 |

#### （2）管理后台与多模态认证设置（`[admin]`）
| 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `listen_lan` | Array<String> | `["192.168.1.1:23456"]` | `Hot-Reload` | 管理面板监听的局域网 `IP:Port` 列表（禁止填入 `0.0.0.0` 或 `[::]` 以强制物理隔离 WAN 口直接访问）。默认自动启用 HTTPS。 |
| `canonical_origin` | String | `"https://192.168.1.1:23456"` | `Hot-Reload` | 服务端固定受信 Origin（用于校验管理请求 `Origin` 头、防 DNS Rebinding 及绑定 Ed25519 挑战签名域）。 |
| `secret_path` | String | 首次启动随机生成 16 位路径 | `Hot-Reload` | 管理后台安全入口路径（如 `"/_vane_9f3k2x8q"`，长度要求 `>= 8` 或设为 `"/"`）。未命中路径的请求直接静默关闭连接。 |
| `username` | String | `"admin"` | `Hot-Reload` | 全局唯一管理员登录名（默认 `"admin"` 可无需修改，也支持在设置页按需修改；全系统采用单管理员设计，不做多用户管理）。 |
| `must_change_password` | bool | `true` | `Hot-Reload` | 初始密码强制修改标志。初次部署默认密码为 `"admin321"`；当该值为 `true` 或密码哈希仍匹配 `"admin321"` 时，登录后强制锁定在改密步骤，**禁止跳过进入管理页面**。 |
| `password_login_enabled` | bool | `true` | `Hot-Reload` | 是否允许密码登录。仅当已完成首次改密且至少绑定 1 把有效 `authorized_ed25519_keys` 公钥后，才允许设为 `false`（切换为纯密钥登录）。 |
| `password_hash` | Secret | 初始默认密码 `"admin321"` 的哈希 | `Hot-Reload` | 管理员密码的 `PBKDF2-HMAC-SHA256` 哈希。新密码要求 **最少 8 位 + 必须含英文字母 + 含数字或特殊符号之一**（禁止与 `"admin321"` 或旧密码相同），API 永不回显哈希值。 |
| `totp_enabled` | bool | `false` | `Hot-Reload` | 是否启用 RFC 6238 TOTP 动态口令二次验证。在设置页扫码并输入一次正确的 6 位验证码后方可激活，同时自动生成一次性恢复码。 |
| `totp_secret` | Secret | `""` | `Hot-Reload` | Base32 编码的 TOTP 密钥，落盘时自动以 `enc:v1:...` AEAD 信封加密保存。 |
| `authorized_ed25519_keys` | Array<Object> | `[]` | `Hot-Reload` | 授权免密挑战登录的管理员公钥列表（每项含 `id` 备注名与 `ssh-ed25519 AAAAC3...` 公钥文本），支持设置页一键生成下载私钥或导入现有 SSH 公钥。 |
| `session_ttl_secs` | u64 | `3600` (1h) | `Hot-Reload` | 登录态保活有效期（默认 `3600` 秒即 **1 小时**；支持自定义，允许范围 **`300 ~ 86400` 秒**，**最大硬上限为 24 小时**，超出范围后端校验直接拒绝）。修改密码、切换 2FA 或点击“注销所有设备”时立即清空全部活跃会话。 |
| `docker_socket` | String | `"/var/run/docker.sock"` | `Hot-Reload` | Docker Engine Unix Socket 路径。留空或关闭 `modules.docker` 则停用容器管理模块；路径不存在时自动隔离降级。 |

#### （3）入站安全护盾与防爆破设置（`[security]`）
| 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `tls_handshake_timeout_secs` | u64 | `5` | `Hot-Reload` | 公网 TLS 握手最大允许耗时（范围 `2 ~ 30` 秒），超时立即断开 TCP，防御僵尸网络半连接耗尽路由器 FD。 |
| `http_header_timeout_secs` | u64 | `10` | `Hot-Reload` | 读取 HTTP 请求头超时时间（范围 `3 ~ 60` 秒，请求头上限固定 `16 KB`），防御 Slowloris 慢速攻击。 |
| `max_login_failures` | u32 | `5` | `Hot-Reload` | 触发自动封禁的最大连续认证失败或恶意路径探测次数（范围 `3 ~ 20`，按 IPv4 `/32` 与 IPv6 `/64` 子网聚合计数）。 |
| `ban_duration_secs` | u64 | `1800` (30m) | `Hot-Reload` | 触发阈值后的源 IP / IPv6 `/64` 子网封禁时长（范围 `60 ~ 86400` 秒）；设置页支持实时查看封禁列表并一键手动解封。 |
| `kernel_ban_offload` | bool | `true` | `Hot-Reload` | 启用后，被封禁的恶意源网段同步写入内核 `nftables set` / `ipset` 在网卡 Prerouting 阶段直接静默 `DROP`，并清理关联 `conntrack`。 |

#### （4）防火墙自动联动设置（`[firewall]`）
| 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `auto_manage` | bool | `true` | `Hot-Reload` | 是否由 `vane` 自动维护路由器防火墙端口放行链。遵循“先绑定成功、后开对应协议栈端口；规则停用立即关端口并清理 `conntrack`”。 |
| `backend` | String | `"auto"` | `Hot-Reload` | 防火墙驱动后端：`"auto"`（自动探测 `fw4` `nftables` 或 `fw3` `iptables-legacy` / `iptables-nft`）、`"nftables"`、`"iptables_legacy"`。 |
| `wan_interfaces` | Array<String> | `["pppoe-wan"]` | `Hot-Reload` | 公网入站接口名列表（设置页提供下拉框自动枚举当前系统网卡），所有 WAN 放行规则严格限定 `iifname` 匹配该列表。 |
| `lan_interfaces` | Array<String> | `["br-lan"]` | `Hot-Reload` | 局域网接口名列表，用于子设备 IPv6 转发的出站接口 `oifname` 约束与管理面局域网准入校验。 |

#### （5）DNS 服务商、双栈 DDNS 与 ACME 证书设置（`[dns_providers]`, `[[ddns]]`, `[[acme]]`）
| 模块 / 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `dns_providers.<id>.provider` | String | `"cloudflare"` | `Hot-Reload` | 支持 `"cloudflare"`、`"aliyun"`、`"dnspod"`、`"huaweicloud"`。可配置多个账号供不同域名复用。 |
| `dns_providers.<id>.api_token` | Secret | `""` | `Hot-Reload` | 云厂商 API 令牌/密钥。**保存时自动以 `enc:v1:...` 信封加密落盘，读取时脱敏为 `****`**；设置页提供“测试连通性”按钮。 |
| `dns_providers.<id>.happy_eyeballs_delay_ms` | u64 | `250` | `Hot-Reload` | RFC 8305 双栈连接竞速延迟（范围 `100 ~ 2000` ms），首选栈握手超时后立即并发尝试另一协议栈。 |
| `ddns[].enabled` | bool | `true` | `Hot-Reload` | 独立启停单条 DDNS 任务，异常重试与其他域名完全隔离。 |
| `ddns[].records` | Array<String> | `["A", "AAAA"]` | `Hot-Reload` | 需维护的解析记录类型（可选 `["A"]`、`["AAAA"]` 或双栈 `["A", "AAAA"]`）。 |
| `ddns[].source` | Object | `{kind="interface", name="pppoe-wan"}` | `Hot-Reload` | 地址获取方式：① `interface`（从指定网卡直读有效公网 IPv4 / 非 Deprecated 公网 IPv6）；② `prefix_and_iid`（提取路由器 PD 前缀 + 子设备固定后缀合成精确 `/128` IPv6）；③ `external_url`（HTTPS 接口查询兜底）。 |
| `ddns[].on_missing_public_ip` | String | `"keep_existing"` | `Hot-Reload` | 当未检测到有效公网 IP 时的策略：`"keep_existing"`（保留云端原记录并告警，默认推荐）或 `"delete_record"`。 |
| `ddns[].firewall_allow_tcp_ports` | Array<u16> | `[]` | `Hot-Reload` | 针对子设备 IPv6 DDNS：自动在 `FORWARD` 链放行目标为该设备当前精确 `/128` 地址的指定 TCP/UDP 端口，前缀变动时原子替换。 |
| `acme[].domain` / `extra_domains` | String / Array | — | `Hot-Reload` | 主域名（如 `"*.home.example.com"`）与附加 SAN 域名列表，默认签发 ECDSA P-256 证书，支持设置页一键“立即申请/续期”。 |
| `acme[].renew_before_days` | u32 | `30` | `Hot-Reload` | 证书到期前自动触发 DNS-01 续期的天数（范围 `7 ~ 60` 天）。续期成功后无锁热替换内存证书池。 |

#### （6）反向代理高级自定义设置（`[[reverse_proxy]]` & `[[reverse_proxy.rules]]`）
| 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `stack` / `listen_port` | String / u16 | `"dual"` / `8443` | `Hot-Reload` | 支持 `"dual"`、`"ipv4_only"`、`"ipv6_only"`；同端口首字节嗅探自适应 HTTP 自动 308 跳 HTTPS 与 TLS 终结。 |
| `strict_sni` | bool | `true` | `Hot-Reload` | 公网 IP 直连或未知 SNI 在 `ClientHello` 阶段直接拒绝握手，防止默认证书暴露私人域名。 |
| `open_wan_firewall` | bool | `true` | `Hot-Reload` | 监听成功后自动在 WAN `INPUT` 链放行对应协议栈端口，规则停用立即撤销。 |
| `max_concurrent_conns` | usize | `256` | `Hot-Reload` | 该监听器的并发连接配额（受全机 `global_max_conns` 总预算约束）。 |
| `rules[].mode` | String | `"proxy"` | `Hot-Reload` | 规则工作模式：`"proxy"`（流式反代至内网 `upstream`）、`"redirect"`（返回 `301/302/307/308` 跳转，支持 `{{stun.<name>.public_addr}}` 动态变量）、`"static"`（直接返回自定义状态码与文本/HTML 内容）。 |
| `rules[].path_prefix` / `strip_prefix` | String / bool | `"/"` / `false` | `Hot-Reload` | 按 URL 路径前缀匹配分流（如 `"/qb"`），开启 `strip_prefix` 时转发前自动剥离该前缀。 |
| `rules[].upstream_tls_mode` | String | `"strict"` | `Hot-Reload` | 当 `upstream` 为 `https://` 时的校验方式：`"strict"`（系统根证书校验）、`"pinned_sha256"`（校验指定后端自签证书指纹 `upstream_cert_sha256`）、`"insecure_skip_verify"`（忽略内网自签证书错误）。 |
| `rules[].upstream_host_header` | String | `""` (保持原 Host) | `Hot-Reload` | 自定义发往上游的 `Host` 头（如 `"192.168.1.100:8006"` 或 `"localhost"`，解决部分内网管理页校验 Host 报错）。 |
| `rules[].sanitize_forwarded_headers` | bool | `true` | `Hot-Reload` | 剥离外部伪造的 `Forwarded` / `X-Forwarded-*` / `X-Real-IP` 并重写为真实客户端地址，防绕过内网免密鉴权。 |
| `rules[].request_headers_set` / `response_headers_set` | Map | `{}` | `Hot-Reload` | 自定义注入或覆盖请求头/响应头（如添加 HSTS、CORS 或自定义鉴权 Header）。 |
| `rules[].auth_gate` | bool | `false` | `Hot-Reload` | 网关前置门禁：开启后访问该反代规则需先通过 `vane` 唯一管理员会话认证（不做多用户体系，轻量保护内网无密码工具页）。 |
| `rules[].allowed_cidrs` / `denied_cidrs` | Array<String> | `[]` | `Hot-Reload` | 单条反代规则独立的源 IPv4/IPv6 CIDR 准入黑白名单。 |
| `rules[].max_body_mb` / `read_timeout_secs` | u64 | `0` (不限) / `120` | `Hot-Reload` | 单次请求体最大 MB 限制（`0` 表示流式不限大小，适合大文件上传）与上游读取空闲超时秒数。 |

#### （7）端口转发、STUN 穿透、Web 终端、通知中心与监控设置
| 模块 / 配置项键名 | 类型 | 默认值 | 生效方式 | Web 设置页详细说明与取值约束 |
| :--- | :--- | :--- | :---: | :--- |
| `port_forwards[].proto` / `stack` | String | `"tcp"` / `"dual"` | `Hot-Reload` | 支持 `"tcp"`、`"udp"`、`"tcp_udp"`；支持 `"dual"`、`"ipv4_only"`、`"ipv6_only"` 及 `bind_interface` 定向绑定特定网卡（如 `"tailscale0"`）。 |
| `port_forwards[].engine` | String | `"userspace_splice"` | `Hot-Reload` | `"userspace_splice"`（默认：支持跨栈 `6to4/4to6`、连接配额、白名单与 Proxy Protocol）或 `"kernel_dnat"`（仅纯同栈无策略时可用）。 |
| `port_forwards[].targets` / `load_balance` | Array / String | — / `"failover"` | `Hot-Reload` | 支持配置单个或多个内网目标 `IP:Port`；多目标时支持 `"failover"`（主备故障转移）或 `"round_robin"`（轮询）。 |
| `port_forwards[].send_proxy_protocol` | String | `"none"` | `Hot-Reload` | 可选 `"none"`、`"v1"`、`"v2"`。开启后在用户态转发首包注入 HAProxy Proxy Protocol 报头，向内网后端透传真实公网 IPv4/IPv6 源地址。 |
| `port_forwards[].allowed_time_window` | String | `""` (全天) | `Hot-Reload` | 每日定时开放窗口（如 `"08:00-23:30"`）或设置 `expire_at_unix`（**一键临时开门 N 分钟**，到期自动关端口并断流 `conntrack`）。 |
| `port_forwards[].udp_session_timeout_secs` | u64 | `60` | `Hot-Reload` | UDP 转发会话空闲超时时间（范围 `10 ~ 600` 秒，DNS 建议 `15s`，游戏串流/VPN 建议 `180s`）。 |
| `stun[].stun_servers` | Array<String> | `["stun.example.com:3478"]` | `Hot-Reload` | 支持配置多个 STUN 节点自动故障切换；支持 `proto = "udp" | "tcp"` 与 `keepalive_secs = 25`。 |
| `stun[].on_change_cloudflare_redirect` | Object | `null` | `Hot-Reload` | 可选联动 Cloudflare Redirect Rules API：穿透 `IP:Port` 变化时自动更新云端重定向规则，实现固定无端口域名自动跳转最新穿透端口。 |
| `web_terminal.shell` / `default_cwd` | String | `"auto"` / `"/root"` | `Hot-Reload` | 当 `modules.web_terminal = true` 时生效：自动探测 `/bin/ash` 或 `/bin/sh` 及默认工作目录；同时支持一键进入指定 Docker 容器终端。 |
| `web_terminal.idle_timeout_secs` / `max_sessions` | u64 / usize | `900` (15m) / `2` | `Hot-Reload` | 终端无输入空闲自动断开秒数（范围 `60 ~ 3600` 秒）与最大并发终端会话数（`1 ~ 4`），断连立即向进程组发送 `SIGHUP -> SIGKILL` 回收。 |
| `notifications[].provider` / `events` | String / Array | — | `Hot-Reload` | 统一通知中心：支持 `"webhook"`、`"bark"`、`"telegram"`、`"wecom"`、`"feishu"`、`"dingtalk"`、`"ntfy"`，密钥均以 `enc:v1:...` 加密保存；可自由勾选订阅事件。 |
| `monitor.interfaces` / `temp_alert_celsius` | Array / u8 | `["pppoe-wan", "br-lan"]` / `85` | `Hot-Reload` | 自定义监控网卡、温度传感器路径及高温（默认 `85°C`）/低可用内存（默认 `32 MB`）告警阈值。 |
| `docker.protected_containers` | Array<String> | `["vane"]` | `Hot-Reload` | 受保护容器名称列表，面板禁止对其执行停止或删除操作，防止误关网关自身。 |

---

### 9.2 统一配置文件完整示例 (`config.example.toml`, 权限 `0600`)

```toml
[system]
timezone_offset = "UTC"                # 默认 UTC 或自动读取系统 /etc/TZ / Zoneinfo
worker_threads = 2                     # 2 个 I/O 线程，单线程栈 512KB，blocking 线程池上限 2
log_ring_capacity = 300                # 内存环形日志容量（自动过滤脱敏凭据）
global_max_conns = 512                 # 全机数据面最大并发连接硬上限（管理面独立保留 16 槽位）

# 子功能模块总开关：除「概览看板」、「运行日志」、「系统设置」3 项常驻外，
# 其余所有子功能均可在设置页一键关闭（彻底停止后台协程、关闭防火墙端口并在 UI 隐藏菜单）
[modules]
reverse_proxy = true
port_forward = true
ddns = true
acme = true
stun = false                           # 默认按需开启
web_terminal = false                   # Web 终端默认关闭，可在设置页按需打开
cron = false                           # 默认按需开启
docker = true

[admin]
# 默认仅绑定局域网地址并自动启用 HTTPS（首次启动自动生成本地自签 ECDSA 证书或复用 ACME 证书）
listen_lan = ["192.168.1.1:23456"]
canonical_origin = "https://192.168.1.1:23456"
secret_path = "/_vane_init_change_me"  # 首次引导时自动替换为 16 位随机安全路径
username = "admin"                     # 全局唯一管理员（默认用户名可不修改，不做多用户管理）
# 1) 初次部署默认密码为 "admin321"，must_change_password = true 强制登录后硬步骤改密：
#    新密码需 >= 8 位且包含英文字母 + 数字/符号之一；未改密或仍为 "admin321" 时禁止跳过进入管理页面！
must_change_password = true
password_login_enabled = true
password_hash = "pbkdf2-sha256$100000$<default_admin_salt>$<default_admin_hash>"
# 2) 可选开启 TOTP 双因素认证（RFC 6238，内置单调递增步长水位防回退重放）
totp_enabled = false
totp_secret = ""
totp_recovery_hashes = []              # 核销时强制先原子写盘成功再放行会话
# 3) 可选配置 Ed25519 公钥挑战签名登录（自动解析 OpenSSH ssh-ed25519 Wire Format 提取 32B 公钥）
authorized_ed25519_keys = [
  # { id = "admin_key_1", pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@workstation" }
]
session_ttl_secs = 3600                # 登录态保活默认 1 小时 (3600s)，允许自定义范围 300 ~ 86400s (最大 24 小时)
docker_socket = "/var/run/docker.sock"

[web_terminal]
# 仅当 [modules].web_terminal = true 时启用，默认关闭
shell = "auto"                         # 自动选择 /bin/ash 或 /bin/sh
default_cwd = "/root"
idle_timeout_secs = 900                # 空闲 15 分钟自动断开并回收进程组
max_sessions = 2

[security]
tls_handshake_timeout_secs = 5
http_header_timeout_secs = 10
max_login_failures = 5                 # IPv4 按 /32、IPv6 按 /64 子网聚合计数
ban_duration_secs = 1800
kernel_ban_offload = true              # 封禁时同步写入防火墙前置 drop 集合并清理对应 Conntrack

[firewall]
auto_manage = true                     # 启动首轮先预清扫残留链，仅对实际绑定成功的协议栈开门
backend = "auto"                       # 自动探测 fw4 (nftables) | fw3-legacy (iptables-legacy) | fw3-nft
wan_interfaces = ["pppoe-wan"]
lan_interfaces = ["br-lan"]

[dns_providers.cf_home]
provider = "cloudflare"
# 支持填写明文（启动时自动通过 ChaCha20-Poly1305 + AAD 加封为 enc:v1:... 落盘），Web API 读取时自动脱敏
api_token = "enc:v1:dGhpcyBpcyBhbiBleGFtcGxlIGFlYWQgc2VhbGVkIHRva2Vu..."
happy_eyeballs_delay_ms = 250          # RFC 8305 双栈连接竞速延迟

# --- M3: 全栈事件驱动 DDNS（先订阅后 Dump，剔除 CGNAT v4 与 Tentative/Deprecated/Temporary v6） ---
[[ddns]]
name = "router_dual_stack"
enabled = true
provider = "cf_home"
domain = "home.example.com"
records = ["A", "AAAA"]
source = { kind = "interface", name = "pppoe-wan" }
on_missing_public_ip = "keep_existing" # 无公网地址时保留原记录并告警，不误删记录
split_dns_lan_ips = ["192.168.1.1"]

[[ddns]]
name = "nas_direct_ipv6"
enabled = true
provider = "cf_home"
domain = "nas-v6.home.example.com"
records = ["AAAA"]
# 提取当前有效 PD 前缀 + 固定接口后缀合成精确 /128 地址；防火墙 FORWARD 仅放行该完整 /128 地址的 5000 端口
source = { kind = "prefix_and_iid", prefix_iface = "br-lan", iid = "::200:5eff:fe00:5301" }
firewall_allow_tcp_ports = [5000]

# --- M4: ACME 泛域名证书自动续期 ---
[[acme]]
domain = "*.home.example.com"
extra_domains = ["home.example.com"]
email = "admin@example.com"
dns_provider = "cf_home"
cert_dir = "/data/vane/certs"
renew_before_days = 30

# --- M1: 双栈单端口复用与流式反向代理 ---
[[reverse_proxy]]
name = "main_https_gateway"
stack = "dual"                         # dual | ipv4_only | ipv6_only
listen_port = 8443
strict_sni = true                      # 未知 SNI 或公网 IP 直连直接中止握手
open_wan_firewall = true
max_concurrent_conns = 256

[[reverse_proxy.rules]]
host = "nas.home.example.com"
upstream = "http://192.168.1.100:5000"
websocket = true
sanitize_forwarded_headers = true      # 严格重写 Forwarded / X-Forwarded-* 并校验 Host/:authority
auth_gate = false

# --- M2: 4x4 全矩阵双引擎端口转发 ---
[[port_forwards]]
name = "nas_ssh_dual_to_v4"
enabled = true
proto = "tcp"
stack = "dual"
# 提示：配置了连接限额、CIDR 过滤、Proxy Protocol 或跨栈时自动运行于用户态受限 splice 引擎；
# 仅纯同栈且无网关层策略时可选 kernel_dnat
engine = "userspace_splice"
listen_port = 2222
target = "192.168.1.100:22"
open_wan_firewall = true
max_concurrent_conns = 64
allowed_cidrs = []

# --- M5: STUN 映射探测与保活 ---
[[stun]]
name = "https_nat1_v4"
enabled = true
proto = "tcp"
local_port = 8443
stun_server = "stun.example.com:3478"
keepalive_secs = 25
# 含敏感 Key 的 Webhook URL 同样支持 enc:v1:... 自动信封加密落盘
webhook_url = "enc:v1:d2ViaG9vay1zZWFsZWQtdXJsLWV4YW1wbGU=..."

# --- M7: 安全计划任务（支持内置 Docker API 动作或无 Shell 结构化参数数组） ---
[[cron]]
name = "prune_dangling_docker_images"
enabled = true
schedule = "0 0 4 * * *"
timeout_secs = 60
action = { kind = "docker_prune_images", dangling_only = true }

[[cron]]
name = "custom_health_ping"
enabled = false
schedule = "0 */30 * * * *"
timeout_secs = 15
action = { kind = "exec", program = "/bin/ping", args = ["-c", "1", "-W", "3", "192.0.2.1"] }
```

---

## 10. 分阶段落地与实机验收门槛（Verification Matrix）

1. **Milestone 1：高安全双栈底座、舱壁监督器与轻量容器运维面板**
   - 完成 `ModuleSupervisor`（通过 QEMU/实机子任务 `panic!` 隔离测试）、掉电安全原子写（含父目录 `fsync`）、默认 HTTPS 管理面板、单调水位 TOTP 与 Ed25519 绑定挑战鉴权。
   - 完成按需系统监控、轻量 Docker Socket 客户端与可按需开关的 Web 终端（`web_terminal`），替代传统独立容器管理面板。
2. **Milestone 2：`fw3/fw4` 精确防火墙引擎、零竞态双栈 DDNS、ACME 与流式反代**
   - 在隔离 `netns` 与真机上分别验证 `fw3 (iptables-legacy)` 与 `fw4 (nftables)` 的链挂载优先级、单栈降级、`conntrack` 立即断流与 `SIGKILL` 后重启预清扫。
   - 完成先订阅后 Dump 的 Netlink DDNS（含 `/128` 子设备 IPv6 合成）、RFC 8305 双栈竞速客户端、ACME 热更新与严格 SNI 反代。
3. **Milestone 3：4×4 双引擎端口转发、STUN 与结构化 Cron（完成全量网关能力闭环）**
   - 完成受全局配额保护的 TCP `splice` 与 UDP `PKTINFO` 端口转发、STUN 探测与结构化 Cron，验证总 `VmRSS`、`PSS` 与内核 Pipe 内存水位达标后正式完成旧网关服务切换。
