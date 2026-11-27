# 安全策略 (Security Policy)

## 安全设计底线

Vane 运行于路由器边界并管理公网端口防火墙，安全是最高优先级：
1. **默认仅监听局域网 (`192.168.1.1:23456`)**，且初次登录强制修改初始密码 `admin321`（已配置合法纯 Passkey 认证时除外）。
2. **本机高危端口与上游 SSRF 硬保护**：严禁在 WAN `INPUT`/`FORWARD` 或反向代理上游暴露 `22`, `23`, `53`, `80`, `443`, `2375`, `2376`, `23456` 等路由器管理与核心服务端口；校验覆盖运行中活态 + 配置 `admin.listen_lan`、本机全部网卡地址、链路本地/云元数据/NAT64 网段，并在反向代理拨号前执行单次 DNS 解析与解析后全量 IP 校验。
3. **高权限执行与更新边界**：防火墙命令采用参数数组、`fw3` 原子 `iptables-restore --noflush` 与固定安全 `PATH`；`admin.allow_cron_exec`、`admin.allow_manual_update_upload`、`admin.update_signing_public_key` 与 `admin.docker_socket` 均为配置文件只读项（不可经 Web 修改）。CLI `vane update` 已移除 `curl | sh` 改为纯 Rust HTTPS + Ed25519 验签自更新；手动上传更新默认仅放行通过受信任 Ed25519 公钥（`config.toml` 自定义公钥优先，其次二进制内置官方公钥，均缺失时 Fail-Closed）验签且不降级的发布包，探测子进程在 root 下主动降权至 `nobody (65534:65534)`，且仍可在 `config.toml` 设 `admin.allow_manual_update_upload = false` 彻底关闭；启用 Web 终端或 `allow_cron_exec` 仍具有宿主高权限，切勿在非受信环境下开启。
4. **Web 终端默认关闭 (`modules.web_terminal = false`)**，容器示例 `docker-compose.example.yml` 默认不挂载 `/var/run/docker.sock`。

## 当前管理面边界

- 管理监听使用 TLS（管理证书采用世代目录原子切换），Cookie 带有 `HttpOnly`、`Secure` 与 `SameSite=Strict`。
- 明文 GET/HEAD 只跳转至配置的 HTTPS Origin，不拼接客户端 Host；明文写请求不进入管理 API。
- Host/Origin 白名单检查覆盖管理请求，写操作与 WebSocket 缺少 Origin 时拒绝；可选启用 `secret_path` 安全入口路径（默认 `"/"`），开启后先校验 Fail2Ban 封禁状态再匹配路径，且仅首次初始化/待改密时向 `stderr` 打印明文路径。
- 登录防爆破使用实际 TCP 对端（不可经 `X-Real-IP`/`X-Forwarded-For` 伪造），管理面/`secret_path` 与反向代理门户 `Fail2Ban` 按信任域完全隔离，表满且未确认内核卸载时 Fail-Closed 拒绝新请求。
- Step-Up 二次认证（`REAUTH_REQUIRED` / `MFA_REAUTH_REQUIRED`）：启用 TOTP 或 Passkey 后，备份导出/导入（含安全基线降级 `409` 二次确认）、TOTP/Passkey 因子增删开关与恢复码重置、模块二次认证关闭、手动更新及管理面敏感配置修改均强制强因子（MFA）参与；恢复码消费与生成已完成并发加锁并移出耗时 PBKDF2 持锁区间。
- 静态资源仅来自构建清单，拒绝路径穿越；未知 API 不回退到单页应用；Svelte 5 前端无 `{@html}` / `innerHTML` / `eval` 等不安全 DOM 注入点。
- 存储与加密：`Vault` 采用 `enc:v2:` 无歧义 AAD 帧格式（兼容透明升级 `enc:v1:`），加密备份升级为 `VANEBAK2`（600k PBKDF2 + 完整 40B 文件头 AAD + 强口令校验，兼容 `VANEBAK1`，导入体上限 8 MiB），`acme-accounts` 强制 `vault.open` 验签，日志与外部通知统一脱敏清洗。
- 模块关闭与紧急封锁回收：禁用 `cron`、`docker`、`reverse_proxy`、`web_terminal`、`ddns`、`acme` 时主动取消托管 Cron 任务与进程组（`JoinSet` + `CancellationToken` + `waitid`）、吊销 `proxy_gate` 会话与活跃宿主/容器 PTY（含 I/O 超时防挂死）并裁剪 `cert_table`；`vane firewall lockdown` 与守护进程共享持久化 `.lockdown` 状态（每 2 秒同步停/启 WAN 监听），不清空既有 Fail2Ban 内核封禁，并在 `DryRun`/降级时显式告警。
- 当前版本仍待完成真实 OpenWrt `fw3`/`fw4` 物理设备、断电恢复及外部 CA/DNS/通知渠道的实网验收，请勿未经验证直接暴露于不可信公网生产环境。

## 报告安全漏洞

若发现潜在安全问题，请通过 GitHub Security Advisories 私密提交报告，切勿在公开 Issue 中直接披露未修复的利用细节。
