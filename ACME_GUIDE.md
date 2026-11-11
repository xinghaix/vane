# ACME 签发、续期与验收边界

## 协议与账号

使用 [instant-acme 0.8.5](https://docs.rs/instant-acme/0.8.5/instant_acme/) 的 RFC8555 状态机，通过 Vane 的共享有界 HTTPS 客户端发送请求。生产环境拒绝 HTTP Directory 以及 CA 返回的 HTTP 子端点，不跟随重定向，不关闭 TLS 校验。

支持内置 CA 标识和自定义 HTTPS Directory；内置标识仅映射地址，不保证该机构当前仍接受新签发。请先使用对应 CA 的测试环境确认账号资格、速率限制和服务条款。开启签发会按客户端协议同意所选 CA 的服务条款。

账户依据 Directory、email、EAB kid 分开持久化。账户私钥由 Vault 加密，位于配置目录的 acme-accounts 子目录；不是每次启动新建账户。EAB kid 与 base64url HMAC 密钥须同时配置。

## DNS-01 与委派

- dns_provider 引用已配置的 Cloudflare、阿里云或 DNSPod 账号，需要区域查询、TXT 创建/删除权限。
- challenge_alias_domain 支持裸域名或完整 _acme-challenge 前缀名称。必须事先在权威 DNS 配置原始挑战名到目标名的 CNAME。
- Vane 先持久化挑战意图，再创建 TXT。已有相同挑战值会拒绝占用，避免把其他任务的记录当成自身记录清理。
- 传播检查使用系统 DNS 解析器，查询原始挑战名，遵循 CNAME，合并 TXT 分段；系统递归解析器看到记录不等于全球传播完成，最终由 CA 验证决定成功。
- 传播、授权和订单都有时限；只清理日志中确切名称与值匹配的 TXT，不清空整个 TXT RRset。
- 清理失败或任务被取消时保留 acme-challenges 日志，在该规则下次运行前恢复清理。停用/删除规则、删除账号或凭据撤销后不保证自动清理；应保留凭据并先完成清理，再删除配置。

## 证书验证与落盘

不会调用自签证书生成器冒充 CA 签发。验证证书与私钥匹配、请求域名 SAN、真实 X509 有效期、链中相邻签发者名称/CA 约束与签名；拒绝自签叶证书。公开信任仍由客户端自己的根证书库决定，测试 CA 的证书不会因此变成公开可信。

每条规则存储为 cert_dir 下的独立域名目录（通配符转为 wildcard_ 前缀），其中：

- generation-<随机值>/fullchain.pem：证书链。
- generation-<随机值>/privkey.pem：私钥。
- generation-<随机值>/bundle.json：包含证书与私钥的完整一致性快照。
- current：原子切换的代际符号链接。

私钥和 bundle 为 0600，受管代际目录为 0700。写完并同步整代后才切换 current，保留当前和上一代。Vane 从单份 bundle 加载，避免分别读取不同时刻的证书与密钥。外部消费者如需严格一致，应先解析 current 一次，再从同一代目录读取两文件，不要跨切换窗口分别重新解析 current。

证书到达 renew_before_days 阈值才自动续期；有效且覆盖域名/CA 未变的证书直接复用。常规每小时检查，失败五分钟后重试，最多两个同时签发任务。人工“签发”会强制新订单，注意 CA 限流。

## 部署和管理面

CopyToDir 使用相同代际布局，错误会明确报告。Webhook 发送 certificate_pem，只有 include_private_key=true 时才附带 private_key_pem；携带私钥必须使用 HTTPS。部署按证书及钩子配置指纹去重，失败未写成功标记，后续可以重试。HTTP 2xx 仅代表 Webhook 接收端接受请求，不证明外部服务已加载证书。

use_for_admin 只有证书覆盖 canonical_origin 主机名时才更新独立管理证书解析器；最多一条启用规则可更新管理证书。通过 IP 访问而证书只有 DNS SAN 时，客户端仍会拒绝，不绕过校验。重启初期使用本地管理证书，ACME 调度加载缓存后才切换；该启动过渡仍需目标部署验收。

状态 active、cleanup_failed、deployment_failed、failed 分开报告。清理/部署失败不冒充全流程成功；当前可用证书不会因为新订单失败而被伪证书替换。

## 已执行的本地验证

- 本地 CA 验证真实 ECDSA JWS、EAB HMAC、URL 绑定、nonce 与 badNonce 重试。
- 解析真实 CSR，用测试 CA 密钥签发返回证书；验证 SAN、有效期、密钥匹配、证书链拒绝错误签发者。
- 实际 UDP DNS 测试 CNAME 与分段 TXT 传播检查。
- 传播超时、取消意图日志、清理失败后恢复、账户恢复复用、代际切换失败保留旧证书、部署去重与管理域名保护。

未执行真实 CA/生产 DNS 签发、公开信任链浏览器验收、OpenWrt 掉电测试及长期续期测试。新增账户/挑战目录与代际证书目录的跨机备份集成还需在备份子系统阶段补齐，不能仅备份旧版平铺证书文件。
