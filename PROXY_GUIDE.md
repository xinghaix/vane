# 反向代理行为与验收范围

## 协议与路由

数据面使用 Hyper 解析 HTTP/1.1 和 HTTP/2，不再单次读取请求并拼接字符串。支持二进制正文、分片请求、chunked 上传及流式响应；请求体不整包缓存。按域名和最长路径前缀选择规则，支持单层通配域名、路径剥离和上游基础路径/查询串。

入站 Host / HTTP2 :authority 必须与 TLS SNI 一致，HTTP/1 绝对形式 URI、重复 Host 和不匹配 authority 会拒绝。明文 HTTP 只为配置中匹配的域名/路径返回 HTTPS 308；保留合法路径和查询串，不反射任意 Host。

静态响应、跳转和代理规则都应用响应头配置。上游 HTTP 使用 HTTP/1.1；不支持 HTTP/2 extended CONNECT，不能将它当作普通 WebSocket 升级使用。目前每个请求独立连接上游，不做连接池复用。

## 头部与凭据

默认清除 Forwarded、X-Forwarded-*、X-Real-IP，并写入真实 TCP 对端信息。CIDR 黑白名单同样只使用真实对端，拒绝伪造转发头绕过限制。

逐跳头以及 Connection 指定的附加头都会删除，再由 Hyper 按消息正文重新编码传输。未经首部策略检查的 trailers 不转发。自定义头禁止覆盖 Host、Content-Length 和逐跳控制字段；Host 使用专用 upstream_host_header 配置。

管理会话 Cookie 不发送给上游，上游也不能通过 Set-Cookie 覆盖管理会话。后端自己的 Cookie 和 Authorization 正常透传，除非配置显式移除。反代自定义请求头中的静态凭据尚需在配置安全阶段补齐 Vault 全覆盖，当前不要把未加封的配置文件当成无敏感数据。

## 上游 HTTPS

- strict：系统可信根加内置可信根，验证证书及服务器名称。
- pinned_sha256：验证指定叶证书 SHA256 指纹和有效期；TLS 握手签名仍必须有效。适合预先核验过指纹的内部证书。
- insecure_skip_verify：显式跳过证书身份校验，并记录警告。仍验证握手签名，但无法防止持有其他证书的中间人，不建议使用。

upstream_sni 和 upstream_host_header 分别控制 TLS 服务器名称与 HTTP Host，两者不是同一个设置。任何 TLS/连接失败不会回退到明文 HTTP。

## 管理员门禁与 WebSocket

auth_gate=true 的普通 HTTP 请求需有效 FullAdmin 会话；必须改初始密码的会话不能通过。写请求还需可信 Origin。当前复用管理 Cookie 适用于管理面与反代同主机名、不同端口的部署；不同主机名之间的交互式登录交接尚待管理 UI/认证阶段完成，不会通过放宽 Cookie Domain 来冒充支持。

WebSocket 必须满足规则 websocket=true、合法 HTTPS Origin 和一次性票据，即使 auth_gate=false 也不豁免。票据流程：

1. 在管理面完整登录后，以可信 Origin 向 POST /api/proxy/ticket 提交 listener、authority、path。
2. authority 包含反代实际端口，例如 proxy.example.com:8443；path 是完整 WS 路径及原有查询串。
3. 将返回的 ticket 作为 vane_ticket 查询参数附加到目标 WSS URL。
4. 票据 30 秒失效、只能使用一次，绑定管理员会话摘要、目标路径和来源网段；代理转发前移除票据参数。

浏览器发起 WS 的 Origin 可以是目标 HTTPS origin 或管理面的 canonical_origin。会话撤销/过期会在一秒级检查后关闭隧道。原有后端网页如果自动建立 WebSocket，必须增加上述取票集成；当前管理 UI 尚未提供通用取票交互，不能宣称任意第三方 WebSocket 页面开箱即用。

## 资源与停止

max_body_mb=0 表示流式不限总大小，不表示无限缓存；非零值对已知和未知长度上传均生效。规则 read_timeout_secs 限制正文与上游传输空闲时间。TLS 握手、请求头、连接阶段另有固定时限。

每连接 HTTP2 并发流上限为 16；监听器及全局连接配额在 TLS 和 WebSocket 生命周期内持有。停止监听器会取消活动连接、上游驱动和升级隧道，并等待任务退出后撤销放行。防火墙规则下发失败不继续宣布监听器成功开放；内核后端原子性与其他模块的停止顺序仍待防火墙专项验收。

## 已验证与未验证

真实 localhost TCP/TLS 测试覆盖二进制 POST、分片/chunked、伪造头清洗、HTTP2、IPv6 前后端、源 CIDR、防伪 authority、上传上限、严格/固定指纹/不安全 TLS 模式、WebSocket Origin/票据重放/撤权、活动上游取消与配额归还。

尚未执行公网压测、长期背压测试、真实第三方应用兼容测试或 OpenWrt 防火墙运行验收。端口转发、STUN、内核防火墙以及跨主机登录交接是后续工作，不因本模块测试通过而视为完成。
