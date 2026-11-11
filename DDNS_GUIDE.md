# DDNS 使用与验收边界

## 服务商与凭据

通过 [配置示例](<config.example.toml>) 的 dns_providers 设置 Cloudflare Token、阿里云 AccessKey 或 DNSPod SecretId/SecretKey，再由 DDNS 规则的 provider 引用账号 ID。凭据、外部地址源 URL、自定义请求 URL/Headers/Body 均由 Vault 加封，更新时不可直接拷贝另一字段的密文。

可设置 zone_name 限定托管区域。Cloudflare 配合 zone_id 可免去区域发现请求；仅设置 zone_name 时仍需区域查询权限。未指定区域时，Cloudflare 逐层匹配名称，阿里云/DNSPod 分页发现账号中的托管域，始终取最长匹配区域。

多条同名同类型同线路记录不自动猜测目标，需消除歧义再启用 DDNS。阿里云/DNSPod 更新和删除仅处理配置的 line，不触碰其他线路。成功指服务商已接受请求，不代表递归 DNS 缓存已经全球收敛。

## 地址源与调度

- interface：选择接口公网 IPv4/IPv6，可按索引和 IPv6 优先子网筛选。Linux 会排除 tentative、deprecated、DADFAILED 地址。
- prefix_and_iid：当前接口前缀加固定 64 位后缀；必须由用户确保子设备实际使用该 IID。
- neighbor_mac：Linux 使用 ip -j -6 neigh 查询真实邻居，要求完整 iproute2 JSON 支持。首次必须观察到设备的全球地址，后缀缓存在配置目录；设备休眠或前缀重分配时复用观察到的后缀。没有观测/缓存时不会推导 EUI-64。
- external_url：IPv4/IPv6 URL 分别强制对应的出站地址族。HTTP 失败、解析失败与“没有公网地址”是不同结果。
- custom_http_extract：通过双栈 HTTP 从文本或 JSON 响应提取相应 IP。

每条规则独立对账，reconcile_interval_secs 范围 30–86400 秒。Linux RTNETLINK 地址/链路变更额外触发对账，合并两秒内的变化；非 Linux 使用定时对账。手动与后台请求使用同一规则锁，不同规则互不阻塞。

## 自定义 HTTP

支持 Method、URL、Headers、Body 模板变量 ip、ipv4、ipv6、domain、token。URL 参数值采用百分号编码；JSON Body 在解析后的字符串值内替换，避免引号注入；表单 Body 依据 Content-Type 编码。

HTTP 非 2xx、超时、响应过大、未匹配 success_keyword 均视为失败。自定义服务的“200 但失败”格式必须配置合适的 success_keyword；未知协议不能自动判断其业务成功。当前自定义 HTTP 不支持隐式删除记录，需使用 keep_existing。

## 状态语义

- synced：配置的地址族均已获得服务商确认。
- partial：部分地址族成功，或 DNS 成功但防火墙失败。
- failed：请求失败，没有本次确认的成功更新。
- waiting_public_ip：缺公网 IP 且保留现有记录，没有伪装成更新成功。
- disabled：模块或规则停用，不发更新请求。

ipv4/ipv6 子状态分别记录 synced、deleted、kept_missing_ip、failed、disabled 与脱敏错误。last_sync_unix 仅在配置地址族全部成功且防火墙对账无错误时推进；源查询超时不会触发删除。last_ipv4/last_ipv6 保留最近一次服务商确认值，不冒充当前接口观测值。

## Split DNS

配置 split_dns_lan_ips 后，会在配置目录生成专用 split-dns.hosts 文件；停用/删除规则会删除相应条目。文件采用原子写入，不修改系统 hosts。

需由部署管理员把该文件接入现有 dnsmasq 的 addn-hosts（或支持目录监控的 hostsdir）配置。使用 addn-hosts 时修改文件后还需按目标系统规范重载 dnsmasq；当前程序不会擅自重启系统 DNS，也不宣称仅生成文件即可生效。文件为 0600，非 root DNS 进程需由管理员配置安全读取权限或单独部署副本。

## 本地测试与尚未验证项

本地测试覆盖自定义请求实际收发、Vault 解密、双栈部分成功、源错误不误删、原生 DNS 删除报文、NDP 解析、Linux 地址标志过滤和 Split DNS 输出。真实服务商限流/权限、Linux RTNETLINK 实际事件、NDP 缓存跨重启以及 fw3/fw4 放行撤销需要专用测试账号和隔离 Linux/OpenWrt 环境验证。
