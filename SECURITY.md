# 安全策略 (Security Policy)

## 安全设计底线

Vane 运行于路由器边界并管理公网端口防火墙，安全是最高优先级：
1. **默认仅监听局域网 (`192.168.1.1:23456`)**，且初次登录强制修改初始密码 `admin321`。
2. **本机高危端口硬保护**：严禁在 WAN `INPUT` 链放行 `22`, `23`, `53`, `80`, `443`, `2375`, `2376`, `23456` 等路由器管理与核心服务端口。
3. **外部命令审计**：防火墙命令采用参数数组与超时；Web 终端和更新命令具有高权限，不能将其描述为已全面消除 Shell 风险。
4. **Web 终端默认关闭 (`modules.web_terminal = false`)**。

## 当前管理面边界

- 管理监听使用 TLS，Cookie 带有 HttpOnly、Secure 与 SameSite=Strict。
- 明文 GET/HEAD 只跳转至配置的 HTTPS Origin，不拼接客户端 Host；明文写请求不进入管理 API。
- Host/Origin 白名单检查覆盖管理请求，写操作与 WebSocket 缺少 Origin 时拒绝。
- 登录防爆破使用实际 TCP 对端，不能通过 X-Real-IP 或 X-Forwarded-For 改写。
- 静态资源仅来自构建清单，拒绝路径穿越；未知 API 不回退到单页应用。
- 关闭模块时，其管理动作 API 返回 MODULE_DISABLED；已建立任务和终端的完整回收仍需进一步审计。
- 当前版本尚未完成公网部署安全验收，TOTP 恢复码消费、模块生命周期及真实服务商集成仍需继续完善。

## 报告安全漏洞

若发现潜在安全问题，请通过 GitHub Security Advisories 私密提交报告，切勿在公开 Issue 中直接披露未修复的利用细节。
