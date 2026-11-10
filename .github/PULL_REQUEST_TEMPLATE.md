## 变更说明 (Summary)
- 

## 安全与双栈自检清单 (Security & Dual-Stack Checklist)
- [ ] 已同时覆盖 IPv4 与 IPv6 双栈场景
- [ ] 未引入硬编码个人/设备敏感信息
- [ ] 防火墙改动已确认不会误开放 `22/53/80/443/23456` 等受保护本地端口
- [ ] `cargo test` 与 `cd web-ui && npm run build` 全部通过
