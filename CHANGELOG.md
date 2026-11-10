# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-11-10

### Added
- 全栈 IPv4/IPv6 双栈路由器网关守护进程与 Svelte 5 (Runes) 响应式 PWA 控制台（默认端口 `23456`）。
- 单管理员三合一认证（PBKDF2-SHA256 + 单调水位 TOTP + OpenSSH Ed25519）与首次登录强制修改默认密码 (`admin321`) 硬门禁。
- `ChaCha20-Poly1305` + `HKDF-SHA256` 字段级信封加密 (`Vault`) 与 `.vane.bak` 跨设备加密备份。
- 适配 OpenWrt `fw4` (`nftables`) 与 `fw3` (`iptables`) 的隔离防火墙引擎、`conntrack` 状态表清理、一键 `Lockdown` 与 IPv4 `/32` + IPv6 `/64` 自适应 `Fail2Ban`。
- 可插拔子功能模块（反向代理、4x4 端口转发、动态 DDNS、ACME 证书、STUN 穿透、默认关闭的受控 Web 终端、轻量 Cron 计划任务、Docker 容器管理）与 `ModuleSupervisor` 舱壁隔离。
- 一键安装与持久化无损更新脚本 `scripts/install.sh` 及自动化 CI/Release 工作流。
