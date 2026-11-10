# Vane — 面向资源受限路由器的高安全双栈全能网关

**[English](README.md)** | **简体中文**

[![CI](https://github.com/xinghaix/vane/actions/workflows/ci.yml/badge.svg)](https://github.com/xinghaix/vane/actions/workflows/ci.yml)
[![Release](https://github.com/xinghaix/vane/actions/workflows/release.yml/badge.svg)](https://github.com/xinghaix/vane/actions/workflows/release.yml)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fxinghaix%2Fvane-blue)](https://github.com/xinghaix/vane/pkgs/container/vane)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-emerald.svg)](LICENSE)

**Vane** 是一款专为嵌入式路由器（OpenWrt / ImmortalWrt / ARM64 / x86_64 软路由与迷你主机）设计的 **单静态二进制、全栈 IPv4/IPv6、高安全边界** 一站式网关管理守护进程。

采用 **Rust + Svelte 5 (Runes)** 构建，前后端通过 `rust-embed` 与预压缩（`.br` / `.gz`）融为单一静态文件，常规内存占用 **< 12 MB**，支持中英文双语切换、模块按需启停与舱壁故障隔离。

---

## 核心特性

1. **全方位 IPv4 + IPv6 双栈第一公民**
   - 显式 `IPV6_V6ONLY` 控制与双栈独立监听，跨 Linux / OpenWrt / macOS 行为一致。
   - 自动剔除 CGNAT (`100.64.0.0/10`)、RFC1918 私网、Link-Local (`fe80::/10`) 与 ULA (`fc00::/7`)。
   - 支持 `prefix_and_iid` 与 `neighbor_mac` EUI-64 **子设备 `/128` IPv6 公网地址自动合成**，并在前缀重委托时原子更新防火墙 `FORWARD` 放行链。
2. **安全为最大底线**
   - **默认 5 位管理端口 `23456`**（默认仅绑定局域网 `192.168.1.1:23456`）。
   - **首次登录强制改密硬门禁**：初始账号 `admin` / `admin321`，首次登录强制进入 `MustChangePassword` 硬步骤，未修改为合规强密码（英文 + 数字或符号，至少 8 位）前后端直接以 `403 MUST_CHANGE_INITIAL_PASSWORD` 拒绝一切管理 API。
   - **单管理员三合一认证**：PBKDF2-HMAC-SHA256 口令 + 单调水位防回退重放 TOTP + OpenSSH Ed25519 公钥挑战签名。登录态默认保活 `1h`（可在 `5m ~ 24h` 间配置）。
   - **字段级信封加密 (`Vault`)**：所有第三方 API Token / Secret 自动以 `ChaCha20-Poly1305` + `HKDF-SHA256` 加密为 `enc:v1:...`（字段路径绑定为 `AAD` 防跨字段替换）。
   - **双栈自适应 Fail2Ban**：按 IPv4 `/32` 与 IPv6 `/64` 前缀聚合封禁（防止攻击者利用 IPv6 SLAAC 临时地址轮换绕过封禁）。
   - **防火墙严格隔离**：原生适配 OpenWrt `fw4` (`nftables`) 与 `fw3` (`iptables`)，仅操作独立子链 `vane_wan_in` / `vane_fwd_in` / `vane_dnat_pre`，硬编码拒绝开放 `22/53/80/443/23456` 等本机敏感端口，支持一键 `Lockdown` 紧急封锁与规则关闭时立即清理 `conntrack` 状态表。
3. **可插拔模块与舱壁隔离 (`ModuleSupervisor`)**
   - 除常驻的 **全景看板**、**运行日志**、**系统设置** 外，其余 8 大子模块（**反向代理、端口转发、动态 DDNS、ACME 证书、STUN 穿透、Web 终端 [默认关闭，可选打开]、计划任务、Docker 容器**）均可在设置页一键开关。
4. **中英双语响应式 UI 与 PWA**
   - 基于 **Svelte 5 Runes** 构建，仅内置精简的 **简体中文 (`zh`) / 英文 (`en`)** 双语支持，兼容电脑端与手机端并支持 PWA 安装。

---

## 快速安装与持久化更新

### 1. OpenWrt / Linux 一键安装或无损更新

```sh
curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh
```

- **在线自更新**（自动校验 `SHA256SUMS`、备份旧版并平滑重启服务）：
  ```sh
  vane update
  ```
- **一键回滚至上一版本**：
  ```sh
  curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh -s -- --rollback
  ```

### 2. Docker / GHCR 容器部署

```sh
docker pull ghcr.io/xinghaix/vane:latest
docker compose -f docker-compose.example.yml up -d
```

---

## 开源协议

本项目采用 **[GNU General Public License v3.0 (GPL-3.0-or-later)](LICENSE)** 协议开源。
