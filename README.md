# Vane — Ultra-Lightweight Secure Dual-Stack Router Gateway

**English** | **[简体中文](README_CN.md)**

[![CI](https://github.com/xinghaix/vane/actions/workflows/ci.yml/badge.svg)](https://github.com/xinghaix/vane/actions/workflows/ci.yml)
[![Release](https://github.com/xinghaix/vane/actions/workflows/release.yml/badge.svg)](https://github.com/xinghaix/vane/actions/workflows/release.yml)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fxinghaix%2Fvane-blue)](https://github.com/xinghaix/vane/pkgs/container/vane)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-emerald.svg)](LICENSE)

**Vane** is an all-in-one, security-first, full IPv4/IPv6 dual-stack gateway daemon purpose-built for resource-constrained embedded routers (OpenWrt / ImmortalWrt / ARM64 / x86_64 appliances).

Built with **Rust + Svelte 5 (Runes)**, Vane compiles into a single static binary with pre-compressed `.br` / `.gz` web assets, with a module supervisor. Runtime memory usage and firewall behavior still require validation on target devices.

---

> **Development status:** This is not production-ready. ACME now implements the real DNS-01 order protocol and DDNS sends real provider requests, but live CA/DNS and Linux/OpenWrt acceptance tests are still pending. Some Cron actions only log messages. Manual notifications now perform real delivery; background alert events are not yet connected. The feature list includes design goals, not a claim of completed acceptance testing. Do not deploy this version as a public production gateway.

## Admin access

- Use HTTPS on the configured LAN address (default: https://192.168.1.1:23456). Verify and trust the generated self-signed certificate through a trusted channel; do not disable TLS verification.
- The admin certificate and key persist in the certs directory alongside the configuration. Invalid, mismatched or unwritable credentials fail startup instead of silently changing trust.
- IPv4 and IPv6 listener failures are reported; there is no implicit loopback fallback.
- Mutating APIs and WebSockets require a trusted HTTPS Origin. Host must match a configured listener or canonical_origin. CLI clients must also send Origin and verify TLS.
- Client IPs come from the TCP peer, never from forwarding headers.

## Key Features

1. **First-Class IPv4 + IPv6 Dual-Stack Everywhere**
   - Explicit `IPV6_V6ONLY` socket control and dual-stack listeners across Linux, OpenWrt, and macOS.
   - Automatically filters out CGNAT (`100.64.0.0/10`), RFC1918 private addresses, Link-Local (`fe80::/10`), and ULA (`fc00::/7`).
   - Uses fixed IIDs or observed NDP neighbors with a persisted suffix cache; it never guesses an EUI-64 address from a MAC. Sub-device firewall rules are reconciled after confirmed DNS updates; firewall atomicity still requires target-device verification.
2. **Security as the Bottom Line**
   - **Default 5-Digit Admin Port (`23456`)**: Binds exclusively to LAN (`192.168.1.1:23456`) by default.
   - **Mandatory Initial Password Change Gate**: Ships with initial credentials `admin` / `admin321`. On first login, all management APIs return `403 MUST_CHANGE_INITIAL_PASSWORD` until a strong password (8–128 chars, letters + digits/symbols, not `admin321`) is set.
   - **Single-Admin Tri-Modal Auth**: PBKDF2-HMAC-SHA256 + monotonic-watermark TOTP + OpenSSH Ed25519 challenge-response. Configurable session TTL (`3600s` default, up to `86400s` / 24h).
   - **Field-Level Envelope Encryption (`Vault`)**: Automatically seals all secrets in `config.toml` as `enc:v1:...` using `ChaCha20-Poly1305` + `HKDF-SHA256` with the field path bound as `AAD`.
   - **Dual-Stack Adaptive Fail2Ban**: Aggregates bans by IPv4 `/32` and IPv6 `/64` prefix to defeat SLAAC privacy address rotation.
   - **Isolated Firewall Chains**: Native support for OpenWrt `fw4` (`nftables`) and `fw3` (`iptables`) via dedicated `vane_*` chains, protected local port guard (`22/53/80/443/23456`), `conntrack` state flushing, and 1-click WAN `Lockdown`.
3. **Pluggable Modules & Fault Isolation**
   - Dashboard, Logs, and Settings remain always active; the other **8 modules** (**Reverse Proxy, Port Forwarding, DDNS, ACME TLS, STUN NAT Traversal, Web Terminal [off by default], Cron Scheduler, Docker Manager**) can be toggled on/off at runtime.
4. **Bilingual (中文 / English) Responsive PWA**
   - Built with **Svelte 5 Runes**, supporting Bilingual UI (`zh` / `en`), Dark/Light/Auto themes, desktop Bento Grid, and mobile Bottom Tab Bar.

---

## Quick Installation & Persistent Updates

### 1. One-Line Install / Upgrade (OpenWrt `procd` & Linux `systemd`)

```sh
curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh
```

- **Self-Update to Latest Release** (verifies `SHA256SUMS` and atomically swaps binary):
  ```sh
  vane update
  ```
- **Rollback to Previous Version**:
  ```sh
  curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh -s -- --rollback
  ```

### 2. Container Deployment (GHCR Multi-Arch Image)

```sh
docker pull ghcr.io/xinghaix/vane:latest
docker compose -f docker-compose.example.yml up -d
```

### 3. CLI Commands

```sh
vane run --config /etc/vane/config.toml        # Start gateway daemon
vane check --config /etc/vane/config.toml      # Validate configuration
vane auth-reset --config /etc/vane/config.toml # Reset password to admin321 (forces password change on next login)
vane update                                    # Upgrade binary to latest GitHub Release
vane version                                   # Print version and target architecture
```

---

## License

Licensed under the **[GNU General Public License v3.0 (GPL-3.0-or-later)](LICENSE)**.
