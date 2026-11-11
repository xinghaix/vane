# Vane Production Verification Guide

This document outlines verification steps for Vane features that require real-world environmental interaction (DNS, ACME, Docker, Firewall, etc.) and cannot be fully validated via unit tests.

## 1. Firewall & Lockdown
* **Real-world requirement**: Needs an OpenWrt environment with `fw4` (nftables) or `fw3` (iptables).
* **Verification**:
  - Check `/etc/config/firewall` before and after enabling Vane.
  - Verify that `add rule inet vane_input...` commands successfully register in `nft list ruleset`.
  - Verify `1-Click WAN Lockdown` triggers immediate termination of established connections.

## 2. DDNS & ACME
* **Real-world requirement**: Valid credentials for DNS providers (Cloudflare, Aliyun, etc.) and public-facing port 80/443 access for HTTP-01 ACME.
* **Verification**:
  - Monitor `logs` UI for success messages: "DNS provider X confirmed update" or "ACME certificate status: active".
  - Verify TLS certificate is installed and valid in the browser.

## 3. Docker & Web Terminal
* **Real-world requirement**: Docker engine running with `/var/run/docker.sock` accessible.
* **Verification**:
  - `Docker` tab lists running containers and their states.
  - `Web Terminal` can successfully `exec` into a container or shell into the host.

## 4. Cron & Notifications
* **Real-world requirement**: Configured webhooks (Feishu, Telegram, ntfy).
* **Verification**:
  - Manual `Test` button in Notification settings sends a verification message.
  - Check Cron schedule in logs: "Cron job X executed successfully".