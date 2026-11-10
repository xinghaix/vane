#!/bin/sh
# Vane 官方一键安装与持久化无损热更新脚本 (支持 OpenWrt procd 与 Linux systemd)
# 仓库地址: https://github.com/xinghaix/vane
set -eu

REPO="xinghaix/vane"
BIN_PATH="/usr/bin/vane"
CONF_DIR="/etc/vane"
ACTION="${1:-install}"

log() { printf "\033[1;32m[Vane]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[Vane Error]\033[0m %s\n" "$*" >&2; exit 1; }

detect_target() {
  ARCH="$(uname -m)"
  case "$ARCH" in
    aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
    x86_64|amd64)  echo "x86_64-unknown-linux-musl" ;;
    armv7l|armv7*) echo "armv7-unknown-linux-musleabihf" ;;
    *) err "暂不支持的 CPU 架构: $ARCH" ;;
  esac
}

fetch_latest_tag() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name":' \
    | sed -E 's/.*"([^"]+)".*/\1/'
}

install_or_update_binary() {
  TARGET="$(detect_target)"
  TAG="${VANE_VERSION:-$(fetch_latest_tag)}"
  [ -n "$TAG" ] || err "无法获取最新 Release 版本号"
  ARCHIVE="vane-${TAG}-${TARGET}.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
  TMP_DIR="$(mktemp -d /tmp/vane-upgrade.XXXXXX)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  log "正在下载 ${ARCHIVE} (${TAG})..."
  curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}"
  curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"

  log "正在校验 SHA-256 签名完整性..."
  (cd "$TMP_DIR" && grep " ${ARCHIVE}\$" SHA256SUMS | sha256sum -c -)

  tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
  chmod 0755 "${TMP_DIR}/vane"

  if [ -f "$BIN_PATH" ]; then
    cp -f "$BIN_PATH" "${BIN_PATH}.bak"
  fi
  mv -f "${TMP_DIR}/vane" "${BIN_PATH}.new"
  mv -f "${BIN_PATH}.new" "$BIN_PATH"
  log "二进制已原子更新至 ${BIN_PATH} (版本: ${TAG})"
}

setup_service() {
  mkdir -p "$CONF_DIR"
  chmod 0700 "$CONF_DIR"

  if [ -f /etc/openwrt_release ] || [ -x /sbin/procd ]; then
    cat > /etc/init.d/vane <<'EOF'
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/vane run --config /etc/vane/config.toml
    procd_set_param respawn 3600 5 5
    procd_set_param limits core="0" nofile="8192 8192"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
    chmod 0755 /etc/init.d/vane
    /etc/init.d/vane enable
    /etc/init.d/vane restart
    log "OpenWrt procd 服务已启用并启动 (默认管理地址: https://192.168.1.1:23456)"
  elif command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/vane.service <<'EOF'
[Unit]
Description=Vane Dual-Stack Router Gateway Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/vane
ExecStart=/usr/bin/vane run --config /etc/vane/config.toml
Restart=always
RestartSec=3
LimitNOFILE=8192
MemoryMax=28M

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now vane.service
    systemctl restart vane.service
    log "systemd 服务已启用并启动 (默认管理端口: 23456)"
  fi
}

case "$ACTION" in
  --rollback|rollback)
    [ -f "${BIN_PATH}.bak" ] || err "未找到备份二进制 ${BIN_PATH}.bak"
    mv -f "${BIN_PATH}.bak" "$BIN_PATH"
    setup_service
    log "已成功回滚至上一版本"
    ;;
  --uninstall|uninstall)
    [ -x /etc/init.d/vane ] && /etc/init.d/vane stop && /etc/init.d/vane disable && rm -f /etc/init.d/vane
    command -v systemctl >/dev/null 2>&1 && systemctl disable --now vane.service 2>/dev/null || true
    rm -f /etc/systemd/system/vane.service "$BIN_PATH" "${BIN_PATH}.bak"
    log "Vane 服务已卸载（配置文件保留在 ${CONF_DIR}）"
    ;;
  *)
    install_or_update_binary
    setup_service
    ;;
esac
