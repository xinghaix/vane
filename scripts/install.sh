#!/bin/sh
# Vane 官方一键安装与持久化无损热更新脚本 (支持 OpenWrt procd 与 Linux systemd)
# 仓库地址: https://github.com/xinghaix/vane
# 可选环境变量:
#   VANE_VERSION        - 指定安装的 SemVer 标签 (例如 v0.1.0)
#   VANE_RELEASE_PUBKEY - 指定发布公钥（Ed25519 PEM 文件/文本，或 minisign 公钥文件/RW... 字符串）
#                         设置后强制验证 SHA256SUMS.sig / SHA256SUMS.minisig 密码学分离签名
set -eu

REPO="xinghaix/vane"
BIN_PATH="/usr/bin/vane"
CONF_DIR="/etc/vane"
ACTION="${1:-install}"

TMP_DIR=""
STAGED_NEW=""
STAGED_BAK=""

cleanup() {
  if [ -n "$STAGED_NEW" ]; then
    rm -f "$STAGED_NEW"
  fi
  if [ -n "$STAGED_BAK" ]; then
    rm -f "$STAGED_BAK"
  fi
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

log() { printf "\033[1;32m[Vane]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[Vane Error]\033[0m %s\n" "$*" >&2; exit 1; }

curl_https() {
  # 严格限定 HTTPS + TLS 1.2+，防止 -L 重定向降级到明文 HTTP 或其他协议
  curl --proto '=https' --tlsv1.2 -fsSL "$@"
}

validate_semver_tag() {
  _tag="$1"
  [ -n "$_tag" ] || return 1
  case "$_tag" in
    *..*) return 1 ;;
  esac
  [ "$(printf '%s\n' "$_tag" | wc -l | tr -d '[:space:]')" = "1" ] || return 1
  printf '%s\n' "$_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$'
}

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
  curl_https "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name":' \
    | head -n 1 \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

verify_release_signature() {
  _sums_file="$1"
  _base_url="$2"

  if [ -z "${VANE_RELEASE_PUBKEY:-}" ]; then
    log "提示: 未配置 VANE_RELEASE_PUBKEY，将仅校验 SHA256SUMS 摘要（不含密码学签名验证；生产环境建议配置 VANE_RELEASE_PUBKEY）"
    return 0
  fi

  _is_minisign=0
  if [ "${VANE_RELEASE_SIG_FORMAT:-}" = "minisign" ]; then
    _is_minisign=1
  elif [ -f "$VANE_RELEASE_PUBKEY" ] && head -n 1 "$VANE_RELEASE_PUBKEY" | grep -q '^untrusted comment:'; then
    _is_minisign=1
  else
    case "$VANE_RELEASE_PUBKEY" in
      RW*) _is_minisign=1 ;;
    esac
  fi

  if [ "$_is_minisign" -eq 1 ]; then
    command -v minisign >/dev/null 2>&1 \
      || err "已配置 minisign 公钥但系统未安装 minisign，无法验证密码学签名"
    log "正在下载并验证 SHA256SUMS.minisig 密码学签名..."
    curl_https "${_base_url}/SHA256SUMS.minisig" -o "${TMP_DIR}/SHA256SUMS.minisig"
    if [ -f "$VANE_RELEASE_PUBKEY" ]; then
      minisign -Vm "$_sums_file" -x "${TMP_DIR}/SHA256SUMS.minisig" -p "$VANE_RELEASE_PUBKEY" \
        || err "SHA256SUMS minisign 密码学签名验证失败！"
    else
      minisign -Vm "$_sums_file" -x "${TMP_DIR}/SHA256SUMS.minisig" -P "$VANE_RELEASE_PUBKEY" \
        || err "SHA256SUMS minisign 密码学签名验证失败！"
    fi
    log "SHA256SUMS minisign 密码学签名验证通过"
    return 0
  fi

  command -v openssl >/dev/null 2>&1 \
    || err "已配置 Ed25519 公钥但系统未安装 openssl，无法验证密码学签名"

  if [ -f "$VANE_RELEASE_PUBKEY" ]; then
    _pubkey_file="$VANE_RELEASE_PUBKEY"
  elif printf '%s\n' "$VANE_RELEASE_PUBKEY" | grep -q 'BEGIN PUBLIC KEY'; then
    _pubkey_file="${TMP_DIR}/release.pub.pem"
    (umask 077 && printf '%s\n' "$VANE_RELEASE_PUBKEY" > "$_pubkey_file")
  else
    err "无法识别的 VANE_RELEASE_PUBKEY 格式（支持 Ed25519 PEM 文件/文本或 minisign 公钥）"
  fi

  log "正在下载并验证 SHA256SUMS.sig (Ed25519) 密码学签名..."
  curl_https "${_base_url}/SHA256SUMS.sig" -o "${TMP_DIR}/SHA256SUMS.sig"
  openssl pkeyutl -verify -pubin -inkey "$_pubkey_file" -rawin \
    -in "$_sums_file" -sigfile "${TMP_DIR}/SHA256SUMS.sig" >/dev/null \
    || err "SHA256SUMS Ed25519 密码学签名验证失败！"
  log "SHA256SUMS Ed25519 密码学签名验证通过"
}

verify_archive_sha256() {
  _archive_name="$1"
  _archive_path="$2"
  _sums_file="$3"

  log "正在校验安装包 SHA-256 哈希摘要..."
  # 使用定串精确匹配文件名，避免正则元字符（如 '.'）误匹配
  EXPECTED_SHA="$(awk -v f="$_archive_name" '($2 == f || $2 == ("*" f)) && NF == 2 { print $1; exit }' "$_sums_file")"
  printf '%s\n' "$EXPECTED_SHA" | grep -Eq '^[0-9a-fA-F]{64}$' \
    || err "SHA256SUMS 中未找到 ${_archive_name} 对应的有效 SHA-256 摘要"

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$_archive_path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$_archive_path" | awk '{print $1}')"
  else
    err "缺少 sha256sum 或 shasum 工具，无法校验安装包哈希摘要"
  fi

  EXPECTED_LOWER="$(printf '%s' "$EXPECTED_SHA" | tr 'A-F' 'a-f')"
  ACTUAL_LOWER="$(printf '%s' "$ACTUAL_SHA" | tr 'A-F' 'a-f')"
  [ "$EXPECTED_LOWER" = "$ACTUAL_LOWER" ] \
    || err "SHA-256 哈希摘要校验失败: 期望 ${EXPECTED_LOWER}, 实际 ${ACTUAL_LOWER}"
  log "SHA-256 哈希摘要校验通过"
}

install_or_update_binary() {
  TARGET="$(detect_target)"
  if [ -n "${VANE_VERSION:-}" ]; then
    TAG="$VANE_VERSION"
  else
    TAG="$(fetch_latest_tag)"
  fi
  [ -n "$TAG" ] || err "无法获取最新 Release 版本号"
  validate_semver_tag "$TAG" || err "非法的 SemVer 版本号: ${TAG}"

  ARCHIVE="vane-${TAG}-${TARGET}.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
  BIN_DIR="$(dirname "$BIN_PATH")"

  [ ! -L "$BIN_PATH" ] || err "目标路径 ${BIN_PATH} 是符号链接，拒绝覆盖"
  [ ! -L "${BIN_PATH}.bak" ] || err "备份路径 ${BIN_PATH}.bak 是符号链接，拒绝操作"

  TMP_DIR="$(mktemp -d /tmp/vane-upgrade.XXXXXX)"
  chmod 0700 "$TMP_DIR"
  trap cleanup EXIT

  log "正在通过 HTTPS 下载 ${ARCHIVE} (${TAG})..."
  curl_https "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}"
  curl_https "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"

  verify_release_signature "${TMP_DIR}/SHA256SUMS" "$BASE_URL"
  verify_archive_sha256 "$ARCHIVE" "${TMP_DIR}/${ARCHIVE}" "${TMP_DIR}/SHA256SUMS"

  # 仅定位并验证归档中的单一顶层普通文件 vane / ./vane，拒绝符号链接、硬链接与多余文件
  TAR_MEMBER=""
  MATCH_COUNT=0
  TAR_MATCHES="$(tar -tzf "${TMP_DIR}/${ARCHIVE}" | awk '$0 == "vane" || $0 == "./vane" { print }')"
  if [ -n "$TAR_MATCHES" ]; then
    MATCH_COUNT="$(printf '%s\n' "$TAR_MATCHES" | wc -l | tr -d '[:space:]')"
    TAR_MEMBER="$(printf '%s\n' "$TAR_MATCHES" | head -n 1)"
  fi
  [ "$MATCH_COUNT" = "1" ] || err "安装包中未找到唯一的 vane 二进制条目 (匹配数: ${MATCH_COUNT})"

  TAR_LISTING="$(tar -tvzf "${TMP_DIR}/${ARCHIVE}" "$TAR_MEMBER" 2>/dev/null || true)"
  [ "$(printf '%s\n' "$TAR_LISTING" | wc -l | tr -d '[:space:]')" = "1" ] \
    || err "拒绝提取重复或异常的归档条目: ${TAR_MEMBER}"
  case "$TAR_LISTING" in
    -*) ;;
    *) err "拒绝提取非常规文件条目: ${TAR_MEMBER}" ;;
  esac

  EXTRACT_DIR="${TMP_DIR}/extract"
  mkdir -m 0700 "$EXTRACT_DIR"
  if tar --help 2>&1 | grep -q -- '--no-same-permissions'; then
    tar -x --no-same-owner --no-same-permissions -z -f "${TMP_DIR}/${ARCHIVE}" -C "$EXTRACT_DIR" "$TAR_MEMBER"
  else
    (umask 077 && tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$EXTRACT_DIR" "$TAR_MEMBER")
  fi

  EXTRACTED_BIN="${EXTRACT_DIR}/vane"
  [ "$(ls -A "$EXTRACT_DIR")" = "vane" ] || err "解压目录检测到意外条目，已中止安装"
  [ -f "$EXTRACTED_BIN" ] && [ ! -L "$EXTRACTED_BIN" ] && [ -s "$EXTRACTED_BIN" ] \
    || err "解压出的 vane 不是有效常规文件"
  chmod 0755 "$EXTRACTED_BIN"

  # 在目标二进制同级目录 (/usr/bin) 内通过 mktemp 暂存，确保同一文件系统原子 rename 替换
  STAGED_NEW="$(mktemp "${BIN_DIR}/.vane.new.XXXXXX")"
  cp "$EXTRACTED_BIN" "$STAGED_NEW"
  chmod 0755 "$STAGED_NEW"

  if [ -f "$BIN_PATH" ]; then
    [ ! -L "${BIN_PATH}.bak" ] || err "备份路径 ${BIN_PATH}.bak 是符号链接，拒绝操作"
    STAGED_BAK="$(mktemp "${BIN_DIR}/.vane.bak.XXXXXX")"
    cp "$BIN_PATH" "$STAGED_BAK"
    chmod 0755 "$STAGED_BAK"
    [ ! -L "${BIN_PATH}.bak" ] || err "备份路径 ${BIN_PATH}.bak 在写入前变为符号链接，拒绝操作"
    mv -f "$STAGED_BAK" "${BIN_PATH}.bak"
    STAGED_BAK=""
  fi

  [ ! -L "$BIN_PATH" ] || err "目标路径 ${BIN_PATH} 在替换前变为符号链接，拒绝覆盖"
  mv -f "$STAGED_NEW" "$BIN_PATH"
  STAGED_NEW=""
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
# 日常运行约 16~24 MiB，大备份 (.vane.bak) 导入峰值需 60~80 MiB；保留 64M 上限避免导入 OOM
MemoryMax=64M

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
    [ ! -L "$BIN_PATH" ] || err "目标路径 ${BIN_PATH} 是符号链接，拒绝回滚覆盖"
    [ -f "${BIN_PATH}.bak" ] && [ ! -L "${BIN_PATH}.bak" ] || err "未找到有效常规文件备份 ${BIN_PATH}.bak"
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
