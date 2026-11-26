#!/bin/sh
# 标准化发版脚本：同步版本号、运行全套检查并推送签名 Release Tag
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "用法: ./scripts/release.sh v0.1.0" >&2
  exit 1
fi

# 严格校验 SemVer 版本标签，杜绝非法字符或路径/替换注入
case "$VERSION" in
  *..*)
    echo "错误: 版本标签格式非法 (${VERSION})" >&2
    exit 1
    ;;
esac
if [ "$(printf '%s\n' "$VERSION" | wc -l | tr -d '[:space:]')" != "1" ] \
  || ! printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$'; then
  echo "错误: 版本标签必须符合 SemVer 格式，例如 v0.1.0 或 v0.1.0-rc.1 (收到: ${VERSION})" >&2
  exit 1
fi

CLEAN_VER="${VERSION#v}"

echo "==> 1/4 同步 [package] 版本号至 ${CLEAN_VER}..."
TMP_CARGO="$(mktemp Cargo.toml.XXXXXX)"
trap 'rm -f "$TMP_CARGO"' EXIT
awk -v ver="$CLEAN_VER" '
  BEGIN { in_pkg = 0; replaced = 0 }
  /^\[package\][[:space:]]*$/ { in_pkg = 1; print; next }
  /^\[/ { in_pkg = 0; print; next }
  in_pkg && !replaced && /^version[[:space:]]*=[[:space:]]*"[^"]*"/ {
    rest = $0
    sub(/^version[[:space:]]*=[[:space:]]*"[^"]*"/, "", rest)
    printf "version = \"%s\"%s\n", ver, rest
    replaced = 1
    next
  }
  { print }
  END { if (!replaced) exit 1 }
' Cargo.toml > "$TMP_CARGO" || {
  echo "错误: 未能在 Cargo.toml 的 [package] 段中定位 version 字段" >&2
  exit 1
}
mv -f "$TMP_CARGO" Cargo.toml
trap - EXIT

echo "==> 2/4 构建前端预压缩产物..."
(cd web-ui && npm ci && npm run build)

echo "==> 3/4 运行后端全量单元测试与配置校验..."
cargo test
cargo run -- check --config config.example.toml

echo "==> 4/4 创建并推送 GPG/SSH 签名版本标签 ${VERSION}..."
git add Cargo.toml Cargo.lock
git commit -m "chore(release): prepare ${VERSION}" || true
git tag -s "${VERSION}" -m "Release ${VERSION}"
git push origin main --follow-tags
echo "已推送签名标签 ${VERSION}，GitHub Actions 将自动交叉编译多架构固件、生成 SHA256SUMS（及可选签名）并发布 Release 与 GHCR 镜像。"
