#!/bin/sh
# 标准化发版脚本：同步版本号、运行全套检查并推送 Release Tag
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "用法: ./scripts/release.sh v0.1.0"
  exit 1
fi
CLEAN_VER="${VERSION#v}"

echo "==> 1/4 同步版本号至 ${CLEAN_VER}..."
sed -i.bak -E "s/^version = \".*\"/version = \"${CLEAN_VER}\"/" Cargo.toml && rm -f Cargo.toml.bak

echo "==> 2/4 构建前端预压缩产物..."
(cd web-ui && npm ci && npm run build)

echo "==> 3/4 运行后端全量单元测试与配置校验..."
cargo test
cargo run -- check --config config.example.toml

echo "==> 4/4 创建并推送签名版本标签 ${VERSION}..."
git add Cargo.toml Cargo.lock
git commit -m "chore(release): prepare ${VERSION}" || true
git tag -a "${VERSION}" -m "Release ${VERSION}"
git push origin main --follow-tags
echo "已推送 ${VERSION}，GitHub Actions 将自动交叉编译多架构固件、生成 SHA256SUMS 并发布 Release 与 GHCR 镜像。"
