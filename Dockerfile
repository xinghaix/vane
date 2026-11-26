# Stage 1: 构建 Svelte 5 (Runes) 前端与 .br/.gz 预压缩静态包
# 固定基础镜像精确补丁版本，避免可变浮动标签引入供应链漂移（生产建议进一步固定 @sha256 摘要）
FROM --platform=$BUILDPLATFORM node:22.14-alpine3.21 AS web-builder
WORKDIR /src/web-ui
COPY web-ui/package.json web-ui/package-lock.json ./
RUN npm ci
COPY web-ui/ ./
RUN npm run build

# Stage 2: 构建 Rust 单静态二进制
FROM rust:1.85-alpine3.21 AS rust-builder
RUN apk add --no-cache musl-dev make perl
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY config.example.toml ./config.example.toml
COPY --from=web-builder /src/web-ui/dist ./web-ui/dist
RUN cargo build --release --locked

# Stage 3: 极简安全运行时镜像（含双栈 nftables / iptables / conntrack 工具）
FROM alpine:3.20.6
RUN apk add --no-cache \
    nftables \
    iptables \
    iptables-legacy \
    ip6tables \
    conntrack-tools \
    ca-certificates \
    tzdata \
    && addgroup -g 10001 -S vane \
    && adduser -u 10001 -S -G vane -H -s /sbin/nologin vane \
    && mkdir -p /data/vane \
    && chown vane:vane /data/vane \
    && chmod 0700 /data/vane

COPY --from=rust-builder /src/target/release/vane /usr/local/bin/vane
EXPOSE 23456
VOLUME ["/data/vane"]

# 权限说明（非 Root 与 NET_ADMIN 权衡）：
# 1) 默认保持 UID 0（配合 docker-compose 中 cap_drop: ALL + 仅保留 NET_ADMIN / NET_BIND_SERVICE），
#    以便调用 nftables / iptables / conntrack 自动管理防火墙与绑定 <1024 特权端口（Docker 默认不会为非 Root 用户开启 Ambient Capabilities）。
# 2) 若部署模式关闭自动防火墙管理（firewall.auto_manage = false）且仅监听 >=1024 端口，
#    强烈建议取消下方 USER 行注释，或在 docker-compose.yml 中设置 `user: "10001:10001"` 并彻底移除 NET_ADMIN / NET_BIND_SERVICE。
# USER vane

ENTRYPOINT ["/usr/local/bin/vane"]
CMD ["run", "--config", "/data/vane/config.toml"]
