# Stage 1: 构建 Svelte 5 (Runes) 前端与 .br/.gz 预压缩静态包
FROM --platform=$BUILDPLATFORM node:22-alpine AS web-builder
WORKDIR /src/web-ui
COPY web-ui/package.json web-ui/package-lock.json ./
RUN npm ci
COPY web-ui/ ./
RUN npm run build

# Stage 2: 构建 Rust 单静态二进制
FROM rust:1-alpine AS rust-builder
RUN apk add --no-cache musl-dev make perl
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY config.example.toml ./config.example.toml
COPY --from=web-builder /src/web-ui/dist ./web-ui/dist
RUN cargo build --release --locked

# Stage 3: 极简安全运行时镜像（含双栈 nftables / iptables / conntrack 工具）
FROM alpine:3.20
RUN apk add --no-cache \
    nftables \
    iptables \
    iptables-legacy \
    ip6tables \
    conntrack-tools \
    ca-certificates \
    tzdata \
    && mkdir -p /data/vane && chmod 0700 /data/vane

COPY --from=rust-builder /src/target/release/vane /usr/local/bin/vane
EXPOSE 23456
VOLUME ["/data/vane"]
ENTRYPOINT ["/usr/local/bin/vane"]
CMD ["run", "--config", "/data/vane/config.toml"]
