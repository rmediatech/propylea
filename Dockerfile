# ==============================================================================
# Propylea (Προπύλαια) — Production Multi-Stage Dockerfile
# Sovereign Ultra-Low-Memory L7 Reverse Proxy, Multi-Domain SNI TLS Multiplexer
# & Active Perimeter Defense Gateway in Pure Rust
# ==============================================================================

# Build Stage
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev perl make

WORKDIR /usr/src/propylea

# Copy dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build static release binary with Musl
RUN cargo build --release

# Runtime Stage — Minimal hardened unprivileged image (<25MB)
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S propylea && adduser -S propylea -G propylea

WORKDIR /etc/propylea

# Copy binary from builder
COPY --from=builder /usr/src/propylea/target/release/propylea /usr/local/bin/propylea

# Copy default config template
COPY propylea.example.toml /etc/propylea/propylea.toml

# Set permissions
RUN chown -R propylea:propylea /etc/propylea

USER propylea

# HTTP (80), HTTPS (443), MeshSync Port (9443)
EXPOSE 80 443 9443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:80/healthz || exit 1

ENTRYPOINT ["propylea"]
CMD ["serve", "--config", "/etc/propylea/propylea.toml"]
