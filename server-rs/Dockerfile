# syntax=docker/dockerfile:1
# Dialog server (Rust). Same configuration, schema and API as ../server (Go).

# ---- build stage ------------------------------------------------------------
FROM rust:1-bookworm AS build
# protoc: libsignal's build scripts generate protobuf code.
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# sqlx::query! macros check queries against .sqlx/ (no database during the build).
ENV SQLX_OFFLINE=true
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/chatserver /chatserver

# ---- runtime stage ----------------------------------------------------------
# Distroless with glibc/libgcc: no shell, no package manager. TLS roots are built into the
# binary (rustls + webpki roots).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /chatserver /usr/local/bin/chatserver

# 65532 = nonroot in distroless images.
USER 65532:65532
ENV CHATAPP_LISTEN_ADDR=:8080
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/chatserver", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/chatserver"]
