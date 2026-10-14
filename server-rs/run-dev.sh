#!/usr/bin/env bash
# Runs the server for local testing: port 8081, its own database (chatapp_rs) and MinIO bucket,
# with MySQL on 127.0.0.1:3307 and MinIO on 127.0.0.1:9200 (e.g. from `docker compose up -d
# mysql minio`).
set -euo pipefail
cd "$(dirname "$0")"
# Read ../.env without evaluating it (values such as tcp(host:port) are not shell syntax).
while IFS='=' read -r key value; do
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] && export "$key=$value"
done < ../.env
export CHATAPP_MYSQL_DSN="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(127.0.0.1:3307)/chatapp_rs"
export CHATAPP_MINIO_ENDPOINT="${CHATAPP_RS_MINIO_ENDPOINT:-127.0.0.1:9200}"
export CHATAPP_MINIO_BUCKET=chatapp-rs-attachments
export CHATAPP_LISTEN_ADDR="${CHATAPP_RS_LISTEN_ADDR:-127.0.0.1:8081}"
export CHATAPP_DISABLE_RATE_LIMITS=true
export CHATAPP_SMS_PROVIDER=log
export CHATAPP_LOG_LEVEL="${CHATAPP_RS_LOG_LEVEL:-${CHATAPP_LOG_LEVEL:-info}}"
exec cargo run ${CHATAPP_RS_RELEASE:+--release}
