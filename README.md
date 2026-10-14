# Dialog server

The server of [Dialog](https://dialog.pm), an end-to-end encrypted messenger. It relays
ciphertext only: accounts, devices and pre-keys, the encrypted message queue, encrypted
attachments (S3-compatible storage), presence, private groups (zkgroup), key transparency, push
wake-ups (FCM / APNs VoIP, without content) and TURN credentials for calls. Messages are
encrypted on the users' devices; the server cannot read them.

Written in Rust (axum, sqlx, MySQL 8, S3/MinIO). The clients:
[DialogPM/desktop](https://github.com/DialogPM/desktop) and
[DialogPM/dialog.app](https://github.com/DialogPM/dialog.app) (Android, iOS).

- `server-rs/` — the server (`src/`, SQL `migrations/`, `.sqlx/` offline query data)
- `docker-compose.yml`, `.env.example` — a complete stack: MySQL, MinIO, the server, coturn
- `docs/` — the HTTP/WebSocket API, push setup, key transparency, private groups

## Quick start

```bash
cp .env.example .env      # set the secrets: CHATAPP_SERVER_SECRET, MySQL and MinIO passwords
docker compose up -d --build
curl -s http://127.0.0.1:8080/v1/info
```

Then put a TLS reverse proxy in front of it (below) and point the apps at your domain
(`CHATAPP_DEFAULT_SERVER` when building them, or "Change server" at sign-up).

## Development

```bash
docker compose up -d mysql minio        # or your own MySQL 8 and S3 endpoint
cd server-rs
SQLX_OFFLINE=true cargo test --bins     # unit tests
./run-dev.sh                            # the server on 127.0.0.1:8081 (reads ../.env)
```

## Docker

`server-rs/Dockerfile` is a multi-stage build producing the `chatserver` binary on
`gcr.io/distroless/cc-debian12:nonroot` (runs as UID 65532, no shell). The image has a
`HEALTHCHECK` that runs `chatserver -healthcheck` (probes `GET /healthz`, which also pings
MySQL).

The repository root has a `docker-compose.yml` with MySQL 8.4, MinIO (with console) and the
server:

```sh
cp .env.example .env        # edit all secrets!
docker compose up -d --build
docker compose logs -f server
curl http://127.0.0.1:8080/v1/info
```

- The server is published on `CHATAPP_PUBLISH` (default `127.0.0.1:8080`) for a reverse proxy
  on the same host.
- The MinIO console is at <http://127.0.0.1:9001> (log in with the MinIO access/secret key).
- Data lives in the `mysql-data` and `minio-data` volumes.

## Configuration

All configuration is via environment variables (see also [`.env.example`](../.env.example)).

| Variable | Default | Description |
|---|---|---|
| `CHATAPP_SERVER_SECRET` | **required** | Random secret, at least 32 characters. |
| `CHATAPP_MYSQL_DSN` | **required** | go-sql-driver DSN, e.g. `user:pass@tcp(host:3306)/chatapp`. `parseTime`, utf8mb4 and UTC are forced. |
| `CHATAPP_MINIO_ACCESS_KEY` | **required** | MinIO / S3 access key. |
| `CHATAPP_MINIO_SECRET_KEY` | **required** | MinIO / S3 secret key. |
| `CHATAPP_LISTEN_ADDR` | `:8080` | HTTP listen address. |
| `CHATAPP_MINIO_ENDPOINT` | `localhost:9000` | MinIO / S3 endpoint (`host:port`, no scheme). |
| `CHATAPP_MINIO_BUCKET` | `chatapp-attachments` | Bucket; created at startup if missing. |
| `CHATAPP_MINIO_USE_SSL` | `false` | Use HTTPS to reach MinIO. |
| `CHATAPP_MINIO_REGION` | *(empty)* | Optional S3 region. |
| `CHATAPP_SERVER_NAME` | `Dialog` | Name reported by `GET /v1/info`. |
| `CHATAPP_REGISTRATION_ENABLED` | `true` | Allow `POST /v1/accounts`. |
| `CHATAPP_MAX_DEVICES` | `6` | Devices per account (1..127). |
| `CHATAPP_MAX_GROUP_MEMBERS` | `256` | Members per group, including the creator. |
| `CHATAPP_ATTACHMENT_MAX_BYTES` | `104857600` | Max attachment size (100 MiB). |
| `CHATAPP_ATTACHMENT_TTL_DAYS` | `30` | Lifetime of `kind=message` attachments. |
| `CHATAPP_ATTACHMENT_DAILY_BYTES` | `2147483648` | Upload quota per account and 24 hours (`429 quota_exceeded` beyond it). |
| `CHATAPP_MESSAGE_TTL_DAYS` | `30` | Lifetime of unacknowledged envelopes. |
| `CHATAPP_VAULT_QUOTA_BYTES` | `1073741824` | Vault quota per account (1 GiB). |
| `CHATAPP_SMS_PROVIDER` | `log` | `log` (print codes to the log), `twilio` or `none` (disables phone verification). |
| `CHATAPP_TWILIO_ACCOUNT_SID` | | Twilio account SID (twilio provider). |
| `CHATAPP_TWILIO_AUTH_TOKEN` | | Twilio auth token (twilio provider). |
| `CHATAPP_TWILIO_FROM` | | Sender number in E.164 (twilio provider). |
| `CHATAPP_FCM_CREDENTIALS_FILE` | *(empty)* | Firebase service account JSON for mobile push (see "Push notifications"). Empty disables push. |
| `CHATAPP_TRUSTED_PROXY_HEADER` | *(empty)* | Header carrying the client IP set by your reverse proxy (`X-Forwarded-For` uses the right-most entry, or `X-Real-IP`). Only set it if the server is reachable exclusively through the proxy. |
| `CHATAPP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `CHATAPP_LOG_FORMAT` | `text` | `text` or `json`. |

Tokens, auth keys, message contents and query strings are never logged.

## Push notifications

Mobile apps are suspended in the background, so when an envelope is stored for a device with
no open WebSocket the server sends a content-free "new message" wake-up through Firebase
Cloud Messaging (HTTP v1 API). Android is reached directly, iOS through FCM's APNs
integration. Clients register their FCM token with `PUT /v1/devices/current/push` (API
section 14).

Setup:

1. Create (or open) a project in the [Firebase console](https://console.firebase.google.com/)
   and add the Android and iOS apps to it.
2. **Service account key**: Firebase console → ⚙ *Project settings* → *Service accounts* →
   *Firebase Admin SDK* → **Generate new private key**. This downloads a JSON file
   (`"type": "service_account"`, with `project_id`, `client_email`, `private_key`). Treat it
   as a secret: it can send pushes to all your users. Never commit it.
3. **iOS**: FCM can only reach iPhones if an APNs key is uploaded: create an APNs
   *Authentication Key* (.p8) in the Apple Developer account (*Certificates, Identifiers &
   Profiles* → *Keys*, enable "Apple Push Notifications service"), then upload it in
   Firebase → *Project settings* → **Cloud Messaging** → *Apple app configuration* → *APNs
   Authentication Key* (with the Key ID and your Team ID).
4. Point `CHATAPP_FCM_CREDENTIALS_FILE` at the JSON file and restart. With docker compose:

   ```sh
   mkdir -p secrets
   cp ~/Downloads/<project>-firebase-adminsdk-*.json secrets/fcm-service-account.json
   chmod 644 secrets/fcm-service-account.json   # the container runs as UID 65532
   echo 'CHATAPP_FCM_CREDENTIALS_FILE=/run/secrets/chatapp/fcm-service-account.json' >> .env
   docker compose up -d
   ```

   (`./secrets` is mounted read-only at `/run/secrets/chatapp`; override the host directory
   with `CHATAPP_SECRETS_DIR`.) The startup log shows `push notifications enabled` with the
   project id, and `GET /v1/info` returns `"push_enabled": true`. An unreadable or invalid
   file makes the server refuse to start.

Behaviour:

- Access tokens are obtained with a JWT signed by the service account key (OAuth2 JWT
  bearer flow), cached and refreshed before they expire. The server needs outbound HTTPS to
  `oauth2.googleapis.com` and `fcm.googleapis.com`.
- Pushes are sent asynchronously by a small worker pool with a bounded queue: sending a
  message never waits for FCM (when the queue is full the push is dropped and logged).
- At most one push per device every 15 s (bursts are coalesced); `online=true` (ephemeral)
  messages and devices with an open WebSocket are never pushed.
- 5xx / 429 responses and network errors are retried with exponential backoff (honouring
  `Retry-After`); `UNREGISTERED` / `INVALID_ARGUMENT` clear the device's token.
- Tokens, the key and message contents are never logged (only account/device ids and FCM
  error codes).

## Voice calls (TURN)

Calls are WebRTC between the two devices (DTLS-SRTP, end-to-end encrypted); the signaling
goes through the normal encrypted message channel. Devices behind NAT or strict firewalls
need a TURN relay, otherwise many calls cannot connect. The relay only forwards encrypted
packets.

1. In `.env`:
   ```
   CHATAPP_TURN_SECRET=<openssl rand -base64 32>
   CHATAPP_TURN_URLS=turn:chat.example.com:3478?transport=udp,turn:chat.example.com:3478?transport=tcp
   ```
2. `docker compose --profile calls up -d` starts coturn (host network) with the same secret.
3. Open `3478/udp`, `3478/tcp` and `49160-49400/udp` in the firewall. Behind NAT, add
   `--external-ip=<public ip>` to the coturn command in `docker-compose.yml`.

Clients get short-lived credentials from `GET /v1/calls/ice` (coturn "use-auth-secret":
username `<expiry>:<tag>`, password `base64(HMAC-SHA1(secret, username))`, valid for
`CHATAPP_TURN_TTL_SECONDS`, default 1 h, rounded up to 10 minutes). The tag is a truncated
HMAC-SHA256 of the account id and the expiry: coturn logs usernames next to client IPs, and
must not be able to tell which account used the relay; the tag changes every window. The
bundled coturn refuses to relay to private and loopback addresses and enforces quotas
(`--user-quota=12` allocations per credential, `--total-quota=1200`, `--max-bps=375000`
≈ 3 Mbit/s per session; adjust in `docker-compose.yml` to the server's bandwidth).
`/v1/info` reports `turn_enabled`.

## Deployment behind a TLS reverse proxy

The server speaks plain HTTP; terminate TLS in a reverse proxy. The proxy must support
WebSocket upgrades on `/v1/ws`, must not buffer attachment uploads/downloads, and must allow
request bodies of at least `CHATAPP_ATTACHMENT_MAX_BYTES`.

Caddy (automatic HTTPS; WebSockets are proxied transparently):

```caddyfile
chat.example.com {
	encode zstd gzip

	# Attachments can be up to 100 MiB (plus some slack).
	request_body {
		max_size 110MB
	}

	reverse_proxy 127.0.0.1:8080 {
		# Replace X-Forwarded-For with the real client address; the server is configured
		# with CHATAPP_TRUSTED_PROXY_HEADER=X-Forwarded-For and uses the right-most entry.
		header_up X-Forwarded-For {remote_host}
		# Stream request/response bodies (attachments) instead of buffering them.
		flush_interval -1
	}
}
```

Then set in `.env`:

```sh
CHATAPP_TRUSTED_PROXY_HEADER=X-Forwarded-For
CHATAPP_PUBLISH=127.0.0.1:8080
```

Notes:

- WebSocket connections are long-lived; the server pings every 30 s and drops dead sockets
  after 75 s, so proxy idle timeouts must be above ~90 s (Caddy has none by default; for nginx
  set `proxy_read_timeout 120s` and `proxy_set_header Upgrade/Connection`).
- Clients that cannot set headers on the WebSocket handshake pass `?token=`; make sure your
  proxy does not log query strings (Caddy's access log does by default if enabled).
- Expose the MinIO API only on the internal network; clients never talk to MinIO directly.

## Operational notes

- **Background jobs** run every 10 minutes: expire unacknowledged envelopes, delete expired
  `message` attachments (object + row) and uploads that never completed within 24 h, and
  clean expired recovery challenges and phone codes.
- **Graceful shutdown** on SIGINT/SIGTERM: stop accepting requests, finish in-flight
  requests (20 s), close WebSockets with "going away", stop the jobs.
- **Scaling**: WebSocket routing, presence and rate limits are process-local. Run a single
  instance (it comfortably handles many thousands of connections); scaling out would need a
  pub/sub bus between instances.
- **Backups**: back up MySQL (e.g. `mysqldump --single-transaction`) and the MinIO bucket.
- **Spam reports / bans** (Rust server binary only, run with the server's environment; it
  applies pending migrations first and prints plain text):
  - `chatserver reports list [--all] [--limit N]`: open reports (all with `--all`), newest
    first, with id, reporter, reported account, count, attached message ids, dates, status.
  - `chatserver reports resolve <id>`: marks a report resolved (a new report from the same
    reporter reopens it).
  - `chatserver reports ban-account <account_id>`: bans the account (`accounts.banned_at`):
    its tokens stop working, all device sessions and push tokens are revoked, new logins and
    device links are refused, open reports against it are resolved, and the running server
    closes its WebSockets within 10 minutes. Data is kept; lift a ban with
    `UPDATE accounts SET banned_at = NULL` (the user then logs in again).

## License

[GNU Affero General Public License v3.0](LICENSE).
