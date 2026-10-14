//! MySQL pool, embedded schema migrations and row helpers.

use std::time::Duration;

use sqlx::mysql::{
    MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlRow, MySqlSslMode,
};
use sqlx::{Connection, MySqlPool, Row};
use tracing::{info, warn};

/// Embedded migrations (identical to the Go server's, so both can share a database).
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (
        1,
        "0001_init.sql",
        include_str!("../migrations/0001_init.sql"),
    ),
    (
        2,
        "0002_push.sql",
        include_str!("../migrations/0002_push.sql"),
    ),
    (
        3,
        "0003_username.sql",
        include_str!("../migrations/0003_username.sql"),
    ),
    (
        4,
        "0004_totp.sql",
        include_str!("../migrations/0004_totp.sql"),
    ),
    (
        5,
        "0005_group_rules.sql",
        include_str!("../migrations/0005_group_rules.sql"),
    ),
    (
        6,
        "0006_sealed_sender.sql",
        include_str!("../migrations/0006_sealed_sender.sql"),
    ),
    (
        7,
        "0007_phone_discoverable.sql",
        include_str!("../migrations/0007_phone_discoverable.sql"),
    ),
    (
        8,
        "0008_group_invites.sql",
        include_str!("../migrations/0008_group_invites.sql"),
    ),
    (
        9,
        "0009_message_requests.sql",
        include_str!("../migrations/0009_message_requests.sql"),
    ),
    (
        10,
        "0010_account_security.sql",
        include_str!("../migrations/0010_account_security.sql"),
    ),
    (
        11,
        "0011_moderation.sql",
        include_str!("../migrations/0011_moderation.sql"),
    ),
    (
        12,
        "0012_username_links.sql",
        include_str!("../migrations/0012_username_links.sql"),
    ),
    (
        13,
        "0013_groups_v2.sql",
        include_str!("../migrations/0013_groups_v2.sql"),
    ),
    (
        14,
        "0014_key_transparency.sql",
        include_str!("../migrations/0014_key_transparency.sql"),
    ),
    (
        15,
        "0015_push_calls.sql",
        include_str!("../migrations/0015_push_calls.sql"),
    ),
    (
        16,
        "0016_admin.sql",
        include_str!("../migrations/0016_admin.sql"),
    ),
    (
        17,
        "0017_device_revocation.sql",
        include_str!("../migrations/0017_device_revocation.sql"),
    ),
];

/// Parses a go-sql-driver style DSN (`user:pass@tcp(host:port)/db?params`) so existing
/// configurations keep working. `mysql://` URLs are accepted as well.
pub fn parse_dsn(dsn: &str) -> Result<MySqlConnectOptions, String> {
    parse_dsn_full(dsn).map(|(o, _)| o)
}

/// go-sql-driver parameters that configure the driver itself (not session variables).
const DRIVER_PARAMS: &[&str] = &[
    "allowAllFiles", "allowCleartextPasswords", "allowFallbackToPlaintext", "allowNativePasswords",
    "allowOldPasswords", "charset", "checkConnLiveness", "collation", "clientFoundRows",
    "columnsWithAlias", "connectionAttributes", "interpolateParams", "loc", "maxAllowedPacket",
    "multiStatements", "parseTime", "readTimeout", "rejectReadOnly", "serverPubKey", "timeTruncate",
    "timeout", "tls", "writeTimeout",
];

/// URL-unescapes a DSN component (Go: url.QueryUnescape / PathUnescape).
fn unescape(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// Parses the DSN; also returns the session variables to SET on every connection (Go's driver
/// sends unknown DSN parameters as system variables, e.g. `sql_mode`, `transaction_isolation`).
pub fn parse_dsn_full(dsn: &str) -> Result<(MySqlConnectOptions, Vec<(String, String)>), String> {
    let mut session = Vec::new();
    let opts = if dsn.starts_with("mysql://") {
        dsn.parse::<MySqlConnectOptions>().map_err(|e| format!("parse mysql url: {e}"))?
    } else {
        let at = dsn.rfind('@').ok_or("dsn: missing '@'")?;
        let (userinfo, rest) = (&dsn[..at], &dsn[at + 1..]);
        let (user, pass) = match userinfo.find(':') {
            Some(i) => (&userinfo[..i], Some(&userinfo[i + 1..])),
            None => (userinfo, None),
        };
        // Like go-sql-driver: the last '/' starts the database name (unix socket paths contain '/').
        let slash = rest.rfind('/').ok_or("dsn: missing '/dbname'")?;
        let (addr, path) = (&rest[..slash], &rest[slash + 1..]);
        let (db, params) = match path.find('?') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (path, ""),
        };
        let mut o = MySqlConnectOptions::new().username(user).database(&unescape(db));
        if let Some(p) = pass {
            o = o.password(p);
        }
        if let Some(inner) = addr.strip_prefix("tcp(").and_then(|a| a.strip_suffix(')')) {
            if !inner.is_empty() {
                // host:port, [v6]:port, or a bare host.
                let (host, port) = if let Some(rest) = inner.strip_prefix('[') {
                    let (h, after) = rest.split_once(']').ok_or("dsn: bad IPv6 address")?;
                    (h, after.strip_prefix(':'))
                } else {
                    match inner.rsplit_once(':') {
                        Some((h, p)) => (h, Some(p)),
                        None => (inner, None),
                    }
                };
                o = o.host(host);
                if let Some(p) = port {
                    o = o.port(p.parse().map_err(|_| "dsn: bad port")?);
                }
            }
        } else if let Some(sock) = addr.strip_prefix("unix(").and_then(|a| a.strip_suffix(')')) {
            o = o.socket(sock);
        } else if !addr.is_empty() {
            return Err(format!("dsn: unsupported network address {addr:?}"));
        }
        // Like the Go driver: plaintext unless tls is requested.
        o = o.ssl_mode(MySqlSslMode::Disabled);
        for kv in params.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = unescape(v);
            match k {
                "tls" => {
                    o = o.ssl_mode(match v.as_str() {
                        "true" => MySqlSslMode::VerifyIdentity,
                        "false" => MySqlSslMode::Disabled,
                        "skip-verify" => MySqlSslMode::Required,
                        "preferred" => MySqlSslMode::Preferred,
                        other => return Err(format!("dsn: unsupported tls config {other:?}")),
                    })
                }
                k if DRIVER_PARAMS.contains(&k) => {}
                k => {
                    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                        return Err(format!("dsn: invalid parameter name {k:?}"));
                    }
                    session.push((k.to_string(), v));
                }
            }
        }
        o
    };
    // The server relies on these regardless of the DSN.
    Ok((opts.charset("utf8mb4").collation("utf8mb4_unicode_ci").timezone(Some(String::from("+00:00"))), session))
}

pub async fn open(dsn: &str) -> Result<MySqlPool, String> {
    let (opts, session) = parse_dsn_full(dsn)?;
    // Same as go-sql-driver: SET <name>=<value> with the raw values, on every new connection.
    // Built once at startup; 'static keeps sqlx's executor lifetimes simple.
    let set_sql: Option<&'static str> = (!session.is_empty()).then(|| {
        let assignments: Vec<String> = session.iter().map(|(k, v)| format!("{k}={v}")).collect();
        &*Box::leak(format!("SET {}", assignments.join(", ")).into_boxed_str())
    });
    MySqlPoolOptions::new()
        .max_connections(50)
        .min_connections(0)
        .max_lifetime(Duration::from_secs(30 * 60))
        .idle_timeout(Duration::from_secs(5 * 60))
        // Go's pool waits for a free connection; wait long rather than fail fast.
        .acquire_timeout(Duration::from_secs(60))
        // A transaction dropped without commit (an early return with `?`) is rolled back by sqlx
        // only on the connection's next use, keeping its row locks until then; Go rolls back at
        // once. Touch the connection when it is released so the ROLLBACK goes out immediately.
        // Every connection goes back to the pool with no transaction open. A request cancelled
        // at the wrong moment (client gone mid-request, e.g. a phone switching networks) can
        // leave one open on the server side while sqlx believes it is closed; the next users of
        // the connection would then run inside it, their writes never committed and its row
        // locks held for good. ROLLBACK is a no-op otherwise, and doubles as the liveness check.
        .after_release(|conn, _| {
            Box::pin(async move {
                use sqlx::Executor;
                Ok(conn.execute("ROLLBACK").await.is_ok())
            })
        })
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if let Some(q) = set_sql {
                    use sqlx::Executor;
                    conn.execute(q).await?;
                }
                Ok(())
            })
        })
        .connect_with(opts)
        .await
        .map_err(|e| format!("mysql connect: {e}"))
}

/// Opens the pool, retrying until `deadline` (MySQL may start at the same time as the server).
pub async fn open_with_retry(dsn: &str, deadline: Duration) -> Result<MySqlPool, String> {
    let start = tokio::time::Instant::now();
    let mut delay = Duration::from_secs(1);
    loop {
        match open(dsn).await {
            Ok(p) => return Ok(p),
            Err(e) if start.elapsed() + delay < deadline => {
                warn!(error = %e, retry_in = ?delay, "database not ready, retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Splits a migration file into statements: a statement ends with ';' at the end of a line;
/// full-line "--" comments are dropped.
fn split_statements(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("--") {
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
        if t.ends_with(';') {
            let s = cur.trim().trim_end_matches(';').trim().to_string();
            if !s.is_empty() {
                out.push(s);
            }
            cur.clear();
        }
    }
    let s = cur.trim().to_string();
    if !s.is_empty() {
        out.push(s);
    }
    out
}

/// Applies pending migrations under a MySQL named lock (several instances may start at once).
pub async fn migrate(pool: &MySqlPool) -> Result<(), String> {
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let got: Option<i64> = sqlx::query_scalar!("SELECT GET_LOCK('chatapp_migrations', 60)")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("acquire migration lock: {e}"))?;
    if got != Some(1) {
        return Err("could not acquire migration lock".into());
    }
    let result = async {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INT NOT NULL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at BIGINT NOT NULL
            ) ENGINE=InnoDB",
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("create schema_migrations: {e}"))?;
        let applied: Vec<i64> = sqlx::query!("SELECT version AS `version: i64` FROM schema_migrations")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|r| r.version)
            .collect();
        for (version, name, sql) in MIGRATIONS {
            if applied.contains(version) {
                continue;
            }
            info!(version, name, "applying migration");
            // MySQL DDL is not transactional; each statement commits implicitly.
            for (i, stmt) in split_statements(sql).iter().enumerate() {
                sqlx::raw_sql(stmt)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| format!("migration {name} statement {}: {e}", i + 1))?;
            }
            sqlx::query!(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                version,
                name,
                crate::now_millis()
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("record migration {name}: {e}"))?;
        }
        Ok::<(), String>(())
    }
    .await;
    let _ = sqlx::query!("SELECT RELEASE_LOCK('chatapp_migrations') AS released")
        .fetch_one(&mut *conn)
        .await;
    result
}

fn mysql_code(err: &sqlx::Error) -> Option<u16> {
    match err {
        sqlx::Error::Database(e) => e
            .try_downcast_ref::<MySqlDatabaseError>()
            .map(|m| m.number()),
        _ => None,
    }
}

/// MySQL duplicate-key error (1062).
pub fn is_duplicate_key(err: &sqlx::Error) -> bool {
    mysql_code(err) == Some(1062)
}

/// MySQL foreign key violation on insert/update (1452).
pub fn is_foreign_key_violation(err: &sqlx::Error) -> bool {
    mysql_code(err) == Some(1452)
}

/// Deadlock (1213) or lock wait timeout (1205).
pub fn is_retryable(err: &sqlx::Error) -> bool {
    matches!(mysql_code(err), Some(1213) | Some(1205))
}

pub async fn ping(pool: &MySqlPool) -> bool {
    match pool.acquire().await {
        Ok(mut c) => c.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// Typed column access that tolerates the schema's signed/unsigned and binary-collation
/// columns (sqlx is strict about both). Panics on a missing column or NULL in a non-Option
/// accessor, which is a programming error (caught by the panic middleware).
pub trait RowExt {
    fn i64(&self, col: &str) -> i64;
    fn opt_i64(&self, col: &str) -> Option<i64>;
    fn string(&self, col: &str) -> String;
    fn opt_string(&self, col: &str) -> Option<String>;
    fn bytes(&self, col: &str) -> Vec<u8>;
    fn opt_bytes(&self, col: &str) -> Option<Vec<u8>>;
    fn boolean(&self, col: &str) -> bool;
}

impl RowExt for MySqlRow {
    fn i64(&self, col: &str) -> i64 {
        self.opt_i64(col)
            .unwrap_or_else(|| panic!("column {col} is NULL"))
    }
    fn opt_i64(&self, col: &str) -> Option<i64> {
        if let Ok(v) = self.try_get::<Option<i64>, _>(col) {
            return v;
        }
        if let Ok(v) = self.try_get::<Option<u64>, _>(col) {
            return v.map(|x| x as i64);
        }
        if let Ok(v) = self.try_get::<Option<i32>, _>(col) {
            return v.map(i64::from);
        }
        if let Ok(v) = self.try_get::<Option<u32>, _>(col) {
            return v.map(i64::from);
        }
        if let Ok(v) = self.try_get::<Option<i8>, _>(col) {
            return v.map(i64::from);
        }
        if let Ok(v) = self.try_get::<Option<u8>, _>(col) {
            return v.map(i64::from);
        }
        if let Ok(v) = self.try_get::<Option<bool>, _>(col) {
            return v.map(i64::from);
        }
        // DECIMAL results (e.g. SUM over BIGINT) arrive as decimal strings, which sqlx only
        // decodes into String when the type check is skipped.
        if let Ok(v) = self.try_get_unchecked::<Option<String>, _>(col) {
            return v.and_then(|s| s.split('.').next()?.trim().parse().ok());
        }
        panic!("column {col}: not an integer")
    }
    fn string(&self, col: &str) -> String {
        self.opt_string(col)
            .unwrap_or_else(|| panic!("column {col} is NULL"))
    }
    fn opt_string(&self, col: &str) -> Option<String> {
        if let Ok(v) = self.try_get::<Option<String>, _>(col) {
            return v;
        }
        match self.try_get::<Option<Vec<u8>>, _>(col) {
            Ok(v) => v.map(|b| String::from_utf8_lossy(&b).into_owned()),
            Err(e) => panic!("column {col}: {e}"),
        }
    }
    fn bytes(&self, col: &str) -> Vec<u8> {
        self.opt_bytes(col)
            .unwrap_or_else(|| panic!("column {col} is NULL"))
    }
    fn opt_bytes(&self, col: &str) -> Option<Vec<u8>> {
        if let Ok(v) = self.try_get::<Option<Vec<u8>>, _>(col) {
            return v;
        }
        match self.try_get::<Option<String>, _>(col) {
            Ok(v) => v.map(String::into_bytes),
            Err(e) => panic!("column {col}: {e}"),
        }
    }
    fn boolean(&self, col: &str) -> bool {
        self.i64(col) != 0
    }
}

/// Runs a transactional unit up to 3 times while it fails on a deadlock / lock wait timeout
/// (Go's InTx). Use it where the request has single-use side effects before the transaction
/// (so the request-level retry in api::retry_deadlocks must not replay it).
pub async fn retry_tx<T, F, Fut>(mut unit: F) -> Result<T, crate::error::ApiError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, crate::error::ApiError>>,
{
    let mut attempt = 0u64;
    loop {
        match unit().await {
            Err(e) if e.retryable && attempt < 2 => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(20 * attempt)).await;
            }
            Err(mut e) => {
                e.retryable = false;
                return Err(e);
            }
            Ok(v) => return Ok(v),
        }
    }
}

/// "?, ?, ?" with n placeholders.
pub fn placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn() {
        assert!(parse_dsn("chatapp:p@ss:w@tcp(127.0.0.1:3307)/chatapp?parseTime=true").is_ok());
        assert!(parse_dsn("mysql://u:p@localhost:3306/db").is_ok());
        assert!(parse_dsn("nonsense").is_err());
    }

    #[test]
    fn dsn_go_semantics() {
        let (o, vars) = parse_dsn_full("u:p@tcp([::1]:3307)/my%2Ddb?tls=skip-verify&sql_mode=%27STRICT_ALL_TABLES%27&parseTime=true").unwrap();
        assert_eq!(o.get_host(), "::1");
        assert_eq!(o.get_port(), 3307);
        assert_eq!(o.get_database(), Some("my-db"));
        assert_eq!(vars, vec![("sql_mode".to_string(), "'STRICT_ALL_TABLES'".to_string())]);
        assert!(parse_dsn("u:p@tcp(h:1)/d?tls=bogus").is_err());
        assert!(parse_dsn("u:p@unix(/tmp/mysql.sock)/d").is_ok());
    }

    #[test]
    fn migrations_list_matches_directory() {
        let mut files: Vec<String> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        files.sort();
        let listed: Vec<&str> = MIGRATIONS.iter().map(|m| m.1).collect();
        assert_eq!(files, listed, "add new migration files to MIGRATIONS");
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.0, i as i64 + 1);
            assert!(m.1.starts_with(&format!("{:04}_", m.0)));
        }
    }

    #[test]
    fn statements() {
        let s =
            split_statements("-- c\nCREATE TABLE a (\n x INT\n);\n\nINSERT INTO a VALUES (1);\n");
        assert_eq!(s.len(), 2);
        assert!(s[0].starts_with("CREATE TABLE a"));
    }
}
