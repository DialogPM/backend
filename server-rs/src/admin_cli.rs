//! Operator commands run with the server binary instead of starting the server:
//!
//! ```text
//! chatserver reports list [--all] [--limit N]   open spam reports (all with --all), newest first
//! chatserver reports resolve <id>               marks a report resolved
//! chatserver reports ban-account <account_id>   bans an account (see `ban_account`)
//! ```
//!
//! They use the same environment (CHATAPP_MYSQL_DSN, ...) and database as the server, apply
//! pending migrations first, and print plain text.

use sqlx::{MySqlPool, Row};

use crate::config::Config;
use crate::db::{self, RowExt};
use crate::ids;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 10_000;

pub const USAGE: &str = "usage:
  chatserver reports list [--all] [--limit N]
  chatserver reports resolve <id>
  chatserver reports ban-account <account_id>";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    List { all: bool, limit: i64 },
    Resolve { id: u64 },
    BanAccount { account: String },
}

/// Parses the arguments after the program name. `Ok(None)`: not an admin command (normal
/// server startup and its flags).
pub fn parse(args: &[String]) -> Result<Option<Command>, String> {
    let Some(first) = args.first() else {
        return Ok(None);
    };
    if first != "reports" {
        return Ok(None);
    }
    let rest = &args[1..];
    match rest.first().map(String::as_str) {
        Some("list") => {
            let (mut all, mut limit) = (false, DEFAULT_LIMIT);
            let mut it = rest[1..].iter();
            while let Some(a) = it.next() {
                let (name, inline) = match a.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (a.as_str(), None),
                };
                match name.trim_start_matches('-') {
                    "all" if a.starts_with('-') && inline.is_none() => all = true,
                    "limit" if a.starts_with('-') => {
                        let v = inline
                            .or_else(|| it.next().cloned())
                            .ok_or("--limit needs a value")?;
                        limit = v
                            .parse::<i64>()
                            .ok()
                            .filter(|n| (1..=MAX_LIMIT).contains(n))
                            .ok_or_else(|| format!("--limit must be between 1 and {MAX_LIMIT}"))?;
                    }
                    _ => return Err(format!("unknown argument {a:?}")),
                }
            }
            Ok(Some(Command::List { all, limit }))
        }
        Some("resolve") => match &rest[1..] {
            [id] => id
                .parse::<u64>()
                .map(|id| Some(Command::Resolve { id }))
                .map_err(|_| format!("invalid report id {id:?}")),
            _ => Err("reports resolve takes exactly one report id".into()),
        },
        Some("ban-account") => match &rest[1..] {
            [acct] => ids::normalize_uuid(acct)
                .map(|account| Some(Command::BanAccount { account }))
                .ok_or_else(|| format!("invalid account id {acct:?} (expected a UUID)")),
            _ => Err("reports ban-account takes exactly one account id".into()),
        },
        Some(other) => Err(format!("unknown reports command {other:?}")),
        None => Err("missing reports command".into()),
    }
}

/// Runs the command against the configured database.
pub async fn run(cmd: Command) -> Result<(), String> {
    let cfg = Config::from_env().map_err(|e| format!("configuration: {e}"))?;
    let pool = db::open(&cfg.mysql_dsn)
        .await
        .map_err(|e| format!("database: {e}"))?;
    db::migrate(&pool)
        .await
        .map_err(|e| format!("migrations: {e}"))?;
    let out = match cmd {
        Command::List { all, limit } => list(&pool, all, limit).await,
        Command::Resolve { id } => resolve(&pool, id).await,
        Command::BanAccount { account } => ban_account(&pool, &account).await,
    }
    .map_err(|e| format!("database: {e}"))?;
    print!("{out}");
    pool.close().await;
    Ok(())
}

struct ReportRow {
    id: u64,
    reporter: String,
    reported: String,
    count: i64,
    envelopes: usize,
    created_at: i64,
    updated_at: i64,
    resolved_at: Option<i64>,
    reported_banned: bool,
}

async fn list(pool: &MySqlPool, all: bool, limit: i64) -> Result<String, sqlx::Error> {
    let filter = if all { "" } else { "WHERE r.resolved_at IS NULL" };
    let rows = sqlx::query(&format!(
        "SELECT r.id, r.reporter_id, r.reported_id, r.envelope_ids, r.report_count, r.created_at,
                r.updated_at, r.resolved_at, a.banned_at
         FROM spam_reports r LEFT JOIN accounts a ON a.id = r.reported_id
         {filter} ORDER BY r.updated_at DESC, r.id DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let reports = rows
        .iter()
        .map(|r| ReportRow {
            id: r.try_get::<u64, _>("id").unwrap_or_default(),
            reporter: r.string("reporter_id"),
            reported: r.string("reported_id"),
            count: r.try_get::<u32, _>("report_count").map(i64::from).unwrap_or_default(),
            envelopes: r
                .opt_string("envelope_ids")
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .map_or(0, |v| v.len()),
            created_at: r.i64("created_at"),
            updated_at: r.i64("updated_at"),
            resolved_at: r.opt_i64("resolved_at"),
            reported_banned: r.opt_i64("banned_at").is_some(),
        })
        .collect::<Vec<_>>();
    Ok(format_reports(&reports, all))
}

fn format_reports(reports: &[ReportRow], all: bool) -> String {
    if reports.is_empty() {
        return if all { "no spam reports\n" } else { "no open spam reports\n" }.into();
    }
    let mut out = format!(
        "{:>6}  {:<36}  {:<36}  {:>5}  {:>4}  {:<20}  {:<20}  {}\n",
        "ID", "REPORTER", "REPORTED", "COUNT", "MSGS", "CREATED", "UPDATED", "STATUS"
    );
    for r in reports {
        let mut status = match r.resolved_at {
            Some(t) => format!("resolved {}", fmt_time(t)),
            None => "open".to_string(),
        };
        if r.reported_banned {
            status.push_str(" (account banned)");
        }
        out.push_str(&format!(
            "{:>6}  {:<36}  {:<36}  {:>5}  {:>4}  {:<20}  {:<20}  {}\n",
            r.id,
            r.reporter,
            r.reported,
            r.count,
            r.envelopes,
            fmt_time(r.created_at),
            fmt_time(r.updated_at),
            status
        ));
    }
    out
}

async fn resolve(pool: &MySqlPool, id: u64) -> Result<String, sqlx::Error> {
    let now = crate::now_millis();
    let res = sqlx::query!(
        "UPDATE spam_reports SET resolved_at = ?, resolution = 'dismissed' WHERE id = ? AND resolved_at IS NULL",
        now,
        id
    )
    .execute(pool)
    .await?;
    if res.rows_affected() > 0 {
        return Ok(format!("report {id} resolved\n"));
    }
    let exists = sqlx::query!("SELECT id FROM spam_reports WHERE id = ?", id)
        .fetch_optional(pool)
        .await?;
    Ok(match exists {
        Some(_) => format!("report {id} was already resolved\n"),
        None => format!("report {id} not found\n"),
    })
}

/// Bans an account (see `admin::moderation::ban_account`). Open WebSockets are closed by the
/// running server's maintenance job (within its 10-minute interval); the ban can be lifted
/// with the admin API (POST /v1/admin/accounts/{id}/unban).
async fn ban_account(pool: &MySqlPool, account: &str) -> Result<String, sqlx::Error> {
    Ok(match crate::admin::moderation::ban_account(pool, account, None).await? {
        None => format!("account {account} not found\n"),
        Some(o) => format!(
            "account {account} {}; {} device session(s) revoked, {} open report(s) resolved\n",
            if o.already_banned { "was already banned" } else { "banned" },
            o.devices,
            o.reports_resolved
        ),
    })
}

/// Unix milliseconds as "YYYY-MM-DD HH:MM:SS" (UTC).
fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn non_admin_arguments_start_the_server() {
        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&args("-healthcheck")), Ok(None));
    }

    #[test]
    fn parses_list() {
        assert_eq!(parse(&args("reports list")), Ok(Some(Command::List { all: false, limit: DEFAULT_LIMIT })));
        assert_eq!(parse(&args("reports list --all --limit 5")), Ok(Some(Command::List { all: true, limit: 5 })));
        assert_eq!(parse(&args("reports list -limit=7")), Ok(Some(Command::List { all: false, limit: 7 })));
        assert!(parse(&args("reports list --limit 0")).is_err());
        assert!(parse(&args("reports list --limit")).is_err());
        assert!(parse(&args("reports list extra")).is_err());
    }

    #[test]
    fn parses_resolve_and_ban() {
        assert_eq!(parse(&args("reports resolve 42")), Ok(Some(Command::Resolve { id: 42 })));
        assert!(parse(&args("reports resolve x")).is_err());
        assert!(parse(&args("reports resolve")).is_err());
        let id = "0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11";
        assert_eq!(
            parse(&args(&format!("reports ban-account {}", id.to_uppercase()))),
            Ok(Some(Command::BanAccount { account: id.into() }))
        );
        assert!(parse(&args("reports ban-account nope")).is_err());
        assert!(parse(&args("reports")).is_err());
        assert!(parse(&args("reports delete 1")).is_err());
    }

    #[test]
    fn formats_times_in_utc() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00");
        assert_eq!(fmt_time(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(fmt_time(1_790_000_000_123), "2026-09-21 14:13:20");
    }

    #[test]
    fn formats_report_table() {
        assert_eq!(format_reports(&[], false), "no open spam reports\n");
        let out = format_reports(
            &[ReportRow {
                id: 3,
                reporter: "a".into(),
                reported: "b".into(),
                count: 2,
                envelopes: 1,
                created_at: 0,
                updated_at: 0,
                resolved_at: None,
                reported_banned: true,
            }],
            false,
        );
        assert!(out.starts_with("    ID  REPORTER"));
        assert!(out.contains("     3  a "));
        assert!(out.trim_end().ends_with("open (account banned)"));
    }
}
