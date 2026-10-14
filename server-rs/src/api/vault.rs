//! Encrypted record vault (API section 10).

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::keys::null_default;
use super::{query_int, reply};
use crate::auth::Principal;
use crate::db::{placeholders, RowExt};
use crate::error::{bad_request, too_large, unauthorized, ApiError, ApiResult};
use crate::state::AppState;
use crate::validate::{
    b64, parse_json, MAX_VAULT_RECORDS, MAX_VAULT_RECORD_DATA, MAX_VAULT_RECORD_ID_LEN,
};

/// JSON body limit of PUT /v1/vault/records: larger than the default so that a request can
/// carry several near-maximum records.
const MAX_VAULT_BODY: usize = 16 << 20;

const DEFAULT_VAULT_LIMIT: i64 = 500;

fn validate_vault_id(id: &str) -> Result<(), ApiError> {
    if id.is_empty()
        || id.len() > MAX_VAULT_RECORD_ID_LEN
        || id.chars().count() > MAX_VAULT_RECORD_ID_LEN
    {
        return Err(bad_request("record id must be 1..128 characters"));
    }
    if id.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(bad_request("record id must not contain control characters"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RecordIn {
    #[serde(default, deserialize_with = "null_default")]
    id: String,
    /// null or absent stores a NULL (deleted) record.
    #[serde(default, with = "b64::opt")]
    data: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct PutVaultRequest {
    #[serde(default, deserialize_with = "null_default")]
    records: Vec<RecordIn>,
}

pub async fn put_records(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: PutVaultRequest = parse_json(body, MAX_VAULT_BODY).await?;
    if req.records.is_empty() {
        return Err(bad_request("records must not be empty"));
    }
    if req.records.len() > MAX_VAULT_RECORDS {
        return Err(bad_request("at most 500 records per request"));
    }
    // Later entries with the same id win.
    let mut order: Vec<String> = Vec::new();
    let mut by_id: HashMap<String, Option<Vec<u8>>> = HashMap::new();
    for rec in req.records {
        validate_vault_id(&rec.id)?;
        if rec
            .data
            .as_ref()
            .is_some_and(|d| d.len() > MAX_VAULT_RECORD_DATA)
        {
            return Err(too_large("record data exceeds 256 KiB"));
        }
        if !by_id.contains_key(&rec.id) {
            order.push(rec.id.clone());
        }
        by_id.insert(rec.id, rec.data);
    }
    let len_of = |id: &str| by_id[id].as_ref().map_or(0, |d| d.len() as i64);

    let mut tx = st.db.begin().await?;
    let used = match sqlx::query!("SELECT vault_bytes FROM accounts WHERE id = ? FOR UPDATE", &p.account)
        .fetch_optional(&mut *tx)
        .await?
    {
        Some(r) => r.vault_bytes,
        None => return Err(unauthorized("account not found")),
    };
    let sql = format!(
        "SELECT record_id, size FROM vault_records WHERE account_id = ? AND record_id IN ({}) FOR UPDATE",
        placeholders(order.len())
    );
    let mut q = sqlx::query(&sql).bind(&p.account);
    for id in &order {
        q = q.bind(id);
    }
    let old_size: HashMap<String, i64> = q
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|r| (r.string("record_id"), r.i64("size")))
        .collect();
    let delta: i64 = order
        .iter()
        .map(|id| len_of(id) - old_size.get(id).copied().unwrap_or(0))
        .sum();
    if delta > 0 && used + delta > st.cfg.vault_quota_bytes {
        return Err(too_large("vault quota exceeded"));
    }
    // Reserve a block of sequence numbers from the global counter. The counter row lock is
    // held until commit, so sequence numbers become visible in order.
    let n = order.len() as i64;
    let res =
        sqlx::query!("UPDATE vault_counter SET value = LAST_INSERT_ID(value + ?) WHERE id = 1", n)
            .execute(&mut *tx)
            .await?;
    let mut seq = res.last_insert_id() as i64 - n;
    for id in &order {
        seq += 1;
        sqlx::query!(
            "INSERT INTO vault_records (account_id, record_id, data, size, seq) VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE data = VALUES(data), size = VALUES(size), seq = VALUES(seq)",
            &p.account,
            id,
            &by_id[id],
            len_of(id),
            seq
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!("UPDATE accounts SET vault_bytes = GREATEST(0, vault_bytes + ?) WHERE id = ?", delta, &p.account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(reply(StatusCode::OK, json!({"seq": seq})))
}

#[derive(Serialize)]
struct RecordOut {
    id: String,
    #[serde(with = "b64::opt")]
    data: Option<Vec<u8>>,
    seq: i64,
}

pub async fn get_records(
    State(st): State<AppState>,
    p: Principal,
    RawQuery(q): RawQuery,
) -> ApiResult {
    let since = query_int(q.as_deref(), "since", 0, 0, 1 << 62)?;
    let limit = query_int(
        q.as_deref(),
        "limit",
        DEFAULT_VAULT_LIMIT,
        1,
        MAX_VAULT_RECORDS as i64,
    )?;
    let rows = sqlx::query!("SELECT record_id AS `record_id: String`, data, seq AS `seq: i64` FROM vault_records WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?", &p.account, since, limit + 1)
        .fetch_all(&st.db)
        .await?;
    let mut out: Vec<RecordOut> = rows
        .into_iter()
        .map(|r| RecordOut {
            id: r.record_id,
            data: r.data,
            seq: r.seq,
        })
        .collect();
    let more = out.len() as i64 > limit;
    out.truncate(limit as usize);
    Ok(reply(StatusCode::OK, json!({"records": out, "more": more})))
}
