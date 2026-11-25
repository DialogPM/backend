//! Bots (docs/API.md section 22).
//!
//! A bot is created by an account and driven from outside with its token: a script calls the
//! Bot API (`/bot/<token>/sendMessage`...) and the server delivers the text to the people
//! who started the bot. Two rules make it safe to offer:
//!
//! * a bot can write only to a chat that its user started and has not stopped (`bot_chats`,
//!   checked here on every send), so a bot cannot reach anyone on its own;
//! * a bot never learns who it talks to: it sees a random chat id, different for every bot.
//!
//! Bot messages are *not* end-to-end encrypted: the script hands the server plain text, and
//! what people write to a bot is kept as text until the script collects it. They travel as
//! envelopes of type 9, which no client can send; apps mark these chats accordingly.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, Transaction};
use tokio::sync::Notify;

use super::messages::{self, Envelope};
use super::username::normalize_username;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::db::{is_duplicate_key, RowExt};
use crate::error::{bad_request, conflict, forbidden, not_found, too_large, unauthorized, ApiError, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{parse_json, path_uuid, read_body, MAX_JSON_BODY};

/// Envelope type of a bot's message: content is the JSON of [`BotContent`], in the clear.
/// Only this module creates it (`messages::valid_envelope_type` refuses it from clients).
pub const ENVELOPE_BOT: i64 = 9;

const MAX_BOTS_PER_ACCOUNT: i64 = 20;
const MAX_NAME_CHARS: usize = 64;
const MAX_ABOUT_CHARS: usize = 512;
const MAX_COMMANDS: usize = 50;
const MAX_COMMAND_DESCRIPTION_CHARS: usize = 256;
/// Longest text of one message, either way (characters, like Telegram).
pub const MAX_TEXT_CHARS: usize = 4096;
/// Updates a bot has not collected are kept this long.
pub const UPDATE_TTL_MS: i64 = 2 * 86_400_000;
/// Most updates kept for one bot; the oldest are dropped beyond it.
const MAX_PENDING_UPDATES: i64 = 10_000;
const MAX_POLL_SECONDS: i64 = 50;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Command {
    pub command: String,
    #[serde(default)]
    pub description: String,
}

/// What a client receives in a type 9 envelope.
#[derive(Serialize)]
struct BotContent<'a> {
    id: &'a str,
    text: &'a str,
    sent_at: i64,
    /// The bot asks that the message arrives without sound.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    silent: bool,
}

// ---------------------------------------------------------------------------------------
// Validation.

/// A bot's username: a username (same rules as accounts) of at least 5 characters that ends
/// in "bot", so nobody mistakes a bot for a person.
fn bot_username(input: &str) -> Result<String, ApiError> {
    let (u, ok) = normalize_username(input);
    if !ok || u.len() < 5 || !u.ends_with("bot") {
        return Err(bad_request(
            "a bot's username has 5-32 characters (letters, digits, _ or ., starting with a letter) and ends in \"bot\"",
        ));
    }
    Ok(u)
}

fn clean_text(field: &str, v: &str, max: usize, required: bool) -> Result<String, ApiError> {
    let t = v.trim();
    if required && t.is_empty() {
        return Err(bad_request(format!("{field} must not be empty")));
    }
    if t.chars().count() > max {
        return Err(bad_request(format!("{field} has at most {max} characters")));
    }
    if t.chars().any(|c| c.is_control() && c != '\n') {
        return Err(bad_request(format!("{field} must not contain control characters")));
    }
    Ok(t.to_string())
}

fn message_text(v: &str) -> Result<String, ApiError> {
    if v.trim().is_empty() {
        return Err(bad_request("text must not be empty"));
    }
    if v.chars().count() > MAX_TEXT_CHARS {
        return Err(too_large(format!("text has at most {MAX_TEXT_CHARS} characters")));
    }
    Ok(v.to_string())
}

/// Commands as the apps list them after "/": 1-32 characters, a-z 0-9 _, starting with a letter.
fn clean_commands(list: Vec<Command>) -> Result<Vec<Command>, ApiError> {
    if list.len() > MAX_COMMANDS {
        return Err(bad_request(format!("at most {MAX_COMMANDS} commands")));
    }
    let mut out: Vec<Command> = Vec::with_capacity(list.len());
    for c in list {
        let name = c.command.trim().trim_start_matches('/').to_ascii_lowercase();
        let b = name.as_bytes();
        let ok = (1..=32).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
        if !ok {
            return Err(bad_request(
                "a command has 1-32 characters: letters, digits or _, starting with a letter",
            ));
        }
        if out.iter().any(|o| o.command == name) {
            return Err(bad_request(format!("duplicate command /{name}")));
        }
        let description = clean_text("description", &c.description, MAX_COMMAND_DESCRIPTION_CHARS, false)?.replace('\n', " ");
        out.push(Command { command: name, description });
    }
    Ok(out)
}

fn commands_of(r: &MySqlRow) -> Vec<Command> {
    serde_json::from_str(&r.string("commands")).unwrap_or_default()
}

/// What anyone may know about a bot.
fn public_json(r: &MySqlRow) -> Value {
    json!({
        "id": r.string("id"),
        "username": r.string("username"),
        "name": r.string("name"),
        "about": r.string("about"),
        "commands": commands_of(r),
    })
}

const BOT_COLUMNS: &str = "id, owner_account_id, username, name, about, commands, disabled_at, created_at";

// ---------------------------------------------------------------------------------------
// Owner API (the account that creates bots).

#[derive(Deserialize)]
struct CreateRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    about: String,
}

/// Whether `username` is free for a bot: not an account's, not reserved for one, not blocked.
async fn username_free(tx: &mut Transaction<'_, MySql>, username: &str) -> Result<bool, sqlx::Error> {
    if crate::admin::usernames::is_blocked(tx, username).await? {
        return Ok(false);
    }
    let taken = sqlx::query("SELECT 1 FROM accounts WHERE username = ? UNION ALL SELECT 1 FROM username_reservations WHERE username = ? AND expires_at >= ?")
        .bind(username)
        .bind(username)
        .bind(crate::now_millis())
        .fetch_optional(&mut **tx)
        .await?;
    Ok(taken.is_none())
}

/// Whether a bot holds `username` (accounts cannot take a bot's name).
pub async fn username_is_bot(tx: &mut Transaction<'_, MySql>, username: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM bots WHERE username = ?").bind(username).fetch_optional(&mut **tx).await?.is_some())
}

fn owner_json(r: &MySqlRow, chats: i64) -> Value {
    let mut v = public_json(r);
    v["created_at"] = r.i64("created_at").into();
    v["disabled"] = r.opt_i64("disabled_at").is_some().into();
    v["subscribers"] = chats.into();
    v
}

/// POST /v1/bots {"username","name","about"} -> {"bot": {...}, "token": "..."}
///
/// The token is shown once: only its hash is stored.
pub async fn create(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(&format!("bot-manage:{}", p.account), st.limits.bot_manage_account)?;
    let req: CreateRequest = parse_json(body, MAX_JSON_BODY).await?;
    let username = bot_username(&req.username)?;
    let name = clean_text("name", &req.name, MAX_NAME_CHARS, true)?.replace('\n', " ");
    let about = clean_text("about", &req.about, MAX_ABOUT_CHARS, false)?;
    let (token, hash) = ids::new_token();
    let id = ids::new_uuid();
    let now = crate::now_millis();

    let mut tx = st.db.begin().await?;
    // Serializes the count below against this account's other requests.
    sqlx::query("SELECT id FROM accounts WHERE id = ? FOR UPDATE").bind(&p.account).fetch_optional(&mut *tx).await?;
    let count = sqlx::query("SELECT COUNT(*) AS n FROM bots WHERE owner_account_id = ?")
        .bind(&p.account)
        .fetch_one(&mut *tx)
        .await?
        .i64("n");
    if count >= MAX_BOTS_PER_ACCOUNT {
        return Err(conflict(format!("an account can have at most {MAX_BOTS_PER_ACCOUNT} bots")).with("reason", "too_many_bots"));
    }
    if !username_free(&mut tx, &username).await? {
        return Err(conflict("this username is taken").with("reason", "username_taken"));
    }
    match sqlx::query("INSERT INTO bots (id, owner_account_id, username, name, about, commands, token_hash, created_at) VALUES (?,?,?,?,?,'[]',?,?)")
        .bind(&id)
        .bind(&p.account)
        .bind(&username)
        .bind(&name)
        .bind(&about)
        .bind(&hash)
        .bind(now)
        .execute(&mut *tx)
        .await
    {
        Err(e) if is_duplicate_key(&e) => return Err(conflict("this username is taken").with("reason", "username_taken")),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    tx.commit().await?;
    let bot = json!({
        "id": id, "username": username, "name": name, "about": about, "commands": [],
        "created_at": now, "disabled": false, "subscribers": 0,
    });
    Ok(reply(StatusCode::OK, json!({ "bot": bot, "token": token })))
}

/// GET /v1/bots -> {"bots": [...]}: the caller's bots.
pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult {
    let rows = sqlx::query(&format!(
        "SELECT {BOT_COLUMNS}, (SELECT COUNT(*) FROM bot_chats c WHERE c.bot_id = bots.id AND c.active = 1) AS chats
         FROM bots WHERE owner_account_id = ? ORDER BY created_at, id"
    ))
    .bind(&p.account)
    .fetch_all(&st.db)
    .await?;
    let bots: Vec<Value> = rows.iter().map(|r| owner_json(r, r.i64("chats"))).collect();
    Ok(reply(StatusCode::OK, json!({ "bots": bots })))
}

#[derive(Deserialize)]
struct UpdateRequest {
    name: Option<String>,
    about: Option<String>,
    commands: Option<Vec<Command>>,
}

async fn owned(st: &AppState, p: &Principal, id: &str) -> Result<String, ApiError> {
    let id = path_uuid("id", id)?;
    let row = sqlx::query("SELECT owner_account_id FROM bots WHERE id = ?").bind(&id).fetch_optional(&st.db).await?;
    match row {
        Some(r) if r.string("owner_account_id") == p.account => Ok(id),
        _ => Err(not_found("unknown bot")),
    }
}

/// PATCH /v1/bots/{id} {"name"?, "about"?, "commands"?} -> the bot
pub async fn update(State(st): State<AppState>, p: Principal, Path(id): Path<String>, body: Body) -> ApiResult {
    st.rate_limit(&format!("bot-manage:{}", p.account), st.limits.bot_manage_account)?;
    let req: UpdateRequest = parse_json(body, MAX_JSON_BODY).await?;
    let id = owned(&st, &p, &id).await?;
    if let Some(name) = &req.name {
        let name = clean_text("name", name, MAX_NAME_CHARS, true)?.replace('\n', " ");
        sqlx::query("UPDATE bots SET name = ? WHERE id = ?").bind(name).bind(&id).execute(&st.db).await?;
    }
    if let Some(about) = &req.about {
        let about = clean_text("about", about, MAX_ABOUT_CHARS, false)?;
        sqlx::query("UPDATE bots SET about = ? WHERE id = ?").bind(about).bind(&id).execute(&st.db).await?;
    }
    if let Some(commands) = req.commands {
        set_commands(&st, &id, commands).await?;
    }
    let r = sqlx::query(&format!(
        "SELECT {BOT_COLUMNS}, (SELECT COUNT(*) FROM bot_chats c WHERE c.bot_id = bots.id AND c.active = 1) AS chats FROM bots WHERE id = ?"
    ))
    .bind(&id)
    .fetch_one(&st.db)
    .await?;
    Ok(reply(StatusCode::OK, owner_json(&r, r.i64("chats"))))
}

async fn set_commands(st: &AppState, bot: &str, commands: Vec<Command>) -> Result<(), ApiError> {
    let commands = clean_commands(commands)?;
    let text = serde_json::to_string(&commands).expect("commands serialize");
    sqlx::query("UPDATE bots SET commands = ? WHERE id = ?").bind(text).bind(bot).execute(&st.db).await?;
    Ok(())
}

/// POST /v1/bots/{id}/token -> {"token": "..."}: a new token; the old one stops working.
pub async fn reset_token(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    st.rate_limit(&format!("bot-manage:{}", p.account), st.limits.bot_manage_account)?;
    let id = owned(&st, &p, &id).await?;
    let (token, hash) = ids::new_token();
    sqlx::query("UPDATE bots SET token_hash = ? WHERE id = ?").bind(&hash).bind(&id).execute(&st.db).await?;
    Ok(reply(StatusCode::OK, json!({ "token": token })))
}

/// DELETE /v1/bots/{id}: the bot, its chats and its pending updates are gone; its token
/// stops working. The people who had started it are told (event `bot_deleted`).
pub async fn delete(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    st.rate_limit(&format!("bot-manage:{}", p.account), st.limits.bot_manage_account)?;
    let id = owned(&st, &p, &id).await?;
    let users = sqlx::query("SELECT account_id FROM bot_chats WHERE bot_id = ?").bind(&id).fetch_all(&st.db).await?;
    sqlx::query("DELETE FROM bots WHERE id = ?").bind(&id).execute(&st.db).await?;
    let event = json!({"kind": "bot_deleted", "bot_id": id});
    for u in &users {
        st.hub.send_event(&u.string("account_id"), 0, &event);
    }
    wake(&id);
    Ok(no_content())
}

/// GET /v1/bots/{id}/subscribers (owner) -> {"subscribers": [{"chat_id","since","mine"}]}
///
/// The chats the bot may write to, as the bot itself knows them: by chat id. The server does
/// not know anyone's name, and the owner learns no account. `mine`: the owner's own chat.
pub async fn subscribers(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    let id = owned(&st, &p, &id).await?;
    let rows = sqlx::query("SELECT chat_id, account_id, updated_at FROM bot_chats WHERE bot_id = ? AND active = 1 ORDER BY updated_at DESC LIMIT 1000")
        .bind(&id)
        .fetch_all(&st.db)
        .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| json!({"chat_id": r.string("chat_id"), "since": r.i64("updated_at"), "mine": r.string("account_id") == p.account}))
        .collect();
    Ok(reply(StatusCode::OK, json!({ "subscribers": list })))
}

/// POST /v1/bots/{id}/send (owner) {"chat_id","text"}: the Bot API's sendMessage without the
/// token, for the "test message" of the apps.
pub async fn owner_send(State(st): State<AppState>, p: Principal, Path(id): Path<String>, body: Body) -> ApiResult {
    let id = owned(&st, &p, &id).await?;
    let params = Params::read(None, body).await?;
    send_message(&st, &id, &params).await
}

// ---------------------------------------------------------------------------------------
// User API (anyone talking to a bot).

async fn bot_row(st: &AppState, id: &str) -> Result<MySqlRow, ApiError> {
    let id = path_uuid("id", id)?;
    sqlx::query(&format!("SELECT {BOT_COLUMNS} FROM bots WHERE id = ?"))
        .bind(&id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| not_found("unknown bot"))
}

/// "active" | "stopped" | "none" for (bot, account).
async fn chat_state(st: &AppState, bot: &str, account: &str) -> Result<&'static str, sqlx::Error> {
    let row = sqlx::query("SELECT active FROM bot_chats WHERE bot_id = ? AND account_id = ?")
        .bind(bot)
        .bind(account)
        .fetch_optional(&st.db)
        .await?;
    Ok(match row {
        None => "none",
        Some(r) if r.i64("active") == 1 => "active",
        Some(_) => "stopped",
    })
}

async fn info_reply(st: &AppState, p: &Principal, r: &MySqlRow) -> ApiResult {
    let mut v = public_json(r);
    v["state"] = chat_state(st, &r.string("id"), &p.account).await?.into();
    v["mine"] = (r.string("owner_account_id") == p.account).into();
    v["disabled"] = r.opt_i64("disabled_at").is_some().into();
    Ok(reply(StatusCode::OK, v))
}

/// GET /v1/bots/{id} -> public description plus the caller's chat state.
pub async fn get(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    let r = bot_row(&st, &id).await?;
    info_reply(&st, &p, &r).await
}

/// GET /v1/bots/username/{username}
pub async fn by_username(State(st): State<AppState>, p: Principal, Path(username): Path<String>) -> ApiResult {
    st.rate_limit(&format!("dir-number:acct:{}", p.account), st.limits.directory_number)?;
    let (u, ok) = normalize_username(&username);
    if !ok {
        return Err(not_found("unknown bot"));
    }
    let r = sqlx::query(&format!("SELECT {BOT_COLUMNS} FROM bots WHERE username = ?"))
        .bind(&u)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| not_found("unknown bot"))?;
    info_reply(&st, &p, &r).await
}

/// GET /v1/bot-chats -> {"chats": [{"bot": {...}, "state"}]}: every bot the caller ever
/// started (a new device restores its bot conversations from this).
pub async fn chats(State(st): State<AppState>, p: Principal) -> ApiResult {
    let rows = sqlx::query(
        "SELECT b.id, b.username, b.name, b.about, b.commands, c.active
         FROM bot_chats c JOIN bots b ON b.id = c.bot_id WHERE c.account_id = ? ORDER BY c.created_at",
    )
    .bind(&p.account)
    .fetch_all(&st.db)
    .await?;
    let chats: Vec<Value> = rows
        .iter()
        .map(|r| json!({"bot": public_json(r), "state": if r.i64("active") == 1 { "active" } else { "stopped" }}))
        .collect();
    Ok(reply(StatusCode::OK, json!({ "chats": chats })))
}

/// Queues an update for the bot's script and wakes a waiting getUpdates.
async fn push_update(st: &AppState, bot: &str, chat: &str, kind: &str, message_id: Option<&str>, body: Option<&str>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO bot_updates (bot_id, chat_id, kind, message_id, body, created_at) VALUES (?,?,?,?,?,?)")
        .bind(bot)
        .bind(chat)
        .bind(kind)
        .bind(message_id)
        .bind(body)
        .bind(crate::now_millis())
        .execute(&st.db)
        .await?;
    wake(bot);
    Ok(())
}

/// Tells the caller's other devices that the chat with `bot` changed state.
fn announce_state(st: &AppState, p: &Principal, bot: &str, state: &str) {
    st.hub.send_event(&p.account, p.device, &json!({"kind": "bot_chat", "bot_id": bot, "state": state}));
}

#[derive(Deserialize, Default)]
struct UserMessage {
    /// Client's message id (a UUID); a repeated id is accepted once.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    text: String,
}

/// POST /v1/bots/{id}/start -> {"state": "active"}
///
/// The only way a chat with a bot begins or resumes. The bot receives the message "/start".
pub async fn start(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    st.rate_limit(&format!("bot-msg:{}", p.account), st.limits.bot_message_account)?;
    let r = bot_row(&st, &id).await?;
    let bot = r.string("id");
    if r.opt_i64("disabled_at").is_some() {
        return Err(forbidden("this bot is disabled").with("reason", "bot_disabled"));
    }
    let now = crate::now_millis();
    sqlx::query(
        "INSERT INTO bot_chats (bot_id, account_id, chat_id, active, created_at, updated_at) VALUES (?,?,?,1,?,?)
         ON DUPLICATE KEY UPDATE active = 1, updated_at = VALUES(updated_at)",
    )
    .bind(&bot)
    .bind(&p.account)
    .bind(ids::new_attachment_id())
    .bind(now)
    .bind(now)
    .execute(&st.db)
    .await?;
    let chat = chat_id(&st, &bot, &p.account).await?.ok_or_else(|| not_found("unknown bot"))?.0;
    push_update(&st, &bot, &chat, "message", Some(&ids::new_uuid()), Some("/start")).await?;
    announce_state(&st, &p, &bot, "active");
    Ok(reply(StatusCode::OK, json!({"state": "active"})))
}

/// (chat id, active) of (bot, account).
async fn chat_id(st: &AppState, bot: &str, account: &str) -> Result<Option<(String, bool)>, sqlx::Error> {
    let row = sqlx::query("SELECT chat_id, active FROM bot_chats WHERE bot_id = ? AND account_id = ?")
        .bind(bot)
        .bind(account)
        .fetch_optional(&st.db)
        .await?;
    Ok(row.map(|r| (r.string("chat_id"), r.i64("active") == 1)))
}

/// POST /v1/bots/{id}/stop -> {"state": "stopped"}: from now on the bot's sends are refused.
pub async fn stop(State(st): State<AppState>, p: Principal, Path(id): Path<String>) -> ApiResult {
    let bot = path_uuid("id", &id)?;
    let Some((chat, active)) = chat_id(&st, &bot, &p.account).await? else {
        return Err(not_found("unknown bot"));
    };
    if active {
        sqlx::query("UPDATE bot_chats SET active = 0, updated_at = ? WHERE bot_id = ? AND account_id = ?")
            .bind(crate::now_millis())
            .bind(&bot)
            .bind(&p.account)
            .execute(&st.db)
            .await?;
        push_update(&st, &bot, &chat, "stopped", None, None).await?;
    }
    announce_state(&st, &p, &bot, "stopped");
    Ok(reply(StatusCode::OK, json!({"state": "stopped"})))
}

/// POST /v1/bots/{id}/messages {"id"?, "text"} -> {"server_timestamp"}
///
/// A message to the bot, kept until its script collects it (getUpdates). Only in a started chat.
pub async fn send_to_bot(State(st): State<AppState>, p: Principal, Path(id): Path<String>, body: Body) -> ApiResult {
    st.rate_limit(&format!("bot-msg:{}", p.account), st.limits.bot_message_account)?;
    let req: UserMessage = parse_json(body, MAX_JSON_BODY).await?;
    let text = message_text(&req.text)?;
    let message_id = match req.id.as_deref() {
        Some(id) => path_uuid("id", id)?,
        None => ids::new_uuid(),
    };
    let r = bot_row(&st, &id).await?;
    let bot = r.string("id");
    if r.opt_i64("disabled_at").is_some() {
        return Err(forbidden("this bot is disabled").with("reason", "bot_disabled"));
    }
    match chat_id(&st, &bot, &p.account).await? {
        Some((chat, true)) => {
            let seen = sqlx::query("SELECT 1 FROM bot_updates WHERE bot_id = ? AND message_id = ?")
                .bind(&bot)
                .bind(&message_id)
                .fetch_optional(&st.db)
                .await?;
            if seen.is_none() {
                push_update(&st, &bot, &chat, "message", Some(&message_id), Some(&text)).await?;
            }
        }
        _ => return Err(forbidden("start the bot first").with("reason", "bot_not_started")),
    }
    Ok(reply(StatusCode::OK, json!({"server_timestamp": crate::now_millis()})))
}

// ---------------------------------------------------------------------------------------
// Bot API (the bot's script, authenticated by the token in the path).

static WAKERS: LazyLock<Mutex<HashMap<String, Arc<Notify>>>> = LazyLock::new(Default::default);

fn waker(bot: &str) -> Arc<Notify> {
    WAKERS.lock().unwrap().entry(bot.to_string()).or_default().clone()
}

fn wake(bot: &str) {
    if let Some(n) = WAKERS.lock().unwrap().get(bot) {
        n.notify_waiters();
    }
}

fn release_waker(bot: &str, n: Arc<Notify>) {
    let mut map = WAKERS.lock().unwrap();
    drop(n);
    if map.get(bot).is_some_and(|n| Arc::strong_count(n) == 1) {
        map.remove(bot);
    }
}

fn ok(result: Value) -> ApiResult {
    Ok(reply(StatusCode::OK, json!({"ok": true, "result": result})))
}

/// Parameters of a Bot API call: the query string and/or a JSON object body (body wins).
struct Params(serde_json::Map<String, Value>);

impl Params {
    async fn read(query: Option<&str>, body: Body) -> Result<Params, ApiError> {
        let mut map = serde_json::Map::new();
        if let Some(q) = query {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                map.insert(k.into_owned(), Value::String(v.into_owned()));
            }
        }
        let bytes = read_body(body, MAX_JSON_BODY).await?;
        if !bytes.iter().all(|b| b.is_ascii_whitespace()) {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Object(o)) => map.extend(o),
                _ => return Err(bad_request("the body must be a JSON object")),
            }
        }
        Ok(Params(map))
    }

    fn str(&self, name: &str) -> Option<String> {
        match self.0.get(name)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn int(&self, name: &str, def: i64, min: i64, max: i64) -> Result<i64, ApiError> {
        let v = match self.0.get(name) {
            None | Some(Value::Null) => return Ok(def),
            Some(Value::Number(n)) => n.as_i64(),
            Some(Value::String(s)) if s.is_empty() => return Ok(def),
            Some(Value::String(s)) => s.parse().ok(),
            Some(_) => None,
        };
        v.ok_or_else(|| bad_request(format!("{name} must be an integer"))).map(|n| n.clamp(min, max))
    }

    fn flag(&self, name: &str) -> bool {
        match self.0.get(name) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s == "true" || s == "1",
            _ => false,
        }
    }
}

/// The bot of `token`; 401 for anything else (bad tokens are limited per address).
async fn authenticate(st: &AppState, token: &str, ip: &str) -> Result<MySqlRow, ApiError> {
    let row = if ids::valid_token_format(token) {
        sqlx::query(&format!("SELECT {BOT_COLUMNS} FROM bots WHERE token_hash = ?"))
            .bind(ids::hash_token(token))
            .fetch_optional(&st.db)
            .await?
    } else {
        None
    };
    match row {
        Some(r) if r.opt_i64("disabled_at").is_some() => Err(forbidden("this bot is disabled").with("reason", "bot_disabled")),
        Some(r) => Ok(r),
        None => {
            st.rate_limit(&format!("bot-token:ip:{ip}"), st.limits.bot_token_ip)?;
            Err(unauthorized("invalid bot token"))
        }
    }
}

/// GET|POST /bot/{token}/{method}
pub async fn bot_api(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((token, method)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: Body,
) -> ApiResult {
    let ip = st.client_ip(&headers, peer);
    let bot = authenticate(&st, &token, &ip).await?;
    let params = Params::read(query.as_deref(), body).await?;
    let id = bot.string("id");
    match method.to_ascii_lowercase().as_str() {
        "getme" => ok(public_json(&bot)),
        "sendmessage" => send_message(&st, &id, &params).await,
        "getupdates" => get_updates(&st, &id, &params).await,
        "getmycommands" => ok(json!(commands_of(&bot))),
        "setmycommands" => {
            let commands: Vec<Command> = match params.0.get("commands") {
                Some(Value::String(s)) => serde_json::from_str(s).map_err(|_| bad_request("commands must be a JSON array"))?,
                Some(v) => serde_json::from_value(v.clone()).map_err(|_| bad_request("commands must be an array of {command, description}"))?,
                None => return Err(bad_request("commands is required")),
            };
            set_commands(&st, &id, commands).await?;
            ok(Value::Bool(true))
        }
        _ => Err(not_found("unknown method")),
    }
}

/// sendMessage {chat_id, text, silent?} -> {message_id, date}
///
/// Refused with 403 unless the chat was started by its user and is not stopped.
async fn send_message(st: &AppState, bot: &str, params: &Params) -> ApiResult {
    let chat = params.str("chat_id").ok_or_else(|| bad_request("chat_id is required"))?;
    let text = message_text(&params.str("text").ok_or_else(|| bad_request("text is required"))?)?;
    let silent = params.flag("silent") || params.flag("disable_notification");
    st.rate_limit(&format!("bot-send:{bot}"), st.limits.bot_send)?;
    st.rate_limit(&format!("bot-send:{bot}:{chat}"), st.limits.bot_send_chat)?;

    let row = sqlx::query("SELECT account_id, active FROM bot_chats WHERE chat_id = ? AND bot_id = ?")
        .bind(&chat)
        .bind(bot)
        .fetch_optional(&st.db)
        .await?;
    let account = match row {
        Some(r) if r.i64("active") == 1 => r.string("account_id"),
        Some(_) => return Err(forbidden("the user stopped the bot").with("reason", "bot_stopped")),
        None => return Err(bad_request("chat not found").with("reason", "chat_not_found")),
    };

    let now = crate::now_millis();
    let message_id = ids::new_uuid();
    let content = serde_json::to_vec(&BotContent { id: &message_id, text: &text, sent_at: now, silent }).expect("bot content serializes");
    let mut tx = st.db.begin().await?;
    if sqlx::query("SELECT id FROM accounts WHERE id = ? FOR SHARE").bind(&account).fetch_optional(&mut *tx).await?.is_none() {
        return Err(bad_request("chat not found").with("reason", "chat_not_found"));
    }
    let devices = messages::device_registrations(&mut tx, &account).await?;
    let mut envs: Vec<Envelope> = devices
        .keys()
        .map(|d| Envelope {
            id: ids::new_uuid(),
            kind: ENVELOPE_BOT,
            source_account: bot.to_string(),
            source_device: 0,
            destination_device: *d,
            group_id: None,
            timestamp: now,
            server_timestamp: now,
            content: content.clone(),
            dest_account: account.clone(),
        })
        .collect();
    messages::drop_for_full_queues(&mut tx, &mut envs).await?;
    messages::insert_envelopes(&mut tx, &envs).await?;
    tx.commit().await?;
    messages::deliver(st, &envs, false);
    ok(json!({"message_id": message_id, "date": now / 1000, "chat": {"id": chat}}))
}

fn update_json(r: &MySqlRow) -> Value {
    let chat = json!({"id": r.string("chat_id")});
    let id = r.i64("update_id");
    match r.string("kind").as_str() {
        "stopped" => json!({"update_id": id, "chat_stopped": {"chat": chat, "date": r.i64("created_at") / 1000}}),
        _ => json!({"update_id": id, "message": {
            "message_id": r.opt_string("message_id"),
            "chat": chat,
            "date": r.i64("created_at") / 1000,
            "text": r.opt_string("body").unwrap_or_default(),
        }}),
    }
}

/// getUpdates {offset?, limit?, timeout?} -> [update]
///
/// Like Telegram's: `offset` confirms (deletes) every update below it; `timeout` (seconds, at
/// most 50) waits for an update instead of answering with an empty list.
async fn get_updates(st: &AppState, bot: &str, params: &Params) -> ApiResult {
    let offset = params.int("offset", 0, 0, i64::MAX)?;
    let limit = params.int("limit", 100, 1, 100)?;
    let timeout = params.int("timeout", 0, 0, MAX_POLL_SECONDS)?;
    if offset > 0 {
        sqlx::query("DELETE FROM bot_updates WHERE bot_id = ? AND update_id < ?").bind(bot).bind(offset).execute(&st.db).await?;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout as u64);
    let notify = waker(bot);
    let result = loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let rows = sqlx::query("SELECT update_id, chat_id, kind, message_id, body, created_at FROM bot_updates WHERE bot_id = ? AND update_id >= ? ORDER BY update_id LIMIT ?")
            .bind(bot)
            .bind(offset)
            .bind(limit)
            .fetch_all(&st.db)
            .await;
        match rows {
            Err(e) => break Err(e),
            Ok(rows) if !rows.is_empty() => break Ok(rows),
            Ok(rows) => {
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    break Ok(rows);
                }
            }
        }
    };
    release_waker(bot, notify);
    let rows = result?;
    ok(Value::Array(rows.iter().map(update_json).collect()))
}

/// Periodic cleanup (jobs.rs): updates nobody collected in time, and the overflow of bots
/// whose script never collects.
pub async fn cleanup(st: &AppState) -> Result<u64, sqlx::Error> {
    let mut n = sqlx::query("DELETE FROM bot_updates WHERE created_at < ? LIMIT 10000")
        .bind(crate::now_millis() - UPDATE_TTL_MS)
        .execute(&st.db)
        .await?
        .rows_affected();
    let heavy = sqlx::query("SELECT bot_id, COUNT(*) AS n, MAX(update_id) AS newest FROM bot_updates GROUP BY bot_id HAVING COUNT(*) > ?")
        .bind(MAX_PENDING_UPDATES)
        .fetch_all(&st.db)
        .await?;
    for r in &heavy {
        n += sqlx::query("DELETE FROM bot_updates WHERE bot_id = ? AND update_id <= ?")
            .bind(r.string("bot_id"))
            .bind(r.i64("newest") - MAX_PENDING_UPDATES)
            .execute(&st.db)
            .await?
            .rows_affected();
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert_eq!(bot_username("@Weather_Bot").unwrap(), "weather_bot");
        assert!(bot_username("bot").is_err());
        assert!(bot_username("weather").is_err());
        assert!(bot_username("1weatherbot").is_err());
    }

    #[test]
    fn commands() {
        let c = clean_commands(vec![Command { command: "/Start".into(), description: " Begin\nnow ".into() }]).unwrap();
        assert_eq!(c, vec![Command { command: "start".into(), description: "Begin now".into() }]);
        assert!(clean_commands(vec![Command { command: "a b".into(), description: String::new() }]).is_err());
        let twice = vec![Command { command: "a".into(), description: String::new() }; 2];
        assert!(clean_commands(twice).is_err());
    }

    #[test]
    fn texts() {
        assert!(message_text("  ").is_err());
        assert!(message_text(&"x".repeat(MAX_TEXT_CHARS)).is_ok());
        assert!(message_text(&"x".repeat(MAX_TEXT_CHARS + 1)).is_err());
    }
}
