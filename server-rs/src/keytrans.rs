//! Key transparency (docs/KEY-TRANSPARENCY.md): an append-only Merkle log (RFC 6962 / 9162
//! hashing and proofs) of every account's identity key, with signed tree heads.
//!
//! * The log lives in MySQL (`kt_leaves`, `kt_state`). Every instance keeps the tree of leaf
//!   hashes in memory (all perfect subtree hashes, 2n hashes) and catches up from the
//!   database before answering, so several instances serve the same log.
//! * The sequencer appends a leaf for every account that has none yet (backfill at startup,
//!   right after a registration, and periodically), assigning contiguous indices under the
//!   `kt_state` row lock.
//! * Tree heads are signed with an Ed25519 key derived from CHATAPP_SERVER_SECRET, published
//!   in /v1/info (`kt_public_key`) and pinned by clients.
//!
//! The leaf and tree-head encodings are mirrored by crates/chat-core/src/keytrans.rs.

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::sync::Mutex;


pub type Hash = [u8; 32];

/// Leaf encoding version (first byte of the leaf data).
pub const LEAF_VERSION: u8 = 1;
/// Signature context of tree heads.
pub const STH_CONTEXT: &[u8] = b"chatapp/kt/sth/v1";
/// Accounts appended per sequencer transaction.
const SEQUENCE_BATCH: usize = 500;
/// How often the sequencer looks for accounts without a leaf.
const SEQUENCE_INTERVAL: Duration = Duration::from_secs(30);
/// Leaves loaded per query when catching up.
const LOAD_BATCH: i64 = 10_000;

/// Leaf data: version || account UUID (16 bytes) || key length (1 byte) || identity key
/// (libsignal serialization) || created_at (ms, u64 big endian).
pub fn leaf_data(account_id: &str, identity_key: &[u8], created_at: i64) -> Option<Vec<u8>> {
    let id = uuid::Uuid::parse_str(account_id).ok()?;
    let len = u8::try_from(identity_key.len()).ok()?;
    let mut d = Vec::with_capacity(1 + 16 + 1 + identity_key.len() + 8);
    d.push(LEAF_VERSION);
    d.extend_from_slice(id.as_bytes());
    d.push(len);
    d.extend_from_slice(identity_key);
    d.extend_from_slice(&(created_at as u64).to_be_bytes());
    Some(d)
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// Largest power of two strictly smaller than `n` (n >= 2).
fn split(n: u64) -> u64 {
    1 << (63 - (n - 1).leading_zeros())
}

/// Merkle tree over leaf hashes, keeping every perfect aligned subtree hash.
#[derive(Default)]
pub struct Tree {
    /// levels[k][i] = hash of leaves [i * 2^k, (i + 1) * 2^k).
    levels: Vec<Vec<Hash>>,
}

impl Tree {
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    pub fn leaf(&self, i: u64) -> Option<Hash> {
        self.levels.first()?.get(i as usize).copied()
    }

    pub fn push(&mut self, leaf: Hash) {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(leaf);
        let mut k = 0;
        while self.levels[k].len() % 2 == 0 {
            let n = self.levels[k].len();
            let parent = node_hash(&self.levels[k][n - 2], &self.levels[k][n - 1]);
            if self.levels.len() == k + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[k + 1].push(parent);
            k += 1;
        }
    }

    /// MTH(D[lo:hi]), lo < hi <= len.
    fn subtree(&self, lo: u64, hi: u64) -> Hash {
        let n = hi - lo;
        if n.is_power_of_two() && lo % n == 0 {
            return self.levels[n.trailing_zeros() as usize][(lo / n) as usize];
        }
        let k = split(n);
        node_hash(&self.subtree(lo, lo + k), &self.subtree(lo + k, hi))
    }

    /// Root of the first `n` leaves.
    pub fn root(&self, n: u64) -> Hash {
        if n == 0 {
            empty_root()
        } else {
            self.subtree(0, n)
        }
    }

    /// Audit path of leaf `m` in the tree of the first `n` leaves (RFC 6962 PATH).
    pub fn inclusion(&self, m: u64, n: u64) -> Vec<Hash> {
        fn path(t: &Tree, m: u64, lo: u64, hi: u64, out: &mut Vec<Hash>) {
            if hi - lo <= 1 {
                return;
            }
            let k = split(hi - lo);
            if m < lo + k {
                path(t, m, lo, lo + k, out);
                out.push(t.subtree(lo + k, hi));
            } else {
                path(t, m, lo + k, hi, out);
                out.push(t.subtree(lo, lo + k));
            }
        }
        let mut out = Vec::new();
        if m < n && n <= self.len() {
            path(self, m, 0, n, &mut out);
        }
        out
    }

    /// Consistency proof between the trees of the first `m` and `n` leaves (RFC 6962 PROOF),
    /// 0 < m <= n <= len; empty when m == n.
    pub fn consistency(&self, m: u64, n: u64) -> Vec<Hash> {
        fn sub(t: &Tree, m: u64, lo: u64, hi: u64, complete: bool, out: &mut Vec<Hash>) {
            let size = hi - lo;
            if m == size {
                if !complete {
                    out.push(t.subtree(lo, hi));
                }
                return;
            }
            let k = split(size);
            if m <= k {
                sub(t, m, lo, lo + k, complete, out);
                out.push(t.subtree(lo + k, hi));
            } else {
                sub(t, m - k, lo + k, hi, false, out);
                out.push(t.subtree(lo, lo + k));
            }
        }
        let mut out = Vec::new();
        if 0 < m && m < n && n <= self.len() {
            sub(self, m, 0, n, true, &mut out);
        }
        out
    }
}

/// A signed tree head.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TreeHead {
    pub tree_size: u64,
    #[serde(with = "crate::validate::b64")]
    pub root_hash: Vec<u8>,
    pub timestamp: i64,
    #[serde(with = "crate::validate::b64")]
    pub signature: Vec<u8>,
}

/// The message a tree head signature covers.
pub fn sth_message(size: u64, root: &[u8], timestamp: i64) -> Vec<u8> {
    let mut m = Vec::with_capacity(STH_CONTEXT.len() + 8 + 32 + 8);
    m.extend_from_slice(STH_CONTEXT);
    m.extend_from_slice(&size.to_be_bytes());
    m.extend_from_slice(root);
    m.extend_from_slice(&(timestamp as u64).to_be_bytes());
    m
}

/// One log entry as served to clients.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Entry {
    pub index: u64,
    pub account_id: String,
    #[serde(with = "crate::validate::b64")]
    pub identity_key: Vec<u8>,
    pub created_at: i64,
}

struct LogState {
    tree: Tree,
}

pub struct KtLog {
    signing: SigningKey,
    pub public_key: [u8; 32],
    state: Mutex<LogState>,
}

/// A consistent view of the log (taken under the lock): head plus whatever proofs were asked.
pub struct View {
    pub head: TreeHead,
    pub consistency: Option<Vec<Hash>>,
    pub inclusion: Option<Vec<Hash>>,
}

#[derive(Debug)]
pub enum KtError {
    Db(sqlx::Error),
    /// The requested sizes / index are not part of the log.
    Range(String),
    /// The database rows are not a contiguous log.
    Corrupt(String),
}

impl From<sqlx::Error> for KtError {
    fn from(e: sqlx::Error) -> Self {
        KtError::Db(e)
    }
}

impl From<KtError> for crate::error::ApiError {
    fn from(e: KtError) -> Self {
        match e {
            KtError::Db(e) => e.into(),
            KtError::Range(m) => crate::error::bad_request(m),
            KtError::Corrupt(m) => crate::error::internal_from("key transparency log", m),
        }
    }
}

fn row_hash(id: &str, key: &[u8], at: i64) -> Result<Hash, KtError> {
    leaf_data(id, key, at)
        .map(|d| leaf_hash(&d))
        .ok_or_else(|| KtError::Corrupt(format!("malformed leaf for {id}")))
}

impl KtLog {
    pub fn new(server_secret: &str) -> KtLog {
        let mut mac = Hmac::<Sha256>::new_from_slice(server_secret.as_bytes()).expect("hmac key");
        mac.update(b"chatapp/kt/signing-key");
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        KtLog { signing, public_key, state: Mutex::new(LogState { tree: Tree::default() }) }
    }

    pub fn sign(&self, size: u64, root: &Hash) -> TreeHead {
        let timestamp = crate::now_millis();
        let signature = self.signing.sign(&sth_message(size, root, timestamp)).to_bytes().to_vec();
        TreeHead { tree_size: size, root_hash: root.to_vec(), timestamp, signature }
    }

    /// Brings the in-memory tree up to date with the database. When the last known leaf no
    /// longer matches its row (the database was restored or tampered with), the tree is rebuilt
    /// from scratch: whatever the database now says is what gets signed, and clients detect the
    /// rewrite through consistency proofs and gossip.
    async fn catch_up(&self, db: &MySqlPool, st: &mut LogState) -> Result<(), KtError> {
        let len = st.tree.len();
        if len > 0 {
            let row = sqlx::query!(
                "SELECT account_id AS `account_id: String`, identity_key, created_at FROM kt_leaves WHERE idx = ?",
                len as i64 - 1
            )
            .fetch_optional(db)
            .await?;
            let same = match &row {
                Some(r) => Some(row_hash(&r.account_id, &r.identity_key, r.created_at)?) == st.tree.leaf(len - 1),
                None => false,
            };
            if !same {
                tracing::error!(size = len, "key transparency: the stored log changed under us, rebuilding");
                st.tree = Tree::default();
            }
        }
        loop {
            let from = st.tree.len() as i64;
            let rows = sqlx::query!(
                "SELECT idx, account_id AS `account_id: String`, identity_key, created_at FROM kt_leaves WHERE idx >= ? ORDER BY idx LIMIT ?",
                from,
                LOAD_BATCH
            )
            .fetch_all(db)
            .await?;
            let n = rows.len() as i64;
            for r in &rows {
                if r.idx != st.tree.len() as i64 {
                    return Err(KtError::Corrupt(format!("gap in the log at {}", st.tree.len())));
                }
                st.tree.push(row_hash(&r.account_id, &r.identity_key, r.created_at)?);
            }
            if n < LOAD_BATCH {
                return Ok(());
            }
        }
    }

    fn view(&self, st: &LogState, since: u64) -> Result<View, KtError> {
        let size = st.tree.len();
        if since > size {
            return Err(KtError::Range(format!("the log has only {size} entries")));
        }
        let consistency = (since > 0).then(|| st.tree.consistency(since, size));
        Ok(View { head: self.sign(size, &st.tree.root(size)), consistency, inclusion: None })
    }

    /// Current signed head, with a consistency proof from `since` (0 = none) when asked.
    pub async fn head(&self, db: &MySqlPool, since: u64) -> Result<View, KtError> {
        let mut st = self.state.lock().await;
        self.catch_up(db, &mut st).await?;
        self.view(&st, since)
    }

    /// The latest entry of `account_id` (an honest log has exactly one) with its inclusion
    /// proof under the current head.
    pub async fn proof(&self, db: &MySqlPool, account_id: &str, since: u64) -> Result<Option<(Entry, View)>, KtError> {
        let mut st = self.state.lock().await;
        self.catch_up(db, &mut st).await?;
        let size = st.tree.len();
        let row = sqlx::query!(
            "SELECT idx, account_id AS `account_id: String`, identity_key, created_at FROM kt_leaves WHERE account_id = ? AND idx < ? ORDER BY idx DESC LIMIT 1",
            account_id,
            size as i64
        )
        .fetch_optional(db)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let entry = Entry { index: r.idx as u64, account_id: r.account_id, identity_key: r.identity_key, created_at: r.created_at };
        let mut view = self.view(&st, since)?;
        view.inclusion = Some(st.tree.inclusion(entry.index, size));
        Ok(Some((entry, view)))
    }

    /// Consistency proof between two sizes of the log.
    pub async fn consistency(&self, db: &MySqlPool, first: u64, second: u64) -> Result<Vec<Hash>, KtError> {
        let mut st = self.state.lock().await;
        self.catch_up(db, &mut st).await?;
        if first == 0 || first > second || second > st.tree.len() {
            return Err(KtError::Range("sizes must satisfy 0 < first <= second <= log size".into()));
        }
        Ok(st.tree.consistency(first, second))
    }

    /// Entries [start, end) (for clients monitoring their own account).
    pub async fn entries(db: &MySqlPool, start: u64, end: u64) -> Result<Vec<Entry>, KtError> {
        let rows = sqlx::query!(
            "SELECT idx, account_id AS `account_id: String`, identity_key, created_at FROM kt_leaves WHERE idx >= ? AND idx < ? ORDER BY idx",
            start as i64,
            end as i64
        )
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Entry {
                index: r.idx as u64,
                account_id: r.account_id,
                identity_key: r.identity_key,
                created_at: r.created_at,
            })
            .collect())
    }
}

/// Appends a leaf for every account that has none (contiguous indices, serialized by the
/// `kt_state` row lock). Returns how many were appended.
pub async fn sequence(db: &MySqlPool) -> Result<u64, sqlx::Error> {
    let mut appended = 0u64;
    loop {
        let mut tx = db.begin().await?;
        let size = match sqlx::query!("SELECT size FROM kt_state WHERE id = 1 FOR UPDATE").fetch_optional(&mut *tx).await? {
            Some(r) => r.size,
            None => {
                sqlx::query!("INSERT INTO kt_state (id, size) VALUES (1, 0)").execute(&mut *tx).await?;
                0
            }
        };
        let rows = sqlx::query!(
            "SELECT a.id AS `id: String`, a.identity_key, a.created_at FROM accounts a
             WHERE NOT EXISTS (SELECT 1 FROM kt_leaves l WHERE l.account_id = a.id)
             ORDER BY a.created_at, a.id LIMIT ?",
            SEQUENCE_BATCH as i64
        )
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            tx.commit().await?;
            return Ok(appended);
        }
        for (i, r) in rows.iter().enumerate() {
            sqlx::query!(
                "INSERT INTO kt_leaves (idx, account_id, identity_key, created_at) VALUES (?, ?, ?, ?)",
                size + i as i64,
                r.id,
                r.identity_key,
                r.created_at
            )
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query!("UPDATE kt_state SET size = ? WHERE id = 1", size + rows.len() as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        appended += rows.len() as u64;
        if rows.len() < SEQUENCE_BATCH {
            return Ok(appended);
        }
    }
}

/// Sequences now (after a registration); failures are retried by the background sequencer.
pub async fn sequence_now(db: &MySqlPool) {
    for attempt in 0..3u64 {
        match sequence(db).await {
            Ok(_) => return,
            Err(e) if crate::db::is_retryable(&e) => tokio::time::sleep(Duration::from_millis(20 * (attempt + 1))).await,
            Err(e) => {
                tracing::warn!(error = %e, "key transparency: sequencing failed");
                return;
            }
        }
    }
}

/// Background sequencer: backfills existing accounts at startup, then catches stragglers.
pub async fn run_sequencer(db: MySqlPool) {
    loop {
        match sequence(&db).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(appended = n, "key transparency: accounts added to the log"),
            Err(e) => tracing::warn!(error = %e, "key transparency: sequencing failed"),
        }
        tokio::time::sleep(SEQUENCE_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference RFC 6962 MTH, straight from the definition.
    fn mth(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                let k = split(n as u64) as usize;
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&(i as u64).to_be_bytes())).collect()
    }

    #[test]
    fn roots_match_the_definition() {
        let ls = leaves(70);
        let mut t = Tree::default();
        assert_eq!(t.root(0), empty_root());
        for (i, l) in ls.iter().enumerate() {
            t.push(*l);
            for n in 0..=i + 1 {
                assert_eq!(t.root(n as u64), mth(&ls[..n]), "size {n}");
            }
        }
    }

    /// RFC 9162 2.1.3.2 (same algorithm as the client's verifier).
    fn verify_inclusion(index: u64, size: u64, leaf: Hash, path: &[Hash], root: Hash) -> bool {
        if index >= size {
            return false;
        }
        let (mut f, mut s, mut r) = (index, size - 1, leaf);
        for p in path {
            if s == 0 {
                return false;
            }
            if f & 1 == 1 || f == s {
                r = node_hash(p, &r);
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            } else {
                r = node_hash(&r, p);
            }
            f >>= 1;
            s >>= 1;
        }
        s == 0 && r == root
    }

    /// RFC 9162 2.1.4.2.
    fn verify_consistency(m: u64, n: u64, first: Hash, second: Hash, proof: &[Hash]) -> bool {
        if m == n {
            return proof.is_empty() && first == second;
        }
        if m == 0 || m > n || proof.is_empty() {
            return false;
        }
        let mut p: Vec<Hash> = proof.to_vec();
        if m.is_power_of_two() {
            p.insert(0, first);
        }
        let (mut f, mut s) = (m - 1, n - 1);
        while f & 1 == 1 {
            f >>= 1;
            s >>= 1;
        }
        let (mut fr, mut sr) = (p[0], p[0]);
        for c in &p[1..] {
            if s == 0 {
                return false;
            }
            if f & 1 == 1 || f == s {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            } else {
                sr = node_hash(&sr, c);
            }
            f >>= 1;
            s >>= 1;
        }
        fr == first && sr == second && s == 0
    }

    #[test]
    fn proofs_verify() {
        let ls = leaves(40);
        let mut t = Tree::default();
        for l in &ls {
            t.push(*l);
        }
        for n in 1..=40u64 {
            let root = t.root(n);
            for m in 0..n {
                let path = t.inclusion(m, n);
                assert!(verify_inclusion(m, n, ls[m as usize], &path, root), "inclusion {m}/{n}");
                assert!(!verify_inclusion(m, n, [9u8; 32], &path, root), "wrong leaf {m}/{n}");
                if !path.is_empty() {
                    assert!(!verify_inclusion(m, n, ls[m as usize], &path[..path.len() - 1], root), "truncated {m}/{n}");
                }
            }
            for m in 1..=n {
                let proof = t.consistency(m, n);
                assert!(verify_consistency(m, n, t.root(m), root, &proof), "consistency {m}->{n}");
                if m < n {
                    assert!(!verify_consistency(m, n, t.root(m), [9u8; 32], &proof));
                }
            }
        }
    }

    #[test]
    fn signed_heads_verify_with_the_published_key() {
        let log = KtLog::new("0123456789abcdef0123456789abcdef");
        let head = log.sign(3, &[7u8; 32]);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&log.public_key).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&head.signature).unwrap();
        assert!(key.verify_strict(&sth_message(3, &[7u8; 32], head.timestamp), &sig).is_ok());
        assert!(key.verify_strict(&sth_message(4, &[7u8; 32], head.timestamp), &sig).is_err());
        assert_eq!(KtLog::new("0123456789abcdef0123456789abcdef").public_key, log.public_key);
    }

    #[test]
    fn leaf_encoding() {
        let d = leaf_data("6f1c2a52-6a87-4a3c-9b1f-3c6c1d5a2b10", &[5u8; 33], 1_700_000_000_000).unwrap();
        assert_eq!(d.len(), 1 + 16 + 1 + 33 + 8);
        assert_eq!(d[0], LEAF_VERSION);
        assert!(leaf_data("not-a-uuid", &[5u8; 33], 0).is_none());
    }
}
