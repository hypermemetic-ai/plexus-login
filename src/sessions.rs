//! IDENTITY-19: sessions — what a person holds once they have signed in.
//!
//! Every way in (a password, the IdP's code flow, a nostr key) ends here:
//! the identity the provider's adapter proved is kept on the server, and
//! the browser gets only a random session id in an `HttpOnly` cookie,
//! which no script on any page can read. The provider's token never leaves
//! the shell.
//!
//! The id is kept hashed, so the table holds nothing a browser could
//! present. A session ends at its expiry or at sign-out; [`Sessions::alive`]
//! is how the activations notice, on every call, that a connection's
//! session is gone (sign-out stops its sockets answering).
//!
//! [`Gate`] is the WebSocket upgrade's validator: the session cookie first,
//! then (IDENTITY-42) a minted session token (`mgs_…`, from
//! `session.login`) as the bearer value or the `access_token` cookie, then a
//! provider's own credential (synapse's `-t` token, a NIP-98 event, an
//! agent's key proof) through the adapters' [`Carriers`].
//!
//! FRAME-21: a table kept in a journal ([`Sessions::journaled`]) survives
//! a restart. Every session started is a JSON line — its key (the id's
//! sha256, never the id), its end, whether it idles, its last use, the
//! stamped identity — written and fsynced before the id is handed out (a
//! row that cannot be written: no session, an error); a browser's use is a
//! line once a grain, every ending (by hand, by idleness, by the cap) a line
//! too. Opening replays the lines (ended and expired rows dropped, a torn
//! last line skipped) and rewrites the file to the live set; it is
//! rewritten again whenever it passes ten times the live set (at least
//! 1,000 rows). The file is 0600, beside a lock (`<path>.lock`) held for the
//! table's life: a second server on it does not start. Sign-ins in flight
//! stay in memory (one under way at a restart starts again), and so do the
//! identity backend's tokens ([`crate::app_session::TokenStore::reseat`]).
//! [`Sessions::new`] is the in-memory table: a restart signs everyone out.
//!
//! ACCESS-29: every table here is bounded and kept by when its entries end
//! ([`Ending`]): an insert drops what has ended and makes room in O(log n),
//! never by a scan of the table — so a flood of anonymous
//! `GET /login/start`s costs each one its own entry and nothing more. A
//! browser's session also ends when it goes unused for
//! [`IDLE_SECS_DEFAULT`] (`--session-idle-minutes`): no socket open on it
//! and no page loaded with it.

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use plexus_auth_core::adapters::Carriers;
use plexus_core::plexus::{AuthContext, SessionValidator};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::access::LoginAccess;
use crate::names::LoginNames;

/// IDENTITY-38: at most this many login transactions wait at once — each
/// is one anonymous `GET /login/start` — and at most this many sessions
/// live; past either, the one nearest its end makes room (ACCESS-29: found
/// by the index, not a scan). The loopback sign-ins and their one-time codes
/// are held to [`MAX_PENDING`] each too.
pub const MAX_PENDING: usize = 10_000;
pub const MAX_LIVE: usize = 100_000;

/// ACCESS-29 (ACCESS-4 L2): a browser's session ends after this long unused
/// — no socket open on it (an open socket asks after it every second) and no
/// page loaded with it — as well as at its expiry. Two hours; 0 turns it
/// off. A minted token (`session.login`, an agent's) keeps only its expiry.
pub const IDLE_SECS_DEFAULT: i64 = 2 * 3600;

/// IDENTITY-42: what a session token `session.login` mints starts with.
pub const TOKEN_PREFIX: &str = "mgs_";

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 32 random bytes, URL-safe base64: a session id, a PKCE verifier, a
/// login transaction's state.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// FRAME-21: the answer when a session could not be kept (its journal
/// refused the row): 503, and no cookie.
pub fn not_kept(e: io::Error) -> axum::response::Response {
    use axum::response::IntoResponse;
    tracing::error!("a session could not be kept: {e}");
    (axum::http::StatusCode::SERVICE_UNAVAILABLE, [(axum::http::header::RETRY_AFTER, "5")], "Signing in is unavailable for a moment: your session could not be kept. Try again.").into_response()
}

/// A named cookie's value in a `Cookie` header.
pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (n, v) = pair.trim().split_once('=')?;
        (n == name && !v.is_empty()).then_some(v.trim())
    })
}

#[derive(Clone)]
struct Session {
    ctx: AuthContext,
    /// ACCESS-29: a browser's session, which ends when unused
    /// ([`Sessions::with_idle`]); a minted token is not.
    idles: bool,
    /// When it was last presented or asked after.
    seen: i64,
    /// FRAME-21: the last use the journal holds (a `touch` row), so a
    /// restart keeps a browser's idle clock to within a grain of it.
    touched: i64,
}

/// ACCESS-29: a table of entries that end, kept beside an index by when —
/// an insert drops the ended from the index's front and, at its cap, the
/// entry nearest its end: O(log n), never a scan of the table. ACCESS-44:
/// among entries ending in the same second the earliest inserted goes
/// first — the index carries an insertion sequence, so which one makes
/// room is never the luck of a random id.
struct Ending<V> {
    map: HashMap<String, (V, i64, u64)>,
    by_end: BTreeSet<(i64, u64, String)>,
    seq: u64,
}

impl<V> Ending<V> {
    fn new() -> Self {
        Self { map: HashMap::new(), by_end: BTreeSet::new(), seq: 0 }
    }

    /// Keeps `v` under `key` until `ends`, `cap` entries at most: the keys
    /// it pushed out to make room (FRAME-21: a journal records them).
    fn insert(&mut self, key: String, v: V, ends: i64, cap: usize) -> Vec<String> {
        self.purge(now());
        self.remove(&key);
        let mut evicted = Vec::new();
        while self.map.len() >= cap.max(1) {
            let Some((_, _, k)) = self.by_end.pop_first() else { break };
            self.map.remove(&k);
            evicted.push(k);
        }
        self.seq += 1;
        self.by_end.insert((ends, self.seq, key.clone()));
        self.map.insert(key, (v, ends, self.seq));
        evicted
    }

    /// Drops every entry ended by `t`, from the front of the index.
    fn purge(&mut self, t: i64) {
        while self.by_end.first().is_some_and(|(e, _, _)| *e <= t) {
            let (_, _, k) = self.by_end.pop_first().expect("checked");
            self.map.remove(&k);
        }
    }

    /// The entry under `key`, while it lasts.
    fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.map.get_mut(key).filter(|(_, e, _)| *e > now()).map(|(v, _, _)| v)
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.map.get(key).filter(|(_, e, _)| *e > now()).map(|(v, _, _)| v)
    }

    /// Takes the entry under `key` out, ended or not: it and when it ends.
    fn remove(&mut self, key: &str) -> Option<(V, i64)> {
        let (v, e, n) = self.map.remove(key)?;
        self.by_end.remove(&(e, n, key.to_string()));
        Some((v, e))
    }

    /// Takes the entry under `key` out, if it still lasts.
    fn take(&mut self, key: &str) -> Option<V> {
        self.remove(key).filter(|(_, e)| *e > now()).map(|(v, _)| v)
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A login on its way out to an IdP and back: what the callback needs to
/// finish it. Keyed by its `state`.
#[derive(Clone, Debug)]
pub struct Pending {
    pub provider: String,
    pub verifier: String,
    pub next: String,
    pub expires: i64,
}

/// AUTH-7: how long a loopback sign-in (`auth.login {browser}`) waits for
/// the person, and how long the one-time code it ends with lasts.
pub const CLI_STATE_SECS: i64 = 600;
pub const CLI_CODE_SECS: i64 = 60;

/// AUTH-7: a loopback sign-in on its way through the login page: where the
/// browser goes back to when the person has signed in.
#[derive(Clone, Debug)]
struct CliPending {
    redirect: String,
}

/// AUTH-7: the one-time code a finished loopback sign-in hands the
/// browser: who signed in, bound to the sign-in's state.
#[derive(Clone)]
struct CliCode {
    state: String,
    ctx: AuthContext,
}

/// FRAME-21: one line of the journal.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Row {
    /// A session started: its key, its end, whether it idles, when it was
    /// last used, who.
    Start { key: String, ends: i64, idles: bool, seen: i64, ctx: AuthContext },
    /// A browser's session used at `at` — written at most once a grain
    /// ([`Sessions::touch_grain`]).
    Touch { key: String, at: i64 },
    /// A session ended (sign-out, idleness, the cap).
    End { key: String },
}

impl Row {
    fn line(&self) -> Vec<u8> {
        let mut l = serde_json::to_vec(self).expect("a row serializes");
        l.push(b'\n');
        l
    }
}

/// FRAME-21: where the journal's bytes go — a file, or (in a test) a sink
/// that refuses.
pub(crate) trait Sink: Send {
    /// Appends `bytes`; `sync`: durably (fsynced) before it answers.
    fn append(&mut self, bytes: &[u8], sync: bool) -> io::Result<()>;
    /// Replaces everything with `bytes`, durably and atomically.
    fn rewrite(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// The journal's file, 0600, beside its lock (`<path>.lock`), which is held
/// for as long as the table lives — on a file of its own, because a
/// compaction renames a new journal into place and a lock on the old one
/// would stay with the old inode.
pub(crate) struct FileSink {
    path: PathBuf,
    file: std::fs::File,
    _lock: std::fs::File,
}

fn open_0600(path: &Path, fresh: bool) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.read(true).append(true).mode(0o600);
    if fresh {
        o.create_new(true);
    } else {
        o.create(true);
    }
    o.open(path)
}

pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

impl FileSink {
    /// Takes the lock beside `path`, then opens (or makes) the journal: the
    /// sink and what the journal held. `what` names the file in the refusal
    /// a second server gets (`sessions`, IDENTITY-49's `invites`).
    pub(crate) fn open(path: &Path, what: &str) -> io::Result<(Self, Vec<u8>)> {
        use std::os::unix::fs::PermissionsExt;
        let ctx = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(ctx)?;
        }
        let lock_path = with_suffix(path, ".lock");
        let lock = open_0600(&lock_path, false).map_err(ctx)?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is held by another server ({}): one server keeps one {what} file", path.display(), lock_path.display()),
            ),
            std::fs::TryLockError::Error(e) => io::Error::new(e.kind(), format!("cannot lock {}: {e}", lock_path.display())),
        })?;
        let mut file = open_0600(path, false).map_err(ctx)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(ctx)?;
        let mut held = Vec::new();
        file.read_to_end(&mut held).map_err(ctx)?;
        Ok((Self { path: path.to_path_buf(), file, _lock: lock }, held))
    }
}

impl Sink for FileSink {
    fn append(&mut self, bytes: &[u8], sync: bool) -> io::Result<()> {
        self.file.write_all(bytes)?;
        if sync {
            self.file.sync_data()?;
        }
        Ok(())
    }

    fn rewrite(&mut self, bytes: &[u8]) -> io::Result<()> {
        let tmp = with_suffix(&self.path, ".new");
        let _ = std::fs::remove_file(&tmp);
        let mut file = open_0600(&tmp, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        self.file = file;
        Ok(())
    }
}

/// FRAME-21: past this many rows, and ten times the live set, the journal
/// is rewritten to the live set.
const COMPACT_FLOOR: usize = 1_000;

/// The journal: its sink and how many rows it holds.
struct Journal {
    sink: Box<dyn Sink>,
    rows: usize,
}

/// The session table. See the module docs.
pub struct Sessions {
    live: Mutex<Ending<Session>>,
    /// FRAME-21: the journal, when the table was opened on one. Taken
    /// before `live` when both are held; `live` is never held across a
    /// write to it (an open socket asks `alive` every second).
    journal: Mutex<Option<Journal>>,
    /// At most this many sessions live ([`MAX_LIVE`]).
    cap: usize,
    pending: Mutex<Ending<Pending>>,
    /// AUTH-7: loopback sign-ins, by state.
    cli: Mutex<Ending<CliPending>>,
    /// AUTH-7: their codes, by the code's hash.
    codes: Mutex<Ending<CliCode>>,
    ttl_secs: i64,
    /// ACCESS-29: how long a browser's session may go unused (0: forever).
    idle_secs: i64,
    /// The session cookie's name (this shell's, IDENTITY-38).
    cookie: String,
    /// The login transaction cookie's name (this shell's).
    login_cookie: String,
    names: LoginNames,
}

impl Sessions {
    /// Sessions that last `ttl_secs` from sign-in, in cookies of the base
    /// names `names` gives (no shell: nothing per shell).
    pub fn new(ttl_secs: i64, names: &LoginNames) -> Self {
        Self::build(ttl_secs, names, names.session_cookie.clone(), names.login_cookie.clone())
    }

    /// Sessions for a shell reached at `public_url`: its cookies named for it
    /// ([`LoginNames::session_cookie_for`], IDENTITY-38), so two servers on
    /// one host keep apart.
    pub fn for_shell(ttl_secs: i64, names: &LoginNames, public_url: &str) -> Self {
        Self::build(ttl_secs, names, names.session_cookie_for(public_url), names.login_cookie_for(public_url))
    }

    /// FRAME-21: [`Sessions::new`], kept in a journal at `path`
    /// ([`Sessions::journaled`]).
    pub fn open(path: impl AsRef<Path>, ttl_secs: i64, names: &LoginNames) -> io::Result<Self> {
        Self::new(ttl_secs, names).journaled(path)
    }

    /// FRAME-21: this table kept in a journal at `path` (the host names it:
    /// menger's is `<database>.sessions.jsonl` beside its database), so a
    /// restart signs no one out — every session that still stands is
    /// loaded, with its last use, and the file is rewritten to them. The
    /// file is made 0600, beside a lock (`<path>.lock`) held for the
    /// table's life: a second table (another server) on it is refused,
    /// naming it. `Sessions::for_shell(…).journaled(path)?` is what
    /// [`crate::wiring::Wiring`] builds under `sessions_file`.
    pub fn journaled(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let (sink, held) = FileSink::open(path, "sessions")?;
        self.replay(&held, path);
        let me = self.with_sink(Box::new(sink));
        me.compact().map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        Ok(me)
    }

    /// The rows in `held`, in order, into the table: a start that has not
    /// ended, a use, an end. A line that is not a row (a torn last write)
    /// is skipped.
    fn replay(&self, held: &[u8], path: &Path) {
        let mut live = self.live.lock().unwrap();
        let t = now();
        for line in held.split(|b| *b == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)) {
            match serde_json::from_slice::<Row>(line) {
                Ok(Row::Start { key, ends, idles, seen, ctx }) if ends > t => {
                    live.insert(key, Session { ctx, idles, seen, touched: seen }, ends, self.cap);
                }
                Ok(Row::Start { .. }) => {}
                Ok(Row::Touch { key, at }) => {
                    if let Some(s) = live.map.get_mut(&key).map(|(s, _, _)| s) {
                        s.seen = s.seen.max(at);
                        s.touched = s.seen;
                    }
                }
                Ok(Row::End { key }) => {
                    live.remove(&key);
                }
                Err(e) => tracing::warn!(file = %path.display(), "a sessions row that does not read is skipped: {e}"),
            }
        }
    }

    fn with_sink(self, sink: Box<dyn Sink>) -> Self {
        *self.journal.lock().unwrap() = Some(Journal { sink, rows: 0 });
        self
    }

    /// Every session that stands: its key and identity (FRAME-21: what a
    /// host re-seats beside it after a restart).
    pub fn standing(&self) -> Vec<(String, AuthContext)> {
        let mut live = self.live.lock().unwrap();
        live.purge(now());
        live.map.iter().map(|(k, (s, _, _))| (k.clone(), s.ctx.clone())).collect()
    }

    /// Rewrites the journal to the live set.
    fn compact(&self) -> io::Result<()> {
        let mut journal = self.journal.lock().unwrap();
        match journal.as_mut() {
            Some(j) => self.compact_into(j),
            None => Ok(()),
        }
    }

    /// The live set, read under `live` alone, written to the journal after
    /// it is let go. Called with the journal held, so no row lands between.
    fn compact_into(&self, j: &mut Journal) -> io::Result<()> {
        let bytes: Vec<u8> = {
            let mut live = self.live.lock().unwrap();
            live.purge(now());
            live.by_end
                .iter()
                .flat_map(|(ends, _, key)| {
                    let (s, _, _) = &live.map[key];
                    Row::Start { key: key.clone(), ends: *ends, idles: s.idles, seen: s.seen, ctx: s.ctx.clone() }.line()
                })
                .collect()
        };
        let rows = bytes.iter().filter(|b| **b == b'\n').count();
        j.sink.rewrite(&bytes)?;
        j.rows = rows;
        Ok(())
    }

    /// Writes `rows` to the held journal (`sync`: durably); past ten times
    /// the live set, rewrites it.
    fn append(&self, j: &mut Journal, rows: &[Row], sync: bool) -> io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let bytes: Vec<u8> = rows.iter().flat_map(Row::line).collect();
        j.sink.append(&bytes, sync)?;
        j.rows += rows.len();
        let live = self.live.lock().unwrap().len();
        if j.rows > (live * 10).max(COMPACT_FLOOR) {
            if let Err(e) = self.compact_into(j) {
                tracing::error!("the sessions journal could not be compacted: {e}");
            }
        }
        Ok(())
    }

    /// Records sessions that ended — already out of `live`. An ending is
    /// never undone, so a row that cannot be written is logged.
    fn record_ends(&self, keys: Vec<String>) {
        if keys.is_empty() {
            return;
        }
        let mut journal = self.journal.lock().unwrap();
        let Some(j) = journal.as_mut() else { return };
        let rows: Vec<Row> = keys.into_iter().map(|key| Row::End { key }).collect();
        if let Err(e) = self.append(j, &rows, true) {
            tracing::error!("a session's end could not be written to the journal (it may stand again after a restart): {e}");
        }
    }

    /// How often a browser's use is written: an eighth of its idle time, at
    /// least a second — so a restart loses at most that much of its clock.
    fn touch_grain(&self) -> i64 {
        (self.idle_secs / 8).max(1)
    }

    fn build(ttl_secs: i64, names: &LoginNames, cookie: String, login_cookie: String) -> Self {
        Self {
            live: Mutex::new(Ending::new()),
            journal: Mutex::new(None),
            cap: MAX_LIVE,
            pending: Mutex::new(Ending::new()),
            cli: Mutex::new(Ending::new()),
            codes: Mutex::new(Ending::new()),
            ttl_secs,
            idle_secs: IDLE_SECS_DEFAULT,
            cookie,
            login_cookie,
            names: names.clone(),
        }
    }

    /// ACCESS-29: a browser's session ends after `secs` unused
    /// ([`IDLE_SECS_DEFAULT`] unless said; 0: only at its expiry).
    pub fn with_idle(mut self, secs: i64) -> Self {
        self.idle_secs = secs.max(0);
        self
    }

    /// The session cookie's name.
    pub fn cookie_name(&self) -> &str {
        &self.cookie
    }

    /// The login transaction cookie's name: binds a code-flow callback to
    /// the browser that started it.
    pub fn login_cookie_name(&self) -> &str {
        &self.login_cookie
    }

    /// The metadata key a session-backed identity carries, beside
    /// `expires_at`: the hash [`Sessions::alive`] is asked about. Its one
    /// definition ([`LoginNames::session_key`]).
    pub fn session_key(&self) -> &str {
        &self.names.session_key
    }

    /// Every name this table writes.
    pub fn names(&self) -> &LoginNames {
        &self.names
    }

    /// Starts a session for an identity a provider proved: the cookie value
    /// to set and when it ends. The identity is stamped with the session's
    /// key and expiry, so a call can ask whether it still stands.
    /// FRAME-21: on a journal, the session is written before it is handed
    /// out; a row that cannot be written is an error and no session.
    pub fn create(&self, ctx: AuthContext) -> io::Result<(String, i64)> {
        self.start(random_token(), ctx, self.ttl_secs, true)
    }

    /// IDENTITY-42: mints a session token (`mgs_…`) for an identity, lasting
    /// `ttl_secs`: the token and when it ends. Kept hashed, as a cookie's
    /// session is; it ends at its expiry or [`Sessions::end_key`].
    /// FRAME-21: written before it is handed out, as [`Sessions::create`].
    pub fn mint(&self, ctx: AuthContext, ttl_secs: i64) -> io::Result<(String, i64)> {
        self.start(format!("{TOKEN_PREFIX}{}", random_token()), ctx, ttl_secs, false)
    }

    fn start(&self, id: String, mut ctx: AuthContext, ttl_secs: i64, idles: bool) -> io::Result<(String, i64)> {
        let key = hash(&id);
        let expires = now() + ttl_secs;
        if let Some(meta) = ctx.metadata.as_object_mut() {
            meta.insert(self.names.session_key.clone(), key.clone().into());
            meta.insert("expires_at".into(), expires.into());
        }
        let t = now();
        // FRAME-21: durable before it exists — the row written and fsynced
        // under the journal alone, then the session put in `live`, then
        // what the cap pushed out written as ended.
        let mut journal = self.journal.lock().unwrap();
        if let Some(j) = journal.as_mut() {
            self.append(j, &[Row::Start { key: key.clone(), ends: expires, idles, seen: t, ctx: ctx.clone() }], true)?;
        }
        let evicted = self.live.lock().unwrap().insert(key, Session { ctx, idles, seen: t, touched: t }, expires, self.cap);
        if let (Some(j), false) = (journal.as_mut(), evicted.is_empty()) {
            let rows: Vec<Row> = evicted.into_iter().map(|key| Row::End { key }).collect();
            if let Err(e) = self.append(j, &rows, true) {
                tracing::error!("the cap's ends could not be written to the journal: {e}");
            }
        }
        Ok((id, expires))
    }

    /// The session under `key` while it stands — before its expiry and, a
    /// browser's, used within [`Sessions::with_idle`]'s time — marked used
    /// now. One gone idle is dropped.
    fn used(&self, key: &str) -> Option<AuthContext> {
        let t = now();
        let (ctx, touch) = {
            let mut live = self.live.lock().unwrap();
            let s = live.get_mut(key)?;
            if s.idles && self.idle_secs > 0 && t - s.seen > self.idle_secs {
                live.remove(key);
                drop(live);
                self.record_ends(vec![key.to_string()]);
                return None;
            }
            s.seen = t;
            // FRAME-21: a browser's use, written once a grain.
            let touch = s.idles && self.idle_secs > 0 && t - s.touched >= self.touch_grain();
            if touch {
                s.touched = t;
            }
            (s.ctx.clone(), touch)
        };
        if touch {
            let mut journal = self.journal.lock().unwrap();
            if let Some(j) = journal.as_mut() {
                // Not fsynced: a lost touch costs at most a grain of the clock.
                if let Err(e) = self.append(j, &[Row::Touch { key: key.to_string(), at: t }], false) {
                    tracing::warn!("a session's use could not be written to the journal: {e}");
                }
            }
        }
        Some(ctx)
    }

    /// The identity a session id stands for, while it lasts.
    pub fn get(&self, id: &str) -> Option<AuthContext> {
        self.used(&hash(id))
    }

    /// Ends a session (sign-out). Its sockets stop answering on their next
    /// call ([`Sessions::alive`]).
    pub fn end(&self, id: &str) {
        self.end_key(&hash(id));
    }

    /// IDENTITY-42: ends the session whose key (the hash its identity
    /// carries under [`Sessions::session_key`]) this is; whether it stood.
    pub fn end_key(&self, key: &str) -> bool {
        let removed = self.live.lock().unwrap().remove(key);
        let Some((_, ends)) = removed else { return false };
        self.record_ends(vec![key.to_string()]);
        ends > now()
    }

    /// Whether the session a connection's identity names still stands.
    pub fn alive(&self, key: &str) -> bool {
        self.used(key).is_some()
    }

    /// Keeps a login transaction for ten minutes; its state.
    pub fn begin(&self, provider: &str, verifier: String, next: String) -> String {
        let state = random_token();
        let expires = now() + 600;
        let p = Pending { provider: provider.into(), verifier, next, expires };
        self.pending.lock().unwrap().insert(state.clone(), p, expires, MAX_PENDING);
        state
    }

    /// Takes a login transaction back, once.
    pub fn finish(&self, state: &str) -> Option<Pending> {
        self.pending.lock().unwrap().take(state)
    }

    /// AUTH-7: how long a browser's sign-in lasts.
    pub fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    /// AUTH-7, `auth.login {browser {redirect}}`: keeps a loopback sign-in
    /// for ten minutes; its state.
    pub fn begin_cli(&self, redirect: String) -> String {
        let state = format!("s_{}", random_token());
        let expires = now() + CLI_STATE_SECS;
        self.cli.lock().unwrap().insert(state.clone(), CliPending { redirect }, expires, MAX_PENDING);
        state
    }

    /// AUTH-7: whether `state` names a loopback sign-in still waiting.
    pub fn cli_waiting(&self, state: &str) -> bool {
        self.cli.lock().unwrap().get(state).is_some()
    }

    /// AUTH-7: the person signed in as `ctx`: the loopback sign-in `state`
    /// is taken (once) and a one-time code bound to it issued, good for
    /// [`CLI_CODE_SECS`] — the redirect to send the browser to, and the
    /// code. `None`: no such sign-in waits.
    pub fn finish_cli(&self, state: &str, ctx: AuthContext) -> Option<(String, String)> {
        let pending = self.cli.lock().unwrap().take(state)?;
        let code = format!("c_{}", random_token());
        let c = CliCode { state: state.to_string(), ctx };
        self.codes.lock().unwrap().insert(hash(&code), c, now() + CLI_CODE_SECS, MAX_PENDING);
        Some((pending.redirect, code))
    }

    /// AUTH-7, `auth.login {code {code, state}}`: who signed in, once — the
    /// code must be the one issued for `state`, and fresh.
    pub fn take_code(&self, code: &str, state: &str) -> Option<AuthContext> {
        let c = self.codes.lock().unwrap().take(&hash(code))?;
        (c.state == state).then_some(c.ctx)
    }
}

/// AUTH-7: a loopback sign-in's redirect, as `auth.login {browser}` takes it:
/// `http://127.0.0.1:<port>/…`, `http://localhost:<port>/…` or
/// `http://[::1]:<port>/…` — the client's own port on this machine, nothing
/// else (no user, no fragment). The normalized URL, or why not.
pub fn loopback_redirect(text: &str) -> Result<String, String> {
    let refuse = || format!("`{}` is not a loopback redirect: http://127.0.0.1:<port>/… or http://localhost:<port>/…", text.trim());
    let u = url::Url::parse(text.trim()).map_err(|_| refuse())?;
    let host_ok = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST)
        || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST)
        || matches!(u.host(), Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost"));
    if u.scheme() != "http" || !host_ok || u.port().is_none() || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err(refuse());
    }
    Ok(u.to_string())
}

/// A minted session token a value the transport offers carries: the bearer
/// value itself, or the `access_token` cookie of a `Cookie` header.
fn minted_token(value: &str) -> Option<&str> {
    let v = value.trim();
    if v.starts_with(TOKEN_PREFIX) && !v.contains([';', '=', ' ']) {
        return Some(v);
    }
    cookie(v, "access_token").filter(|t| t.starts_with(TOKEN_PREFIX))
}

/// What the gate calls for every identity it admits (the app's
/// [`LoginAccess::notice`]).
type Notice = Arc<dyn Fn(&AuthContext) + Send + Sync>;

/// The WebSocket upgrade's validator: a session cookie, else a minted
/// session token, else a provider's own credential through the carriers.
pub struct Gate {
    sessions: Arc<Sessions>,
    carriers: Option<Arc<Carriers>>,
    /// AUTH-7: who signs in holding nothing is put on the waiting list here,
    /// as it opens the socket — the gate refuses its calls before any method
    /// could notice it. SCAFFOLD-3: the app's [`LoginAccess::notice`].
    notice: Option<Notice>,
}

impl Gate {
    pub fn new(sessions: Arc<Sessions>, carriers: Option<Arc<Carriers>>) -> Self {
        Self { sessions, carriers, notice: None }
    }

    /// AUTH-7: a sign-in holding no grant waits for an admin
    /// ([`LoginAccess::notice`]).
    pub fn noticing<A: LoginAccess>(mut self, access: A) -> Self {
        self.notice = Some(Arc::new(move |ctx: &AuthContext| access.notice(ctx)));
        self
    }

    async fn identify(&self, value: &str) -> Option<AuthContext> {
        if let Some(ctx) = cookie(value, self.sessions.cookie_name()).and_then(|id| self.sessions.get(id)) {
            return Some(ctx);
        }
        // IDENTITY-42: a minted token is a session or nobody — an ended or
        // expired one proves no one (refused 401: AUTH-6, a credential
        // presented and refused).
        if let Some(token) = minted_token(value) {
            return self.sessions.get(token);
        }
        match &self.carriers {
            Some(c) => c.validate(value).await,
            None => None,
        }
    }
}

#[async_trait]
impl SessionValidator for Gate {
    async fn validate(&self, value: &str) -> Option<AuthContext> {
        let ctx = self.identify(value).await?;
        if let Some(notice) = &self.notice {
            notice(&ctx);
        }
        Some(ctx)
    }

    /// AUTH-11: the transport asks while the socket is open, and closes it
    /// once its session is signed out or expired.
    fn alive(&self, ctx: &AuthContext) -> Result<(), String> {
        if ctx.expired() {
            return Err("your sign-in has expired: sign in again".into());
        }
        match ctx.get_metadata_string(self.sessions.session_key()) {
            Some(key) if !self.sessions.alive(&key) => Err("you have signed out: sign in again".into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names() -> LoginNames {
        LoginNames::for_app("menger")
    }

    fn alice() -> AuthContext {
        AuthContext::new("alice".into(), "sid".into(), vec![], json!({ "name": "alice" }))
    }

    #[test]
    fn a_session_stands_until_it_ends() {
        let s = Sessions::new(3600, &names());
        let (id, expires) = s.create(alice()).unwrap();
        let ctx = s.get(&id).expect("signed in");
        assert_eq!(ctx.user_id, "alice");
        assert_eq!(ctx.metadata["expires_at"], expires);
        let key = ctx.metadata["menger_session"].as_str().unwrap().to_string();
        assert!(s.alive(&key));
        assert_ne!(key, id, "the table keeps a hash, not the cookie");
        s.end(&id);
        assert!(s.get(&id).is_none());
        assert!(!s.alive(&key), "its sockets see it gone");
    }

    #[test]
    fn an_expired_session_is_nobody() {
        let s = Sessions::new(-1, &names());
        let (id, _) = s.create(alice()).unwrap();
        assert!(s.get(&id).is_none());
    }

    #[test]
    fn a_login_transaction_is_taken_once() {
        let s = Sessions::new(3600, &names());
        let state = s.begin("auth0", "verifier".into(), "/".into());
        assert_eq!(s.finish(&state).unwrap().verifier, "verifier");
        assert!(s.finish(&state).is_none());
        assert!(s.finish("forged").is_none());
    }

    #[test]
    fn a_table_names_its_cookies_for_its_shell() {
        let s = Sessions::for_shell(3600, &names(), "http://127.0.0.1:4456");
        assert_eq!((s.cookie_name(), s.login_cookie_name(), s.session_key()), ("menger_session_4456", "menger_login_4456", "menger_session"));
        let s = Sessions::for_shell(3600, &LoginNames::for_app("toy"), "https://toy.example");
        assert_eq!((s.cookie_name(), s.login_cookie_name(), s.session_key()), ("__Host-toy_session", "__Secure-toy_login", "toy_session"));
        let (id, _) = s.create(alice()).unwrap();
        assert!(s.get(&id).unwrap().metadata["toy_session"].is_string(), "stamped under the app's key");
    }

    #[test]
    fn waiting_logins_are_capped() {
        let s = Sessions::new(3600, &names());
        let first = s.begin("auth0", "v".into(), "/".into());
        for _ in 0..MAX_PENDING + 50 {
            s.begin("auth0", "v".into(), "/".into());
        }
        assert_eq!(s.pending.lock().unwrap().len(), MAX_PENDING);
        let _ = first;
    }

    #[test]
    fn a_flood_of_logins_is_held_to_the_cap_without_a_scan_per_insert() {
        // ACCESS-29: ten times the cap, each insert O(log n) — the scan the
        // table did before made this a billion steps.
        let s = Sessions::new(3600, &names());
        let started = std::time::Instant::now();
        let first = s.begin("auth0", "v".into(), "/".into());
        for _ in 0..MAX_PENDING * 10 {
            s.begin("auth0", "v".into(), "/".into());
        }
        let p = s.pending.lock().unwrap();
        assert_eq!((p.len(), p.by_end.len()), (MAX_PENDING, MAX_PENDING), "the index and the table agree");
        drop(p);
        assert!(s.finish(&first).is_none(), "the oldest made room");
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
    }

    #[test]
    fn a_browser_session_unused_past_its_idle_time_ends_and_a_minted_token_does_not() {
        // ACCESS-29 (ACCESS-4 L2).
        let s = Sessions::new(3600, &names()).with_idle(60);
        let (id, _) = s.create(alice()).unwrap();
        let (token, _) = s.mint(alice(), 3600).unwrap();
        let key = s.get(&id).unwrap().metadata["menger_session"].as_str().unwrap().to_string();
        let minted = s.get(&token).unwrap().metadata["menger_session"].as_str().unwrap().to_string();
        assert!(s.alive(&key), "used: it stands");
        // An hour unused.
        for k in [&key, &minted] {
            s.live.lock().unwrap().get_mut(k).unwrap().seen -= 3000;
        }
        assert!(!s.alive(&key) && s.get(&id).is_none(), "idle: ended");
        assert!(s.alive(&minted) && s.get(&token).is_some(), "a minted token keeps only its expiry");
        let off = Sessions::new(3600, &names()).with_idle(0);
        let (id, _) = off.create(alice()).unwrap();
        let key = off.get(&id).unwrap().metadata["menger_session"].as_str().unwrap().to_string();
        off.live.lock().unwrap().get_mut(&key).unwrap().seen -= 3000;
        assert!(off.get(&id).is_some(), "0: no idle end");
    }

    #[test]
    fn asking_after_a_session_keeps_it_in_use() {
        let s = Sessions::new(3600, &names()).with_idle(60);
        let (id, _) = s.create(alice()).unwrap();
        let key = s.get(&id).unwrap().metadata["menger_session"].as_str().unwrap().to_string();
        s.live.lock().unwrap().get_mut(&key).unwrap().seen -= 50;
        assert!(s.alive(&key), "an open socket's ask is a use");
        s.live.lock().unwrap().get_mut(&key).unwrap().seen -= 50;
        assert!(s.get(&id).is_some(), "the ask moved its last use to now");
    }

    #[tokio::test]
    async fn the_gate_reads_only_its_own_cookie() {
        let s = Arc::new(Sessions::for_shell(3600, &names(), "http://127.0.0.1:4456"));
        let (id, _) = s.create(alice()).unwrap();
        let gate = Gate::new(s.clone(), None);
        assert!(gate.validate(&format!("menger_session_4451=x; menger_session_4456={id}")).await.is_some());
        assert!(gate.validate(&format!("menger_session={id}")).await.is_none(), "another server's name is not ours");
    }

    #[tokio::test]
    async fn a_minted_token_opens_as_a_bearer_or_the_access_token_cookie_until_it_ends() {
        let s = Arc::new(Sessions::new(3600, &names()));
        let (token, expires) = s.mint(alice(), 60).unwrap();
        assert!(token.starts_with("mgs_") && token.len() >= 47, "{token}");
        assert!(expires <= now() + 60);
        let gate = Gate::new(s.clone(), None);
        let ctx = gate.validate(&token).await.expect("bearer");
        assert_eq!(ctx.user_id, "alice");
        assert!(gate.validate(&format!("theme=dark; access_token={token}")).await.is_some(), "cookie");
        assert!(gate.validate("mgs_forged").await.is_none());
        let key = ctx.metadata["menger_session"].as_str().unwrap().to_string();
        assert!(s.end_key(&key));
        assert!(gate.validate(&token).await.is_none(), "ended");
        assert!(!s.end_key(&key), "once");
        let (old, _) = s.mint(alice(), -1).unwrap();
        assert!(gate.validate(&old).await.is_none(), "expired");
    }

    #[test]
    fn a_loopback_sign_in_ends_in_one_code_for_its_state() {
        let s = Sessions::new(3600, &names());
        let state = s.begin_cli("http://127.0.0.1:53817/cb".into());
        assert!(s.cli_waiting(&state));
        let (redirect, code) = s.finish_cli(&state, alice()).expect("waiting");
        assert_eq!(redirect, "http://127.0.0.1:53817/cb");
        assert!(!s.cli_waiting(&state) && s.finish_cli(&state, alice()).is_none(), "the state is taken once");
        assert!(s.take_code(&code, "s_other").is_none(), "bound to its state");
        let s2 = Sessions::new(3600, &names());
        let st = s2.begin_cli("http://localhost:1/x".into());
        let (_, c) = s2.finish_cli(&st, alice()).unwrap();
        assert_eq!(s2.take_code(&c, &st).unwrap().user_id, "alice");
        assert!(s2.take_code(&c, &st).is_none(), "once");
    }

    #[test]
    fn only_a_loopback_port_is_a_redirect() {
        for ok in ["http://127.0.0.1:53817/cb", "http://localhost:9/", "http://[::1]:8080/cb?x=1"] {
            assert!(loopback_redirect(ok).is_ok(), "{ok}");
        }
        for bad in ["https://127.0.0.1:1/cb", "http://127.0.0.1/cb", "http://evil.example:1/", "http://127.0.0.2:1/", "http://u@127.0.0.1:1/", "http://127.0.0.1:1/#x", "nope"] {
            assert!(loopback_redirect(bad).is_err(), "{bad}");
        }
    }

    /// FRAME-21: a journal that refuses its row.
    struct Refusing;

    impl Sink for Refusing {
        fn append(&mut self, _: &[u8], _: bool) -> io::Result<()> {
            Err(io::Error::other("the disk is full"))
        }
        fn rewrite(&mut self, _: &[u8]) -> io::Result<()> {
            Err(io::Error::other("the disk is full"))
        }
    }

    #[test]
    fn a_session_whose_row_cannot_be_written_is_not_handed_out() {
        let s = Sessions::new(3600, &names()).with_sink(Box::new(Refusing));
        let err = s.create(alice()).expect_err("no row, no session");
        assert!(err.to_string().contains("disk is full"), "{err}");
        assert!(s.mint(alice(), 60).is_err());
        assert_eq!(s.live.lock().unwrap().len(), 0, "nothing stands that the journal does not hold");
    }

    #[test]
    fn the_caps_evictions_are_journaled_as_ends() {
        // FRAME-21: a session the cap pushed out does not come back at a
        // restart (whose table may hold more).
        let dir = std::env::temp_dir().join(format!("plexus-login-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sessions.jsonl");
        let ids: Vec<String> = {
            let mut s = Sessions::open(&path, 3600, &names()).unwrap();
            s.cap = 3;
            (0..5).map(|_| s.mint(alice(), 600).unwrap().0).collect()
        };
        let s = Sessions::open(&path, 3600, &names()).unwrap();
        assert!(s.get(&ids[0]).is_none() && s.get(&ids[1]).is_none(), "the two the cap pushed out stay out");
        assert!(ids[2..].iter().all(|id| s.get(id).is_some()), "the three it kept stand");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_second_table_on_one_journal_is_refused_naming_it() {
        let dir = std::env::temp_dir().join(format!("plexus-login-lock-{}", std::process::id()));
        let path = dir.join("sessions.jsonl");
        let first = Sessions::open(&path, 3600, &names()).expect("the first opens");
        let err = Sessions::open(&path, 3600, &names()).err().expect("the second is refused");
        assert!(err.to_string().contains(&path.display().to_string()) && err.to_string().contains("another server"), "{err}");
        drop(first);
        assert!(Sessions::open(&path, 3600, &names()).is_ok(), "free again once the first is gone");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ids_are_random_and_long() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert!(a.len() >= 43);
    }

    #[tokio::test]
    async fn the_gate_takes_the_session_cookie_among_others() {
        let s = Arc::new(Sessions::new(3600, &names()));
        let (id, _) = s.create(alice()).unwrap();
        let gate = Gate::new(s.clone(), None);
        assert!(gate.validate(&format!("theme=dark; menger_session={id}")).await.is_some());
        assert!(gate.validate("menger_session=forged").await.is_none());
        assert!(gate.validate(&id).await.is_none(), "a bare id is not a cookie");
    }
}
