//! IDENTITY-49: sign-in codes — an admin hands someone a role.
//!
//! The console's one-time link ([`crate::once`]) is the local admin's door:
//! proof of the machine, loopback only. A sign-in code is a different thing:
//! it carries only what its issuer chose — one role on one scope, so many
//! uses, until a time — so it may be redeemed from anywhere. Someone opens
//! its link (`/login?code=…`), scans its QR code, or types it into the login
//! page; whoever is signed in already gets the role on their own principal,
//! anyone else a new guest principal (`oidc:invite/<id>.<n>`, named by the
//! code's label) and a session.
//!
//! | piece | what it is |
//! | --- | --- |
//! | [`Invites`] | the codes: issue, list, withdraw, redeem; kept in a journal ([`Invites::journaled`]) |
//! | [`crate::invites_activation::InvitesActivation`] | `invites.issue`, `invites.list`, `invites.revoke` on the service's socket |
//! | `GET /login?code=…`, `POST /login/invite` | the login page's half ([`crate::web_login`]) |
//!
//! **A code** is twelve Crockford base-32 characters (60 random bits) and a
//! check character, grouped `XXXX-XXXX-XXXXX`; typed in, case, dashes and
//! spaces do not matter, `O` reads as `0` and `I`/`L` as `1`. Only its
//! sha256 is kept on disk; the code itself is shown to its issuer (and
//! admins) while the server that made it runs.
//!
//! **Refusals say one thing** — spent, expired, withdrawn, mistyped and
//! unknown alike ([`REFUSED`]) — so the page is no oracle, and every guess
//! is a guess against the page's throttles (`throttle.rs`).
//!
//! **A restart keeps them** (with a journal): every code issued, its count,
//! what was withdrawn, and the grants codes made, which [`Invites::restore`]
//! gives back to rules that forget at a restart. A guest's grant is kept
//! until its session's end (a guest has no other way back in); a signed-in
//! person's until the code is withdrawn with `sign_out` — a grant taken back
//! with `auth.revoke` alone is given again at the next start.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use plexus_core::plexus::AuthContext;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::access::LoginAccess;
use crate::sessions::{now, FileSink, Sessions, Sink};

/// What the page says to a code that signs no one in — whatever the reason.
pub const REFUSED: &str =
    "That code does not sign anyone in: it may be mistyped, used up, expired or withdrawn. Ask whoever gave it to you for another.";

/// The OIDC provider name a guest's principal carries (`oidc:invite/…`);
/// no `--auth-provider` may take it.
pub const GUEST_PROVIDER: &str = "invite";

/// At most this many codes may be open (redeemable) at once.
pub const MAX_OPEN: usize = 1_000;
/// Uses a code may carry.
pub const MAX_USES: u32 = 1_000;
/// How long a code lasts unless said, and at most.
pub const DEFAULT_EXPIRES_SECS: i64 = 24 * 3600;
pub const MAX_EXPIRES_SECS: i64 = 30 * 24 * 3600;

/// `invites.issue`'s parameters.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    /// The role the code grants.
    pub role: String,
    /// Where (`*` when not said).
    #[serde(default)]
    pub scope: Option<String>,
    /// How many people it signs in (default 1).
    #[serde(default)]
    pub uses: Option<u32>,
    /// How long it lasts: `30m`, `24h`, `7d`, or seconds (default 24h, at
    /// most 30d).
    #[serde(default)]
    pub expires_in: Option<String>,
    /// What it is for ("kitchen table"); a guest is named by it.
    #[serde(default)]
    pub label: Option<String>,
}

/// One person a code signed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redemption {
    pub principal: String,
    pub at: i64,
    /// A guest principal the code made (else someone signed in already).
    pub guest: bool,
    /// A guest's grant lasts until its session ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
}

/// A code as `invites.issue` and `invites.list` answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteView {
    pub id: String,
    /// The code itself — only to its issuer and admins, and only while the
    /// server that made it runs (only its hash is kept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Its link: `<public origin>/login?code=…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Its link as a QR code (SVG).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qr_svg: Option<String>,
    pub role: String,
    pub scope: String,
    pub uses: u32,
    pub used: u32,
    pub left: u32,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub issued_by: String,
    pub issued_at: i64,
    /// `open`, `spent`, `expired` or `withdrawn`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    pub redeemed: Vec<Redemption>,
}

/// What a redemption did.
#[derive(Debug, Clone)]
pub enum Redeemed {
    /// A new guest: the identity to start a session for.
    Guest(AuthContext),
    /// The signed-in caller holds the role now (or held it from this code
    /// already).
    Granted { principal: String },
}

/// A code as kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Invite {
    id: String,
    /// The canonical code's sha256.
    hash: String,
    role: String,
    scope: String,
    uses: u32,
    used: u32,
    expires_at: i64,
    #[serde(default)]
    label: Option<String>,
    issued_by: String,
    issued_at: i64,
    #[serde(default)]
    revoked_at: Option<i64>,
    /// Withdrawn with `sign_out`: its grants taken back, never given again.
    #[serde(default)]
    taken_back: bool,
    #[serde(default)]
    redeemed: Vec<Redemption>,
}

/// A journal line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "row", rename_all = "snake_case")]
enum Row {
    Issue { invite: Invite },
    Redeem { id: String, redemption: Redemption },
    Revoke { id: String, at: i64, sign_out: bool },
}

impl Row {
    fn line(&self) -> Vec<u8> {
        let mut l = serde_json::to_vec(self).expect("a row serializes");
        l.push(b'\n');
        l
    }
}

#[derive(Default)]
struct State {
    by_id: BTreeMap<String, Invite>,
    by_hash: HashMap<String, String>,
    /// The codes this server made, by id — never written.
    codes: HashMap<String, String>,
}

impl State {
    fn put(&mut self, inv: Invite) {
        self.by_hash.insert(inv.hash.clone(), inv.id.clone());
        self.by_id.insert(inv.id.clone(), inv);
    }

    fn apply(&mut self, row: Row) {
        match row {
            Row::Issue { invite } => self.put(invite),
            Row::Redeem { id, redemption } => {
                if let Some(inv) = self.by_id.get_mut(&id) {
                    if redemption.guest || !inv.redeemed.iter().any(|r| r.principal == redemption.principal) {
                        inv.used += 1;
                    }
                    inv.redeemed.push(redemption);
                }
            }
            Row::Revoke { id, at, sign_out } => {
                if let Some(inv) = self.by_id.get_mut(&id) {
                    inv.revoked_at.get_or_insert(at);
                    inv.taken_back |= sign_out;
                }
            }
        }
    }
}

/// The journal: its sink and how many rows it holds.
struct Journal {
    sink: Box<dyn Sink>,
    rows: usize,
}

/// The sign-in codes. See the module docs.
pub struct Invites {
    state: Mutex<State>,
    /// Taken before `state` when both are held; held across a redemption,
    /// so redemptions are one at a time.
    journal: Mutex<Option<Journal>>,
    /// Where links point: the webapp's public URL.
    public_url: String,
}

impl Invites {
    /// Codes whose links point at `public_url`, in memory: a restart forgets
    /// them.
    pub fn new(public_url: &str) -> Self {
        Self { state: Mutex::default(), journal: Mutex::new(None), public_url: public_url.trim_end_matches('/').to_string() }
    }

    /// These codes kept in a journal at `path`: 0600, beside a lock
    /// (`<path>.lock`) held while they live, as FRAME-21 keeps sessions — a
    /// second server on the file is refused, naming it. Opening replays the
    /// rows (a torn last line skipped) and rewrites the file to what is
    /// kept: every code that can still be redeemed or whose grants still
    /// stand.
    pub fn journaled(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let (sink, held) = FileSink::open(path, "invites")?;
        {
            let mut state = self.state.lock().unwrap();
            for line in held.split(|b| *b == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)) {
                match serde_json::from_slice::<Row>(line) {
                    Ok(row) => state.apply(row),
                    Err(e) => tracing::warn!(file = %path.display(), "an invites row that does not read is skipped: {e}"),
                }
            }
        }
        *self.journal.lock().unwrap() = Some(Journal { sink: Box::new(sink), rows: 0 });
        {
            let mut journal = self.journal.lock().unwrap();
            self.compact_into(journal.as_mut().expect("just set")).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        }
        Ok(self)
    }

    /// Rewrites the journal to what is kept (dropping, from memory too,
    /// every code that is over and whose grants are gone).
    fn compact_into(&self, j: &mut Journal) -> io::Result<()> {
        let t = now();
        let bytes: Vec<u8> = {
            let mut state = self.state.lock().unwrap();
            let gone: Vec<String> = state.by_id.values().filter(|i| !kept(i, t)).map(|i| i.id.clone()).collect();
            for id in gone {
                if let Some(i) = state.by_id.remove(&id) {
                    state.by_hash.remove(&i.hash);
                    state.codes.remove(&id);
                }
            }
            state.by_id.values().flat_map(|i| Row::Issue { invite: i.clone() }.line()).collect()
        };
        j.rows = bytes.iter().filter(|b| **b == b'\n').count();
        j.sink.rewrite(&bytes)
    }

    /// Writes `row` durably to the held journal (none: in memory, nothing
    /// to write); past ten times the codes kept, rewrites it.
    fn write(&self, journal: &mut Option<Journal>, row: &Row) -> io::Result<()> {
        let Some(j) = journal.as_mut() else { return Ok(()) };
        j.sink.append(&row.line(), true)?;
        j.rows += 1;
        let n = self.state.lock().unwrap().by_id.len();
        if j.rows > (n * 10).max(COMPACT_FLOOR) {
            if let Err(e) = self.compact_into(j) {
                tracing::error!("the invites journal could not be compacted: {e}");
            }
        }
        Ok(())
    }

    /// Gives the grants codes made back to `access` (at a start): how many.
    /// A guest's while its session could still stand; a signed-in person's
    /// unless the code was withdrawn with `sign_out`.
    pub fn restore<A: LoginAccess>(&self, access: &A) -> usize {
        let t = now();
        let grants: Vec<(String, String, String)> = {
            let state = self.state.lock().unwrap();
            state
                .by_id
                .values()
                .filter(|i| !i.taken_back)
                .flat_map(|i| i.redeemed.iter().filter(|r| grant_stands(r, t)).map(|r| (r.principal.clone(), i.role.clone(), i.scope.clone())))
                .collect()
        };
        let mut n = 0;
        for (principal, role, scope) in grants {
            match access.invite_grant(&principal, &role, &scope) {
                Ok(()) => n += 1,
                Err(e) => tracing::warn!(principal = %principal, role = %role, "a sign-in code's grant could not be given back: {e}"),
            }
        }
        n
    }

    /// Where a code's link points.
    pub fn url_of(&self, code: &str) -> String {
        format!("{}/login?code={code}", self.public_url)
    }

    /// `invites.issue`: a code for `req`, by `issuer`.
    pub fn issue<A: LoginAccess>(&self, access: &A, issuer: &AuthContext, req: Issue) -> Result<InviteView, String> {
        let by = issuer.principal().ok_or("sign in first")?.to_string();
        let role = req.role.trim().to_ascii_lowercase();
        if role.is_empty() || role.len() > 64 || !role.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
            return Err(format!("`{}` is not a role", req.role.trim()));
        }
        let scope = A::scope_of(req.scope.as_deref().unwrap_or("*"))?;
        access.invite_check(issuer, &role, &scope)?;
        let uses = req.uses.unwrap_or(1);
        if !(1..=MAX_USES).contains(&uses) {
            return Err(format!("uses is 1 to {MAX_USES}"));
        }
        let secs = match req.expires_in.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_EXPIRES_SECS,
            Some(text) => duration(text).ok_or_else(|| format!("expires_in `{text}`: a number and s, m, h or d (30m, 24h, 7d)"))?,
        };
        if !(1..=MAX_EXPIRES_SECS).contains(&secs) {
            return Err("expires_in is at most 30d".into());
        }
        let label = req.label.as_deref().map(clean).filter(|l| !l.is_empty());
        let mut journal = self.journal.lock().unwrap();
        let t = now();
        let (code, id) = {
            let state = self.state.lock().unwrap();
            if state.by_id.values().filter(|i| open(i, t)).count() >= MAX_OPEN {
                return Err(format!("{MAX_OPEN} codes are open already: withdraw some (invites.revoke)"));
            }
            let mut id = random_id();
            while state.by_id.contains_key(&id) {
                id = random_id();
            }
            (new_code(), id)
        };
        let invite = Invite {
            id: id.clone(),
            hash: hash(&normalize(&code).expect("a fresh code reads")),
            role,
            scope,
            uses,
            used: 0,
            expires_at: t + secs,
            label,
            issued_by: by,
            issued_at: t,
            revoked_at: None,
            taken_back: false,
            redeemed: Vec::new(),
        };
        self.write(&mut journal, &Row::Issue { invite: invite.clone() }).map_err(|e| {
            tracing::error!("a sign-in code could not be kept: {e}");
            "the code could not be kept: try again".to_string()
        })?;
        let mut state = self.state.lock().unwrap();
        state.codes.insert(id.clone(), code);
        state.put(invite);
        Ok(self.view(&state, &id, true, true))
    }

    /// The view of a code; the code itself (and link, and QR) when
    /// `secret` and this server made it.
    fn view(&self, state: &State, id: &str, secret: bool, qr: bool) -> InviteView {
        let i = &state.by_id[id];
        let t = now();
        let code = state.codes.get(id).filter(|_| secret).cloned();
        let url = code.as_deref().map(|c| self.url_of(c));
        let qr_svg = url.as_deref().filter(|_| qr && open(i, t)).and_then(crate::qr::svg);
        let state_word = if i.revoked_at.is_some() {
            "withdrawn"
        } else if i.used >= i.uses {
            "spent"
        } else if i.expires_at <= t {
            "expired"
        } else {
            "open"
        };
        InviteView {
            id: i.id.clone(),
            code,
            url,
            qr_svg,
            role: i.role.clone(),
            scope: i.scope.clone(),
            uses: i.uses,
            used: i.used,
            left: i.uses.saturating_sub(i.used),
            expires_at: i.expires_at,
            label: i.label.clone(),
            issued_by: i.issued_by.clone(),
            issued_at: i.issued_at,
            state: state_word.into(),
            revoked_at: i.revoked_at,
            redeemed: i.redeemed.clone(),
        }
    }

    /// `invites.list`: every code for an admin, else the caller's own,
    /// newest first; the QR codes of open ones when `qr`.
    pub fn list<A: LoginAccess>(&self, access: &A, caller: &AuthContext, qr: bool) -> Vec<InviteView> {
        let admin = access.is_admin(caller);
        let me = caller.principal().map(|p| p.to_string()).unwrap_or_default();
        let state = self.state.lock().unwrap();
        let mut ids: Vec<(i64, String)> =
            state.by_id.values().filter(|i| admin || i.issued_by == me).map(|i| (i.issued_at, i.id.clone())).collect();
        ids.sort_by(|a, b| b.cmp(a));
        ids.into_iter().map(|(_, id)| self.view(&state, &id, true, qr)).collect()
    }

    /// `invites.revoke`: the code (by id or by the code) stops working;
    /// with `sign_out`, its grants are taken back and its guests' sessions
    /// ended. The code as it stands, and how many sessions ended. Only its
    /// issuer or an admin; to anyone else it does not exist.
    pub fn revoke<A: LoginAccess>(&self, access: &A, caller: &AuthContext, key: &str, sign_out: bool, sessions: &Sessions) -> Result<(InviteView, usize), String> {
        let me = caller.principal().ok_or("sign in first")?.to_string();
        let admin = access.is_admin(caller);
        let mut journal = self.journal.lock().unwrap();
        let (id, grants) = {
            let state = self.state.lock().unwrap();
            let key = key.trim();
            let id = match state.by_id.get(key) {
                Some(i) => Some(i.id.clone()),
                None => normalize(key).and_then(|c| state.by_hash.get(&hash(&c)).cloned()),
            };
            let inv = id.as_ref().and_then(|id| state.by_id.get(id)).filter(|i| admin || i.issued_by == me);
            let inv = inv.ok_or_else(|| format!("no code `{key}` of yours here: invites.list says which there are"))?;
            let grants: Vec<Redemption> = if sign_out && !inv.taken_back { inv.redeemed.clone() } else { Vec::new() };
            (inv.id.clone(), grants)
        };
        let at = now();
        self.write(&mut journal, &Row::Revoke { id: id.clone(), at, sign_out }).map_err(|e| {
            tracing::error!("a sign-in code's withdrawal could not be kept: {e}");
            "the withdrawal could not be kept: try again".to_string()
        })?;
        let mut state = self.state.lock().unwrap();
        state.apply(Row::Revoke { id: id.clone(), at, sign_out });
        let (role, scope) = (state.by_id[&id].role.clone(), state.by_id[&id].scope.clone());
        let mut ended = 0;
        if !grants.is_empty() {
            let guests: Vec<&str> = grants.iter().filter(|r| r.guest).map(|r| r.principal.as_str()).collect();
            for (key, ctx) in sessions.standing() {
                if ctx.principal().is_some_and(|p| guests.contains(&p.to_string().as_str())) && sessions.end_key(&key) {
                    ended += 1;
                }
            }
            for r in &grants {
                if let Err(e) = access.invite_revoke(&r.principal, &role, &scope) {
                    tracing::warn!(principal = %r.principal, "a sign-in code's grant could not be taken back: {e}");
                }
            }
        }
        Ok((self.view(&state, &id, true, false), ended))
    }

    /// The page's redemption of `code`: `caller`, when signed in, gets the
    /// role; anyone else a guest identity whose session lasts `guest_ttl`.
    /// `Err` is [`REFUSED`] for any code that signs no one in, or the words
    /// for a server that could not keep it.
    pub fn redeem<A: LoginAccess>(&self, access: &A, code: &str, caller: Option<&AuthContext>, guest_ttl: i64) -> Result<Redeemed, String> {
        let canon = normalize(code).ok_or(REFUSED)?;
        // One redemption at a time: the count is checked and spent together.
        let mut journal = self.journal.lock().unwrap();
        let t = now();
        let signed_in = caller.filter(|c| c.is_authenticated()).and_then(|c| c.principal()).map(|p| p.to_string());
        let (inv, redemption) = {
            let state = self.state.lock().unwrap();
            let inv = state.by_hash.get(&hash(&canon)).and_then(|id| state.by_id.get(id)).ok_or(REFUSED)?.clone();
            match &signed_in {
                // Theirs already, from this code (spent since or not): nothing spent.
                Some(p) if inv.revoked_at.is_none() && inv.redeemed.iter().any(|r| &r.principal == p) => {
                    return Ok(Redeemed::Granted { principal: p.clone() })
                }
                _ if !open(&inv, t) => return Err(REFUSED.into()),
                Some(p) => (inv, Redemption { principal: p.clone(), at: t, guest: false, until: None }),
                None => {
                    let principal = format!("oidc:{GUEST_PROVIDER}/{}.{}", inv.id, inv.used + 1);
                    (inv, Redemption { principal, at: t, guest: true, until: Some(t + guest_ttl.max(1)) })
                }
            }
        };
        access.invite_grant(&redemption.principal, &inv.role, &inv.scope).map_err(|e| {
            tracing::error!(role = %inv.role, "a sign-in code's role could not be granted: {e}");
            format!("Signing in with a code is unavailable: {e}")
        })?;
        let row = Row::Redeem { id: inv.id.clone(), redemption: redemption.clone() };
        if let Err(e) = self.write(&mut journal, &row) {
            tracing::error!("a sign-in code's use could not be kept: {e}");
            let _ = access.invite_revoke(&redemption.principal, &inv.role, &inv.scope);
            return Err("Signing in is unavailable for a moment: the code's use could not be kept. Try again.".into());
        }
        self.state.lock().unwrap().apply(row);
        Ok(if redemption.guest {
            let meta = guest_meta(&redemption.principal, inv.label.as_deref(), &inv.id);
            Redeemed::Guest(AuthContext::new(redemption.principal.clone(), "invite".into(), vec![], meta))
        } else {
            Redeemed::Granted { principal: redemption.principal }
        })
    }
}

/// Rows past this many, and ten times the codes kept, rewrite the journal.
const COMPACT_FLOOR: usize = 1_000;

/// Whether a code can still sign someone in at `t`.
fn open(i: &Invite, t: i64) -> bool {
    i.revoked_at.is_none() && i.used < i.uses && i.expires_at > t
}

/// Whether a redemption's grant still stands at `t`.
fn grant_stands(r: &Redemption, t: i64) -> bool {
    !r.guest || r.until.is_some_and(|u| u > t)
}

/// Whether a code is kept: open, or a grant it made still stands.
fn kept(i: &Invite, t: i64) -> bool {
    open(i, t) || (!i.taken_back && i.redeemed.iter().any(|r| grant_stands(r, t)))
}

/// `30m`, `24h`, `7d`, `90s` or bare seconds.
fn duration(text: &str) -> Option<i64> {
    let (n, unit) = match text.char_indices().last()? {
        (i, c) if c.is_ascii_alphabetic() => (&text[..i], c.to_ascii_lowercase()),
        _ => (text, 's'),
    };
    let n: i64 = n.trim().parse().ok().filter(|n| *n > 0)?;
    n.checked_mul(match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return None,
    })
}

/// A label: printable, at most 80 characters.
fn clean(text: &str) -> String {
    text.trim().chars().filter(|c| !c.is_control()).take(80).collect()
}

/// A code's id: eight hex digits.
fn random_id() -> String {
    let mut b = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── The code ───────────────────────────────────────────────────────────

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh code: 60 random bits, its check character, grouped.
pub fn new_code() -> String {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let n = u64::from_le_bytes(b) & ((1 << 60) - 1);
    let data: String = (0..12).rev().map(|i| ALPHABET[((n >> (i * 5)) & 31) as usize] as char).collect();
    let canon = format!("{data}{}", check(&data));
    grouped(&canon)
}

/// The check character of twelve data characters.
fn check(data: &str) -> char {
    let h = Sha256::digest([b"plexus-login invite\0".as_slice(), data.as_bytes()].concat());
    ALPHABET[(h[0] % 32) as usize] as char
}

/// `XXXX-XXXX-XXXXX`.
fn grouped(canon: &str) -> String {
    format!("{}-{}-{}", &canon[..4], &canon[4..8], &canon[8..])
}

/// A code as typed, canonical (thirteen characters, no dashes), or `None`
/// for one that is not a code (a wrong length, a character not in the
/// alphabet, a check that fails).
pub fn normalize(typed: &str) -> Option<String> {
    let mut out = String::with_capacity(13);
    for c in typed.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c if ALPHABET.contains(&(c as u8)) && c.is_ascii() => c,
            _ => return None,
        };
        out.push(c);
        if out.len() > 13 {
            return None;
        }
    }
    (out.len() == 13 && out[12..].starts_with(check(&out[..12]))).then_some(out)
}

fn hash(canon: &str) -> String {
    Sha256::digest(canon.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Where a host keeps its codes when it named a sessions file and no
/// invites file: beside it, `<stem>-invites.jsonl`.
pub fn beside(sessions_file: &Path) -> PathBuf {
    let stem = sessions_file.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "sessions".into());
    sessions_file.with_file_name(format!("{stem}-invites.jsonl"))
}

fn guest_meta(principal: &str, label: Option<&str>, id: &str) -> serde_json::Value {
    json!({ "principal": principal, "name": label.unwrap_or("guest"), "provider": GUEST_PROVIDER, "auth_method": "invite", "invite": id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_sixty_bits_a_check_and_typeable() {
        let c = new_code();
        assert_eq!(c.len(), 15, "{c}");
        assert_eq!(c.matches('-').count(), 2);
        let canon = normalize(&c).expect("its own code reads");
        assert_eq!(grouped(&canon), c);
        // Typed loosely: lower case, no dashes, spaces.
        assert_eq!(normalize(&c.to_lowercase().replace('-', " ")).as_deref(), Some(canon.as_str()));
        // O for 0 and I/L for 1.
        let zeroes = format!("000000000000{}", check("000000000000"));
        assert_eq!(normalize(&zeroes.replace('0', "O")).as_deref(), Some(zeroes.as_str()));
        let ones = format!("111111111111{}", check("111111111111"));
        assert_eq!(normalize(&ones.replacen('1', "I", 3).replacen('1', "l", 3)).as_deref(), Some(ones.as_str()));
        // A mistyped character fails the check (one in 32 slips through,
        // and then only as another unknown code).
        let flipped = (0..32)
            .filter(|i| {
                let mut s: Vec<char> = canon.chars().collect();
                s[3] = ALPHABET[*i] as char;
                let s: String = s.into_iter().collect();
                s != canon && normalize(&s).is_some()
            })
            .count();
        assert!(flipped <= 2, "{flipped} of 31 typos pass the check");
        assert!(normalize("").is_none() && normalize("0000-0000-0000").is_none() && normalize("UUUU-UUUU-UUUUU").is_none());
        assert!(normalize(&format!("{c}0")).is_none(), "too long");
        // Two codes differ.
        assert_ne!(new_code(), new_code());
    }

    #[test]
    fn a_duration_is_a_number_and_a_unit() {
        assert_eq!(duration("30m"), Some(1800));
        assert_eq!(duration("24h"), Some(86_400));
        assert_eq!(duration("7D"), Some(604_800));
        assert_eq!(duration("90"), Some(90));
        assert_eq!(duration("1s"), Some(1));
        assert!(duration("h").is_none() && duration("-5m").is_none() && duration("5w").is_none() && duration("0").is_none());
    }

    #[test]
    fn the_journal_sits_beside_the_sessions_file() {
        assert_eq!(beside(Path::new("/var/lib/toy/sessions.jsonl")), Path::new("/var/lib/toy/sessions-invites.jsonl"));
        assert_eq!(beside(Path::new("menger.db.sessions.jsonl")), Path::new("menger.db.sessions-invites.jsonl"));
    }
}
