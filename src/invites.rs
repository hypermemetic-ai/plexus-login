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
//! | `GET /login?code=…`, `POST /login/code` | the login page's half ([`crate::web_login`]) |
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
    /// (`<path>.lock`) held while they live, as FRAME-21 keeps sessions.
    pub fn journaled(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let _ = path;
        Err(io::Error::other("IDENTITY-49: not yet"))
    }

    /// Gives the grants codes made back to `access` (at a start): how many.
    pub fn restore<A: LoginAccess>(&self, access: &A) -> usize {
        let _ = access;
        0
    }

    /// Where a code's link points.
    pub fn url_of(&self, code: &str) -> String {
        format!("{}/login?code={code}", self.public_url)
    }

    /// `invites.issue`: a code for `req`, by `issuer`.
    pub fn issue<A: LoginAccess>(&self, access: &A, issuer: &AuthContext, req: Issue) -> Result<InviteView, String> {
        let _ = (access, issuer, req);
        Err("IDENTITY-49: not yet".into())
    }

    /// `invites.list`: every code for an admin, else the caller's own; the
    /// QR codes when `qr`.
    pub fn list<A: LoginAccess>(&self, access: &A, caller: &AuthContext, qr: bool) -> Vec<InviteView> {
        let _ = (access, caller, qr);
        Vec::new()
    }

    /// `invites.revoke`: the code (by id or by the code) stops working;
    /// with `sign_out`, its grants are taken back and its guests' sessions
    /// ended. The code as it stands, and how many sessions ended.
    pub fn revoke<A: LoginAccess>(&self, access: &A, caller: &AuthContext, key: &str, sign_out: bool, sessions: &Sessions) -> Result<(InviteView, usize), String> {
        let _ = (access, caller, key, sign_out, sessions);
        Err("IDENTITY-49: not yet".into())
    }

    /// The page's redemption of `code`: `caller`, when signed in, gets the
    /// role; anyone else a guest identity whose session lasts `guest_ttl`.
    /// `Err` is [`REFUSED`] for any code that signs no one in, or the words
    /// for a server that could not keep it.
    pub fn redeem<A: LoginAccess>(&self, access: &A, code: &str, caller: Option<&AuthContext>, guest_ttl: i64) -> Result<Redeemed, String> {
        let _ = (access, code, caller, guest_ttl);
        Err(REFUSED.into())
    }
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

#[allow(dead_code)]
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
    fn the_journal_sits_beside_the_sessions_file() {
        assert_eq!(beside(Path::new("/var/lib/toy/sessions.jsonl")), Path::new("/var/lib/toy/sessions-invites.jsonl"));
        assert_eq!(beside(Path::new("menger.db.sessions.jsonl")), Path::new("menger.db.sessions-invites.jsonl"));
    }
}
