//! FRAME-21: sessions survive a restart. A table opened on a journal
//! ([`Sessions::open`]) keeps every session it mints — a browser's
//! (`create`, the cookie) and an agent's (`mint`, the `mgs_…` token) — and
//! a table opened again on the same file has them back, each with its
//! identity and its end; an ended, expired or idle-ended one stays gone.
//! The file is the service's own (0600) and holds each session's key — the
//! sha256 of the id — and never the id: a read of it opens nothing.
//!
//! [`Sessions::new`] stays the in-memory table (tether's, a test's).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use plexus_core::plexus::AuthContext;
use plexus_login::sessions::Sessions;
use plexus_login::LoginNames;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// `create` and `mint` answer what they kept: a pair today; once a journal
/// that cannot be written refuses the session, a `Result` of one. The tests
/// read either.
trait Kept {
    fn kept(self) -> (String, i64);
}

impl Kept for (String, i64) {
    fn kept(self) -> (String, i64) {
        self
    }
}

impl<E: std::fmt::Debug> Kept for Result<(String, i64), E> {
    fn kept(self) -> (String, i64) {
        self.expect("the session is kept")
    }
}

fn names() -> LoginNames {
    LoginNames::for_app("toy")
}

fn alice() -> AuthContext {
    AuthContext::new("key:alice".into(), "sid".into(), vec!["editor".into()], json!({ "principal": "key:alice", "name": "alice" }))
}

fn bob() -> AuthContext {
    AuthContext::new("oidc:workos/bob".into(), "wos_sess".into(), vec![], json!({ "principal": "oidc:workos/bob", "provider": "workos" }))
}

/// A directory of its own under cargo's test scratch, emptied first.
fn scratch(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sessions_persist-{name}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn journal(name: &str) -> PathBuf {
    scratch(name).join("sessions.jsonl")
}

fn open(path: &Path) -> Sessions {
    Sessions::open(path, 3600, &names()).expect("the journal opens")
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn lines(path: &Path) -> usize {
    text(path).lines().filter(|l| !l.trim().is_empty()).count()
}

/// The identity's key: the hash the table stamps under `toy_session`.
fn key_of(ctx: &AuthContext) -> String {
    ctx.metadata["toy_session"].as_str().expect("stamped with its key").to_string()
}

#[test]
fn a_session_survives_reopen() {
    let path = journal("survives");
    let (cookie, cookie_ends, before) = {
        let s = open(&path);
        let (cookie, ends) = s.create(alice()).kept();
        let before = s.get(&cookie).expect("signed in");
        (cookie, ends, before)
    };
    let s = open(&path);
    let after = s.get(&cookie).expect("the cookie stands after a restart");
    assert_eq!((after.user_id.as_str(), after.session_id.as_str(), &after.roles), (before.user_id.as_str(), before.session_id.as_str(), &before.roles));
    assert_eq!(after.metadata, before.metadata, "the same identity, stamped the same: its key and expires_at");
    assert_eq!(after.metadata["expires_at"], json!(cookie_ends), "the same end — a restart does not extend it");
    assert!(s.alive(&key_of(&after)), "its sockets ask after it by key, and it stands");
}

#[test]
fn an_agent_token_survives_reopen() {
    // The ticket's row "agents the same": `session login`'s `mgs_…` token.
    let path = journal("agent");
    let (token, ends) = {
        let s = open(&path);
        s.mint(bob(), 600).kept()
    };
    assert!(token.starts_with("mgs_"), "{token}");
    let s = open(&path);
    let ctx = s.get(&token).expect("the token stands after a restart");
    assert_eq!(ctx.user_id, "oidc:workos/bob");
    assert_eq!(ctx.metadata["expires_at"], json!(ends));
    // And it ends by key as before (`auth.logout`).
    assert!(s.end_key(&key_of(&ctx)));
    assert!(s.get(&token).is_none());
}

#[test]
fn an_ended_session_stays_ended() {
    let path = journal("ended");
    let (by_id, by_key, kept) = {
        let s = open(&path);
        let (a, _) = s.create(alice()).kept();
        let (b, _) = s.mint(bob(), 600).kept();
        let (c, _) = s.create(bob()).kept();
        s.end(&a); // sign-out on the page
        let key = key_of(&s.get(&b).unwrap());
        assert!(s.end_key(&key)); // auth.logout
        (a, b, c)
    };
    let s = open(&path);
    assert!(s.get(&by_id).is_none(), "signed out by its cookie: gone after a restart");
    assert!(s.get(&by_key).is_none(), "ended by its key: gone after a restart");
    assert!(s.get(&kept).is_some(), "the one never ended stands");
}

#[test]
fn an_expired_session_is_not_loaded() {
    let path = journal("expired");
    let (short, long) = {
        let s = open(&path);
        let (short, _) = s.mint(alice(), 1).kept();
        let (long, _) = s.mint(bob(), 600).kept();
        (short, long)
    };
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let s = open(&path);
    assert!(s.get(&short).is_none(), "expired while the service was down");
    assert!(s.get(&long).is_some(), "the one still in date stands");
    assert!(!text(&path).contains(&sha256_hex(&short)), "an expired row is not carried into the compacted file");
}

#[test]
fn an_idle_ended_session_stays_ended() {
    // ACCESS-29 L2: a browser's session unused past its idle time ends;
    // a restart must not hand it a fresh idle clock.
    let path = journal("idle");
    let (cookie, token) = {
        let s = Sessions::open(&path, 3600, &names()).unwrap().with_idle(1);
        let (cookie, _) = s.create(alice()).kept();
        let (token, _) = s.mint(bob(), 600).kept();
        assert!(s.get(&cookie).is_some());
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(s.get(&cookie).is_none(), "idle: ended");
        (cookie, token)
    };
    let s = Sessions::open(&path, 3600, &names()).unwrap().with_idle(1);
    assert!(s.get(&token).is_some(), "a minted token keeps only its expiry, and the journal kept it");
    assert!(s.get(&cookie).is_none(), "an idle-ended session stays ended across a restart");
}

#[test]
fn the_file_is_0600_and_holds_no_token() {
    use std::os::unix::fs::PermissionsExt;
    let path = journal("mode");
    let s = open(&path);
    let (cookie, _) = s.create(alice()).kept();
    let (token, _) = s.mint(bob(), 600).kept();
    let meta = std::fs::metadata(&path).expect("the journal is written as the session is minted");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600, "the service's own file");
    let t = text(&path);
    for id in [&cookie, &token] {
        assert!(!t.contains(id.as_str()), "the id itself is never at rest");
        assert!(t.contains(&sha256_hex(id)), "its sha256 is the row's key");
    }
    assert!(!t.contains(token.trim_start_matches("mgs_")), "not even the token's random part");
    for l in t.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("JSON lines: {e}: {l}"));
    }
    // A row read from the file is not a credential: presented, it opens nothing.
    assert!(s.get(&sha256_hex(&cookie)).is_none() && s.get(&sha256_hex(&token)).is_none(), "the key at rest is not a cookie");
}

#[test]
fn a_torn_last_line_is_skipped() {
    // A crash mid-write leaves a line without its end: the rest loads, and
    // the next write does not glue onto the torn bytes.
    use std::io::Write;
    let path = journal("torn");
    let (a, b) = {
        let s = open(&path);
        (s.create(alice()).kept().0, s.mint(bob(), 600).kept().0)
    };
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).expect("the journal exists");
    f.write_all(br#"{"op":"mint","key":"deadbeef","ctx":{"user_id":"mal"#).unwrap();
    drop(f);
    let c = {
        let s = open(&path);
        assert!(s.get(&a).is_some() && s.get(&b).is_some(), "the whole lines before the torn one load");
        s.create(alice()).kept().0
    };
    let s = open(&path);
    assert!(s.get(&a).is_some() && s.get(&b).is_some() && s.get(&c).is_some(), "a mint after the torn line survives the next restart");
    for l in text(&path).lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("every line whole again: {e}: {l}"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn writes_from_many_tasks() {
    let path = journal("many");
    let s = Arc::new(open(&path));
    let mut tasks = Vec::new();
    for i in 0..100 {
        let s = s.clone();
        tasks.push(tokio::task::spawn_blocking(move || if i % 2 == 0 { s.create(alice()).kept().0 } else { s.mint(bob(), 600).kept().0 }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    drop(s);
    for l in text(&path).lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("no interleaved lines: {e}: {l}"));
    }
    let s = open(&path);
    let missing: Vec<_> = ids.iter().filter(|id| s.get(id).is_none()).collect();
    assert!(missing.is_empty(), "{} of 100 sessions lost across the restart", missing.len());
}

#[test]
fn compaction_keeps_the_live_set() {
    let path = journal("compact");
    let live: Vec<String> = {
        let s = open(&path);
        let mut ids: Vec<String> = (0..50).map(|i| if i % 2 == 0 { s.create(alice()).kept().0 } else { s.mint(bob(), 600).kept().0 }).collect();
        for id in ids.drain(5..) {
            s.end(&id);
        }
        ids
    };
    let s = open(&path);
    assert!(live.iter().all(|id| s.get(id).is_some()), "the five never ended stand");
    assert_eq!(lines(&path), 5, "compacted at open: one row per live session");
    // While it runs, churn does not grow the file without bound: past ten
    // times the live set (or 1,000 rows, whichever is more) it is compacted.
    for _ in 0..2_000 {
        let (id, _) = s.mint(bob(), 600).kept();
        s.end(&id);
    }
    assert!(lines(&path) <= 1_001, "{} rows for 5 live sessions", lines(&path));
    drop(s);
    let s = open(&path);
    assert!(live.iter().all(|id| s.get(id).is_some()), "compaction kept every live session");
}

#[test]
fn new_is_still_in_memory() {
    // tether's constructor, and every test's: no file, nothing kept.
    let cwd = std::env::current_dir().unwrap();
    let before: Vec<_> = std::fs::read_dir(&cwd).unwrap().filter_map(Result::ok).map(|e| e.file_name()).collect();
    let s = Sessions::new(3600, &names());
    let (id, _) = s.create(alice()).kept();
    assert!(s.get(&id).is_some());
    let shell = Sessions::for_shell(3600, &names(), "https://toy.example");
    assert_eq!(shell.cookie_name(), "__Host-toy_session");
    let after: Vec<_> = std::fs::read_dir(&cwd).unwrap().filter_map(Result::ok).map(|e| e.file_name()).collect();
    assert_eq!(before, after, "an in-memory table writes nothing");
}
