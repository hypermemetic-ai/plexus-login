//! FRAME-21: sessions survive a restart. A table opened on a journal
//! (`Sessions::for_shell(…).journaled(path)`, as `Wiring` builds it) keeps
//! every session it mints — a browser's (`create`, the cookie) and an agent's (`mint`, the `mgs_…` token) — and
//! a table opened again on the same file has them back, each with its
//! identity and its end; an ended, expired or idle-ended one stays gone.
//! The file is the service's own (0600) and holds each session's key — the
//! sha256 of the id — and never the id: a read of it opens nothing.
//!
//! [`Sessions::new`] stays the in-memory table (tether's, a test's).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use plexus_rpc::core::plexus::AuthContext;
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

/// A directory of its own under cargo's test scratch, emptied first and
/// removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sessions_persist-{name}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A scratch directory and the journal's path in it.
fn journal(name: &str) -> (Scratch, PathBuf) {
    let dir = scratch(name);
    let path = dir.0.join("sessions.jsonl");
    (dir, path)
}

/// The table as the binary builds it (`Wiring` under `sessions_file`): the
/// shell's table, journaled.
fn open_idle(path: &Path, idle: i64) -> Sessions {
    Sessions::for_shell(3600, &names(), "http://127.0.0.1:4456").journaled(path).expect("the journal opens").with_idle(idle)
}

fn open(path: &Path) -> Sessions {
    open_idle(path, plexus_login::sessions::IDLE_SECS_DEFAULT)
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
    let (_dir, path) = journal("survives");
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
    let (_dir, path) = journal("agent");
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
    let (_dir, path) = journal("ended");
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
    let (_dir, path) = journal("expired");
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
    let (_dir, path) = journal("idle");
    let (cookie, token) = {
        let s = open_idle(&path, 1);
        let (cookie, _) = s.create(alice()).kept();
        let (token, _) = s.mint(bob(), 600).kept();
        assert!(s.get(&cookie).is_some());
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(s.get(&cookie).is_none(), "idle: ended");
        (cookie, token)
    };
    let s = open_idle(&path, 1);
    assert!(s.get(&token).is_some(), "a minted token keeps only its expiry, and the journal kept it");
    assert!(s.get(&cookie).is_none(), "an idle-ended session stays ended across a restart");
}

#[test]
fn the_file_is_0600_and_holds_no_token() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path) = journal("mode");
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
    let (_dir, path) = journal("torn");
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
        assert!(!s.alive("deadbeef"), "the torn row is no session");
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
    let (_dir, path) = journal("many");
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
    let (_dir, path) = journal("compact");
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
    // Every 333rd churned session, and the last, stay live: a compaction
    // that lost the row which set it off would lose one of them.
    let mut kept = Vec::new();
    for i in 0..2_000 {
        let (id, _) = s.mint(bob(), 600).kept();
        if i % 333 == 0 || i == 1_999 {
            kept.push(id);
        } else {
            s.end(&id);
        }
    }
    assert!(lines(&path) <= 1_001 + kept.len(), "{} rows for {} live sessions", lines(&path), 5 + kept.len());
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "still the service's own after compaction");
    }
    drop(s);
    let s = open(&path);
    assert!(live.iter().chain(&kept).all(|id| s.get(id).is_some()), "compaction kept every live session, the churn's too");
}

#[test]
fn a_sign_in_in_flight_fails_closed() {
    // A code flow's state, a loopback sign-in and its one-time code are
    // never journaled: one under way at a restart is refused, so nothing is
    // minted twice. (The sign-in page's enrolment and SSO flows are in
    // memory too.)
    let (_dir, path) = journal("inflight");
    let (state, cli_state, code) = {
        let s = open(&path);
        let state = s.begin("workos", "verifier".into(), "/".into());
        let cli_state = s.begin_cli("http://127.0.0.1:53817/cb".into());
        let (_, code) = s.finish_cli(&cli_state, alice()).expect("a code");
        let other = s.begin_cli("http://127.0.0.1:53818/cb".into());
        assert!(s.cli_waiting(&other));
        (state, (cli_state, other), code)
    };
    let s = open(&path);
    assert!(s.finish(&state).is_none(), "a code flow under way at the restart starts again");
    assert!(!s.cli_waiting(&cli_state.1), "a loopback sign-in under way starts again");
    assert!(s.take_code(&code, &cli_state.0).is_none(), "a one-time code given before the restart opens nothing");
}

#[test]
fn an_unpresented_idle_session_stays_ended() {
    // Its last use is the mint's: past its idle time while the service was
    // down, it does not come back with a fresh clock.
    let (_dir, path) = journal("unpresented");
    let (cookie, token) = {
        let s = open_idle(&path, 2);
        let (cookie, _) = s.create(alice()).kept();
        let (token, _) = s.mint(bob(), 600).kept();
        assert!(s.get(&cookie).is_some());
        (cookie, token)
    };
    std::thread::sleep(std::time::Duration::from_millis(3100));
    let s = open_idle(&path, 2);
    assert!(s.get(&token).is_some(), "the minted control token stands");
    assert!(s.get(&cookie).is_none(), "idle across the restart: ended");
}

#[test]
fn a_used_session_keeps_its_clock() {
    // A browser in use is not signed out by a deploy: its uses reach the
    // journal (at a coarse grain), so the clock a restart reads is recent.
    let (_dir, path) = journal("used");
    let cookie = {
        let s = open_idle(&path, 2);
        let (cookie, _) = s.create(alice()).kept();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(s.get(&cookie).is_some());
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(s.get(&cookie).is_some(), "in use: it stands");
        cookie
    };
    let s = open_idle(&path, 2);
    assert!(s.get(&cookie).is_some(), "reopened at once: its last use came with it");
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
