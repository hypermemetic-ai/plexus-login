//! KEEL-45 review (F1, F2): the session reader a route of another crate
//! takes — `Sessions::session_of` / `principal_of` — answers only the
//! browser session of the request, read from every `Cookie` field, and
//! nobody when that is in doubt. The reviewer's attack cases, kept.

use axum::http::{header, HeaderMap, HeaderValue};
use plexus_login::sessions::Sessions;
use plexus_login::LoginNames;
use plexus_rpc::core::plexus::{AuthContext, CEILING_KEY};
use serde_json::json;

const AGENT: &str = "key:54a9677a62e4289ee5a2d0a4751a6f188abafd8b1f2b2d4019ec0768eb3b0d28";
const VICTIM: &str = "idp:c952acd3-60aa-4534-b2e3-83634591fee1";
const EVIL: &str = "idp:00000000-60aa-4534-b2e3-83634591fee1";

fn with(c: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::COOKIE, HeaderValue::from_str(c).unwrap());
    h
}

fn person(principal: &str) -> AuthContext {
    AuthContext::new("u".into(), "sid".into(), vec![], json!({ "principal": principal }))
}

/// F1: an agent's minted token (`mgs_…`, `Sessions::mint`) sent as the
/// session cookie is no browser — whether it carries a ceiling or not.
#[test]
fn an_agents_minted_token_is_never_a_browser_session() {
    let s = Sessions::new(3600, &LoginNames::for_app("toy"));
    let name = s.cookie_name().to_string();
    let narrowed = AuthContext::new("a".into(), "mgs".into(), vec![], json!({ "principal": AGENT, CEILING_KEY: [["viewer@*"]] }));
    let (token, _) = s.mint(narrowed, 600).unwrap();
    let h = with(&format!("{name}={token}"));
    assert!(s.principal_of(&h).is_none(), "a narrowed agent token read as a browser");
    assert!(s.session_of(&h).is_none());
    let (plain, _) = s.mint(person(AGENT), 600).unwrap();
    assert!(s.principal_of(&with(&format!("{name}={plain}"))).is_none(), "an agent token with no ceiling read as a browser");
    assert!(s.get(&token).is_some(), "the token itself still stands, as the gate reads it");
}

/// F1: a browser session that carries a ceiling (`ceiling`, plexus-core's
/// `CEILING_KEY` — the review's probe wrote `_ceiling`, which nothing reads) is never answered as if it
/// had none.
#[test]
fn a_browser_session_carrying_a_ceiling_is_nobody() {
    let s = Sessions::new(3600, &LoginNames::for_app("toy"));
    let ceiled = AuthContext::new("u".into(), "sid".into(), vec![], json!({ "principal": VICTIM, CEILING_KEY: [["viewer@*"]] }));
    let (id, _) = s.create(ceiled).unwrap();
    let h = with(&format!("{}={id}", s.cookie_name()));
    assert!(s.session_of(&h).is_none() && s.principal_of(&h).is_none());
}

/// F2: the name more than once is nobody, whichever comes first; every
/// `Cookie` field is read (HTTP/2 splits them).
#[test]
fn a_cookie_named_twice_is_nobody_and_every_field_is_read() {
    let s = Sessions::new(3600, &LoginNames::for_app("toy"));
    let (victim, _) = s.create(person(VICTIM)).unwrap();
    let (evil, _) = s.create(person(EVIL)).unwrap();
    let name = s.cookie_name().to_string();
    assert!(s.principal_of(&with(&format!("{name}={evil}; {name}={victim}"))).is_none(), "shadowed: first must not win");
    let mut split = HeaderMap::new();
    split.append(header::COOKIE, HeaderValue::from_static("a=b"));
    split.append(header::COOKIE, HeaderValue::from_str(&format!("{name}={victim}")).unwrap());
    assert_eq!(s.principal_of(&split).map(|p| p.to_string()).as_deref(), Some(VICTIM), "a second Cookie field is read");
    split.append(header::COOKIE, HeaderValue::from_str(&format!("{name}={evil}")).unwrap());
    assert!(s.principal_of(&split).is_none(), "named once in each of two fields: nobody");
    assert_eq!(s.principal_of(&with(&format!("{name}={victim}"))).map(|p| p.to_string()).as_deref(), Some(VICTIM));
}
