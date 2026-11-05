//! IDENTITY-49: sign-in codes — an admin issues a code for a role on the
//! service's socket (`invites.issue`), and someone redeems it on the login
//! page from any network: a guest session holding exactly that role, or the
//! role on the signed-in caller's own principal. Uses, expiry and
//! withdrawal end a code; one refusal says it for all; guesses are
//! throttled; a restart keeps codes, counts and grants; the console's
//! one-time link stays loopback-only.
//!
//! A toy service (`auth` and `invites`, SimpleAccess, the `key` provider so
//! login is on) serves its socket on a free port; the login page is driven
//! in process, each request carrying the peer address it comes from, so a
//! peer off this machine is a test's choice. Sessions are started in the
//! table directly for the people already signed in.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::{HeaderMap, HeaderValue, WsClient, WsClientBuilder};
use plexus_auth_core::identity::{Authenticated, Principal};
use plexus_core::plexus::{AuthContext, DynamicHub, GrantSet, RoleStore};
use plexus_login::invites::{Issue, Redeemed, REFUSED};
use plexus_login::simple::SimpleAccess;
use plexus_login::throttle::{Backoff, Limits};
use plexus_login::{Branding, LoginAccess, LoginOptions, Wired, Wiring};
use plexus_transport::TransportServer;
use serde_json::{json, Value};
use tower::ServiceExt;

const BRANDING: Branding = Branding { app: "toy", version: "0.0.1", mark: "t", motto: "" };
const ADMIN: &str = "idp:0b6d1c0e-3f0a-4d55-9d1e-6f0c2a7b9e01";
const ALICE: &str = "idp:c952acd3-60aa-4534-b2e3-83634591fee1";
const BOB: &str = "idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8";
/// A peer off this machine (TEST-NET-3), and another network.
const AWAY: &str = "203.0.113.7";
const ELSEWHERE: &str = "198.51.100.9";

async fn free_port() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

fn person(principal: &str, name: &str) -> AuthContext {
    let p: Principal = principal.parse().unwrap();
    Authenticated::new(p, "sid", vec![], json!({ "name": name, "provider": "plexus-idp" })).into_auth_context()
}

struct Toy {
    ws: u16,
    wired: Wired<SimpleAccess>,
    access: SimpleAccess,
    router: axum::Router,
}

fn options(ws: u16, shell: u16, tweak: impl FnOnce(&mut LoginOptions)) -> LoginOptions {
    let mut opts = LoginOptions::new(BRANDING, ws, shell).with_providers(["key"]).unwrap();
    opts.invites = true;
    tweak(&mut opts);
    opts
}

/// The wiring alone (no socket): what a restart builds again.
fn wire(opts: LoginOptions) -> (Wired<SimpleAccess>, SimpleAccess) {
    let wiring = Wiring::new(opts).unwrap();
    let access = SimpleAccess::new(wiring.sessions(), &[ADMIN.to_string()]).unwrap();
    let wired = wiring.finish(access.clone(), None).unwrap();
    (wired, access)
}

async fn toy(tweak: impl FnOnce(&mut LoginOptions)) -> Toy {
    let (ws, shell) = (free_port().await, free_port().await);
    let (wired, access) = wire(options(ws, shell, tweak));
    let service = DynamicHub::new("toy")
        .with_auth(access.auth_setup(wired.backend.clone()))
        .register(wired.invites_activation().expect("codes are on"));
    access.seed_roles(&service);
    let server = wired.apply(
        TransportServer::builder(Arc::new(service), |h| DynamicHub::arc_into_rpc_module(h).map_err(|e| anyhow::anyhow!("{e}"))).with_websocket(ws),
    );
    tokio::spawn(async move { server.build().await.unwrap().serve().await.unwrap() });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ws)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let router = wired.router().expect("a page");
    Toy { ws, wired, access, router }
}

impl Toy {
    /// A session for someone already signed in: its `Cookie` header.
    fn signed_in(&self, principal: &str, name: &str) -> String {
        let (id, _) = self.wired.sessions.create(person(principal, name)).unwrap();
        format!("{}={id}", self.wired.sessions.cookie_name())
    }

    async fn socket(&self, cookie: &str) -> WsClient {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_str(cookie).unwrap());
        WsClientBuilder::default().set_headers(h).build(format!("ws://127.0.0.1:{}", self.ws)).await.unwrap()
    }

    /// The page, as a browser at `ip` reaches it.
    async fn send(&self, req: Request<Body>, ip: &str) -> axum::response::Response {
        let mut req = req;
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 50_000)));
        self.router.clone().oneshot(req).await.unwrap()
    }

    async fn get(&self, path: &str, ip: &str) -> axum::response::Response {
        self.send(Request::get(path).body(Body::empty()).unwrap(), ip).await
    }

    /// `POST /login/code` from `ip`, with `cookie` when signed in.
    async fn redeem(&self, code: &str, ip: &str, cookie: Option<&str>) -> axum::response::Response {
        let mut req = Request::post("/login/code")
            .header("origin", &self.wired.public_url)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        let body = format!("code={}&next=%2Fapp%2F", url_encode(code));
        self.send(req.body(Body::from(body)).unwrap(), ip).await
    }

    fn admin_ctx(&self) -> AuthContext {
        person(ADMIN, "root")
    }
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The session cookie a response sets, as a `Cookie` header.
fn session_cookie(r: &axum::response::Response, name: &str) -> Option<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")) && !c.contains("Max-Age=0"))
        .and_then(|c| c.split(';').next())
        .map(str::to_string)
}

async fn text(r: axum::response::Response) -> String {
    String::from_utf8(axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

/// A method's whole answer: its data items, or the error that ended it.
async fn call(c: &WsClient, method: &str, params: Value) -> Value {
    let mut p = ObjectParams::new();
    p.insert("method", method).unwrap();
    p.insert("params", params).unwrap();
    let mut sub: Subscription<Value> = c.subscribe("toy.call", p, "toy.call_unsub").await.unwrap();
    let mut out = Vec::new();
    while let Some(Ok(item)) = sub.next().await {
        match item["type"].as_str() {
            Some("data") => out.push(item["content"].clone()),
            Some("error") => {
                out.push(item);
                break;
            }
            Some("done") => break,
            _ => {}
        }
    }
    Value::Array(out)
}

fn refused(v: &Value) -> bool {
    v.to_string().contains("forbidden")
}

/// `invites.issue` on the admin's socket: the invite.
async fn issue(toy: &Toy, params: Value) -> Value {
    let admin = toy.socket(&toy.signed_in(ADMIN, "root")).await;
    let got = call(&admin, "invites.issue", params).await;
    assert_eq!(got[0]["type"], "invite", "{got}");
    got[0].clone()
}

#[tokio::test]
async fn issue_then_redeem_from_a_peer_off_this_machine_is_a_guest_holding_exactly_the_role() {
    let toy = toy(|_| {}).await;
    let inv = issue(&toy, json!({ "role": "viewer", "label": "kitchen table", "uses": 5, "expires_in": "24h" })).await;
    let code = inv["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 15, "{inv}");
    assert_eq!(inv["url"], format!("{}/login?code={code}", toy.wired.public_url));
    assert!(inv["qr_svg"].as_str().unwrap().starts_with("<svg"), "{inv}");
    assert_eq!((inv["role"].as_str(), inv["scope"].as_str(), inv["uses"].as_u64(), inv["left"].as_u64()), (Some("viewer"), Some("*"), Some(5), Some(5)));
    assert_eq!(inv["label"], "kitchen table");
    assert_eq!(inv["issued_by"], ADMIN);

    // The page has a code field; the link fills it in and spends nothing.
    let page = text(toy.get("/login", AWAY).await).await;
    assert!(page.contains(r#"action="/login/code""#), "the code field");
    let linked = toy.get(&format!("/login?code={code}"), AWAY).await;
    assert_eq!(linked.status(), StatusCode::OK);
    assert!(session_cookie(&linked, toy.wired.sessions.cookie_name()).is_none(), "a GET signs no one in");
    assert!(text(linked).await.contains(&format!(r#"value="{code}""#)));

    // Redeemed from off this machine: a guest session.
    let r = toy.redeem(&code, AWAY, None).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/app/");
    let guest = session_cookie(&r, toy.wired.sessions.cookie_name()).expect("a session");
    let ws = toy.socket(&guest).await;
    let who = call(&ws, "auth.whoami", json!({})).await;
    let principal = who[0]["principal"].as_str().unwrap_or_default().to_string();
    assert!(principal.starts_with("oidc:invite/"), "{who}");
    assert_eq!(who[0]["name"], "kitchen table");
    assert_eq!(who[0]["memberships"], json!([{ "role": "viewer", "scope": "*" }]), "exactly the code's role: {who}");
    // A method outside it: forbidden.
    assert!(refused(&call(&ws, "invites.list", json!({})).await));
    assert!(refused(&call(&ws, "auth.roles", json!({})).await));
    assert!(refused(&call(&ws, "invites.issue", json!({ "role": "viewer" })).await));

    // The admin's list: one used, the guest named.
    let admin = toy.socket(&toy.signed_in(ADMIN, "root")).await;
    let list = call(&admin, "invites.list", json!({})).await;
    assert_eq!(list[0]["used"], 1, "{list}");
    assert_eq!(list[0]["left"], 4);
    assert_eq!(list[0]["redeemed"][0]["principal"], principal.as_str());
    assert_eq!(list[0]["redeemed"][0]["guest"], true);
}

#[tokio::test]
async fn uses_expiry_and_withdrawal_end_a_code_with_one_refusal_for_all() {
    let toy = toy(|_| {}).await;
    let cookie = toy.wired.sessions.cookie_name().to_string();
    let words = |s: &str| s.contains("That code does not sign anyone in");

    let two = issue(&toy, json!({ "role": "viewer", "uses": 2 })).await["code"].as_str().unwrap().to_string();
    for _ in 0..2 {
        let r = toy.redeem(&two, AWAY, None).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert!(session_cookie(&r, &cookie).is_some());
    }
    let third = toy.redeem(&two, AWAY, None).await;
    assert_eq!(third.status(), StatusCode::FORBIDDEN, "the (uses+1)th");
    assert!(session_cookie(&third, &cookie).is_none());
    assert!(words(&text(third).await));

    let brief = issue(&toy, json!({ "role": "viewer", "expires_in": "1s" })).await["code"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let r = toy.redeem(&brief, ELSEWHERE, None).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "expired");
    assert!(words(&text(r).await));

    let inv = issue(&toy, json!({ "role": "viewer", "uses": 3 })).await;
    let admin = toy.socket(&toy.signed_in(ADMIN, "root")).await;
    let gone = call(&admin, "invites.revoke", json!({ "id": inv["id"] })).await;
    assert_eq!(gone[0]["type"], "revoked", "{gone}");
    assert_eq!(gone[0]["invite"]["state"], "withdrawn");
    let r = toy.redeem(inv["code"].as_str().unwrap(), ELSEWHERE, None).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "withdrawn");
    assert!(words(&text(r).await));

    // Unknown and mistyped: the same words.
    for typed in ["0000-0000-00000", "not a code"] {
        let r = toy.redeem(typed, ELSEWHERE, None).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(words(&text(r).await), "{typed}");
    }
    assert!(REFUSED.contains("used up") && REFUSED.contains("expired") && REFUSED.contains("withdrawn"));
}

#[tokio::test]
async fn withdrawing_with_sign_out_ends_its_guests_and_takes_back_its_grants() {
    let toy = toy(|_| {}).await;
    let inv = issue(&toy, json!({ "role": "viewer", "uses": 2 })).await;
    let code = inv["code"].as_str().unwrap().to_string();
    let guest = session_cookie(&toy.redeem(&code, AWAY, None).await, toy.wired.sessions.cookie_name()).unwrap();
    let alice = toy.signed_in(ALICE, "alice");
    assert_eq!(toy.redeem(&code, AWAY, Some(&alice)).await.status(), StatusCode::SEE_OTHER);
    assert!(toy.access.holds_any(ALICE));
    let admin = toy.socket(&toy.signed_in(ADMIN, "root")).await;
    let gone = call(&admin, "invites.revoke", json!({ "code": code, "sign_out": true })).await;
    assert_eq!(gone[0]["signed_out"], 1, "the guest's session: {gone}");
    let ws = toy.socket(&guest).await;
    assert!(call(&ws, "auth.whoami", json!({})).await.to_string().contains("error"), "the guest is signed out");
    assert!(!toy.access.holds_any(ALICE), "her role taken back");
}

#[tokio::test]
async fn an_issuer_without_the_role_is_refused() {
    let toy = toy(|_| {}).await;
    // Someone holding nothing reaches no invites method at all.
    let bob = toy.socket(&toy.signed_in(BOB, "bob")).await;
    assert!(refused(&call(&bob, "invites.issue", json!({ "role": "viewer" })).await));

    // Editors may issue (an admin said so); Alice is one.
    let roles = toy.access.roles().clone();
    let mut grants: Vec<String> = plexus_core::plexus::Roles::grants(&*roles, &plexus_auth_core::RoleName::new("editor")).map(|g| match g {
        GrantSet::Listed(set) => set.iter().map(|x| x.to_string()).collect(),
        GrantSet::All => Vec::new(),
    }).unwrap_or_default();
    grants.push("invites.issue".into());
    RoleStore::set(&*roles, &plexus_auth_core::RoleName::new("editor"), GrantSet::listed(grants)).await.unwrap();
    toy.access.invite_grant(ALICE, "editor", "*").unwrap();
    let alice = toy.socket(&toy.signed_in(ALICE, "alice")).await;

    let admin_code = call(&alice, "invites.issue", json!({ "role": "admin" })).await;
    assert_eq!(admin_code[0]["type"], "error", "she does not hold admin: {admin_code}");
    assert!(admin_code[0]["message"].as_str().unwrap().contains("do not hold"), "{admin_code}");
    let viewer = call(&alice, "invites.issue", json!({ "role": "viewer" })).await;
    assert_eq!(viewer[0]["type"], "error", "nor viewer: {viewer}");
    let nonsense = call(&alice, "invites.issue", json!({ "role": "owner" })).await;
    assert_eq!(nonsense[0]["type"], "error", "no such role: {nonsense}");
    let editor = call(&alice, "invites.issue", json!({ "role": "editor" })).await;
    assert_eq!(editor[0]["type"], "invite", "she holds editor: {editor}");
    // A bad parameter is said, not guessed at.
    let typo = call(&alice, "invites.issue", json!({ "role": "editor", "usse": 2 })).await;
    assert_eq!(typo[0]["type"], "error", "{typo}");
}

#[tokio::test]
async fn a_signed_in_caller_gets_the_role_on_their_own_principal_and_no_guest_is_made() {
    let toy = toy(|_| {}).await;
    let code = issue(&toy, json!({ "role": "editor", "uses": 1 })).await["code"].as_str().unwrap().to_string();
    let alice = toy.signed_in(ALICE, "alice");
    assert!(!toy.access.holds_any(ALICE));
    let r = toy.redeem(&code.to_lowercase().replace('-', " "), AWAY, Some(&alice)).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "typed loosely, still the code");
    assert!(session_cookie(&r, toy.wired.sessions.cookie_name()).is_none(), "no new session");
    let ws = toy.socket(&alice).await;
    let who = call(&ws, "auth.whoami", json!({})).await;
    assert_eq!(who[0]["principal"], ALICE);
    assert_eq!(who[0]["memberships"], json!([{ "role": "editor", "scope": "*" }]), "{who}");
    // Again: hers already, no use spent (the one use is gone, and she is fine).
    assert_eq!(toy.redeem(&code, AWAY, Some(&alice)).await.status(), StatusCode::SEE_OTHER);
    let list = toy.wired.invites.as_ref().unwrap().list(&toy.access, &toy.admin_ctx(), false);
    assert_eq!(list[0].used, 1);
    assert_eq!(list[0].redeemed.len(), 1);
    assert!(!list[0].redeemed[0].guest && list[0].redeemed[0].principal == ALICE);
}

#[tokio::test]
async fn a_restart_keeps_codes_their_counts_and_the_grants_they_made() {
    let dir = std::env::temp_dir().join(format!("plexus-login-invites-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let file = dir.join("toy-invites.jsonl");
    let (ws, shell) = (free_port().await, free_port().await);
    let opts = || options(ws, shell, |o| o.invites_file = Some(file.clone()));

    let (code, guest, id) = {
        let (wired, access) = wire(opts());
        let inv = wired.invites.as_ref().unwrap();
        let issued = inv
            .issue(&access, &person(ADMIN, "root"), Issue { role: "viewer".into(), uses: Some(3), label: Some("door".into()), ..Issue::default() })
            .unwrap();
        let code = issued.code.clone().unwrap();
        let guest = match inv.redeem(&access, &code, None, 3600).unwrap() {
            Redeemed::Guest(ctx) => ctx.principal().unwrap().to_string(),
            other => panic!("{other:?}"),
        };
        assert!(matches!(inv.redeem(&access, &code, Some(&person(ALICE, "alice")), 3600).unwrap(), Redeemed::Granted { .. }));
        assert!(access.holds_any(&guest) && access.holds_any(ALICE));
        // A second server on the file is refused while this one runs.
        assert!(Wiring::new(opts()).unwrap().finish(SimpleAccess::new(&Arc::new(plexus_login::sessions::Sessions::new(60, &plexus_login::LoginNames::for_app("toy"))), &[]).unwrap(), None).is_err());
        (code, guest, issued.id)
    };

    // The file: 0600, and the code's hash, never the code.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    let kept = std::fs::read_to_string(&file).unwrap();
    assert!(!kept.contains(&code) && !kept.contains(&code.replace('-', "")), "{kept}");

    // Started again: new rules, which forgot everything but the admin.
    let (wired, access) = wire(opts());
    assert!(access.holds_any(&guest), "the guest's grant is back");
    assert!(access.holds_any(ALICE), "Alice's grant is back");
    let inv = wired.invites.as_ref().unwrap();
    let list = inv.list(&access, &person(ADMIN, "root"), false);
    assert_eq!((list.len(), list[0].id.as_str(), list[0].used, list[0].left), (1, id.as_str(), 2, 1));
    assert!(list[0].code.is_none(), "the code itself was never kept");
    assert!(matches!(inv.redeem(&access, &code, None, 3600), Ok(Redeemed::Guest(_))), "its last use");
    assert_eq!(inv.redeem(&access, &code, None, 3600).unwrap_err(), REFUSED, "then spent");
    drop((wired, access));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn guessing_codes_is_throttled_after_the_limit() {
    let toy = toy(|o| {
        o.limits = Limits { try_per_client: Backoff { free: 3, base: 30, cap: 900, window: 3600 }, ..Limits::default() };
    })
    .await;
    for i in 0..3 {
        let r = toy.redeem("0000-0000-00000", AWAY, None).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "guess {i}");
    }
    let r = toy.redeem("0000-0000-00000", AWAY, None).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
    // The right code from that network waits too; from another it works.
    let code = issue(&toy, json!({ "role": "viewer" })).await["code"].as_str().unwrap().to_string();
    assert_eq!(toy.redeem(&code, AWAY, None).await.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(toy.redeem(&code, ELSEWHERE, None).await.status(), StatusCode::SEE_OTHER);
}

/// The console's link: always the admin, when the caller may use it.
struct Console;

impl plexus_login::once::OnceLinks for Console {
    fn redeem(&self, _token: &str) -> Option<AuthContext> {
        Some(person(ADMIN, "root"))
    }
    fn spent(&self) -> String {
        "spent".into()
    }
    fn hint(&self) -> String {
        "ask the console".into()
    }
}

#[tokio::test]
async fn the_once_link_is_still_refused_from_a_peer_off_this_machine() {
    let toy = toy(|o| o.once = Some(Arc::new(Console))).await;
    let cookie = toy.wired.sessions.cookie_name().to_string();
    let away = toy.get("/login?once=anything", AWAY).await;
    assert_eq!(away.status(), StatusCode::OK, "the plain page");
    assert!(session_cookie(&away, &cookie).is_none(), "no session off this machine");
    let here = toy.get("/login?once=anything", "127.0.0.1").await;
    assert_eq!(here.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&here, &cookie).is_some(), "on loopback, the admin");
}

#[test]
fn codes_need_the_page_and_the_guests_provider_name_is_taken() {
    let opts = LoginOptions { invites: true, page: false, ..LoginOptions::new(BRANDING, 1, 2) }.with_providers(["key"]).unwrap();
    let w = Wiring::new(opts).unwrap();
    let access = SimpleAccess::new(w.sessions(), &[]).unwrap();
    assert!(w.finish(access, None).is_err(), "no page, no codes");
    let named = LoginOptions::new(BRANDING, 1, 2).with_providers(["oidc:invite=http://127.0.0.1:9,toy"]).unwrap();
    assert!(Wiring::new(named).is_err());
}
