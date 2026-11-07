//! SUPERCONDUCTOR-25: only the allow list gets a session — a WorkOS
//! sign-in admitted by its linked GitHub account's numeric id, read from
//! WorkOS's identities endpoint (the fake answers it per user). Our own
//! page's GitHub button, AuthKit's PKCE round trip, and the socket; and with
//! no rules, nothing changes.

mod support;

use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::{HeaderMap, HeaderValue, WsClientBuilder};
use plexus_login::admission::GITHUB_ID;
use plexus_login::identity::Social;
use plexus_login::Allow;
use serde_json::{json, Value};
use support::*;

const HYPERMEMETIC: u64 = 251524973;
const ALLOWED: &str = "hypermemetic@example.test";
const OTHER: &str = "someone-else@example.test";

fn allow() -> Allow {
    Allow::parse([format!("github:{HYPERMEMETIC}")]).unwrap()
}

/// An app on our own page over the WorkOS backend (GitHub only), with
/// `allow`; the fake knows both people's GitHub ids.
async fn page_app(allow: Allow) -> (App, FakeWorkOs) {
    let under = Under::workos_with(KEY, vec![Social::GitHub]).await;
    let fake = under.fake().clone();
    {
        let mut st = fake.state.lock().unwrap();
        st.github_ids.insert(ALLOWED.into(), HYPERMEMETIC);
        st.github_ids.insert(OTHER.into(), 42);
    }
    let a = app_with(under, Tweaks { allow, ..Tweaks::default() }).await;
    (a, fake)
}

/// Presses our page's GitHub button as `email`, through the fake and back:
/// the callback's answer.
async fn github_as(a: &App, fake: &FakeWorkOs, b: &Browser, email: &str) -> Resp {
    fake.state.lock().unwrap().social_as.insert("GitHubOAuth".into(), email.into());
    let out = b.social("github", "/app/x").await;
    assert_eq!(out.status, 303, "{}", out.body);
    let back = b.get(&out.location.unwrap()).await.location.expect("the fake sends the browser back");
    assert!(back.starts_with(&a.base), "{back}");
    b.get(&back).await
}

fn session_of(a: &App, principal: &str) -> Option<plexus_rpc::core::plexus::AuthContext> {
    a.wired.sessions.standing().into_iter().map(|(_, c)| c).find(|c| c.principal().map(|p| p.to_string()).as_deref() == Some(principal))
}

fn holds_session_cookie(b: &Browser, a: &App) -> bool {
    b.jar.lock().unwrap().contains_key(a.wired.sessions.cookie_name())
}

fn says_not_allowed(r: &Resp) -> bool {
    r.body.contains("This account isn&#39;t allowed here.") || r.body.contains("This account isn't allowed here.")
}

#[tokio::test]
async fn our_page_admits_the_allowed_github_id_and_records_it() {
    let (a, fake) = page_app(allow()).await;
    let b = Browser::new(&a);
    let r = github_as(&a, &fake, &b, ALLOWED).await;
    assert_eq!((r.status, r.location.as_deref()), (303, Some("/app/x")), "{}", r.body);
    let me = b.me().await.expect("signed in");
    let principal = me["principal"].as_str().unwrap().to_string();
    assert!(principal.starts_with("oidc:workos/"), "{me}");
    let ctx = session_of(&a, &principal).expect("a session");
    assert_eq!(ctx.metadata[GITHUB_ID], json!(HYPERMEMETIC), "the GitHub id is kept with the session");
    assert_eq!(ctx.get_metadata_string("sign_in_method").as_deref(), Some("oauth"));
    assert_eq!(fake.calls_starting("identities:"), 1, "read once, with the API key");
}

#[tokio::test]
async fn our_page_refuses_another_github_id_with_no_session_and_ends_its_workos_session() {
    let (a, fake) = page_app(allow()).await;
    let b = Browser::new(&a);
    let r = github_as(&a, &fake, &b, OTHER).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(says_not_allowed(&r), "{}", r.body);
    assert!(r.headers.get_all("set-cookie").iter().all(|c| !c.to_str().unwrap().starts_with(a.wired.sessions.cookie_name())), "no session cookie");
    assert!(!holds_session_cookie(&b, &a));
    assert!(b.me().await.is_none(), "no session");
    assert!(a.wired.sessions.standing().is_empty(), "no session in the table");
    // Best effort: the WorkOS session is revoked.
    for _ in 0..50 {
        if !fake.revoked().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(fake.revoked().len(), 1, "the refused sign-in's WorkOS session is ended");

    // A WorkOS user with no GitHub identity at all is refused too.
    let c = Browser::new(&a);
    let r = github_as(&a, &fake, &c, "no-github@example.test").await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(c.me().await.is_none());
}

#[tokio::test]
async fn an_identities_failure_refuses_even_the_allowed_account() {
    let (a, fake) = page_app(allow()).await;
    fake.state.lock().unwrap().identities_unavailable = true;
    let b = Browser::new(&a);
    let r = github_as(&a, &fake, &b, ALLOWED).await;
    assert_eq!(r.status, 403, "fail closed: {}", r.body);
    assert!(says_not_allowed(&r), "{}", r.body);
    assert!(b.me().await.is_none());
    assert!(a.wired.sessions.standing().is_empty());
    // Once WorkOS answers again, the same account gets in.
    fake.state.lock().unwrap().identities_unavailable = false;
    let r = github_as(&a, &fake, &b, ALLOWED).await;
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(b.me().await.is_some());
}

#[tokio::test]
async fn a_principal_rule_admits_without_a_github_lookup() {
    let under = Under::workos_with(KEY, vec![Social::GitHub]).await;
    let fake = under.fake().clone();
    let id = fake.user_id_of(OTHER);
    let a = app_with(under, Tweaks { allow: Allow::parse([format!("principal:oidc:workos/{id}")]).unwrap(), ..Tweaks::default() }).await;
    let b = Browser::new(&a);
    assert_eq!(github_as(&a, &fake, &b, OTHER).await.status, 303);
    assert_eq!(b.me().await.unwrap()["principal"], json!(format!("oidc:workos/{id}")));
    let c = Browser::new(&a);
    assert_eq!(github_as(&a, &fake, &c, ALLOWED).await.status, 403, "not named");
    assert_eq!(fake.calls_starting("identities:"), 0, "no github: rule, no lookup");
}

#[tokio::test]
async fn authkit_s_round_trip_takes_the_same_list() {
    let buttons = ["GitHub=workos:GitHubOAuth", "SSO=workos:authkit"];
    let (a, fake) = app_direct_allowing(Some(KEY), &buttons, allow()).await;
    {
        let mut st = fake.state.lock().unwrap();
        st.github_ids.insert(ALLOWED.into(), HYPERMEMETIC);
        st.github_ids.insert(OTHER.into(), 42);
    }
    let pkce_as = |email: &'static str| {
        let (a, fake) = (&a, &fake);
        async move {
            fake.state.lock().unwrap().social_as.insert("authkit".into(), email.into());
            let b = Browser::new(a);
            let out = b.get("/login/start?button=SSO&next=%2F").await;
            let to = out.location.expect("out to WorkOS");
            assert!(to.contains("provider=authkit"), "{to}");
            let back = b.get(&to).await.location.expect("back");
            let r = b.get(&back).await;
            (b, r)
        }
    };
    let (b, r) = pkce_as(ALLOWED).await;
    assert_eq!((r.status, r.location.as_deref()), (303, Some("/")), "{}", r.body);
    let principal = b.me().await.expect("signed in")["principal"].as_str().unwrap().to_string();
    assert_eq!(session_of(&a, &principal).unwrap().metadata[GITHUB_ID], json!(HYPERMEMETIC));

    let (b, r) = pkce_as(OTHER).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(says_not_allowed(&r), "{}", r.body);
    assert!(!holds_session_cookie(&b, &a) && b.me().await.is_none());
    assert_eq!(a.wired.sessions.standing().len(), 1, "only the allowed one's");

    // Without the API key nothing can read a GitHub id: fail closed.
    let (a, fake) = app_direct_allowing(None, &["SSO=workos:authkit"], allow()).await;
    fake.state.lock().unwrap().github_ids.insert(ALLOWED.into(), HYPERMEMETIC);
    fake.state.lock().unwrap().social_as.insert("authkit".into(), ALLOWED.into());
    let b = Browser::new(&a);
    let to = b.get("/login/start?button=SSO&next=%2F").await.location.unwrap();
    let back = b.get(&to).await.location.unwrap();
    let r = b.get(&back).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(b.me().await.is_none());
}

async fn whoami(a: &App, auth: Option<String>) -> Result<Value, String> {
    let mut h = HeaderMap::new();
    if let Some(t) = auth {
        h.insert("authorization", HeaderValue::from_str(&format!("Bearer {t}")).unwrap());
    }
    let ws = WsClientBuilder::default().set_headers(h).build(format!("ws://127.0.0.1:{}", a.ws)).await.map_err(|e| e.to_string())?;
    let mut p = ObjectParams::new();
    p.insert("method", "auth.whoami").unwrap();
    p.insert("params", json!({})).unwrap();
    let mut sub: Subscription<Value> = ws.subscribe("toy.call", p, "toy.call_unsub").await.map_err(|e| e.to_string())?;
    Ok(sub.next().await.unwrap().unwrap())
}

#[tokio::test]
async fn at_the_socket_a_workos_bearer_is_refused_with_rules_and_admitted_without() {
    let (a, fake) = page_app(allow()).await;
    // Even the allowed person's own WorkOS access token: no lookup is made
    // at the socket, so only a principal: rule could admit a bearer.
    let refused = whoami(&a, Some(fake.access_token_for(ALLOWED))).await;
    assert!(refused.is_err(), "refused at the upgrade: {refused:?}");
    assert!(whoami(&a, Some(fake.access_token_for(OTHER))).await.is_err());

    // No rules: today's behaviour, the bearer is who it says.
    let (a, fake) = page_app(Allow::everyone()).await;
    let ok = whoami(&a, Some(fake.access_token_for(OTHER))).await.expect("admitted");
    assert!(ok["content"]["principal"].as_str().unwrap_or_default().starts_with("oidc:workos/"), "{ok}");
}

#[tokio::test]
async fn with_no_rules_nothing_changes_and_nothing_is_looked_up() {
    let (a, fake) = page_app(Allow::everyone()).await;
    for who in [ALLOWED, OTHER, "no-github@example.test"] {
        let b = Browser::new(&a);
        let r = github_as(&a, &fake, &b, who).await;
        assert_eq!(r.status, 303, "{who}: {}", r.body);
        let principal = b.me().await.expect("signed in")["principal"].as_str().unwrap().to_string();
        assert!(session_of(&a, &principal).unwrap().metadata.get(GITHUB_ID).is_none(), "no GitHub id recorded");
    }
    assert_eq!(fake.calls_starting("identities:"), 0, "no identities call");
    assert!(fake.revoked().is_empty());
}

/// The operator's second GitHub account: `github:<id>=<principal>` admits it
/// and makes its session as the first account's principal, so what that
/// principal owns (its hosts) is the second account's too.
#[tokio::test]
async fn a_second_github_account_signs_in_as_the_first_principal() {
    const SECOND: &str = "second@example.test";
    const SECOND_ID: u64 = 220071806;
    let (a, fake) = page_app(allow()).await;
    fake.state.lock().unwrap().github_ids.insert(SECOND.into(), SECOND_ID);
    // Without the `=` rule the second account is refused.
    let b = Browser::new(&a);
    assert!(says_not_allowed(&github_as(&a, &fake, &b, SECOND).await));

    let owner = "oidc:workos/user_01M4GTJS2WTGNCXY1ZSXNSDE7M";
    let rules = Allow::parse([format!("github:{HYPERMEMETIC},github:{SECOND_ID}={owner}")]).unwrap();
    assert_eq!(rules.to_string(), format!("github:{HYPERMEMETIC},github:{SECOND_ID}={owner}"));
    let (a2, fake2) = page_app(rules).await;
    fake2.state.lock().unwrap().github_ids.insert(SECOND.into(), SECOND_ID);
    let b = Browser::new(&a2);
    let r = github_as(&a2, &fake2, &b, SECOND).await;
    assert_eq!((r.status, r.location.as_deref()), (303, Some("/app/x")), "{}", r.body);
    let me = b.me().await.expect("signed in");
    assert_eq!(me["principal"].as_str(), Some(owner), "the session is the first account's principal: {me}");
    let ctx = session_of(&a2, owner).expect("a session as the owner");
    let own = ctx.get_metadata_string(plexus_login::admission::SIGNED_IN_AS).expect("its own principal kept");
    assert!(own.starts_with("oidc:workos/") && own != owner, "{own}");
    assert_eq!(ctx.metadata[GITHUB_ID], json!(SECOND_ID));

    // Only a github: rule can sign in as another principal.
    assert!(Allow::parse([format!("principal:{owner}={owner}")]).is_err());
}
