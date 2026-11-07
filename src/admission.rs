//! SUPERCONDUCTOR-25: who may have a session at all — an allow list the
//! embedding app sets ([`crate::LoginOptions::allow`], `--allow`), checked
//! before every browser session is made and at the socket.
//!
//! | rule | admits |
//! | --- | --- |
//! | `github:<numeric id>` | a WorkOS sign-in whose linked GitHub identity has that id (WorkOS's `GET /user_management/users/{id}/identities`, the `GitHubOAuth` identity's `idp_id`) — the id, never the username, which can be renamed |
//! | `principal:<principal>` | exactly that principal (`oidc:workos/user_…`, `nostr:<hex>`, `idp:<uuid>`, …) |
//!
//! - **No rule: nothing changes.** No lookup is made, nothing is refused —
//!   every app that sets none (menger) behaves as before.
//! - **Fail closed.** With rules, an identity no rule names gets no session.
//!   A `github:` rule needs the GitHub id, which only the WorkOS identity
//!   backend can fetch (it holds the API key): when that call fails the
//!   sign-in is refused; with no WorkOS backend to ask, no `github:` rule can
//!   pass.
//! - **The browser.** Both paths that start a browser session — our own
//!   page ([`crate::app_session::AppContinuation`]) and the provider round
//!   trips, nostr, one-time links and the password form
//!   ([`crate::web_login`]) — take an [`Admitted`] identity, which only
//!   [`admit`] makes. A refusal is a 403 page that says
//!   [`NOT_ALLOWED`]; no session, no cookie; the backend's session is
//!   revoked, best effort. The GitHub id, once fetched, is kept in the
//!   session's metadata as [`GITHUB_ID`].
//! - **The socket** ([`crate::sessions::Gate`]): session cookies and minted
//!   tokens were admitted when they were made. An identity a provider's
//!   bearer proves (a WorkOS access token, any OIDC token, a nostr event) is
//!   admitted only by a `principal:` rule naming it: no identity lookup is
//!   made per connection, so a `github:` rule never admits a bearer — in
//!   practice WorkOS bearer tokens are refused at the socket. `key:`
//!   principals (hosts, agents) are never subject to the list.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use plexus_rpc::auth_core::identity::Principal;
use plexus_rpc::core::plexus::AuthContext;
use serde_json::Value;

use crate::identity::IdentityBackend;

/// The session metadata key the GitHub numeric id is kept under.
pub const GITHUB_ID: &str = "github_id";

/// What a refused person is told.
pub const NOT_ALLOWED: &str = "This account isn't allowed here.";

/// One admission rule. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// `github:<id>`: a GitHub account by its numeric id.
    GitHub(u64),
    /// `principal:<principal>`: exactly this principal.
    Principal(Principal),
}

impl FromStr for Rule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let bad = |why: &str| format!("--allow {s}: {why}; an allow rule is github:<numeric id> or principal:<principal>");
        match s.split_once(':') {
            Some(("github", id)) => match id.trim().parse::<u64>() {
                Ok(n) if n > 0 && id.trim().bytes().all(|b| b.is_ascii_digit()) => Ok(Self::GitHub(n)),
                _ => Err(bad("a GitHub account's numeric id (not its username, which can be renamed)")),
            },
            Some(("principal", p)) => p.trim().parse::<Principal>().map(Self::Principal).map_err(|e| bad(&e.to_string())),
            _ => Err(bad("unknown rule")),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GitHub(id) => write!(f, "github:{id}"),
            Self::Principal(p) => write!(f, "principal:{p}"),
        }
    }
}

/// The allow list. Empty (the default): everyone, as before.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allow {
    rules: Vec<Rule>,
}

impl Allow {
    /// No rules: no admission check at all.
    pub fn everyone() -> Self {
        Self::default()
    }

    /// The rules `specs` name, each a rule or several separated by commas
    /// or whitespace (`--allow github:251524973`, or an env var's
    /// `github:1,principal:oidc:workos/user_01`). Any bad rule refuses the
    /// whole list — a typo never admits everyone.
    pub fn parse<I, S>(specs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rules = Vec::new();
        for spec in specs {
            for one in spec.as_ref().split([',', ' ', '\t', '\n']).filter(|s| !s.trim().is_empty()) {
                let r: Rule = one.parse()?;
                if !rules.contains(&r) {
                    rules.push(r);
                }
            }
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Whether no rule is set (no check is made).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether a `github:` rule is set (a WorkOS sign-in's GitHub id is
    /// fetched).
    pub fn wants_github(&self) -> bool {
        self.rules.iter().any(|r| matches!(r, Rule::GitHub(_)))
    }

    /// Whether a rule names this identity: its principal, or the GitHub id
    /// its metadata carries ([`GITHUB_ID`], set only by [`admit`]). An empty
    /// list admits everyone.
    pub fn admits(&self, ctx: &AuthContext) -> bool {
        if self.is_empty() {
            return true;
        }
        let principal = ctx.principal();
        let github = ctx.metadata.get(GITHUB_ID).and_then(Value::as_u64);
        self.rules.iter().any(|r| match r {
            Rule::GitHub(id) => github == Some(*id),
            Rule::Principal(p) => principal.as_ref() == Some(p),
        })
    }

    /// At the socket ([`crate::sessions::Gate`]): an identity a provider's
    /// bearer proved. `key:` principals pass; anyone else only by a
    /// `principal:` rule (no GitHub lookup is made here). An empty list
    /// admits everyone.
    pub fn admits_bearer(&self, ctx: &AuthContext) -> bool {
        if self.is_empty() {
            return true;
        }
        let Some(principal) = ctx.principal() else { return false };
        if principal.to_string().starts_with("key:") {
            return true;
        }
        self.rules.iter().any(|r| matches!(r, Rule::Principal(p) if *p == principal))
    }
}

impl fmt::Display for Allow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rules.iter().map(Rule::to_string).collect::<Vec<_>>().join(","))
    }
}

/// An identity the allow list admitted: the only thing a browser session is
/// made from ([`crate::app_session::AppContinuation`],
/// [`crate::web_login`]). Made by [`admit`] alone.
#[derive(Debug, Clone)]
pub struct Admitted(AuthContext);

impl Admitted {
    pub fn into_inner(self) -> AuthContext {
        self.0
    }
}

/// Why [`admit`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No rule names this identity.
    NotAllowed,
    /// The GitHub id could not be fetched (the backend's refusal kind).
    Lookup(&'static str),
}

impl Refused {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::Lookup(_) => "github_lookup_failed",
        }
    }
}

/// The WorkOS user a principal names (`oidc:workos/<user>`), when it is one.
fn workos_subject(ctx: &AuthContext) -> Option<String> {
    let p = ctx.principal()?;
    let s = p.to_string();
    let sub = s.strip_prefix("oidc:workos/")?;
    // Only a subject that round-trips (WorkOS ids need no escaping).
    (Principal::oidc("workos", sub).ok().as_ref() == Some(&p)).then(|| sub.to_string())
}

/// Admits `ctx` or refuses it. With no rules, admits at once and changes
/// nothing. With a `github:` rule and a WorkOS principal, asks `backend`
/// (when it is the WorkOS backend) for the GitHub id and keeps it in the
/// metadata as [`GITHUB_ID`]; a failed lookup refuses. Logs a refusal (the
/// principal and why; never a token).
pub async fn admit(allow: &Allow, mut ctx: AuthContext, backend: Option<&Arc<dyn IdentityBackend>>) -> Result<Admitted, Refused> {
    if allow.is_empty() {
        return Ok(Admitted(ctx));
    }
    // Only what is fetched here is believed.
    if let Some(meta) = ctx.metadata.as_object_mut() {
        meta.remove(GITHUB_ID);
    }
    let principal = ctx.principal().map(|p| p.to_string()).unwrap_or_default();
    if allow.wants_github() {
        if let Some(sub) = workos_subject(&ctx) {
            match backend.filter(|b| b.name() == "workos") {
                Some(b) => match b.github_id(&sub).await {
                    Ok(Some(id)) => {
                        if let Some(meta) = ctx.metadata.as_object_mut() {
                            meta.insert(GITHUB_ID.into(), Value::from(id));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(%principal, refusal = e.kind(), "sign-in refused: the account's GitHub identity could not be read");
                        return Err(Refused::Lookup(e.kind()));
                    }
                },
                None => tracing::warn!(%principal, "a github: allow rule is set, but no WorkOS backend (its API key) is here to read the GitHub id"),
            }
        }
    }
    if allow.admits(&ctx) {
        tracing::info!(%principal, github_id = ?ctx.metadata.get(GITHUB_ID), "sign-in admitted by the allow list");
        Ok(Admitted(ctx))
    } else {
        tracing::warn!(%principal, github_id = ?ctx.metadata.get(GITHUB_ID), "sign-in refused: not on the allow list");
        Err(Refused::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(principal: &str, meta: Value) -> AuthContext {
        let mut m = meta;
        m["principal"] = Value::String(principal.into());
        AuthContext::new(principal.into(), "s".into(), vec![], m)
    }

    #[test]
    fn rules_parse_typed_and_a_bad_one_refuses_the_list() {
        let a = Allow::parse(["github:251524973", "principal:oidc:workos/user_01ADA, github:7"]).unwrap();
        assert_eq!(a.to_string(), "github:251524973,principal:oidc:workos/user_01ADA,github:7");
        assert!(a.wants_github());
        for bad in ["github:hypermemetic", "github:", "github:-1", "github:0", "github:+5", "principal:", "principal:nope", "principal:nostr:abcd", "email:a@b", "251524973"] {
            assert!(Allow::parse([bad]).is_err(), "{bad}");
        }
        assert!(Allow::parse(["github:1", "oops"]).is_err(), "one typo, no list");
        assert!(Allow::parse(Vec::<String>::new()).unwrap().is_empty());
        assert!(Allow::parse([" , "]).unwrap().is_empty());
    }

    #[test]
    fn a_rule_admits_by_principal_or_by_the_fetched_github_id() {
        let a = Allow::parse(["github:251524973", "principal:nostr:abababababababababababababababababababababababababababababababab"]).unwrap();
        assert!(a.admits(&ctx("oidc:workos/user_1", json!({ GITHUB_ID: 251524973u64 }))));
        assert!(!a.admits(&ctx("oidc:workos/user_1", json!({ GITHUB_ID: 1u64 }))));
        assert!(!a.admits(&ctx("oidc:workos/user_1", json!({}))));
        assert!(!a.admits(&ctx("oidc:workos/user_1", json!({ GITHUB_ID: "251524973" }))), "only a number, as admit stores it");
        assert!(a.admits(&ctx("nostr:abababababababababababababababababababababababababababababababab", json!({}))));
        assert!(Allow::everyone().admits(&ctx("oidc:workos/anyone", json!({}))));
    }

    #[test]
    fn at_the_socket_keys_pass_and_bearers_need_a_principal_rule() {
        let a = Allow::parse(["github:251524973"]).unwrap();
        assert!(a.admits_bearer(&ctx("key:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", json!({}))));
        assert!(!a.admits_bearer(&ctx("oidc:workos/user_1", json!({ GITHUB_ID: 251524973u64 }))), "no github rule at the socket");
        let p = Allow::parse(["principal:oidc:workos/user_1"]).unwrap();
        assert!(p.admits_bearer(&ctx("oidc:workos/user_1", json!({}))));
        assert!(!p.admits_bearer(&ctx("oidc:workos/user_2", json!({}))));
        assert!(Allow::everyone().admits_bearer(&ctx("oidc:workos/user_2", json!({}))));
    }

    #[tokio::test]
    async fn no_rules_admit_unchanged_and_a_planted_id_is_not_believed() {
        let c = ctx("oidc:workos/user_1", json!({ GITHUB_ID: 251524973u64 }));
        let same = admit(&Allow::everyone(), c.clone(), None).await.unwrap().into_inner();
        assert_eq!(same.metadata, c.metadata, "nothing touched");
        let a = Allow::parse(["github:251524973"]).unwrap();
        assert_eq!(admit(&a, c, None).await.unwrap_err(), Refused::NotAllowed, "no backend asked, no id believed");
    }
}
