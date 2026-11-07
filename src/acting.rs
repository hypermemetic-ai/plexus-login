//! Acting as someone else — a test deployment's admin becomes any user, or
//! makes one, and comes back.
//!
//! Operator, 2026-11-07: "the admins should have the ability to essentially SU
//! into any user they want or create them. this I believe is a core feature of
//! a test deployment".
//!
//! | method (`people.*`) | who | does |
//! | --- | --- | --- |
//! | `whoami` | anyone (public) | who this connection is, and whether it is acting: `principal`, `name`, `acting_as`, `signed_in_as` (+ `signed_in_as_name`), `admin`, `can_act` |
//! | `known_users` | an admin, on the sign-in cookie | one `role` per role a test user can be given, then one `user` per principal the app knows |
//! | `act_as {principal}` | an admin, on the sign-in cookie | this browser session becomes `principal`: `became` |
//! | `create_user {name, roles}` | an admin, on the sign-in cookie | makes `oidc:test/<name>` with `roles` (granted through the app's [`LoginAccess::dev_grant`]) and becomes it: `became` |
//! | `unbecome` | the acting session (public) | the session is the admin again: `returned` |
//!
//! **Where it exists.** Only where [`enabled`] says so: the app passes its
//! [`Environment`] and it must be exactly [`Environment::Test`], *and* the
//! public URL's host must not be one of the app's production hosts (agents:
//! `agents.menger.sh`; menger: `app.menger.sh`, `menger.sh`). Anywhere else the
//! activation is not built and the methods do not exist. When it is on, a
//! `warn` line at startup says so.
//!
//! **Who.** A caller whose principal holds the app's admin role
//! ([`LoginAccess::is_admin`]), on a browser session — the `HttpOnly` sign-in
//! cookie ([`Sessions::is_browser`]); a minted `mgs_` token or a provider's
//! bearer is refused. An acting session is refused too (return first): one
//! hop, never a chain.
//!
//! **Not another admin.** A principal holding admin cannot be become (nor a
//! test user made with admin): an admin acting as another admin would launder
//! who did what. Nor a `key:` principal — a key is a host or a service, not a
//! person. Becoming yourself is refused as pointless.
//!
//! **How.** The browser keeps its cookie; the session behind it is given the
//! target's identity ([`Sessions::replace`]) — same expiry, same idling — with
//! the admin kept in the metadata: [`SIGNED_IN_AS`] (the admin's principal,
//! as SUPERCONDUCTOR-25's `github:<id>=<principal>` keeps it), [`ACTING_AS`]
//! (`true`), and the admin's own identity whole under [`ORIGIN`], server side
//! only, which `unbecome` puts back. Sockets opened on the session before the
//! switch stop answering ([`Sessions::alive_as`]: the session now names
//! someone else), so the page reconnects as the target.
//!
//! **The allow list.** Sessions made this way do not pass through
//! [`crate::admission::admit`]: they are made under an admitted admin's
//! authority, inside the session that admin already holds — the allow list
//! says who may *sign in*, and nobody signs in here. A test principal
//! (`oidc:test/<name>`) could never pass a `github:` rule, which is the point:
//! it exists only behind an admin, on test.
//!
//! **Audit.** Every `act_as`, `create_user` and `unbecome` is a structured
//! `warn` on the `plexus_login::acting` target — action, admin, target, roles —
//! and goes to the app's [`AuditHook`] when one is set. Never a token or a
//! session id.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::Stream;
use plexus_rpc::auth_core::identity::Principal;
use plexus_rpc::core::plexus::AuthContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::admission::SIGNED_IN_AS;
use crate::access::LoginAccess;
use crate::sessions::Sessions;

/// The session metadata key saying this session acts as someone else (`true`).
pub const ACTING_AS: &str = "acting_as";

/// The session metadata key the admin's own identity is kept under while
/// acting — server side, never answered.
pub const ORIGIN: &str = "acting_origin";

/// The name an acting admin goes by, beside [`SIGNED_IN_AS`].
pub const SIGNED_IN_AS_NAME: &str = "signed_in_as_name";

/// The OIDC provider name test principals are made under: `oidc:test/<name>`.
pub const TEST_PROVIDER: &str = "test";

/// Which deployment this is. The app says (agents: `--env`/`AGENTS_ENV`); only
/// [`Environment::Test`] can act as anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Environment {
    /// A developer's machine (the default).
    #[default]
    Local,
    /// The test deployment: online, real sign-in, and the admin may act as
    /// anyone.
    Test,
    /// Production.
    Prod,
}

impl FromStr for Environment {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" | "dev" => Ok(Self::Local),
            "test" => Ok(Self::Test),
            "prod" | "production" => Ok(Self::Prod),
            other => Err(format!("`{other}` is not an environment: test, prod or local")),
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Local => "local",
            Self::Test => "test",
            Self::Prod => "prod",
        })
    }
}

/// Why acting is not on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEnabled {
    /// The environment is not test.
    NotTest(Environment),
    /// The public URL's host is a production host.
    ProdHost(String),
    /// The public URL does not parse or names no host.
    NoHost(String),
}

impl fmt::Display for NotEnabled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTest(env) => write!(f, "acting as another user is a test deployment's: this one is {env}"),
            Self::ProdHost(h) => write!(f, "acting as another user is refused on {h}, a production host, whatever the environment says"),
            Self::NoHost(u) => write!(f, "acting as another user needs a public URL with a host; `{u}` has none"),
        }
    }
}

/// Whether acting may be on: `env` exactly [`Environment::Test`], and
/// `public_url`'s host none of `prod_hosts` (exact, case-insensitive; a
/// trailing dot ignored).
pub fn enabled(env: Environment, public_url: &str, prod_hosts: &[String]) -> Result<(), NotEnabled> {
    if env != Environment::Test {
        return Err(NotEnabled::NotTest(env));
    }
    let host = url::Url::parse(public_url.trim())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
        .filter(|h| !h.is_empty())
        .ok_or_else(|| NotEnabled::NoHost(public_url.to_string()))?;
    if prod_hosts.iter().any(|p| p.trim().trim_end_matches('.').eq_ignore_ascii_case(&host)) {
        return Err(NotEnabled::ProdHost(host));
    }
    Ok(())
}

/// A role a test user can be given, as the app names it: `id` is what
/// `create_user`'s `roles` takes (`user@local`, `viewer@*`), `label` what a
/// person reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RoleOption {
    pub id: String,
    pub label: String,
}

/// What acting asks of the app, through its [`LoginAccess`] — the seam the
/// dev sign-in already writes grants through. Object-safe, so the activation
/// is not generic; [`ViaAccess`] is the one implementation.
#[async_trait]
trait Rules: Send + Sync + 'static {
    fn is_admin(&self, principal: &str) -> bool;
    fn held(&self, principal: &str) -> Vec<String>;
    fn roles(&self) -> Vec<RoleOption>;
    async fn grant(&self, principal: &str, roles: &[String]) -> Result<(), String>;
    fn known(&self) -> Vec<(String, Option<String>)>;
}

/// The app's [`LoginAccess`] as acting's rules: who is admin
/// ([`LoginAccess::is_admin`]), what a principal holds
/// ([`LoginAccess::held`]), which `role@scope` a test user may be given
/// ([`LoginAccess::grantable`], admin roles left out), the grants written by
/// [`LoginAccess::dev_grant`] — as the dev sign-in writes them — and who the
/// app knows ([`LoginAccess::known_users`]).
struct ViaAccess<A: LoginAccess>(A);

#[async_trait]
impl<A: LoginAccess> Rules for ViaAccess<A> {
    fn is_admin(&self, principal: &str) -> bool {
        self.0.is_admin(principal)
    }
    fn held(&self, principal: &str) -> Vec<String> {
        self.0.held(principal)
    }
    fn roles(&self) -> Vec<RoleOption> {
        self.0
            .grantable()
            .into_iter()
            .filter(|(r, _)| !A::is_admin_role(r))
            .map(|(r, s)| RoleOption { id: format!("{r}@{s}"), label: crate::dev_login::describe(&[(r, s)]) })
            .collect()
    }
    async fn grant(&self, principal: &str, roles: &[String]) -> Result<(), String> {
        for id in roles {
            let (role, scope) = id.split_once('@').ok_or_else(|| format!("`{id}` is not role@scope"))?;
            let role: A::Role = role.parse()?;
            if A::is_admin_role(&role) {
                return Err("a test user cannot be an admin".into());
            }
            self.0.dev_grant(principal, &A::scope_of(scope)?, role).await?;
        }
        Ok(())
    }
    fn known(&self) -> Vec<(String, Option<String>)> {
        self.0.known_users()
    }
}

/// One audited act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActingAudit {
    /// `act_as`, `create_user` or `unbecome`.
    pub action: &'static str,
    /// The admin, by principal.
    pub admin: String,
    /// Whom the session became (`unbecome`: the one it stops being).
    pub target: String,
    /// `create_user`: the roles given.
    pub roles: Vec<String>,
    /// Unix seconds.
    pub at: i64,
}

/// Where the app wants each [`ActingAudit`] (its audit sink, a log).
pub type AuditHook = Arc<dyn Fn(&ActingAudit) + Send + Sync>;

/// A refusal: a short machine word and a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self { reason, message: message.into() }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.message)
    }
}

/// Who a connection is, as `people.whoami` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Whoami {
    pub principal: Option<String>,
    pub name: Option<String>,
    /// This session acts as `principal` for `signed_in_as`.
    pub acting_as: bool,
    /// The admin behind an acting session (or, from the allow list's
    /// `github:<id>=<principal>`, the account that signed in).
    pub signed_in_as: Option<String>,
    pub signed_in_as_name: Option<String>,
    /// Whether `principal` holds the app's admin role.
    pub admin: bool,
    /// Whether this connection may call `act_as` and `create_user` now: an
    /// admin, on the sign-in cookie, not acting.
    pub can_act: bool,
}

/// One principal the app knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KnownUser {
    pub principal: String,
    pub name: Option<String>,
    /// `role@scope`, as held now.
    pub roles: Vec<String>,
    /// Holds admin: cannot be become.
    pub admin: bool,
    /// Made by `create_user`.
    pub test: bool,
    /// The caller.
    pub you: bool,
    /// Has a session standing now.
    pub signed_in: bool,
}

/// What became of the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Became {
    pub principal: String,
    pub name: Option<String>,
    /// The admin behind it.
    pub signed_in_as: String,
}

/// The acting service: the session table, the app's rules, the test users made
/// here. Made only by [`Acting::enable`].
pub struct Acting {
    sessions: Arc<Sessions>,
    rules: Arc<dyn Rules>,
    /// Test users made here: principal → (name, roles given).
    created: Mutex<BTreeMap<String, (String, Vec<String>)>>,
    audit: Option<AuditHook>,
}

fn principal_of(ctx: &AuthContext) -> Option<String> {
    ctx.principal().map(|p| p.to_string())
}

fn meta_str(ctx: &AuthContext, key: &str) -> Option<String> {
    ctx.get_metadata_string(key).filter(|s| !s.is_empty())
}

fn display_name(ctx: &AuthContext) -> Option<String> {
    meta_str(ctx, "name").or_else(|| meta_str(ctx, "username")).or_else(|| meta_str(ctx, "email"))
}

fn is_acting(ctx: &AuthContext) -> bool {
    ctx.metadata.get(ACTING_AS).and_then(Value::as_bool).unwrap_or(false)
}

impl Acting {
    /// Acting over `sessions` and the app's `rules`, if [`enabled`] says so for
    /// `env`, `public_url` and `prod_hosts` — with a `warn` line saying it is
    /// on. Anything else: why not, and nothing is built.
    pub fn enable<A: LoginAccess>(env: Environment, public_url: &str, prod_hosts: &[String], sessions: Arc<Sessions>, access: A) -> Result<Self, NotEnabled> {
        enabled(env, public_url, prod_hosts)?;
        tracing::warn!(
            target: "plexus_login::acting",
            env = %env,
            public_url,
            "ACTING IS ON: an admin may act as any user or create test users here (people.act_as, people.create_user) — a test deployment's feature"
        );
        Ok(Self { sessions, rules: Arc::new(ViaAccess(access)), created: Mutex::default(), audit: None })
    }

    /// The same, sending every [`ActingAudit`] to `hook` as well as the log.
    pub fn with_audit(mut self, hook: AuditHook) -> Self {
        self.audit = Some(hook);
        self
    }

    fn audit(&self, action: &'static str, admin: &str, target: &str, roles: &[String]) {
        let a = ActingAudit { action, admin: admin.into(), target: target.into(), roles: roles.to_vec(), at: crate::sessions::now() };
        tracing::warn!(target: "plexus_login::acting", action, admin, target, roles = ?roles, "an admin acted as another user");
        if let Some(h) = &self.audit {
            h(&a);
        }
    }

    /// The session key `ctx` carries, when it is a browser's session (the
    /// cookie) still naming `ctx`'s principal.
    fn browser_key(&self, ctx: &AuthContext) -> Option<String> {
        let key = ctx.get_metadata_string(self.sessions.session_key())?;
        (self.sessions.is_browser(&key) && self.sessions.alive_as(&key, &ctx.user_id)).then_some(key)
    }

    /// `people.whoami`.
    pub fn whoami(&self, ctx: Option<&AuthContext>) -> Whoami {
        let Some(ctx) = ctx.filter(|c| c.is_authenticated()) else {
            return Whoami { principal: None, name: None, acting_as: false, signed_in_as: None, signed_in_as_name: None, admin: false, can_act: false };
        };
        let principal = principal_of(ctx);
        let admin = principal.as_deref().is_some_and(|p| self.rules.is_admin(p));
        let acting = is_acting(ctx);
        Whoami {
            name: display_name(ctx),
            acting_as: acting,
            signed_in_as: meta_str(ctx, SIGNED_IN_AS),
            signed_in_as_name: meta_str(ctx, SIGNED_IN_AS_NAME),
            admin,
            can_act: admin && !acting && self.browser_key(ctx).is_some(),
            principal,
        }
    }

    /// The caller, when it may act: an admin, on the cookie, not acting. Its
    /// principal and session key.
    fn admin_caller(&self, ctx: &AuthContext) -> Result<(String, String), Refusal> {
        let principal = principal_of(ctx).filter(|_| ctx.is_authenticated()).ok_or_else(|| Refusal::new("signed_out", "sign in first"))?;
        if is_acting(ctx) {
            return Err(Refusal::new("acting", "you are acting as someone else: return to yourself first (people.unbecome)"));
        }
        let key = self.browser_key(ctx).ok_or_else(|| {
            Refusal::new("not_a_browser_session", "only a browser's sign-in (its session cookie) can act as someone else; a token or a bearer cannot")
        })?;
        if !self.rules.is_admin(&principal) {
            return Err(Refusal::new("not_admin", "only an admin can act as someone else"));
        }
        Ok((principal, key))
    }

    /// `people.known_users`: every principal the app knows — the sessions
    /// standing, the app's own list, the test users made here — and the roles a
    /// test user can be given. Never a `key:` principal.
    pub fn known_users(&self, ctx: &AuthContext) -> Result<(Vec<RoleOption>, Vec<KnownUser>), Refusal> {
        let (me, _) = self.admin_caller(ctx)?;
        Ok((self.roles(), self.users(&me)))
    }

    fn roles(&self) -> Vec<RoleOption> {
        self.rules.roles().into_iter().filter(|r| !r.id.trim().to_ascii_lowercase().starts_with("admin")).collect()
    }

    fn users(&self, me: &str) -> Vec<KnownUser> {
        // principal → (name, signed in)
        let mut seen: BTreeMap<String, (Option<String>, bool)> = BTreeMap::new();
        for (_, ctx) in self.sessions.standing() {
            // The admin behind an acting session is known by its own row.
            if let Some(origin) = ctx.metadata.get(ORIGIN).and_then(|v| serde_json::from_value::<AuthContext>(v.clone()).ok()) {
                if let Some(p) = principal_of(&origin) {
                    let e = seen.entry(p).or_default();
                    e.0 = e.0.take().or_else(|| display_name(&origin));
                    e.1 = true;
                }
            }
            if let Some(p) = principal_of(&ctx) {
                let e = seen.entry(p).or_default();
                e.0 = e.0.take().or_else(|| display_name(&ctx));
                e.1 = true;
            }
        }
        for (p, name) in self.rules.known() {
            let e = seen.entry(p).or_default();
            e.0 = e.0.take().or(name);
        }
        let created = self.created.lock().unwrap().clone();
        for (p, (name, _)) in &created {
            let e = seen.entry(p.clone()).or_default();
            e.0 = Some(name.clone());
        }
        seen.entry(me.to_string()).or_default();
        let mut out: Vec<KnownUser> = seen
            .into_iter()
            .filter(|(p, _)| !p.starts_with("key:") && p.parse::<Principal>().is_ok())
            .map(|(p, (name, signed_in))| KnownUser {
                roles: self.rules.held(&p),
                admin: self.rules.is_admin(&p),
                test: created.contains_key(&p),
                you: p == me,
                name,
                signed_in,
                principal: p,
            })
            .collect();
        out.sort_by(|a, b| (!a.you, a.admin == false, a.name.clone().unwrap_or_default().to_lowercase()).cmp(&(!b.you, b.admin == false, b.name.clone().unwrap_or_default().to_lowercase())));
        out
    }

    /// `people.act_as {principal}`: this browser session becomes `target`, an
    /// existing principal the app knows.
    pub fn act_as(&self, ctx: &AuthContext, target: &str) -> Result<Became, Refusal> {
        let (me, key) = self.admin_caller(ctx)?;
        let target = target.trim();
        let known = self.users(&me).into_iter().find(|u| u.principal == target);
        let Some(user) = known else {
            return Err(Refusal::new("unknown_user", format!("`{target}` is no one this app knows: pick from people.known_users, or create a test user")));
        };
        self.switch(ctx, &me, &key, &user.principal, user.name.clone(), "act_as", &[])
    }

    /// `people.create_user {name, roles}`: makes `oidc:test/<name>`, grants it
    /// `roles` through the app's rules, and becomes it.
    pub async fn create_user(&self, ctx: &AuthContext, name: &str, roles: &[String]) -> Result<Became, Refusal> {
        let (me, key) = self.admin_caller(ctx)?;
        let name = crate::dev_login::username(name).map_err(|e| Refusal::new("bad_name", e))?;
        let offered = self.roles();
        let mut given = Vec::new();
        for r in roles.iter().map(|r| r.trim()).filter(|r| !r.is_empty()) {
            if r.to_ascii_lowercase().starts_with("admin") {
                return Err(Refusal::new("admin_role", "a test user cannot be an admin: acting as an admin would hide who did what"));
            }
            if !offered.iter().any(|o| o.id == r) {
                let ids: Vec<&str> = offered.iter().map(|o| o.id.as_str()).collect();
                return Err(Refusal::new("bad_role", format!("`{r}` is not a role a test user can be given here: {}", ids.join(", "))));
            }
            if !given.iter().any(|g: &String| g == r) {
                given.push(r.to_string());
            }
        }
        let principal = Principal::oidc(TEST_PROVIDER, &name).map_err(|e| Refusal::new("bad_name", e.to_string()))?.to_string();
        if self.rules.is_admin(&principal) {
            return Err(Refusal::new("admin_target", format!("{principal} holds admin: an admin cannot act as another admin")));
        }
        self.rules.grant(&principal, &given).await.map_err(|e| Refusal::new("grant_failed", e))?;
        {
            let mut created = self.created.lock().unwrap();
            let entry = created.entry(principal.clone()).or_insert_with(|| (name.clone(), Vec::new()));
            for g in &given {
                if !entry.1.contains(g) {
                    entry.1.push(g.clone());
                }
            }
        }
        self.switch(ctx, &me, &key, &principal, Some(name), "create_user", &given)
    }

    #[allow(clippy::too_many_arguments)]
    fn switch(&self, ctx: &AuthContext, me: &str, key: &str, target: &str, name: Option<String>, action: &'static str, roles: &[String]) -> Result<Became, Refusal> {
        if target == me {
            return Err(Refusal::new("self", "that is you already"));
        }
        if target.starts_with("key:") {
            return Err(Refusal::new("key", "a key is a host or a service, not a person: it cannot be acted as"));
        }
        if self.rules.is_admin(target) {
            return Err(Refusal::new("admin_target", format!("{target} holds admin: an admin cannot act as another admin")));
        }
        target.parse::<Principal>().map_err(|e| Refusal::new("bad_principal", format!("`{target}`: {e}")))?;
        // The session's own identity, as the table holds it (never what the
        // socket brought): kept whole, to be put back.
        let origin = self.sessions.current(key).ok_or_else(|| Refusal::new("signed_out", "your session has ended: sign in again"))?;
        let mut meta = serde_json::Map::new();
        meta.insert("principal".into(), target.into());
        if let Some(n) = &name {
            meta.insert("name".into(), n.clone().into());
        }
        meta.insert("provider".into(), "acting".into());
        meta.insert(SIGNED_IN_AS.into(), me.into());
        if let Some(n) = display_name(ctx) {
            meta.insert(SIGNED_IN_AS_NAME.into(), n.into());
        }
        meta.insert(ACTING_AS.into(), true.into());
        meta.insert(ORIGIN.into(), serde_json::to_value(&origin).map_err(|e| Refusal::new("internal", e.to_string()))?);
        let acting = AuthContext::new(target.to_string(), origin.session_id.clone(), vec![], Value::Object(meta));
        match self.sessions.replace(key, acting) {
            Ok(true) => {}
            Ok(false) => return Err(Refusal::new("signed_out", "your session has ended: sign in again")),
            Err(e) => return Err(Refusal::new("not_kept", format!("the session could not be kept: {e}"))),
        }
        self.audit(action, me, target, roles);
        Ok(Became { principal: target.to_string(), name, signed_in_as: me.to_string() })
    }

    /// `people.unbecome`: the acting session is its admin again.
    pub fn unbecome(&self, ctx: Option<&AuthContext>) -> Result<Became, Refusal> {
        let ctx = ctx.filter(|c| c.is_authenticated()).ok_or_else(|| Refusal::new("signed_out", "sign in first"))?;
        let key = self.browser_key(ctx).ok_or_else(|| Refusal::new("not_a_browser_session", "only the browser session that is acting can return"))?;
        let current = self.sessions.current(&key).ok_or_else(|| Refusal::new("signed_out", "your session has ended: sign in again"))?;
        if !is_acting(&current) {
            return Err(Refusal::new("not_acting", "you are not acting as anyone"));
        }
        let origin: AuthContext = current
            .metadata
            .get(ORIGIN)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| Refusal::new("internal", "the session does not say who it was: sign out and in again"))?;
        let target = principal_of(&current).unwrap_or_default();
        let admin = principal_of(&origin).unwrap_or_default();
        let name = display_name(&origin);
        match self.sessions.replace(&key, origin) {
            Ok(true) => {}
            Ok(false) => return Err(Refusal::new("signed_out", "your session has ended: sign in again")),
            Err(e) => return Err(Refusal::new("not_kept", format!("the session could not be kept: {e}"))),
        }
        self.audit("unbecome", &admin, &target, &[]);
        Ok(Became { principal: admin.clone(), name, signed_in_as: admin })
    }
}

/// Everything `people.*` answers (`{"type": …}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeopleEvent {
    /// `whoami`.
    Whoami(Whoami),
    /// `known_users`: a role a test user can be given.
    Role(RoleOption),
    /// `known_users`: one principal.
    User(KnownUser),
    /// `act_as`, `create_user`: the session is now `principal`.
    Became(Became),
    /// `unbecome`: the session is its admin again.
    Returned(Became),
    /// Refused, and why (`reason`: `not_admin`, `not_a_browser_session`,
    /// `acting`, `admin_target`, `unknown_user`, `bad_role`, …).
    Refused { reason: String, message: String },
}

impl plexus_rpc::client::FromClientError for PeopleEvent {
    fn from_client_error(error: plexus_rpc::client::ClientError) -> Self {
        Self::Refused { reason: "client".into(), message: error.to_string() }
    }
}

impl From<Refusal> for PeopleEvent {
    fn from(r: Refusal) -> Self {
        Self::Refused { reason: r.reason.into(), message: r.message }
    }
}

fn events(v: Vec<PeopleEvent>) -> impl Stream<Item = PeopleEvent> + Send + 'static {
    futures::stream::iter(v)
}

/// The `people` activation over an [`Acting`]: register it on the hub only
/// when [`Acting::enable`] made one — anywhere else the methods do not exist.
#[derive(Clone)]
pub struct PeopleActivation {
    acting: Arc<Acting>,
}

impl PeopleActivation {
    pub fn new(acting: Arc<Acting>) -> Self {
        Self { acting }
    }
}

#[plexus_rpc::macros::activation(
    namespace = "people",
    version = "0.1.0",
    description = "Test only: an admin acts as any user, or makes one, and returns",
    auth = "mixed"
)]
impl PeopleActivation {
    /// Who this connection is, and whether it acts for an admin: principal, name, acting_as, signed_in_as, admin, can_act.
    #[plexus_rpc::macros::method(public)]
    pub async fn whoami(&self, auth: Option<&AuthContext>) -> impl Stream<Item = PeopleEvent> + Send + 'static {
        events(vec![PeopleEvent::Whoami(self.acting.whoami(auth))])
    }

    /// Admin, on the sign-in cookie: one role per role a test user can be given, then one user per principal this app knows.
    #[plexus_rpc::macros::method]
    pub async fn known_users(&self, auth: &AuthContext) -> impl Stream<Item = PeopleEvent> + Send + 'static {
        events(match self.acting.known_users(auth) {
            Ok((roles, users)) => roles.into_iter().map(PeopleEvent::Role).chain(users.into_iter().map(PeopleEvent::User)).collect(),
            Err(r) => vec![r.into()],
        })
    }

    /// Admin, on the sign-in cookie: this browser session becomes `principal` (a known, non-admin user) until people.unbecome.
    #[plexus_rpc::macros::method(params(principal = "The principal to act as, from people.known_users"))]
    pub async fn act_as(&self, auth: &AuthContext, principal: String) -> impl Stream<Item = PeopleEvent> + Send + 'static {
        events(vec![self.acting.act_as(auth, &principal).map_or_else(Into::into, PeopleEvent::Became)])
    }

    /// Admin, on the sign-in cookie: make the test user oidc:test/<name> with `roles` and act as it.
    #[plexus_rpc::macros::method(params(name = "letters, digits, - _ . (at most 64)", roles = "role ids from people.known_users' role events"))]
    pub async fn create_user(&self, auth: &AuthContext, name: String, roles: Option<Vec<String>>) -> impl Stream<Item = PeopleEvent> + Send + 'static {
        let r = self.acting.create_user(auth, &name, &roles.unwrap_or_default()).await;
        events(vec![r.map_or_else(Into::into, PeopleEvent::Became)])
    }

    /// The acting browser session returns to its admin.
    #[plexus_rpc::macros::method(public)]
    pub async fn unbecome(&self, auth: Option<&AuthContext>) -> impl Stream<Item = PeopleEvent> + Send + 'static {
        events(vec![self.acting.unbecome(auth).map_or_else(Into::into, PeopleEvent::Returned)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::LoginNames;
    use crate::simple::{SimpleAccess, SimpleRole};
    use serde_json::json;

    const ADA: &str = "idp:c952acd3-60aa-4534-b2e3-83634591fee1";
    const BOB: &str = "idp:0b6d1c0e-3f0a-4d55-9d1e-6f0c2a7b9e01";
    const EVE: &str = "idp:5e1f0c2a-3f0a-4d55-9d1e-6f0c2a7b9e02";
    const TEST_URL: &str = "https://agents-test.menger.sh";

    fn prod() -> Vec<String> {
        vec!["agents.menger.sh".into(), "app.menger.sh".into(), "menger.sh".into()]
    }

    fn person(principal: &str, name: &str) -> AuthContext {
        AuthContext::new(principal.into(), "sid".into(), vec![], json!({ "principal": principal, "name": name }))
    }

    struct World {
        sessions: Arc<Sessions>,
        access: SimpleAccess,
        acting: Acting,
        audits: Arc<Mutex<Vec<ActingAudit>>>,
    }

    fn world() -> World {
        let sessions = Arc::new(Sessions::new(3600, &LoginNames::for_app("toy")));
        let access = SimpleAccess::new(&sessions, &[ADA.to_string(), EVE.to_string()]).unwrap();
        let audits: Arc<Mutex<Vec<ActingAudit>>> = Arc::default();
        let sink = audits.clone();
        let acting = Acting::enable(Environment::Test, TEST_URL, &prod(), sessions.clone(), access.clone())
            .unwrap()
            .with_audit(Arc::new(move |a: &ActingAudit| sink.lock().unwrap().push(a.clone())));
        World { sessions, access, acting, audits }
    }

    /// A browser session (the cookie) for `ctx`: its id, and the identity a
    /// socket opened on it carries.
    fn browser(w: &World, ctx: AuthContext) -> (String, AuthContext) {
        let (id, _) = w.sessions.create(ctx).unwrap();
        let socket = w.sessions.get(&id).unwrap();
        (id, socket)
    }

    #[test]
    fn only_test_on_a_host_that_is_not_production() {
        assert_eq!(enabled(Environment::Prod, TEST_URL, &prod()), Err(NotEnabled::NotTest(Environment::Prod)));
        assert_eq!(enabled(Environment::Local, "http://127.0.0.1:4470", &prod()), Err(NotEnabled::NotTest(Environment::Local)));
        for p in ["https://agents.menger.sh", "https://AGENTS.menger.sh./", "wss://app.menger.sh/ws", "https://menger.sh"] {
            assert!(matches!(enabled(Environment::Test, p, &prod()), Err(NotEnabled::ProdHost(_))), "{p}");
        }
        assert!(enabled(Environment::Test, TEST_URL, &prod()).is_ok());
        assert!(enabled(Environment::Test, "http://127.0.0.1:4470", &prod()).is_ok());
        assert!(matches!(enabled(Environment::Test, "nope", &prod()), Err(NotEnabled::NoHost(_))));
        assert_eq!("TEST".parse::<Environment>().unwrap(), Environment::Test);
        assert!("staging".parse::<Environment>().is_err());
        let s = Arc::new(Sessions::new(60, &LoginNames::for_app("toy")));
        let a = SimpleAccess::new(&s, &[]).unwrap();
        assert!(Acting::enable(Environment::Prod, TEST_URL, &prod(), s.clone(), a.clone()).is_err());
        assert!(Acting::enable(Environment::Test, "https://agents.menger.sh", &prod(), s, a).is_err());
    }

    #[tokio::test]
    async fn an_admin_on_the_cookie_becomes_a_user_and_returns() {
        let w = world();
        w.access.notice(&person(BOB, "bob"));
        let (id, admin) = browser(&w, person(ADA, "ada"));
        let me = w.acting.whoami(Some(&admin));
        assert!(me.admin && me.can_act && !me.acting_as, "{me:?}");
        let (_, users) = w.acting.known_users(&admin).unwrap();
        assert!(users.iter().any(|u| u.principal == BOB && !u.admin));
        assert!(users.iter().any(|u| u.principal == ADA && u.you && u.admin));

        let b = w.acting.act_as(&admin, BOB).unwrap();
        assert_eq!((b.principal.as_str(), b.signed_in_as.as_str()), (BOB, ADA));
        // The socket that asked is no longer this session's.
        let key = admin.get_metadata_string("toy_session").unwrap();
        assert!(!w.sessions.alive_as(&key, &admin.user_id), "the admin's old socket is closed");
        // The page reconnects with the same cookie: it is bob, for ada.
        let now = w.sessions.get(&id).unwrap();
        let who = w.acting.whoami(Some(&now));
        assert_eq!(who.principal.as_deref(), Some(BOB));
        assert!(who.acting_as && !who.admin && !who.can_act);
        assert_eq!((who.signed_in_as.as_deref(), who.signed_in_as_name.as_deref()), (Some(ADA), Some("ada")));
        assert_eq!(w.acting.act_as(&now, BOB).unwrap_err().reason, "acting", "one hop");

        let back = w.acting.unbecome(Some(&now)).unwrap();
        assert_eq!(back.principal, ADA);
        let again = w.sessions.get(&id).unwrap();
        assert_eq!(again.principal().unwrap().to_string(), ADA);
        assert!(again.metadata.get(ACTING_AS).is_none() && again.metadata.get(ORIGIN).is_none());
        assert!(w.acting.whoami(Some(&again)).can_act);
        assert_eq!(w.acting.unbecome(Some(&again)).unwrap_err().reason, "not_acting");

        let audits = w.audits.lock().unwrap();
        assert_eq!(audits.iter().map(|a| (a.action, a.admin.as_str(), a.target.as_str())).collect::<Vec<_>>(), [("act_as", ADA, BOB), ("unbecome", ADA, BOB)]);
    }

    #[tokio::test]
    async fn refused_for_a_non_admin_a_token_another_admin_and_a_stranger() {
        let w = world();
        w.access.notice(&person(BOB, "bob"));
        let (_, bob) = browser(&w, person(BOB, "bob"));
        assert_eq!(w.acting.known_users(&bob).unwrap_err().reason, "not_admin");
        assert_eq!(w.acting.act_as(&bob, ADA).unwrap_err().reason, "not_admin");
        assert!(!w.acting.whoami(Some(&bob)).can_act);
        // A minted token (mgs_), as a bearer: an admin's, still refused.
        let (token, _) = w.sessions.mint(person(ADA, "ada"), 600).unwrap();
        let minted = w.sessions.get(&token).unwrap();
        assert_eq!(w.acting.act_as(&minted, BOB).unwrap_err().reason, "not_a_browser_session");
        assert!(!w.acting.whoami(Some(&minted)).can_act);
        // A provider's bearer: no session at all.
        assert_eq!(w.acting.act_as(&person(ADA, "ada"), BOB).unwrap_err().reason, "not_a_browser_session");
        let (_, ada) = browser(&w, person(ADA, "ada"));
        browser(&w, person(EVE, "eve"));
        assert_eq!(w.acting.act_as(&ada, EVE).unwrap_err().reason, "admin_target", "no laundering through another admin");
        assert_eq!(w.acting.act_as(&ada, ADA).unwrap_err().reason, "self");
        assert_eq!(w.acting.act_as(&ada, "idp:00000000-0000-4000-8000-000000000000").unwrap_err().reason, "unknown_user");
        assert!(w.audits.lock().unwrap().is_empty(), "nothing refused is audited as done");
    }

    #[tokio::test]
    async fn create_user_makes_a_test_principal_with_its_roles_and_becomes_it() {
        let w = world();
        let (id, ada) = browser(&w, person(ADA, "ada"));
        let (roles, _) = w.acting.known_users(&ada).unwrap();
        assert_eq!(roles.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["viewer@*", "editor@*"], "never admin");
        assert_eq!(w.acting.create_user(&ada, "carol", &["admin@*".into()]).await.unwrap_err().reason, "admin_role");
        assert_eq!(w.acting.create_user(&ada, "carol", &["owner@*".into()]).await.unwrap_err().reason, "bad_role");
        assert_eq!(w.acting.create_user(&ada, "no spaces", &[]).await.unwrap_err().reason, "bad_name");
        let b = w.acting.create_user(&ada, "Carol", &["editor@*".into()]).await.unwrap();
        assert_eq!(b.principal, "oidc:test/carol");
        assert_eq!(w.access.held("oidc:test/carol"), ["editor@*"], "granted through LoginAccess");
        assert!(w.access.holds_any("oidc:test/carol"));
        let now = w.sessions.get(&id).unwrap();
        assert_eq!(now.principal().unwrap().to_string(), "oidc:test/carol");
        assert_eq!(now.get_metadata_string("name").as_deref(), Some("carol"));
        let back = w.acting.unbecome(Some(&now)).unwrap();
        assert_eq!(back.principal, ADA);
        let ada = w.sessions.get(&id).unwrap();
        let (_, users) = w.acting.known_users(&ada).unwrap();
        let carol = users.iter().find(|u| u.principal == "oidc:test/carol").expect("listed");
        assert!(carol.test && carol.roles == ["editor@*"]);
        // Known now: act as her again.
        assert!(w.acting.act_as(&ada, "oidc:test/carol").is_ok());
        let a = w.audits.lock().unwrap();
        assert_eq!(a[0].action, "create_user");
        assert_eq!(a[0].roles, ["editor@*"]);
        let _ = SimpleRole::Viewer;
    }

    #[test]
    fn an_acting_session_survives_a_restart_and_still_returns() {
        let dir = std::env::temp_dir().join(format!("plexus-login-acting-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sessions.jsonl");
        let names = LoginNames::for_app("toy");
        let id = {
            let s = Arc::new(Sessions::open(&path, 3600, &names).unwrap());
            let a = SimpleAccess::new(&s, &[ADA.to_string()]).unwrap();
            a.notice(&person(BOB, "bob"));
            let acting = Acting::enable(Environment::Test, TEST_URL, &prod(), s.clone(), a).unwrap();
            let (id, _) = s.create(person(ADA, "ada")).unwrap();
            let admin = s.get(&id).unwrap();
            acting.act_as(&admin, BOB).unwrap();
            id
        };
        let s = Arc::new(Sessions::open(&path, 3600, &names).unwrap());
        let a = SimpleAccess::new(&s, &[ADA.to_string()]).unwrap();
        let acting = Acting::enable(Environment::Test, TEST_URL, &prod(), s.clone(), a).unwrap();
        let bob = s.get(&id).expect("kept");
        assert_eq!(bob.principal().unwrap().to_string(), BOB);
        assert_eq!(acting.unbecome(Some(&bob)).unwrap().principal, ADA);
        assert_eq!(s.get(&id).unwrap().principal().unwrap().to_string(), ADA);
        let _ = std::fs::remove_dir_all(dir);
    }
}
