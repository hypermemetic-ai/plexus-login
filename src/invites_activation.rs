//! IDENTITY-49: the `invites` activation — sign-in codes on the service's
//! socket ([`crate::invites`]).
//!
//! | method | who | answers |
//! | --- | --- | --- |
//! | `invites.issue {role, scope?, uses?, expires_in?, label?}` | admin (or a role given `invites.issue`) holding `role` | `invite`: the code, its link, its QR code (SVG) |
//! | `invites.list {qr?}` | admin, or a role given `invites.list` (their own codes only) | an `invite` per code |
//! | `invites.revoke {id \| code, sign_out?}` | its issuer, or an admin | `revoked`: the code as it stands, sessions ended |
//!
//! Its own activation, not methods of plexus-core's `auth`: that activation's
//! methods and its `AuthBackend` are plexus-core's, and adding `auth.invite`
//! would be a plexus-core change. Its methods are listed in no role
//! (`roles(...)` is the activation macro's, and this one is written by hand
//! so plexus-login needs no macro dependency): only admin holds them until
//! `auth.role_set` lists them in a role. Every answer is a stream of
//! `{"type": …}` events; a refusal is in band, `{"type": "error", "message"}`.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream;
use plexus_core::plexus::{
    wrap_stream, Activation, AuthContext, ChildMethods, ChildRouter, MethodSchema, PlexusError, PlexusStream, PluginSchema, SchemaResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::access::LoginAccess;
use crate::invites::{InviteView, Invites, Issue};
use crate::sessions::Sessions;

/// The activation's namespace.
pub const NAMESPACE: &str = "invites";

/// What the methods answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvitesEvent {
    /// A code (`issue`, each of `list`).
    Invite(InviteView),
    /// A code withdrawn, and how many sessions that ended.
    Revoked { invite: InviteView, signed_out: usize },
    Error { message: String },
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    #[serde(default)]
    qr: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeParams {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    sign_out: Option<bool>,
}

/// The `invites` activation. Cheap to clone. Register it on the service
/// beside `auth` ([`crate::Wired::invites_activation`]).
#[derive(Clone)]
pub struct InvitesActivation<A: LoginAccess> {
    invites: Arc<Invites>,
    access: A,
    sessions: Arc<Sessions>,
}

impl<A: LoginAccess> InvitesActivation<A> {
    pub fn new(invites: Arc<Invites>, access: A, sessions: Arc<Sessions>) -> Self {
        Self { invites, access, sessions }
    }

    fn answer(&self, method: &str, params: Value, caller: &AuthContext) -> Vec<InvitesEvent> {
        let error = |message: String| vec![InvitesEvent::Error { message }];
        let params = if params.is_null() { json!({}) } else { params };
        match method {
            "issue" => match serde_json::from_value::<Issue>(params) {
                Ok(req) => match self.invites.issue(&self.access, caller, req) {
                    Ok(v) => vec![InvitesEvent::Invite(v)],
                    Err(e) => error(e),
                },
                Err(e) => error(format!("invites.issue: {e}")),
            },
            "list" => match serde_json::from_value::<ListParams>(params) {
                Ok(p) => self.invites.list(&self.access, caller, p.qr.unwrap_or(false)).into_iter().map(InvitesEvent::Invite).collect(),
                Err(e) => error(format!("invites.list: {e}")),
            },
            "revoke" => match serde_json::from_value::<RevokeParams>(params) {
                Ok(p) => match p.id.as_deref().or(p.code.as_deref()) {
                    None => error("invites.revoke: name the code by --id or --code".into()),
                    Some(key) => match self.invites.revoke(&self.access, caller, key, p.sign_out.unwrap_or(false), &self.sessions) {
                        Ok((invite, signed_out)) => vec![InvitesEvent::Revoked { invite, signed_out }],
                        Err(e) => error(e),
                    },
                },
                Err(e) => error(format!("invites.revoke: {e}")),
            },
            _ => unreachable!("checked by call"),
        }
    }
}

/// Each method: its name, description and parameters (JSON Schema).
fn methods() -> Vec<(&'static str, &'static str, Value)> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    vec![
        (
            "issue",
            "Issue a sign-in code: a role on a scope, for so many uses, until a time — its link and QR code",
            json!({
                "type": "object",
                "properties": {
                    "role": s("The role it grants (one you hold): viewer, editor, or any role auth.roles lists"),
                    "scope": s("Where the role holds (default *)"),
                    "uses": { "type": "integer", "minimum": 1, "maximum": crate::invites::MAX_USES, "description": "How many people it signs in (default 1)" },
                    "expires_in": s("How long it lasts: 30m, 24h, 7d, or seconds (default 24h, at most 30d)"),
                    "label": s("What it is for; a guest it signs in is named by it"),
                },
                "required": ["role"],
                "additionalProperties": false,
            }),
        ),
        (
            "list",
            "The sign-in codes issued: every one for an admin, else your own",
            json!({
                "type": "object",
                "properties": { "qr": { "type": "boolean", "description": "Each open code's QR code too (SVG)" } },
                "additionalProperties": false,
            }),
        ),
        (
            "revoke",
            "Withdraw a sign-in code; with sign_out, take back its grants and end its guests' sessions",
            json!({
                "type": "object",
                "properties": {
                    "id": s("The code's id (invites.list)"),
                    "code": s("Or the code itself"),
                    "sign_out": { "type": "boolean", "description": "Also take back the roles it granted and end its guests' sessions" },
                },
                "additionalProperties": false,
            }),
        ),
    ]
}

#[async_trait]
impl<A: LoginAccess> Activation for InvitesActivation<A> {
    type Methods = ChildMethods;

    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Sign-in codes: issue one for a role, list them, withdraw one"
    }

    fn methods(&self) -> Vec<&str> {
        methods().into_iter().map(|(n, _, _)| n).collect()
    }

    fn method_help(&self, method: &str) -> Option<String> {
        methods().into_iter().find(|(n, _, _)| *n == method).map(|(_, d, _)| d.to_string())
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, _raw: Option<&plexus_core::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        if method == "schema" {
            let schema = self.plugin_schema();
            let wanted = params.get("method").and_then(Value::as_str).map(str::to_string);
            let result = match wanted {
                Some(name) => SchemaResult::Method(
                    schema.methods.iter().find(|m| m.name == name).cloned().ok_or(PlexusError::MethodNotFound { activation: NAMESPACE.into(), method: name })?,
                ),
                None => SchemaResult::Plugin(schema),
            };
            return Ok(wrap_stream(stream::once(async move { result }), "invites.schema", vec![NAMESPACE.into()]));
        }
        if !methods().iter().any(|(n, _, _)| *n == method) {
            return Err(PlexusError::MethodNotFound { activation: NAMESPACE.into(), method: method.into() });
        }
        let events = match auth.filter(|a| a.is_authenticated()) {
            Some(caller) => self.answer(method, params, caller),
            None => vec![InvitesEvent::Error { message: "sign in first".into() }],
        };
        let content_type: &'static str = match method {
            "issue" => "invites.issue",
            "list" => "invites.list",
            _ => "invites.revoke",
        };
        Ok(wrap_stream(stream::iter(events), content_type, vec![NAMESPACE.into()]))
    }

    /// Nothing of its own on the socket: reached through the service's
    /// `{service}.call`, behind its gate.
    fn into_rpc_methods(self) -> jsonrpsee::Methods {
        jsonrpsee::Methods::new()
    }

    fn plugin_schema(&self) -> PluginSchema {
        let mut list: Vec<MethodSchema> = methods()
            .into_iter()
            .map(|(name, description, params)| {
                let hash: String = Sha256::digest(format!("{name}\0{description}\0{params}").as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect();
                MethodSchema::new(name, description, hash).with_params(serde_json::from_value(params).expect("a JSON Schema"))
            })
            .collect();
        list.push(MethodSchema::auto_schema());
        PluginSchema::leaf(NAMESPACE, self.version(), self.description(), list)
    }
}

#[async_trait]
impl<A: LoginAccess> ChildRouter for InvitesActivation<A> {
    fn router_namespace(&self) -> &str {
        NAMESPACE
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&plexus_core::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, raw).await
    }

    async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
        None
    }
}
