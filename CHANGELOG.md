# Changelog

All notable changes to plexus-login are documented here. This file starts
at 0.5.0; earlier changes are in the git history and README's notes (tags
`plexus-login-v*`).

## [0.5.0] — unreleased

KEEL-45: on the fixed Plexus line, 0.11 — plexus-rpc 0.11.0, and at least
plexus-core 0.11.1, plexus-transport 0.10.1, plexus-auth-core 0.3.2 and
plexus-macros 0.11.1, the security releases of 2026-11-10 (KEEL-19, KEEL-29,
KEEL-31, KEEL-32, KEEL-33). 0.4.0 was on the 0.10 line (plexus-ui 0.3 takes
it), 0.3.x on the 0.8 line (menger takes 0.3.1). A new minor because
plexus-core's and plexus-transport's types are in this crate's API
(`AuthContext`, `DynamicHub`, `SessionValidator`, `TransportServerBuilder`,
`TrustedProxies`). The move itself needed no source change: every test
passed on 0.11 before anything below.

### Added

- **`once::LinkDir`** (GAMMA-15): one-time sign-in tokens kept as files —
  `<dir>/<sha256 of the token>`, each holding its expiry, 0600, in a
  directory made 0700 and refused when it is a symlink, not a directory or
  another user's; files opened `O_NOFOLLOW`. `mint` (32 random bytes, hex,
  good for `once::ONCE_SECS`, ten minutes; the expired cleared on the way)
  and `take` (true once, removing the file: of two at once, one wins), with
  `mint_at` / `take_at` for a given time. It is menger's DIST-14 mechanism
  (`menger login`) lifted, so a server and a command run beside it share
  links with no method on the wire; an app's `OnceLinks` wraps it with whom
  the link signs in and its page's words. plexus-ui's `serve` and `login`
  take it. A new dependency, `libc` (`O_NOFOLLOW`, `geteuid`).

### Changed

- **`Wired::apply` takes plexus-transport 0.10.1's front door as it is,
  and names what only this crate knows.** The socket refuses a page from
  any origin but the shell's own and `allowed_origins` (403), and answers
  only the names it is reached at (421 otherwise). With no public URL those
  are its loopback names — the transport's default, left alone. With a
  `public_url` (or `allowed_hosts`) `apply` now names them:
  `socket_hosts(ws_port, public_url)` — the loopback names (`[::1]:<port>`
  among them, which the transport adds only on an IPv6 bind and a named
  list would otherwise lose) and the public URL's host as a browser sends
  it — plus `allowed_hosts`. Without that, a
  socket behind a public URL would refuse every page that reached it
  through its proxy. `apply` calls `with_allowed_hosts`, which **replaces**
  a list set before it. Nothing here calls `allow_any_origin()` or
  `allow_any_host()`.
- **`apply` hands the trusted proxies to the transport** when
  `LoginOptions::trusted_proxies` says anything (`with_trusted_proxies`):
  the socket's quotas and its own-origin check read the edge's
  `X-Forwarded-For` / `-Proto` as the page does.
- **The proxy walk is plexus-transport's** (the consolidation review's row
  15, KEEL-40). `client_ip::TrustedProxies` is
  `plexus_rpc::transport::TrustedProxies` (re-exported, with `IpNet` and
  `parse_net`); plexus-login's own copy is gone, and so is its `ipnet`
  dependency. The walk is the same rule. `TrustedProxies::client_ip` is now
  the transport's, `(IpAddr, &HeaderMap) -> IpAddr`; the page's form, with
  a peer that may be unknown, is the free function
  `client_ip::client_ip(&proxies, Option<IpAddr>, &headers)`. A mixed
  `none` spec is refused in the transport's words (`trusted proxy `none`
  stands alone: …`), and a forwarded header from an untrusted peer is
  warned of (once, at error, as before) in the transport's: `X-Forwarded-For/-Proto
  arrives from a peer that is not a trusted proxy and is ignored: …`. A log
  filter on the old words moves with it.
- `shell_origins` and `login::socket_urls` build their loopback part from
  plexus-transport's `host::loopback_hosts` (row 9, the part local to this
  crate). Same values.

### Added

- `LoginOptions::allowed_hosts` (`--allowed-host`): more names the socket
  answers to.
- `Wired::hosts` (what `apply` names; empty: loopback only) and
  `Wired::trusted_proxies`.
- `wiring::socket_hosts(ws_port, public_url)`.
- **One session reader** (row 14): `Sessions::id_of(&HeaderMap)`,
  `Sessions::session_of(&HeaderMap) -> Option<AuthContext>` and
  `Sessions::principal_of(&HeaderMap) -> Option<Principal>`. The page's
  `Login::session`, sign-out and the account page read through them. A
  route of another crate that asks which principal a browser is signed in
  as (plexus-integrations' bridge) takes
  `move |h| sessions.principal_of(h).map(|p| p.to_string())`. They answer
  **the browser session of this request, never an agent's** (the review's
  F1): browser sessions (`Sessions::create`) and agent tokens
  (`Sessions::mint`, `mgs_…`) share one table, and a session is answered
  only when it is a browser's, by its kind; one whose identity carries a
  ceiling (`CEILING_KEY`) is nobody, never answered as if it had none.
- **A cookie named twice is nobody** (F2): `sessions::cookie`, and so the
  socket's gate, the login transaction and the dev sign-in, answer `None`
  when the name appears more than once (another origin on the same host,
  over plain http, can plant a shadowing cookie that the browser sends
  first); `Sessions::id_of` reads every `Cookie` field (HTTP/2 sends one per
  cookie), the name once across all of them.
- Behaviour that moves with F1: the page (`Login::session`, so a shell's
  `--require-login` redirect; the account page; sign-out's provider
  sign-out) no longer takes an agent's minted token sent as the session
  cookie as a signed-in browser. No existing test relied on it. The socket's
  gate still takes a minted token, as a cookie or a bearer, with its
  ceiling.
- Tests changed: `review`'s `an_untrusted_forwarded_header_is_not_believed`
  and `none_still_warns_when_a_forwarded_header_arrives` assert the shared
  part of the warning's words, since the warning is now the transport's;
  what they hold is unchanged.
- Tests: `session_reader` (the review's attack cases, kept: a minted agent
  token, narrowed or not, is no browser; a ceiled browser session is
  nobody; a cookie named twice is nobody, every field is read);
  `sessions::tests::a_cookie_named_twice_is_nobody`; `simple_login`'s `the_socket_admits_the_shells_pages_and_refuses_any_other`,
  `behind_a_public_url_the_socket_answers_its_public_name`,
  `a_scoped_admin_is_refused_what_acts_on_the_whole_service` (an admin on
  scope `TOY` is refused `auth.waiting` by the gate, `forbidden` on `*`;
  the admin on `*` is answered); `wiring::tests::the_socket_answers_its_loopback_names_and_its_public_name`;
  `sessions::tests::a_requests_session_and_principal_are_read_from_its_cookie`.

### Moving from 0.4 (the Plexus 0.10 line; plexus-ui)

In this order:

1. **Move the service to the 0.11 line with this crate**, in one change:
   `plexus-rpc = "0.11.0"` (or plexus-core 0.11.1, plexus-transport 0.10.1,
   plexus-auth-core 0.3.2, plexus-macros 0.11.1 by name), `plexus-login =
   "0.5"`, and plexus-webapp 0.4 if you take it. Then `cargo update -p
   plexus-core -p plexus-transport -p plexus-auth-core -p plexus-macros`, so
   the lockfile holds the security releases rather than 0.11.0 / 0.10.0.
2. **Your service's code across plexus-core 0.11** (its CHANGELOG): every
   `#[activation]` now emits a trait, `{Name}ActivationSchema`, into its
   module (NEST-17; rename a clashing item or say `trait = "…"`);
   `#[child(list = "…")]`'s string form is deprecated; a child's calls back
   are narrowed to its declared `needs` (NEST-16); a dial-out needs
   `DialOut::trust` (KEEL-8); plain `ws://` beyond loopback is refused by a
   mount unless `insecure_ws` (KEEL-7); a keyed child is served only through
   `serve_child_ws` / `serve_child_proven` (KEEL-19), and its key file must
   be yours, 0600, not a link.
3. **Mark every method of yours that acts on the whole service**
   `#[method(everywhere)]` (plexus-macros 0.11.1, KEEL-31), and drop the
   hand-written `reach.is_everywhere()` check it replaces. plexus-core's own
   (`auth.role_set`, `auth.waiting`, `config.*.set|reset|confirm`) are
   marked already: an admin on a narrower scope is refused them by the gate
   now, `forbidden` with scope `*`, before the method runs.
4. **Names and proxies.** `Wired::apply` **replaces** a host list set
   earlier on the builder (`with_allowed_hosts`) whenever there is a public
   URL or `allowed_hosts` — it only ever narrows, never opens, so the cost
   is availability: a name in the earlier list and not in `wired.hosts`
   is refused 421. (`wired.hosts` keeps `[::1]:<port>`, which a list of
   your own named before `apply` might have lost on an IPv6 loopback bind.)
   So put your names in `LoginOptions::allowed_hosts`, or call your
   `with_allowed_hosts` after `apply` with `wired.hosts` included. menger
   today calls `with_allowed_hosts(hosts(ws_port))` before `apply`: move
   that list into `allowed_hosts`. Parse `--trusted-proxy` once, into
   `LoginOptions::trusted_proxies`; `apply` gives the transport the same
   set, so a separate `with_trusted_proxies` is no longer needed.
   `--allowed-origin` / `--allowed-host` `*` refuses the start (no
   wildcard; only `allow_any_origin()` / `allow_any_host()` in code open a
   listener — do not).
5. **If you called `TrustedProxies::client_ip(Some(peer), &h)`**: it is
   `client_ip::client_ip(&proxies, Some(peer), &h)` now (or the
   transport's `proxies.client_ip(peer, &h)`, which takes a known peer).
   If you read the session cookie by hand, use `Sessions::session_of` /
   `principal_of`.
6. **If your pages or tools read `<ns>.list_children` /
   `<ns>.search_children` or a `….schema` below a path the caller holds
   nothing under**: a gated service does not serve the first (KEEL-33) and
   answers the second not found (KEEL-32). Call the list method through
   `{ns}.call` by its own grant.
7. Struct literals: `LoginOptions` gains `allowed_hosts`, `Wired` gains
   `hosts` and `trusted_proxies`. Build them with `..LoginOptions::new(…)`.

### Moving from 0.3 (the Plexus 0.8 line; menger)

0.4.0 changed nothing in this crate's source beyond its Plexus line, so
this is "Moving from 0.4" above, after plexus-core 0.9 and 0.10's own
breaks. Take them first, in this order:

1. **plexus-core 0.9** (RETURNS-47): `current_reach()` is
   `Result<Reach, PlexusError>` — add `?` (menger:
   `tickets-api/src/access/mod.rs`'s `Access::verify`, `docs/src/caller.rs`);
   `with_reach` returns a `Result` and only narrows; `Activation::call`
   called straight runs in no call context, so a test that calls a method
   or a verifier outside a service wraps it in
   `plexus_core::call::test::in_call(…)` (feature `test-util`), or goes
   through a `DynamicHub`. In-process children receive their caller by
   their forward policy. plexus-core 0.8.1's `serve_call` is still there
   (menger's call layer).
2. **plexus-core 0.10** (ASK-1, ASK-2): the in-call question is gone —
   `BidirChannel`, `#[method(bidirectional)]`, `{ns}.respond`,
   `PlexusStreamItem::Request`. A method that needs a yes takes it as a
   parameter. A `MethodRole::DynamicChild { … }` built by hand gains
   `child: None` (NEST-5). Every schema hash moves.
3. **plexus-transport 0.8–0.10**: on core 0.9, 0.10, 0.11 in turn; the
   REST bridge runs through the call context (`with_router_as` to name a
   caller); nothing else a menger-shaped tenant calls changed before
   0.10.1's front door (above, step 4).
4. Then every step of "Moving from 0.4".
