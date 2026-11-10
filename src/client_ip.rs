//! AUTH-22: who a request comes from — the client's IP address, believing
//! `X-Forwarded-For` only from the proxies the operator named.
//!
//! SCAFFOLD-20 found that nothing upstream does this safely: a forwarded
//! header trusted from any peer lets a caller pick its own address, which
//! defeats every per-IP throttle and feeds WorkOS Radar a lie. The rule
//! here is the standard one:
//!
//! - the TCP peer is not a trusted proxy → the client is the peer, and any
//!   `X-Forwarded-For` it sent is ignored;
//! - the peer is a trusted proxy → walk `X-Forwarded-For` from the right
//!   (the hop nearest us) leftwards, skipping addresses that are themselves
//!   trusted proxies; the first that is not is the client. A hop that does
//!   not parse ends the walk at the last trusted hop (whatever is left of
//!   it was written by the client, and proves nothing). If every hop is
//!   trusted, the leftmost is the client.
//!
//! With no trusted proxy configured (the default) the peer is always the
//! client. AUTH-24 #2: behind an edge, that makes every visitor one client,
//! so a page served off loopback must say which it is — `--trusted-proxy
//! <the edge>` or `--trusted-proxy none` (people connect directly) — or it
//! does not start ([`crate::wiring::Wiring::new`]). And an
//! `X-Forwarded-For` arriving from a peer that is not trusted is logged
//! once, loudly: a proxy is in front and is not named. The peer comes from axum's `ConnectInfo<SocketAddr>`: serve the
//! router with `into_make_service_with_connect_info::<SocketAddr>()`
//! (plexus-webapp's `serve_on` does). Without it there is no peer, and the
//! throttles share one bucket for every unknown client.
//!
//! KEEL-45 (the consolidation review's row 15): the walk is
//! plexus-transport's ([`plexus_rpc::transport::proxy`]), which the
//! WebSocket's upgrade runs for its quotas and its own origin; this module
//! re-exports its [`TrustedProxies`] (so one `--trusted-proxy` set, parsed
//! once, serves the page and the socket — [`crate::wiring::Wired::apply`]
//! hands it to the transport) and keeps what the page adds: a peer that may
//! be unknown ([`client_ip`]), and the warning when it is.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::Extension;
pub use plexus_rpc::transport::proxy::{parse_net, IpNet, TrustedProxies};

/// The client's address for a request from `peer` carrying `headers`, by
/// `proxies` (see the module docs); `None` when the peer is unknown (the
/// router was served without connect info).
pub fn client_ip(proxies: &TrustedProxies, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    peer.map(|peer| proxies.client_ip(peer, headers))
}

static NO_PEER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn warn_once(flag: &std::sync::atomic::AtomicBool, words: &str) {
    if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::error!("{words}");
    }
}

/// AUTH-24 #12: a router served without `ConnectInfo` knows no peer, and
/// every client shares one bucket: said once.
pub fn warn_no_peer() {
    warn_once(&NO_PEER, "the sign-in page is served without the peer's address (serve with into_make_service_with_connect_info::<SocketAddr>()): every client shares one throttle bucket");
}

/// The TCP peer, when the server was made with connect info.
pub type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// The peer's address out of [`Peer`].
pub fn peer_ip(peer: &Peer) -> Option<IpAddr> {
    peer.as_ref().map(|Extension(ConnectInfo(addr))| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_forwards() {
        let none = TrustedProxies::default();
        assert_eq!(client_ip(&none, Some(ip("203.0.113.9")), &xff("1.1.1.1")), Some(ip("203.0.113.9")));
        let edge = TrustedProxies::parse(["10.0.0.0/8"]).unwrap();
        assert_eq!(client_ip(&edge, Some(ip("203.0.113.9")), &xff("1.1.1.1")), Some(ip("203.0.113.9")), "not the edge: ignored");
    }

    #[test]
    fn behind_a_trusted_proxy_the_rightmost_untrusted_hop_is_the_client() {
        let edge = TrustedProxies::parse(["10.0.0.0/8", "192.0.2.7"]).unwrap();
        // The client claimed 6.6.6.6; the edge appended the real address.
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &xff("6.6.6.6, 198.51.100.4")), Some(ip("198.51.100.4")));
        // Two trusted hops before the real one.
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &xff("6.6.6.6, 198.51.100.4, 192.0.2.7, 10.9.9.9")), Some(ip("198.51.100.4")));
        // Several headers are one list.
        let mut h = xff("6.6.6.6");
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.4:4431"));
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &h), Some(ip("198.51.100.4")));
        // No header: the proxy itself.
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &HeaderMap::new()), Some(ip("10.1.2.3")));
        // Garbage nearest us ends the walk at the last trusted hop.
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &xff("6.6.6.6, not-an-ip")), Some(ip("10.1.2.3")));
        // All trusted: the leftmost.
        assert_eq!(client_ip(&edge, Some(ip("10.1.2.3")), &xff("10.0.0.5, 10.0.0.6")), Some(ip("10.0.0.5")));
    }

    #[test]
    fn mapped_addresses_and_bare_addresses_count() {
        let edge = TrustedProxies::parse(["127.0.0.1"]).unwrap();
        assert!(edge.contains(&ip("::ffff:127.0.0.1")));
        assert_eq!(client_ip(&edge, Some(ip("::ffff:127.0.0.1")), &xff("[2001:db8::1]:443")), Some(ip("2001:db8::1")));
        assert!(TrustedProxies::parse(["10.0.0.0/33"]).is_err());
        assert!(TrustedProxies::parse(["edge"]).is_err());
        let none = TrustedProxies::parse(["none"]).unwrap();
        assert!(none.direct && none.configured() && none.nets.is_empty());
        assert!(TrustedProxies::parse(["none", "10.0.0.0/8"]).is_err());
        assert!(!TrustedProxies::default().configured());
    }

    #[test]
    fn no_peer_is_no_client() {
        assert_eq!(client_ip(&TrustedProxies::default(), None, &xff("1.1.1.1")), None);
    }
}
