import gleam/list
import slopbgp/types.{type Community, type Route, Community, Route}

/// RFC 8326 BGP Graceful Shutdown well-known community (65535:0 / 0xFFFF0000)
pub const graceful_shutdown_asn = 65_535

pub const graceful_shutdown_val = 0

pub fn graceful_shutdown_community() -> Community {
  Community(graceful_shutdown_asn, graceful_shutdown_val)
}

pub fn has_graceful_shutdown(route: Route) -> Bool {
  list.any(route.communities, fn(c) {
    c.asn == graceful_shutdown_asn && c.value == graceful_shutdown_val
  })
}

/// On inbound reception of a route with GRACEFUL_SHUTDOWN community:
/// Set LOCAL_PREF to 0 so traffic immediately diverts to alternative paths (RFC 8326 §4).
pub fn apply_graceful_shutdown_inbound(route: Route) -> Route {
  case has_graceful_shutdown(route) {
    True -> Route(..route, local_pref: 0)
    False -> route
  }
}

/// On outbound advertisement when draining a peer or node:
/// Attach the GRACEFUL_SHUTDOWN community and depress local_pref to 0 (RFC 8326 §3).
pub fn apply_graceful_shutdown_outbound(route: Route) -> Route {
  let has_comm = has_graceful_shutdown(route)
  let new_comms = case has_comm {
    True -> route.communities
    False -> [graceful_shutdown_community(), ..route.communities]
  }
  Route(..route, local_pref: 0, communities: new_comms)
}
