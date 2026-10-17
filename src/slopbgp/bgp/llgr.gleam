//// RFC 8538 & draft-ietf-idr-long-lived-gr (Long-Lived Graceful Restart for BGP)
////
//// Defines protocol support for Long-Lived Graceful Restart (LLGR):
//// - Capability Code 71 (LLGR Capability)
//// - Well-Known Communities:
////   - LLGR_STALE (65535:1 / 0xFFFF0001)
////   - NO_LLGR    (65535:2 / 0xFFFF0002)
//// - Stale route local preference depression and recovery

import gleam/list
import slopbgp/types.{
  type BgpCapability, type Community, type LlgrAfiSafi, type Route,
  CapLongLivedGracefulRestart, Community, Route,
}

/// RFC 8538 Capability Code for Long-Lived Graceful Restart
pub const capability_code_llgr = 71

/// Well-known Community 65535:1 (LLGR_STALE)
pub const llgr_stale_asn = 65_535

pub const llgr_stale_val = 1

/// Well-known Community 65535:2 (NO_LLGR)
pub const no_llgr_asn = 65_535

pub const no_llgr_val = 2

/// Construct LLGR capability record
pub fn new_llgr_capability(families: List(LlgrAfiSafi)) -> BgpCapability {
  CapLongLivedGracefulRestart(families)
}

/// Create LLGR_STALE community (65535:1)
pub fn llgr_stale_community() -> Community {
  Community(asn: llgr_stale_asn, value: llgr_stale_val)
}

/// Create NO_LLGR community (65535:2)
pub fn no_llgr_community() -> Community {
  Community(asn: no_llgr_asn, value: no_llgr_val)
}

/// Check if a route has the LLGR_STALE community
pub fn has_llgr_stale(route: Route) -> Bool {
  list.any(route.communities, fn(c) {
    c.asn == llgr_stale_asn && c.value == llgr_stale_val
  })
}

/// Check if a route has the NO_LLGR community
pub fn has_no_llgr(route: Route) -> Bool {
  list.any(route.communities, fn(c) {
    c.asn == no_llgr_asn && c.value == no_llgr_val
  })
}

/// Mark a route as Long-Lived Stale:
/// - If the route has NO_LLGR, it cannot be retained; return Error
/// - Otherwise attach LLGR_STALE community and lower LOCAL_PREF to depressed_pref
pub fn mark_route_stale(
  route: Route,
  depressed_local_pref: Int,
) -> Result(Route, String) {
  case has_no_llgr(route) {
    True ->
      Error(
        "Route has NO_LLGR community and cannot be retained as long-lived stale",
      )
    False -> {
      let new_comms = case has_llgr_stale(route) {
        True -> route.communities
        False -> [llgr_stale_community(), ..route.communities]
      }
      Ok(
        Route(..route, local_pref: depressed_local_pref, communities: new_comms),
      )
    }
  }
}

/// Unmark a stale route when peer reconnects and re-advertises valid reachability
pub fn unmark_route_stale(route: Route, restored_local_pref: Int) -> Route {
  let filtered_comms =
    list.filter(route.communities, fn(c) {
      c.asn != llgr_stale_asn || c.value != llgr_stale_val
    })
  Route(..route, local_pref: restored_local_pref, communities: filtered_comms)
}
