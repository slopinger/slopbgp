import gleam/list
import gleam/option.{type Option, None, Some}
import slopbgp/types.{type Route, Community, LargeCommunity, Route}

// RFC 7947 & RFC 7948: Internet Exchange Point (IXP) Route Server Operations
// Supports transparent AS_PATH forwarding, NEXT_HOP preservation, and community control.

pub type RsAction {
  RsDoNotAnnounce(target_as: Int)
  RsAnnounceOnly(target_as: Int)
  RsDoNotAnnounceAny
}

/// Evaluates whether a route is permitted to be announced to a route server client
/// based on RFC 7947 Section 2.3 community filtering rules.
pub fn is_route_permitted_for_client(
  route: Route,
  client_as: Int,
  rs_as: Int,
) -> Bool {
  // 1. Check explicit "do not announce" standard communities
  let has_block_comm =
    list.any(route.communities, fn(c) {
      c == Community(0, client_as) || c == Community(0, rs_as)
    })

  // 2. Check explicit "do not announce" Large communities
  let has_block_large =
    list.any(route.large_communities, fn(lc) {
      lc == LargeCommunity(rs_as, 0, client_as)
      || lc == LargeCommunity(rs_as, 0, 0)
    })

  case has_block_comm || has_block_large {
    True -> False
    False -> {
      // 3. Check selective announcements (standard communities)
      // If any (rs_as, target) community is present (where target != 0),
      // the route must ONLY be announced to explicitly targeted ASNs!
      let selective_standard =
        list.filter_map(route.communities, fn(c) {
          case c.asn == rs_as && c.value != 0 {
            True -> Ok(c.value)
            False -> Error(Nil)
          }
        })

      // 4. Check selective announcements (Large communities)
      // LargeCommunity(rs_as, 1, target)
      let selective_large =
        list.filter_map(route.large_communities, fn(lc) {
          case lc.global_admin == rs_as && lc.local_data1 == 1 {
            True -> Ok(lc.local_data2)
            False -> Error(Nil)
          }
        })

      let all_selective = list.append(selective_standard, selective_large)
      case all_selective {
        [] -> True
        targets -> list.contains(targets, client_as)
      }
    }
  }
}

/// Strip Route Server control communities prior to forwarding to clients
pub fn strip_rs_control_communities(route: Route, rs_as: Int) -> Route {
  let clean_communities =
    list.filter(route.communities, fn(c) { c.asn != 0 && c.asn != rs_as })

  let clean_large =
    list.filter(route.large_communities, fn(lc) { lc.global_admin != rs_as })

  Route(..route, communities: clean_communities, large_communities: clean_large)
}

/// Prepare an outbound route for a Route Server client (RFC 7947):
/// - Filters by community matrix
/// - Preserves AS_PATH without prepending RS ASN (Transparent AS_PATH forwarding)
/// - Preserves NEXT_HOP without overwriting with RS IP (Next-Hop Unchanged)
/// - Strips RS internal control communities
pub fn prepare_routeserver_outbound_route(
  route: Route,
  client_as: Int,
  rs_as: Int,
) -> Option(Route) {
  case is_route_permitted_for_client(route, client_as, rs_as) {
    False -> None
    True -> {
      let cleaned = strip_rs_control_communities(route, rs_as)
      Some(cleaned)
    }
  }
}

/// Attach client control communities to a route
pub fn add_rs_control_community(
  route: Route,
  rs_as: Int,
  action: RsAction,
) -> Route {
  case action {
    RsDoNotAnnounce(target_as) -> {
      let comm = Community(0, target_as)
      let lcomm = LargeCommunity(rs_as, 0, target_as)
      Route(
        ..route,
        communities: [comm, ..route.communities],
        large_communities: [lcomm, ..route.large_communities],
      )
    }

    RsAnnounceOnly(target_as) -> {
      let comm = Community(rs_as, target_as)
      let lcomm = LargeCommunity(rs_as, 1, target_as)
      Route(
        ..route,
        communities: [comm, ..route.communities],
        large_communities: [lcomm, ..route.large_communities],
      )
    }

    RsDoNotAnnounceAny -> {
      let comm = Community(0, rs_as)
      let lcomm = LargeCommunity(rs_as, 0, 0)
      Route(
        ..route,
        communities: [comm, ..route.communities],
        large_communities: [lcomm, ..route.large_communities],
      )
    }
  }
}
