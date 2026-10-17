//// RFC 5065: Autonomous System Confederations for BGP
////
//// Implements BGP confederation member AS routing,
//// AS_CONFED_SEQUENCE (Type 3) and AS_CONFED_SET (Type 4) segments,
//// confederation loop detection, effective path length calculation,
//// and outbound boundary transformation.

import gleam/list
import slopbgp/types.{
  type AsPathSegment, type IpAddress, type Route, AsConfedSequence, AsConfedSet,
  AsSequence, AsSet, Route,
}

/// Detect if an incoming AS_PATH contains an AS Confederation routing loop.
///
/// RFC 5065 Section 5.1: If a BGP speaker receives an update with its own
/// Member AS in an AS_CONFED_SEQUENCE or AS_CONFED_SET, it SHALL discard the route.
pub fn has_confed_loop(
  as_path: List(AsPathSegment),
  my_member_as: Int,
) -> Bool {
  list.any(as_path, fn(seg) {
    case seg {
      AsConfedSequence(asns) | AsConfedSet(asns) ->
        list.contains(asns, my_member_as)
      _ -> False
    }
  })
}

/// Calculate the effective AS_PATH length for BGP decision process.
///
/// RFC 5065 Section 5.3: AS_CONFED_SEQUENCE and AS_CONFED_SET segments
/// are excluded when computing the length of the AS_PATH.
pub fn effective_as_path_length(as_path: List(AsPathSegment)) -> Int {
  list.fold(as_path, 0, fn(acc, seg) {
    case seg {
      AsSequence(asns) -> acc + list.length(asns)
      AsSet(_) -> acc + 1
      AsConfedSequence(_) -> acc
      AsConfedSet(_) -> acc
    }
  })
}

/// Strip all confederation segments (AS_CONFED_SEQUENCE and AS_CONFED_SET) from an AS_PATH.
/// Used when advertising routes outside the confederation to standard eBGP peers.
pub fn strip_confed_segments(
  as_path: List(AsPathSegment),
) -> List(AsPathSegment) {
  list.filter(as_path, fn(seg) {
    case seg {
      AsConfedSequence(_) | AsConfedSet(_) -> False
      AsSequence(_) | AsSet(_) -> True
    }
  })
}

/// Prepend a Member AS to an AS_CONFED_SEQUENCE segment.
///
/// RFC 5065 Section 5.1: When advertising to an intra-confederation peer,
/// the local Member AS is prepended into an AS_CONFED_SEQUENCE.
pub fn prepend_confed_as(
  as_path: List(AsPathSegment),
  member_as: Int,
) -> List(AsPathSegment) {
  case as_path {
    [AsConfedSequence(asns), ..rest] -> [
      AsConfedSequence([member_as, ..asns]),
      ..rest
    ]
    _ -> [AsConfedSequence([member_as]), ..as_path]
  }
}

/// Prepend the public Confederation Identifier to an external AS_PATH.
pub fn prepend_confed_identifier(
  as_path: List(AsPathSegment),
  confed_id: Int,
) -> List(AsPathSegment) {
  case as_path {
    [AsSequence(asns), ..rest] -> [AsSequence([confed_id, ..asns]), ..rest]
    _ -> [AsSequence([confed_id]), ..as_path]
  }
}

/// Transform an outbound route according to RFC 5065 rules:
/// - If target peer is an intra-confederation member peer:
///   prepend local member AS to AS_CONFED_SEQUENCE; preserve NEXT_HOP and MED.
/// - If target peer is outside the confederation (standard eBGP):
///   strip confederation segments; prepend the public Confederation Identifier AS
///   into AS_SEQUENCE; update NEXT_HOP to local peering IP.
pub fn prepare_confed_outbound_route(
  route: Route,
  target_is_confed_member: Bool,
  my_member_as: Int,
  confed_id: Int,
  local_ip: IpAddress,
) -> Route {
  case target_is_confed_member {
    True -> {
      // Intra-confederation: prepend member AS to AS_CONFED_SEQUENCE, preserve NEXT_HOP & MED
      let updated_path = prepend_confed_as(route.as_path, my_member_as)
      Route(..route, as_path: updated_path)
    }
    False -> {
      // External eBGP: strip confederation segments, prepend confed_id, update NEXT_HOP
      let stripped = strip_confed_segments(route.as_path)
      let external_path = prepend_confed_identifier(stripped, confed_id)
      Route(..route, as_path: external_path, next_hop: local_ip)
    }
  }
}
