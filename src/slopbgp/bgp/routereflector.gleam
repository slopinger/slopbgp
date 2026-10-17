//// RFC 4456: BGP Route Reflection (An Alternative to Full Mesh IBGP)
////
//// Implements Route Reflector (RR) client reflection rules,
//// ORIGINATOR_ID (Type 9) and CLUSTER_LIST (Type 10) loop prevention,
//// and reflection path transformations.

import gleam/list
import gleam/option.{None, Some}
import slopbgp/ip.{bytes_to_ipv4, ip_to_bytes}
import slopbgp/types.{type IpAddress, type Route, Ipv4, Route}

/// Check if a route contains an ORIGINATOR_ID loop for the local router
pub fn is_originator_loop(route: Route, my_router_id: IpAddress) -> Bool {
  case route.originator_id {
    Some(id) -> id == my_router_id
    None -> False
  }
}

/// Check if a route contains a CLUSTER_LIST loop for the local RR cluster
pub fn is_cluster_loop(route: Route, my_cluster_id: IpAddress) -> Bool {
  list.contains(route.cluster_list, my_cluster_id)
}

/// Check if a received route should be dropped due to RR loop detection
pub fn has_reflection_loop(
  route: Route,
  my_router_id: IpAddress,
  my_cluster_id: IpAddress,
) -> Bool {
  is_originator_loop(route, my_router_id)
  || is_cluster_loop(route, my_cluster_id)
}

/// Determine whether a route should be reflected to target_peer
/// based on sender role and target role in an iBGP topology.
///
/// RFC 4456 Section 8:
/// 1. Route from non-client -> reflect ONLY to clients (not to other non-clients).
/// 2. Route from client -> reflect to both clients and non-clients.
/// 3. Route from eBGP -> propagate to both clients and non-clients.
pub fn should_reflect_to_peer(
  sender_is_client: Bool,
  target_is_client: Bool,
  sender_is_ebgp: Bool,
) -> Bool {
  case sender_is_ebgp {
    True -> True
    False ->
      case sender_is_client {
        True -> True
        False -> target_is_client
      }
  }
}

/// Reflect an inbound route to an iBGP peer, adding/updating
/// ORIGINATOR_ID and prepending the local cluster_id to CLUSTER_LIST.
///
/// RFC 4456 Section 8:
/// - If ORIGINATOR_ID is not present, set it to sender_router_id.
/// - Prepend my_cluster_id to CLUSTER_LIST.
/// - Preserve NEXT_HOP, LOCAL_PREF, MED, and AS_PATH.
pub fn reflect_route(
  route: Route,
  my_cluster_id: IpAddress,
  sender_router_id: IpAddress,
) -> Route {
  let updated_originator_id = case route.originator_id {
    Some(_) -> route.originator_id
    None -> Some(sender_router_id)
  }

  let updated_cluster_list = [my_cluster_id, ..route.cluster_list]

  Route(
    ..route,
    originator_id: updated_originator_id,
    cluster_list: updated_cluster_list,
  )
}

/// Encode ORIGINATOR_ID attribute (Type 9, 4 octets IPv4, flags 0x80 optional non-transitive)
pub fn encode_originator_id_attr(router_id: IpAddress) -> BitArray {
  let id_bytes = ip_to_bytes(router_id)
  <<0x80:8, 9:8, 4:8, id_bytes:bits>>
}

/// Decode ORIGINATOR_ID attribute data (4 octets)
pub fn decode_originator_id_data(data: BitArray) -> Result(IpAddress, Nil) {
  case bytes_to_ipv4(data) {
    Ok(ip) -> Ok(ip)
    Error(_) -> Error(Nil)
  }
}

/// Encode CLUSTER_LIST attribute (Type 10, multiple of 4 octets, flags 0x80 optional non-transitive)
pub fn encode_cluster_list_attr(clusters: List(IpAddress)) -> BitArray {
  let cluster_bytes =
    list.fold(clusters, <<>>, fn(acc, c) {
      <<acc:bits, { ip_to_bytes(c) }:bits>>
    })
  let len = list.length(clusters) * 4
  <<0x80:8, 10:8, len:8, cluster_bytes:bits>>
}

/// Decode CLUSTER_LIST attribute data
pub fn decode_cluster_list_data(
  data: BitArray,
  acc: List(IpAddress),
) -> List(IpAddress) {
  case data {
    <<a:8, b:8, c:8, d:8, rest:bits>> ->
      decode_cluster_list_data(rest, [Ipv4(a, b, c, d), ..acc])
    _ -> list.reverse(acc)
  }
}
