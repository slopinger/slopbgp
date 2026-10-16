import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/string
import slopbgp/dn42/communities.{
  extract_dn42_latency, has_no_advertise, has_no_export,
}
import slopbgp/ip.{prefix_to_string}
import slopbgp/types.{
  type AsPathSegment, type IpAddress, type IpPrefix, type PeerConfig,
  type RoaStatus, type Route, AsSequence, AsSet, OriginEgp, OriginIgp,
  OriginIncomplete, RoaInvalid, RoaNotFound, RoaValid, Route,
}

pub type Rib {
  Rib(
    // Adj-RIB-In: peer_id -> (prefix_string -> Route)
    adj_rib_in: Dict(String, Dict(String, Route)),
    // Loc-RIB: prefix_string -> Route (best selected route)
    loc_rib: Dict(String, Route),
    // All known prefixes
    prefixes: Dict(String, IpPrefix),
  )
}

pub fn new_rib() -> Rib {
  Rib(adj_rib_in: dict.new(), loc_rib: dict.new(), prefixes: dict.new())
}

pub fn insert_route(rib: Rib, route: Route) -> #(Rib, Option(Route)) {
  let p_str = prefix_to_string(route.prefix)
  let peer_table = case dict.get(rib.adj_rib_in, route.peer_id) {
    Ok(t) -> t
    Error(_) -> dict.new()
  }
  let updated_peer_table = dict.insert(peer_table, p_str, route)
  let updated_adj_in =
    dict.insert(rib.adj_rib_in, route.peer_id, updated_peer_table)
  let updated_prefixes = dict.insert(rib.prefixes, p_str, route.prefix)

  // Re-evaluate Loc-RIB for this prefix
  let candidates = get_candidates_for_prefix(updated_adj_in, p_str)
  let best_route = select_best_route(candidates)

  let previous_best = dict.get(rib.loc_rib, p_str)
  let updated_loc_rib = case best_route {
    Some(best) -> dict.insert(rib.loc_rib, p_str, best)
    None -> dict.delete(rib.loc_rib, p_str)
  }

  let updated_rib =
    Rib(
      adj_rib_in: updated_adj_in,
      loc_rib: updated_loc_rib,
      prefixes: updated_prefixes,
    )

  let changed_route = case previous_best, best_route {
    Ok(prev), Some(curr) if prev == curr -> None
    _, _ -> best_route
  }

  #(updated_rib, changed_route)
}

pub fn withdraw_route(
  rib: Rib,
  peer_id: String,
  prefix: IpPrefix,
) -> #(Rib, Option(Route)) {
  let p_str = prefix_to_string(prefix)
  case dict.get(rib.adj_rib_in, peer_id) {
    Error(_) -> #(rib, None)
    Ok(peer_table) -> {
      let updated_peer_table = dict.delete(peer_table, p_str)
      let updated_adj_in =
        dict.insert(rib.adj_rib_in, peer_id, updated_peer_table)

      let candidates = get_candidates_for_prefix(updated_adj_in, p_str)
      let best_route = select_best_route(candidates)

      let updated_loc_rib = case best_route {
        Some(best) -> dict.insert(rib.loc_rib, p_str, best)
        None -> dict.delete(rib.loc_rib, p_str)
      }

      let updated_rib =
        Rib(
          adj_rib_in: updated_adj_in,
          loc_rib: updated_loc_rib,
          prefixes: rib.prefixes,
        )
      #(updated_rib, best_route)
    }
  }
}

pub fn withdraw_all_from_peer(rib: Rib, peer_id: String) -> Rib {
  case dict.get(rib.adj_rib_in, peer_id) {
    Error(_) -> rib
    Ok(peer_table) -> {
      let affected_prefixes = dict.keys(peer_table)
      let updated_adj_in = dict.delete(rib.adj_rib_in, peer_id)

      let updated_loc_rib =
        list.fold(affected_prefixes, rib.loc_rib, fn(loc, p_str) {
          let candidates = get_candidates_for_prefix(updated_adj_in, p_str)
          case select_best_route(candidates) {
            Some(best) -> dict.insert(loc, p_str, best)
            None -> dict.delete(loc, p_str)
          }
        })

      Rib(
        adj_rib_in: updated_adj_in,
        loc_rib: updated_loc_rib,
        prefixes: rib.prefixes,
      )
    }
  }
}

fn get_candidates_for_prefix(
  adj_rib_in: Dict(String, Dict(String, Route)),
  p_str: String,
) -> List(Route) {
  dict.fold(adj_rib_in, [], fn(acc, _peer_id, peer_table) {
    case dict.get(peer_table, p_str) {
      Ok(route) -> [route, ..acc]
      Error(_) -> acc
    }
  })
}

pub fn select_best_route(candidates: List(Route)) -> Option(Route) {
  case candidates {
    [] -> None
    [first, ..rest] ->
      Some(
        list.fold(rest, first, fn(current_best, next) {
          case compare_routes(next, current_best) {
            True -> next
            False -> current_best
          }
        }),
      )
  }
}

// Returns True if route A is preferred over route B
pub fn compare_routes(a: Route, b: Route) -> Bool {
  // 1. ROA status: Valid > NotFound > Invalid
  let roa_cmp = compare_roa_status(a.roa_status, b.roa_status)
  case roa_cmp {
    Some(pref) -> pref
    None -> {
      // 2. Highest Local Preference
      case a.local_pref != b.local_pref {
        True -> a.local_pref > b.local_pref
        False -> {
          // 3. Shortest AS_PATH length
          let len_a = as_path_length(a.as_path)
          let len_b = as_path_length(b.as_path)
          case len_a != len_b {
            True -> len_a < len_b
            False -> {
              // 4. Lowest Origin code: IGP < EGP < INCOMPLETE
              let orig_a = origin_score(a.origin)
              let orig_b = origin_score(b.origin)
              case orig_a != orig_b {
                True -> orig_a < orig_b
                False -> {
                  // 5. Lowest MED
                  case a.med != b.med {
                    True -> a.med < b.med
                    False -> {
                      // 6. Lowest DN42 latency metric
                      let lat_a = extract_dn42_latency(a.communities)
                      let lat_b = extract_dn42_latency(b.communities)
                      case lat_a, lat_b {
                        Some(la), Some(lb) if la != lb -> la < lb
                        Some(_), None -> True
                        None, Some(_) -> False
                        _, _ -> {
                          // 7. Earliest timestamp / lowest peer_id
                          case a.timestamp != b.timestamp {
                            True -> a.timestamp < b.timestamp
                            False ->
                              string.compare(a.peer_id, b.peer_id) == order.Lt
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

fn compare_roa_status(a: RoaStatus, b: RoaStatus) -> Option(Bool) {
  case a, b {
    RoaValid, RoaValid -> None
    RoaValid, _ -> Some(True)
    _, RoaValid -> Some(False)
    RoaNotFound, RoaNotFound -> None
    RoaNotFound, RoaInvalid -> Some(True)
    RoaInvalid, RoaNotFound -> Some(False)
    RoaInvalid, RoaInvalid -> None
  }
}

pub fn as_path_length(as_path: List(AsPathSegment)) -> Int {
  list.fold(as_path, 0, fn(acc, seg) {
    case seg {
      AsSequence(asns) -> acc + list.length(asns)
      AsSet(_) -> acc + 1
    }
  })
}

fn origin_score(origin: types.Origin) -> Int {
  case origin {
    OriginIgp -> 0
    OriginEgp -> 1
    OriginIncomplete -> 2
  }
}

pub fn prepare_outbound_route(
  route: Route,
  peer: PeerConfig,
  local_ip: IpAddress,
) -> Option(Route) {
  // 1. Loop detection: if peer's AS is in AS_PATH, drop!
  let contains_peer_as =
    list.any(route.as_path, fn(seg) {
      case seg {
        AsSequence(asns) | AsSet(asns) -> list.contains(asns, peer.remote_as)
      }
    })

  case contains_peer_as {
    True -> None
    False -> {
      // 2. Communities: NO_EXPORT, NO_ADVERTISE
      case has_no_advertise(route.communities) {
        True -> None
        False -> {
          // If eBGP and NO_EXPORT, do not advertise
          let is_ebgp = peer.local_as != peer.remote_as
          case is_ebgp && has_no_export(route.communities) {
            True -> None
            False -> {
              // 3. Prepend our local AS to AS_PATH
              let updated_as_path = prepend_as(route.as_path, peer.local_as)

              // 4. Update Next Hop to our local peering IP
              let updated_next_hop = local_ip

              // 5. Add DN42 metric communities if configured
              let updated_communities =
                add_dn42_peer_communities(route.communities, peer)

              Some(
                Route(
                  ..route,
                  as_path: updated_as_path,
                  next_hop: updated_next_hop,
                  communities: updated_communities,
                ),
              )
            }
          }
        }
      }
    }
  }
}

fn prepend_as(as_path: List(AsPathSegment), asn: Int) -> List(AsPathSegment) {
  case as_path {
    [AsSequence(asns), ..rest] -> [AsSequence([asn, ..asns]), ..rest]
    _ -> [AsSequence([asn]), ..as_path]
  }
}

fn add_dn42_peer_communities(
  comms: List(types.Community),
  peer: PeerConfig,
) -> List(types.Community) {
  let with_latency = case peer.dn42_latency {
    Some(ms) -> [communities.latency_to_community(ms), ..comms]
    None -> comms
  }
  let with_bw = case peer.dn42_bandwidth {
    Some(bw) -> [types.Community(communities.dn42_asn, bw), ..with_latency]
    None -> with_latency
  }
  let with_crypto = case peer.dn42_crypto {
    Some(c) -> [types.Community(communities.dn42_asn, c), ..with_bw]
    None -> with_bw
  }
  case peer.dn42_region {
    Some(r) -> [types.Community(communities.dn42_asn, r), ..with_crypto]
    None -> with_crypto
  }
}

pub fn get_all_routes(rib: Rib) -> List(Route) {
  dict.values(rib.loc_rib)
}

pub fn get_peer_routes(rib: Rib, peer_id: String) -> List(Route) {
  case dict.get(rib.adj_rib_in, peer_id) {
    Ok(table) -> dict.values(table)
    Error(_) -> []
  }
}

pub fn count_routes(rib: Rib) -> Int {
  dict.size(rib.loc_rib)
}
