import gleam/dict.{type Dict}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/string
import slopbgp/dn42/communities.{extract_dn42_latency}
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/types.{
  type AsPathSegment, type IpAddress, type IpPrefix, type Origin, type RoaStatus,
  type Route, AsConfedSequence, AsConfedSet, AsSequence, AsSet, OriginEgp,
  OriginIgp, OriginIncomplete, RoaInvalid, RoaNotFound, RoaValid,
}

// RFC 9107: BGP Optimal Route Reflection (BGP-ORR)

pub type ClientGroup {
  ClientGroup(
    name: String,
    client_ids: List(String),
    igp_costs: Dict(String, Int),
  )
}

pub type OrrConfig {
  OrrConfig(
    enabled: Bool,
    rr_location: String,
    rr_igp_costs: Dict(String, Int),
    groups: List(ClientGroup),
  )
}

pub type OrrComparisonResult {
  OrrComparisonResult(
    prefix: IpPrefix,
    client_id: String,
    group_name: String,
    orr_path: Route,
    rr_path: Route,
    orr_next_hop: IpAddress,
    rr_next_hop: IpAddress,
    client_igp_cost_orr: Int,
    client_igp_cost_rr: Int,
    deflection_avoided: Bool,
    cost_saved: Int,
  )
}

pub fn new_orr_config(rr_location: String) -> OrrConfig {
  OrrConfig(
    enabled: True,
    rr_location: rr_location,
    rr_igp_costs: dict.new(),
    groups: [],
  )
}

// --- ORR Best-Path Selection Algorithm ---

pub fn select_orr_best_route(
  candidates: List(Route),
  igp_costs: Dict(String, Int),
) -> Option(Route) {
  case candidates {
    [] -> None
    [first, ..rest] ->
      Some(
        list.fold(rest, first, fn(current_best, next) {
          case compare_orr_routes(next, current_best, igp_costs) {
            True -> next
            False -> current_best
          }
        }),
      )
  }
}

pub fn compare_orr_routes(
  a: Route,
  b: Route,
  igp_costs: Dict(String, Int),
) -> Bool {
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
              // 4. Lowest Origin code
              let orig_a = origin_score(a.origin)
              let orig_b = origin_score(b.origin)
              case orig_a != orig_b {
                True -> orig_a < orig_b
                False -> {
                  // 5. Lowest MED
                  case a.med != b.med {
                    True -> a.med < b.med
                    False -> {
                      // 6. DN42 latency metric
                      let lat_a = extract_dn42_latency(a.communities)
                      let lat_b = extract_dn42_latency(b.communities)
                      case lat_a, lat_b {
                        Some(la), Some(lb) if la != lb -> la < lb
                        Some(_), None -> True
                        None, Some(_) -> False
                        _, _ -> {
                          // 7. BGP-ORR Perspective IGP metric (RFC 9107 Section 3)
                          let cost_a = get_igp_cost(a.next_hop, igp_costs)
                          let cost_b = get_igp_cost(b.next_hop, igp_costs)
                          case cost_a != cost_b {
                            True -> cost_a < cost_b
                            False -> {
                              // 8. RFC 4456 cluster_list length
                              let cl_len_a = list.length(a.cluster_list)
                              let cl_len_b = list.length(b.cluster_list)
                              case cl_len_a != cl_len_b {
                                True -> cl_len_a < cl_len_b
                                False -> {
                                  // 9. Earliest timestamp / lowest peer_id
                                  case a.timestamp != b.timestamp {
                                    True -> a.timestamp < b.timestamp
                                    False ->
                                      string.compare(a.peer_id, b.peer_id)
                                      == order.Lt
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
      }
    }
  }
}

pub fn get_igp_cost(ip: IpAddress, igp_costs: Dict(String, Int)) -> Int {
  let ip_str = ip_to_string(ip)
  case dict.get(igp_costs, ip_str) {
    Ok(cost) -> cost
    Error(_) -> 9999
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

fn as_path_length(path: List(AsPathSegment)) -> Int {
  list.fold(path, 0, fn(acc, seg) {
    case seg {
      AsSequence(asns) -> acc + list.length(asns)
      AsSet(_) -> acc + 1
      AsConfedSequence(_) | AsConfedSet(_) -> acc
    }
  })
}

fn origin_score(orig: Origin) -> Int {
  case orig {
    OriginIgp -> 0
    OriginEgp -> 1
    OriginIncomplete -> 2
  }
}

// --- Deflection Analysis & Auditing ---

pub fn audit_client_prefix(
  prefix: IpPrefix,
  candidates: List(Route),
  client_id: String,
  group_name: String,
  client_costs: Dict(String, Int),
  rr_costs: Dict(String, Int),
) -> Option(OrrComparisonResult) {
  case
    select_orr_best_route(candidates, client_costs),
    select_orr_best_route(candidates, rr_costs)
  {
    Some(orr_route), Some(rr_route) -> {
      let client_cost_orr = get_igp_cost(orr_route.next_hop, client_costs)
      let client_cost_rr = get_igp_cost(rr_route.next_hop, client_costs)
      let deflection = orr_route.peer_id != rr_route.peer_id
      let saved = client_cost_rr - client_cost_orr
      Some(
        OrrComparisonResult(
          prefix: prefix,
          client_id: client_id,
          group_name: group_name,
          orr_path: orr_route,
          rr_path: rr_route,
          orr_next_hop: orr_route.next_hop,
          rr_next_hop: rr_route.next_hop,
          client_igp_cost_orr: client_cost_orr,
          client_igp_cost_rr: client_cost_rr,
          deflection_avoided: deflection,
          cost_saved: case saved > 0 {
            True -> saved
            False -> 0
          },
        ),
      )
    }
    _, _ -> None
  }
}

pub fn audit_orr_deflections(
  candidates_by_prefix: List(#(IpPrefix, List(Route))),
  config: OrrConfig,
) -> List(OrrComparisonResult) {
  list.flat_map(candidates_by_prefix, fn(item) {
    let #(pfx, cands) = item
    list.flat_map(config.groups, fn(grp) {
      list.filter_map(grp.client_ids, fn(cid) {
        audit_client_prefix(
          pfx,
          cands,
          cid,
          grp.name,
          grp.igp_costs,
          config.rr_igp_costs,
        )
        |> option.to_result(Nil)
      })
    })
  })
}

// --- Default Multi-Region DN42 Topology Reference ---

pub fn default_dn42_orr_config() -> OrrConfig {
  let rr_costs =
    dict.new()
    |> dict.insert("172.22.64.1", 5)
    |> dict.insert("172.22.64.2", 90)
    |> dict.insert("172.22.64.3", 240)

  let ams_costs =
    dict.new()
    |> dict.insert("172.22.64.1", 10)
    |> dict.insert("172.22.64.2", 85)
    |> dict.insert("172.22.64.3", 235)

  let nyc_costs =
    dict.new()
    |> dict.insert("172.22.64.1", 90)
    |> dict.insert("172.22.64.2", 8)
    |> dict.insert("172.22.64.3", 180)

  let tyo_costs =
    dict.new()
    |> dict.insert("172.22.64.1", 240)
    |> dict.insert("172.22.64.2", 180)
    |> dict.insert("172.22.64.3", 12)

  OrrConfig(
    enabled: True,
    rr_location: "fra-core1",
    rr_igp_costs: rr_costs,
    groups: [
      ClientGroup("europe-west", ["baragoon_fra", "slop_ams"], ams_costs),
      ClientGroup("north-america", ["slop_nyc1", "slop_nyc2"], nyc_costs),
      ClientGroup("asia-east", ["slop_tyo1"], tyo_costs),
    ],
  )
}

// --- JSON Formatting for API ---

pub fn orr_config_to_json(config: OrrConfig) -> String {
  let groups_json =
    list.map(config.groups, fn(g) {
      let costs_json =
        dict.to_list(g.igp_costs)
        |> list.map(fn(pair) {
          let #(ip, cost) = pair
          #(ip, json.int(cost))
        })
      json.object([
        #("name", json.string(g.name)),
        #(
          "clients",
          json.preprocessed_array(list.map(g.client_ids, json.string)),
        ),
        #("igp_costs", json.object(costs_json)),
      ])
    })

  let rr_costs_json =
    dict.to_list(config.rr_igp_costs)
    |> list.map(fn(pair) {
      let #(ip, cost) = pair
      #(ip, json.int(cost))
    })

  json.object([
    #("enabled", json.bool(config.enabled)),
    #("rr_location", json.string(config.rr_location)),
    #("rr_igp_costs", json.object(rr_costs_json)),
    #("groups", json.preprocessed_array(groups_json)),
  ])
  |> json.to_string
}

pub fn orr_audits_to_json(audits: List(OrrComparisonResult)) -> String {
  let audit_objects =
    list.map(audits, fn(a) {
      json.object([
        #("prefix", json.string(prefix_to_string(a.prefix))),
        #("client_id", json.string(a.client_id)),
        #("group_name", json.string(a.group_name)),
        #("orr_next_hop", json.string(ip_to_string(a.orr_next_hop))),
        #("rr_next_hop", json.string(ip_to_string(a.rr_next_hop))),
        #("client_igp_cost_orr", json.int(a.client_igp_cost_orr)),
        #("client_igp_cost_rr", json.int(a.client_igp_cost_rr)),
        #("deflection_avoided", json.bool(a.deflection_avoided)),
        #("cost_saved", json.int(a.cost_saved)),
      ])
    })

  let total_avoided = list.count(audits, fn(a) { a.deflection_avoided })

  json.object([
    #("total_evaluations", json.int(list.length(audits))),
    #("deflections_avoided", json.int(total_avoided)),
    #("results", json.preprocessed_array(audit_objects)),
  ])
  |> json.to_string
}
