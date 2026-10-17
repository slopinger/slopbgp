//// RFC 7938 BGP Equal-Cost Multi-Path (ECMP) & Weighted ECMP (UCMP) Engine
////
//// Modern datacenter fabrics (RFC 7938 CLOS networks) and multi-homed carrier
//// transit connections require multipath route distribution. When multiple
//// paths have equivalent high-level BGP metrics (ROA validity, LocalPref,
//// AS-Path length, Origin, and MED), instead of picking a single path,
//// the router provisions all equal-cost next-hops into the kernel FIB.
////
//// Additionally supports draft-ietf-idr-link-bandwidth / DN42 bandwidth tags
//// for Unequal-Cost Multi-Path (UCMP) proportional load balancing.

import gleam/dict.{type Dict}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order.{type Order, Gt, Lt}
import gleam/string
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/rib/rib.{as_path_length}
import slopbgp/types.{type IpAddress, type IpPrefix, type Route, ExtCommunity}

pub type MultipathNextHop {
  MultipathNextHop(
    next_hop: IpAddress,
    weight: Int,
    peer_id: String,
    interface: Option(String),
  )
}

pub type MultipathRoute {
  MultipathRoute(
    prefix: IpPrefix,
    best_route: Route,
    ecmp_eligible: List(Route),
    multipath_next_hops: List(MultipathNextHop),
    is_ecmp: Bool,
    is_weighted: Bool,
    total_weight: Int,
  )
}

/// Evaluates a collection of candidate routes for a prefix and computes
/// the ECMP / UCMP multipath resolution up to max_paths.
pub fn select_multipath(
  routes: List(Route),
  max_paths: Int,
) -> Option(MultipathRoute) {
  case routes {
    [] -> None
    _ -> {
      // Sort routes using the standard 10-stage BGP tie breaker
      let sorted =
        list.sort(routes, fn(a, b) {
          case rib.compare_routes(a, b) {
            True -> order_lt()
            False -> order_gt()
          }
        })

      case sorted {
        [] -> None
        [best, ..others] -> {
          // Identify all routes that match ECMP criteria with the best route
          let eligible_others =
            list.filter(others, fn(candidate) {
              is_ecmp_compatible(best, candidate)
            })

          let all_eligible = [best, ..eligible_others]

          // Extract next-hops and weights, deduplicating by IP
          let nh_map: Dict(String, MultipathNextHop) =
            list.fold(all_eligible, dict.new(), fn(acc, r) {
              let ip_str = ip_to_string(r.next_hop)
              case dict.has_key(acc, ip_str) {
                True -> acc
                False -> {
                  let weight = extract_route_weight(r)
                  let hop =
                    MultipathNextHop(
                      next_hop: r.next_hop,
                      weight: weight,
                      peer_id: r.peer_id,
                      interface: None,
                    )
                  dict.insert(acc, ip_str, hop)
                }
              }
            })

          let all_hops =
            dict.values(nh_map)
            |> list.take(int.max(1, max_paths))

          let total_wt =
            list.fold(all_hops, 0, fn(acc, hop) { acc + hop.weight })
          let is_multi = list.length(all_hops) > 1
          let has_variance =
            list.any(all_hops, fn(h) {
              case all_hops {
                [first, ..] -> h.weight != first.weight
                [] -> False
              }
            })

          Some(MultipathRoute(
            prefix: best.prefix,
            best_route: best,
            ecmp_eligible: all_eligible,
            multipath_next_hops: all_hops,
            is_ecmp: is_multi,
            is_weighted: has_variance,
            total_weight: total_wt,
          ))
        }
      }
    }
  }
}

/// Checks whether candidate route meets RFC 7938 ECMP equivalence requirements:
/// 1. Same RPKI ROA validation status
/// 2. Same Local Preference
/// 3. Same AS-Path hop count
/// 4. Same Origin attribute (IGP, EGP, Incomplete)
/// 5. Same Multi-Exit Discriminator (MED)
pub fn is_ecmp_compatible(best: Route, candidate: Route) -> Bool {
  let roa_match = best.roa_status == candidate.roa_status
  let pref_match = best.local_pref == candidate.local_pref
  let as_len_match =
    as_path_length(best.as_path) == as_path_length(candidate.as_path)
  let origin_match = best.origin == candidate.origin
  let med_match = best.med == candidate.med

  roa_match && pref_match && as_len_match && origin_match && med_match
}

/// Extracts route weight for Unequal-Cost Multipath (UCMP).
/// Checks for RFC Link Bandwidth extended community (0x40 0x04)
/// or DN42 bandwidth community (64511:21..29)
pub fn extract_route_weight(route: Route) -> Int {
  // Check DN42 bandwidth communities first: 64511:21 (1 Mbps) .. 64511:29 (10 Gbps)
  let dn42_weight =
    list.find_map(route.communities, fn(comm) {
      case comm.asn == 64_511 {
        True ->
          case comm.value {
            21 -> Ok(1)
            22 -> Ok(2)
            23 -> Ok(5)
            24 -> Ok(10)
            25 -> Ok(20)
            26 -> Ok(50)
            27 -> Ok(100)
            28 -> Ok(500)
            29 -> Ok(1000)
            _ -> Error(Nil)
          }
        False -> Error(Nil)
      }
    })

  case dn42_weight {
    Ok(w) -> w
    Error(_) -> {
      // Check RFC draft-ietf-idr-link-bandwidth (Transitive Two-Octet AS 0x40, Sub-type 0x04)
      let ext_weight =
        list.find_map(route.ext_communities, fn(ext) {
          case ext {
            ExtCommunity(0x40, 0x04, bytes) -> {
              case bytes {
                <<_asn:16, bw_bytes:32>> -> {
                  // Normalize bandwidth (bytes/sec) to relative weight (1..100)
                  let mbps = bw_bytes / 125_000
                  Ok(int.max(1, mbps / 10))
                }
                _ -> Error(Nil)
              }
            }
            _ -> Error(Nil)
          }
        })

      case ext_weight {
        Ok(w) -> w
        Error(_) -> 1
      }
    }
  }
}

/// Generates a Linux kernel iproute2 command for programming multipath FIB
pub fn format_iproute2_command(mp: MultipathRoute) -> String {
  let pfx_str = prefix_to_string(mp.prefix)
  case mp.multipath_next_hops {
    [] -> "ip route replace " <> pfx_str <> " unreachable"
    [single] ->
      "ip route replace " <> pfx_str <> " via " <> ip_to_string(single.next_hop)
    hops -> {
      let hops_str =
        list.map(hops, fn(h) {
          "nexthop via "
          <> ip_to_string(h.next_hop)
          <> " weight "
          <> int.to_string(h.weight)
        })
        |> string.join(" ")
      "ip route replace " <> pfx_str <> " " <> hops_str
    }
  }
}

/// Formats human-readable CLI report for operator inspection
pub fn format_multipath_report(mp: MultipathRoute) -> String {
  let pfx_str = prefix_to_string(mp.prefix)
  let mode_str = case mp.is_ecmp, mp.is_weighted {
    True, True -> "UCMP (Unequal-Cost Weighted Multi-Path)"
    True, False -> "ECMP (Equal-Cost Multi-Path)"
    False, _ -> "SINGLE_PATH (Non-Multipath)"
  }

  let lines = [
    "┌────────────────────────────────────────────────────────┐",
    "│ slopbgp BGP Multipath & ECMP FIB Resolution            │",
    "├────────────────────────────────────────────────────────┤",
    "│ Prefix:            " <> string.pad_end(pfx_str, 36, " ") <> "│",
    "│ Multi-Path Mode:   " <> string.pad_end(mode_str, 36, " ") <> "│",
    "│ Active Paths:      "
      <> string.pad_end(
      int.to_string(list.length(mp.multipath_next_hops)) <> " next-hops",
      36,
      " ",
    )
      <> "│",
    "│ Total Weight:      "
      <> string.pad_end(int.to_string(mp.total_weight), 36, " ")
      <> "│",
    "├────────────────────────────────────────────────────────┤",
    "│ Multipath Next-Hop Members:                            │",
  ]

  let hop_lines =
    list.map(mp.multipath_next_hops, fn(h) {
      let ratio = case mp.total_weight > 0 {
        True -> int.to_string(h.weight * 100 / mp.total_weight) <> "%"
        False -> "100%"
      }
      "  ● Next-Hop: "
      <> string.pad_end(ip_to_string(h.next_hop), 18, " ")
      <> " [Weight: "
      <> string.pad_end(int.to_string(h.weight), 4, " ")
      <> " / "
      <> string.pad_end(ratio, 4, " ")
      <> "] Peer: "
      <> h.peer_id
    })

  let cmd_lines = [
    "├────────────────────────────────────────────────────────┤",
    "│ Kernel FIB Programming Command:                        │",
    "  # " <> format_iproute2_command(mp),
    "└────────────────────────────────────────────────────────┘",
  ]

  string.join(list.flatten([lines, hop_lines, cmd_lines]), "\n")
}

/// JSON serialization for REST API and web dashboard
pub fn multipath_to_json(mp: MultipathRoute) -> String {
  json.object([
    #("prefix", json.string(prefix_to_string(mp.prefix))),
    #("is_ecmp", json.bool(mp.is_ecmp)),
    #("is_weighted", json.bool(mp.is_weighted)),
    #("total_weight", json.int(mp.total_weight)),
    #(
      "next_hops",
      json.array(mp.multipath_next_hops, fn(h) {
        json.object([
          #("next_hop", json.string(ip_to_string(h.next_hop))),
          #("weight", json.int(h.weight)),
          #("peer_id", json.string(h.peer_id)),
        ])
      }),
    ),
    #("fib_command", json.string(format_iproute2_command(mp))),
  ])
  |> json.to_string
}

fn order_lt() -> Order {
  Lt
}

fn order_gt() -> Order {
  Gt
}
