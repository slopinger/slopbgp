//// SlopFilter: High-Performance Expressive BGP Policy & Filtering Pipeline
////
//// Provides a multi-stage routing policy engine with support for prefix sets,
//// AS-Path regular expressions, community wildcards, DN42 latency/region taggers,
//// RFC 6811 RPKI ROA validation matching, RFC 9234 OTC leak drops, and RFC 7999 blackholing.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import slopbgp/bgp/rfc9234.{get_otc}
import slopbgp/dn42/filter.{is_valid_dn42_network}
import slopbgp/filter/hygiene.{type RouteHygieneConfig, validate_route_hygiene}
import slopbgp/ip.{is_prefix_contained}
import slopbgp/types.{
  type AsPathSegment, type Community, type IpAddress, type IpPrefix,
  type LargeCommunity, type RoaStatus, type Route, AsConfedSequence, AsConfedSet,
  AsSequence, AsSet, Community, Ipv4, Route,
}

pub type ComparisonOp {
  CmpEq
  CmpGt
  CmpLt
  CmpGte
  CmpLte
}

pub type PrefixSetMode {
  PrefixExact
  PrefixLonger
  PrefixOrLonger(max_len: Int)
}

pub type FilterMatch {
  MatchAny
  MatchPrefix(prefix: IpPrefix, mode: PrefixSetMode)
  MatchPrefixSet(prefixes: List(IpPrefix), mode: PrefixSetMode)
  MatchAsPathOrigin(asn: Int)
  MatchAsPathContains(asn: Int)
  MatchAsPathRegex(pattern: String)
  MatchAsLength(min: Int, max: Int)
  MatchCommunity(comm: Community)
  MatchCommunityWildcard(asn: Int)
  MatchLargeCommunity(lcomm: LargeCommunity)
  MatchLargeCommunityWildcard(global_admin: Int)
  MatchRoa(status: RoaStatus)
  MatchMed(op: ComparisonOp, value: Int)
  MatchLocalPref(op: ComparisonOp, value: Int)
  MatchDn42Bogon
  MatchDn42Latency(max_ms: Int)
  MatchDn42Region(region_code: Int)
  MatchOtcLeak(ingress_as: Int)
  MatchHygieneViolation(config: RouteHygieneConfig)
}

pub type FilterAction {
  ActionAccept
  ActionReject(reason: String)
  ActionNextRule
  ActionEnforceHygiene(config: RouteHygieneConfig)
  ActionSetLocalPref(Int)
  ActionAddLocalPref(Int)
  ActionSubLocalPref(Int)
  ActionSetMed(Int)
  ActionStripMed
  ActionPrependAs(asn: Int, times: Int)
  ActionAddCommunity(Community)
  ActionRemoveCommunity(Community)
  ActionAddLargeCommunity(LargeCommunity)
  ActionRemoveLargeCommunity(LargeCommunity)
  ActionSetNextHop(IpAddress)
  ActionSetNextHopSelf(local_ip: IpAddress)
  ActionSetOtc(Int)
  ActionStripPrivateAs
  ActionDn42TagLatency(ms: Int)
  ActionDn42TagBandwidth(mbps: Int)
  ActionDn42TagCrypto(crypto_code: Int)
  ActionBlackhole
}

pub type FilterRule {
  FilterRule(
    name: String,
    matches: List(FilterMatch),
    actions: List(FilterAction),
  )
}

pub type FilterPipeline {
  FilterPipeline(
    name: String,
    rules: List(FilterRule),
    default_action: FilterAction,
  )
}

pub type FilterResult {
  FilterResult(
    route: Route,
    accepted: Bool,
    rejection_reason: Option(String),
    applied_rules: List(String),
  )
}

/// Evaluate a single filter match condition against a route
pub fn matches_condition(route: Route, match_cond: FilterMatch) -> Bool {
  case match_cond {
    MatchAny -> True

    MatchPrefix(pfx, mode) -> match_prefix_mode(route.prefix, pfx, mode)

    MatchPrefixSet(prefixes, mode) ->
      list.any(prefixes, fn(pfx) { match_prefix_mode(route.prefix, pfx, mode) })

    MatchAsPathOrigin(target_asn) ->
      case list.last(route.as_path) {
        Ok(AsSequence(asns)) ->
          case list.last(asns) {
            Ok(last_as) -> last_as == target_asn
            Error(_) -> False
          }
        _ -> False
      }

    MatchAsPathContains(target_asn) ->
      list.any(route.as_path, fn(seg) {
        case seg {
          AsSequence(asns) | AsSet(asns) -> list.contains(asns, target_asn)
          AsConfedSequence(asns) | AsConfedSet(asns) ->
            list.contains(asns, target_asn)
        }
      })

    MatchAsPathRegex(pattern) -> match_as_path_regex(route.as_path, pattern)

    MatchAsLength(min_hops, max_hops) -> {
      let len = as_path_length(route.as_path)
      len >= min_hops && len <= max_hops
    }

    MatchCommunity(c) ->
      list.any(route.communities, fn(comm) {
        comm.asn == c.asn && comm.value == c.value
      })

    MatchCommunityWildcard(target_asn) ->
      list.any(route.communities, fn(comm) { comm.asn == target_asn })

    MatchLargeCommunity(lc) ->
      list.any(route.large_communities, fn(l) {
        l.global_admin == lc.global_admin
        && l.local_data1 == lc.local_data1
        && l.local_data2 == lc.local_data2
      })

    MatchLargeCommunityWildcard(admin) ->
      list.any(route.large_communities, fn(l) { l.global_admin == admin })

    MatchRoa(expected) -> route.roa_status == expected

    MatchMed(op, target) -> compare_int(op, route.med, target)

    MatchLocalPref(op, target) -> compare_int(op, route.local_pref, target)

    MatchDn42Bogon -> !is_valid_dn42_network(route.prefix)

    MatchDn42Latency(max_ms) ->
      case get_dn42_latency(route) {
        Some(lat) -> lat <= max_ms
        None -> False
      }

    MatchDn42Region(code) ->
      list.any(route.communities, fn(c) { c.asn == 64_511 && c.value == code })

    MatchOtcLeak(ingress_as) ->
      case get_otc(route) {
        Some(otc_as) -> otc_as != ingress_as
        None -> False
      }

    MatchHygieneViolation(cfg) ->
      case validate_route_hygiene(route, cfg, None) {
        Ok(_) -> False
        Error(_) -> True
      }
  }
}

fn match_prefix_mode(
  route_pfx: IpPrefix,
  target_pfx: IpPrefix,
  mode: PrefixSetMode,
) -> Bool {
  let is_contained = is_prefix_contained(route_pfx, target_pfx)
  case mode {
    PrefixExact -> is_contained && route_pfx.length == target_pfx.length
    PrefixLonger -> is_contained && route_pfx.length > target_pfx.length
    PrefixOrLonger(max_len) ->
      is_contained
      && route_pfx.length >= target_pfx.length
      && route_pfx.length <= max_len
  }
}

fn as_path_length(as_path: List(AsPathSegment)) -> Int {
  list.fold(as_path, 0, fn(acc, seg) {
    case seg {
      AsSequence(asns) -> acc + list.length(asns)
      AsSet(_) -> acc + 1
      AsConfedSequence(_) | AsConfedSet(_) -> acc
    }
  })
}

fn match_as_path_regex(as_path: List(AsPathSegment), pattern: String) -> Bool {
  let as_str =
    list.map(as_path, fn(seg) {
      case seg {
        AsSequence(asns) ->
          list.map(asns, int.to_string)
          |> string.join(" ")
        AsSet(asns) ->
          "{"
          <> {
            list.map(asns, int.to_string)
            |> string.join(",")
          }
          <> "}"
        _ -> ""
      }
    })
    |> string.join(" ")

  case string.starts_with(pattern, "^"), string.ends_with(pattern, "$") {
    True, True -> {
      let core =
        string.drop_start(pattern, 1)
        |> string.drop_end(1)
      as_str == core
    }
    True, False -> {
      let pfx = string.drop_start(pattern, 1)
      string.starts_with(as_str, pfx)
    }
    False, True -> {
      let sfx = string.drop_end(pattern, 1)
      string.ends_with(as_str, sfx)
    }
    False, False -> string.contains(as_str, pattern)
  }
}

fn compare_int(op: ComparisonOp, a: Int, b: Int) -> Bool {
  case op {
    CmpEq -> a == b
    CmpGt -> a > b
    CmpLt -> a < b
    CmpGte -> a >= b
    CmpLte -> a <= b
  }
}

fn get_dn42_latency(route: Route) -> Option(Int) {
  list.find_map(route.communities, fn(c) {
    case c.asn == 64_511 && c.value >= 1000 && c.value <= 1999 {
      True -> Ok(c.value - 1000)
      False -> Error(Nil)
    }
  })
  |> option.from_result
}

/// Execute a complete filter pipeline on a route
pub fn execute_pipeline(
  pipeline: FilterPipeline,
  initial_route: Route,
) -> FilterResult {
  execute_rules_loop(pipeline.rules, initial_route, pipeline.default_action, [])
}

fn execute_rules_loop(
  rules: List(FilterRule),
  current_route: Route,
  default_action: FilterAction,
  applied: List(String),
) -> FilterResult {
  case rules {
    [] -> {
      let #(final_route, accepted, reason) =
        apply_final_action(current_route, default_action)
      FilterResult(
        route: final_route,
        accepted: accepted,
        rejection_reason: reason,
        applied_rules: list.reverse(applied),
      )
    }
    [rule, ..rest_rules] -> {
      let all_matched =
        list.all(rule.matches, fn(m) { matches_condition(current_route, m) })
      case all_matched {
        False ->
          execute_rules_loop(rest_rules, current_route, default_action, applied)
        True -> {
          let updated_applied = [rule.name, ..applied]
          let #(new_route, terminal_decision) =
            apply_actions(current_route, rule.actions)

          case terminal_decision {
            Some(#(accepted, reason)) ->
              FilterResult(
                route: new_route,
                accepted: accepted,
                rejection_reason: reason,
                applied_rules: list.reverse(updated_applied),
              )
            None ->
              execute_rules_loop(
                rest_rules,
                new_route,
                default_action,
                updated_applied,
              )
          }
        }
      }
    }
  }
}

fn apply_actions(
  route: Route,
  actions: List(FilterAction),
) -> #(Route, Option(#(Bool, Option(String)))) {
  list.fold(actions, #(route, None), fn(acc, action) {
    let #(rt, term) = acc
    case term {
      Some(_) -> acc
      None ->
        case action {
          ActionAccept -> #(rt, Some(#(True, None)))
          ActionReject(reason) -> #(rt, Some(#(False, Some(reason))))
          ActionNextRule -> #(rt, None)
          ActionEnforceHygiene(cfg) ->
            case validate_route_hygiene(rt, cfg, None) {
              Ok(clean_rt) -> #(clean_rt, None)
              Error(err) -> #(rt, Some(#(False, Some(err))))
            }
          ActionSetLocalPref(lp) -> #(Route(..rt, local_pref: lp), None)
          ActionAddLocalPref(delta) -> #(
            Route(..rt, local_pref: rt.local_pref + delta),
            None,
          )
          ActionSubLocalPref(delta) -> #(
            Route(..rt, local_pref: rt.local_pref - delta),
            None,
          )
          ActionSetMed(m) -> #(Route(..rt, med: m), None)
          ActionStripMed -> #(Route(..rt, med: 0), None)
          ActionPrependAs(asn, times) -> {
            let prepends = list.repeat(asn, times)
            let new_path = case rt.as_path {
              [AsSequence(asns), ..rest] -> [
                AsSequence(list.append(prepends, asns)),
                ..rest
              ]
              other -> [AsSequence(prepends), ..other]
            }
            #(Route(..rt, as_path: new_path), None)
          }
          ActionAddCommunity(comm) -> {
            let new_comms = [
              comm,
              ..list.filter(rt.communities, fn(c) {
                c.asn != comm.asn || c.value != comm.value
              })
            ]
            #(Route(..rt, communities: new_comms), None)
          }
          ActionRemoveCommunity(comm) -> {
            let new_comms =
              list.filter(rt.communities, fn(c) {
                c.asn != comm.asn || c.value != comm.value
              })
            #(Route(..rt, communities: new_comms), None)
          }
          ActionAddLargeCommunity(lcomm) -> {
            let new_lcomms = [lcomm, ..rt.large_communities]
            #(Route(..rt, large_communities: new_lcomms), None)
          }
          ActionRemoveLargeCommunity(lcomm) -> {
            let new_lcomms =
              list.filter(rt.large_communities, fn(l) {
                l.global_admin != lcomm.global_admin
                || l.local_data1 != lcomm.local_data1
                || l.local_data2 != lcomm.local_data2
              })
            #(Route(..rt, large_communities: new_lcomms), None)
          }
          ActionSetNextHop(nh) -> #(Route(..rt, next_hop: nh), None)
          ActionSetNextHopSelf(local_ip) -> #(
            Route(..rt, next_hop: local_ip),
            None,
          )
          ActionSetOtc(asn) -> #(Route(..rt, otc: Some(asn)), None)
          ActionStripPrivateAs -> {
            let stripped_path =
              list.map(rt.as_path, fn(seg) {
                case seg {
                  AsSequence(asns) ->
                    AsSequence(
                      list.filter(asns, fn(asn) { !is_private_asn(asn) }),
                    )
                  other -> other
                }
              })
            #(Route(..rt, as_path: stripped_path), None)
          }
          ActionDn42TagLatency(ms) -> {
            let lat_comm = Community(asn: 64_511, value: 1000 + ms)
            let new_comms = [
              lat_comm,
              ..list.filter(rt.communities, fn(c) {
                c.asn != 64_511 || c.value < 1000 || c.value > 1999
              })
            ]
            #(Route(..rt, communities: new_comms), None)
          }
          ActionDn42TagBandwidth(mbps) -> {
            let tier = case mbps {
              _ if mbps < 10 -> 21
              _ if mbps < 100 -> 24
              _ if mbps < 1000 -> 27
              _ -> 28
            }
            let bw_comm = Community(asn: 64_511, value: tier)
            let new_comms = [
              bw_comm,
              ..list.filter(rt.communities, fn(c) {
                c.asn != 64_511 || c.value < 21 || c.value > 29
              })
            ]
            #(Route(..rt, communities: new_comms), None)
          }
          ActionDn42TagCrypto(crypto_code) -> {
            let crypto_comm = Community(asn: 64_511, value: crypto_code)
            let new_comms = [crypto_comm, ..rt.communities]
            #(Route(..rt, communities: new_comms), None)
          }
          ActionBlackhole -> {
            let bh_comm = Community(asn: 65_535, value: 666)
            let new_comms = [bh_comm, ..rt.communities]
            #(
              Route(..rt, communities: new_comms, next_hop: Ipv4(192, 0, 2, 1)),
              None,
            )
          }
        }
    }
  })
}

fn apply_final_action(
  route: Route,
  action: FilterAction,
) -> #(Route, Bool, Option(String)) {
  case action {
    ActionAccept -> #(route, True, None)
    ActionReject(reason) -> #(route, False, Some(reason))
    _ -> #(route, True, None)
  }
}

fn is_private_asn(asn: Int) -> Bool {
  // 16-bit private: 64512..65534 (excluding DN42 64511)
  // 32-bit private: 4200000000..4294967294 (excluding DN42 4242420000..4242429999)
  case asn {
    _ if asn >= 64_512 && asn <= 65_534 -> True
    _
      if asn >= 4_200_000_000
      && asn <= 4_294_967_294
      && { asn < 4_242_420_000 || asn > 4_242_429_999 }
    -> True
    _ -> False
  }
}
