import gleam/list
import slopbgp/bgp/graceful_shutdown.{has_graceful_shutdown}
import slopbgp/dn42/filter.{is_valid_dn42_network}
import slopbgp/ip.{is_prefix_contained}
import slopbgp/types.{
  type PolicyAction, type PolicyChain, type PolicyMatch, type PolicyRule,
  type Route, ActionAccept, ActionAddCommunity, ActionAddLargeCommunity,
  ActionPrependAs, ActionReject, ActionRemoveCommunity, ActionSetLocalPref,
  ActionSetMed, ActionSetNextHop, AsConfedSequence, AsConfedSet, AsSequence,
  AsSet, MatchAny, MatchAsLength, MatchAsPathContains, MatchAsPathOrigin,
  MatchCommunity, MatchLargeCommunity, MatchPrefix, MatchRoa, PolicyChain,
  PolicyRule, RoaInvalid, Route,
}

/// Check if a single rule match condition matches a route
pub fn matches_condition(route: Route, match_cond: PolicyMatch) -> Bool {
  case match_cond {
    MatchAny -> True
    MatchPrefix(pfx, min_len, max_len) -> {
      let is_in = is_prefix_contained(route.prefix, pfx)
      is_in && route.prefix.length >= min_len && route.prefix.length <= max_len
    }
    MatchAsPathContains(target_asn) -> {
      list.any(route.as_path, fn(seg) {
        case seg {
          AsSequence(asns) -> list.contains(asns, target_asn)
          AsSet(asns) -> list.contains(asns, target_asn)
          AsConfedSequence(asns) -> list.contains(asns, target_asn)
          AsConfedSet(asns) -> list.contains(asns, target_asn)
        }
      })
    }
    MatchAsPathOrigin(target_asn) -> {
      case list.last(route.as_path) {
        Ok(AsSequence(asns)) -> {
          case list.last(asns) {
            Ok(last_as) -> last_as == target_asn
            Error(_) -> False
          }
        }
        _ -> False
      }
    }
    MatchAsLength(max_length) -> {
      let total_len =
        list.fold(route.as_path, 0, fn(acc, seg) {
          case seg {
            AsSequence(asns) -> acc + list.length(asns)
            AsSet(_) -> acc + 1
            AsConfedSequence(_) -> acc
            AsConfedSet(_) -> acc
          }
        })
      total_len <= max_length
    }
    MatchCommunity(target_comm) -> {
      list.any(route.communities, fn(c) {
        c.asn == target_comm.asn && c.value == target_comm.value
      })
    }
    MatchLargeCommunity(target_lcomm) -> {
      list.any(route.large_communities, fn(lc) {
        lc.global_admin == target_lcomm.global_admin
        && lc.local_data1 == target_lcomm.local_data1
        && lc.local_data2 == target_lcomm.local_data2
      })
    }
    MatchRoa(expected_status) -> route.roa_status == expected_status
  }
}

/// Apply an action to a route, returning whether execution should stop (terminal action)
pub fn apply_action(
  route: Route,
  action: PolicyAction,
) -> #(Route, Bool, Bool) {
  // Returns #(updated_route, is_accepted, is_terminal)
  case action {
    ActionAccept -> #(route, True, True)
    ActionReject -> #(route, False, True)
    ActionSetLocalPref(lp) -> #(Route(..route, local_pref: lp), True, False)
    ActionSetMed(m) -> #(Route(..route, med: m), True, False)
    ActionSetNextHop(nh) -> #(Route(..route, next_hop: nh), True, False)
    ActionPrependAs(asn, times) -> {
      let prepends = list.repeat(asn, times)
      let new_path = case route.as_path {
        [AsSequence(asns), ..rest] -> [
          AsSequence(list.append(prepends, asns)),
          ..rest
        ]
        other -> [AsSequence(prepends), ..other]
      }
      #(Route(..route, as_path: new_path), True, False)
    }
    ActionAddCommunity(comm) -> {
      #(Route(..route, communities: [comm, ..route.communities]), True, False)
    }
    ActionAddLargeCommunity(lcomm) -> {
      #(
        Route(..route, large_communities: [lcomm, ..route.large_communities]),
        True,
        False,
      )
    }
    ActionRemoveCommunity(comm) -> {
      let filtered =
        list.filter(route.communities, fn(c) {
          !{ c.asn == comm.asn && c.value == comm.value }
        })
      #(Route(..route, communities: filtered), True, False)
    }
  }
}

/// Evaluate a full policy chain against a route
pub fn evaluate_chain(route: Route, chain: PolicyChain) -> #(Bool, Route) {
  evaluate_rules_loop(route, chain.rules, chain.default_action)
}

fn evaluate_rules_loop(
  current_route: Route,
  rules: List(PolicyRule),
  default_action: PolicyAction,
) -> #(Bool, Route) {
  case rules {
    [] -> {
      let #(final_route, accepted, _) =
        apply_action(current_route, default_action)
      #(accepted, final_route)
    }
    [rule, ..rest_rules] -> {
      let all_matched =
        list.all(rule.matches, fn(m) { matches_condition(current_route, m) })
      case all_matched {
        False -> evaluate_rules_loop(current_route, rest_rules, default_action)
        True -> {
          // Execute all actions in the matched rule
          let #(route_after_actions, accepted, is_term) =
            list.fold(rule.actions, #(current_route, True, False), fn(acc, act) {
              let #(r, _acc_accepted, term) = acc
              case term {
                True -> acc
                False -> {
                  let #(new_r, act_acc, act_term) = apply_action(r, act)
                  #(new_r, act_acc, act_term)
                }
              }
            })

          case is_term {
            True -> #(accepted, route_after_actions)
            False ->
              evaluate_rules_loop(
                route_after_actions,
                rest_rules,
                default_action,
              )
          }
        }
      }
    }
  }
}

/// Standard DN42 Ingress Policy:
/// 1. Reject invalid DN42 prefix ranges (bogons, martians)
/// 2. Reject ROA invalid routes (RFC 6811 origin validation)
/// 3. RFC 8326 Graceful Shutdown: if peer sent GRACEFUL_SHUTDOWN community, drop local_pref to 0
/// 4. Accept with default local_pref
pub fn dn42_default_import_policy() -> PolicyChain {
  PolicyChain(name: "dn42_default_import", default_action: ActionAccept, rules: [
    PolicyRule(
      name: "reject_roa_invalid",
      matches: [MatchRoa(RoaInvalid)],
      actions: [ActionReject],
    ),
  ])
}

/// Pre-filtering step verifying DN42 prefix legitimacy and graceful shutdown before insertion
pub fn filter_inbound_route(
  route: Route,
  chain: PolicyChain,
) -> Result(Route, String) {
  // Check DN42 address boundaries
  case is_valid_dn42_network(route.prefix) {
    False -> Error("Rejected: Prefix outside DN42 boundaries (bogon/martian)")
    True -> {
      // Evaluate policy chain
      let #(accepted, processed_route) = evaluate_chain(route, chain)
      case accepted {
        False -> Error("Rejected by import policy")
        True -> {
          // RFC 8326 Graceful Shutdown check: depress local_pref if community present
          case has_graceful_shutdown(processed_route) {
            True -> Ok(Route(..processed_route, local_pref: 0))
            False -> Ok(processed_route)
          }
        }
      }
    }
  }
}
