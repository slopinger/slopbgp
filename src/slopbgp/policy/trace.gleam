//// BGP Routing Policy Step-By-Step Trace & Inspection Engine
////
//// Provides deterministic, granular tracing of routing policy evaluation:
//// - Evaluates routes through every rule of a PolicyChain
//// - Logs match evaluation (matched/missed) for each rule
//// - Records attribute mutations (LocalPref, MED, NextHop, Communities, AS-Path prepend)
//// - Produces human-readable CLI execution traces and JSON diagnostic reports

import gleam/int
import gleam/json
import gleam/list
import gleam/string
import slopbgp/policy/filter.{apply_action, matches_condition}
import slopbgp/types.{
  type PolicyAction, type PolicyChain, type PolicyRule, type Route, ActionAccept,
  ActionAddCommunity, ActionAddLargeCommunity, ActionPrependAs, ActionReject,
  ActionRemoveCommunity, ActionSetLocalPref, ActionSetMed, ActionSetNextHop,
}

pub type PolicyTraceStep {
  PolicyTraceStep(
    rule_name: String,
    matched: Bool,
    actions_executed: List(String),
    is_terminal: Bool,
  )
}

pub type PolicyTraceResult {
  PolicyTraceResult(
    chain_name: String,
    initial_route: Route,
    final_route: Route,
    accepted: Bool,
    terminal_rule: String,
    steps: List(PolicyTraceStep),
  )
}

/// Trace route evaluation through a PolicyChain step-by-step
pub fn trace_policy(route: Route, chain: PolicyChain) -> PolicyTraceResult {
  trace_rules_loop(
    route,
    route,
    chain.rules,
    chain.default_action,
    chain.name,
    [],
  )
}

fn trace_rules_loop(
  initial_route: Route,
  current_route: Route,
  rules: List(PolicyRule),
  default_action: PolicyAction,
  chain_name: String,
  steps_acc: List(PolicyTraceStep),
) -> PolicyTraceResult {
  case rules {
    [] -> {
      let #(final_route, accepted, _) =
        apply_action(current_route, default_action)
      let default_step =
        PolicyTraceStep(
          rule_name: "[default_action]",
          matched: True,
          actions_executed: [format_action(default_action)],
          is_terminal: True,
        )
      PolicyTraceResult(
        chain_name: chain_name,
        initial_route: initial_route,
        final_route: final_route,
        accepted: accepted,
        terminal_rule: "[default_action]",
        steps: list.reverse([default_step, ..steps_acc]),
      )
    }
    [rule, ..rest_rules] -> {
      let all_matched =
        list.all(rule.matches, fn(m) { matches_condition(current_route, m) })
      case all_matched {
        False -> {
          let step =
            PolicyTraceStep(
              rule_name: rule.name,
              matched: False,
              actions_executed: [],
              is_terminal: False,
            )
          trace_rules_loop(
            initial_route,
            current_route,
            rest_rules,
            default_action,
            chain_name,
            [step, ..steps_acc],
          )
        }
        True -> {
          let #(route_after_actions, accepted, is_term, executed_actions) =
            list.fold(
              rule.actions,
              #(current_route, True, False, []),
              fn(acc, act) {
                let #(r, _acc_accepted, term, acts) = acc
                case term {
                  True -> acc
                  False -> {
                    let #(new_r, act_acc, act_term) = apply_action(r, act)
                    #(new_r, act_acc, act_term, [format_action(act), ..acts])
                  }
                }
              },
            )

          let step =
            PolicyTraceStep(
              rule_name: rule.name,
              matched: True,
              actions_executed: list.reverse(executed_actions),
              is_terminal: is_term,
            )

          case is_term {
            True -> {
              PolicyTraceResult(
                chain_name: chain_name,
                initial_route: initial_route,
                final_route: route_after_actions,
                accepted: accepted,
                terminal_rule: rule.name,
                steps: list.reverse([step, ..steps_acc]),
              )
            }
            False -> {
              trace_rules_loop(
                initial_route,
                route_after_actions,
                rest_rules,
                default_action,
                chain_name,
                [step, ..steps_acc],
              )
            }
          }
        }
      }
    }
  }
}

fn format_action(action: PolicyAction) -> String {
  case action {
    ActionAccept -> "ACCEPT"
    ActionReject -> "REJECT"
    ActionSetLocalPref(lp) -> "SET_LOCAL_PREF(" <> int.to_string(lp) <> ")"
    ActionSetMed(m) -> "SET_MED(" <> int.to_string(m) <> ")"
    ActionSetNextHop(nh) -> "SET_NEXT_HOP(" <> slopbgp_ip_str(nh) <> ")"
    ActionPrependAs(asn, times) ->
      "PREPEND_AS(AS"
      <> int.to_string(asn)
      <> " x"
      <> int.to_string(times)
      <> ")"
    ActionAddCommunity(c) ->
      "ADD_COMMUNITY("
      <> int.to_string(c.asn)
      <> ":"
      <> int.to_string(c.value)
      <> ")"
    ActionAddLargeCommunity(lc) ->
      "ADD_LARGE_COMMUNITY("
      <> int.to_string(lc.global_admin)
      <> ":"
      <> int.to_string(lc.local_data1)
      <> ":"
      <> int.to_string(lc.local_data2)
      <> ")"
    ActionRemoveCommunity(c) ->
      "REMOVE_COMMUNITY("
      <> int.to_string(c.asn)
      <> ":"
      <> int.to_string(c.value)
      <> ")"
  }
}

fn slopbgp_ip_str(addr: types.IpAddress) -> String {
  case addr {
    types.Ipv4(a, b, c, d) ->
      int.to_string(a)
      <> "."
      <> int.to_string(b)
      <> "."
      <> int.to_string(c)
      <> "."
      <> int.to_string(d)
    types.Ipv6(..) -> "IPv6"
  }
}

/// Format a trace result as human-readable CLI output
pub fn format_trace_result(res: PolicyTraceResult) -> String {
  let verdict_badge = case res.accepted {
    True -> "ACCEPTED"
    False -> "REJECTED"
  }

  let step_lines =
    list.map(res.steps, fn(s) {
      case s.matched {
        False -> "  [-] Rule \"" <> s.rule_name <> "\": MISSED"
        True -> {
          let acts = string.join(s.actions_executed, ", ")
          let term_suffix = case s.is_terminal {
            True -> " [TERMINAL]"
            False -> " [CONTINUE]"
          }
          "  [+] Rule \""
          <> s.rule_name
          <> "\": MATCHED -> Actions: "
          <> acts
          <> term_suffix
        }
      }
    })
    |> string.join("\n")

  "┌────────────────────────────────────────────────────────┐\n"
  <> "│ SlopFilter Policy Trace Engine                         │\n"
  <> "├────────────────────────────────────────────────────────┤\n"
  <> "│ Policy Chain:    "
  <> string.pad_end(res.chain_name, 38, " ")
  <> "│\n"
  <> "│ Final Verdict:   "
  <> string.pad_end(verdict_badge, 38, " ")
  <> "│\n"
  <> "│ Terminal Rule:   "
  <> string.pad_end(res.terminal_rule, 38, " ")
  <> "│\n"
  <> "│ Resulting Pref:  "
  <> string.pad_end(int.to_string(res.final_route.local_pref), 38, " ")
  <> "│\n"
  <> "├────────────────────────────────────────────────────────┤\n"
  <> "│ Evaluation Trace:                                      │\n"
  <> step_lines
  <> "\n└────────────────────────────────────────────────────────┘"
}

/// Serialize trace result as JSON
pub fn trace_result_to_json(res: PolicyTraceResult) -> String {
  json.object([
    #("chain_name", json.string(res.chain_name)),
    #("accepted", json.bool(res.accepted)),
    #("terminal_rule", json.string(res.terminal_rule)),
    #("final_local_pref", json.int(res.final_route.local_pref)),
    #(
      "steps",
      json.array(res.steps, fn(s) {
        json.object([
          #("rule", json.string(s.rule_name)),
          #("matched", json.bool(s.matched)),
          #("actions", json.array(s.actions_executed, json.string)),
          #("terminal", json.bool(s.is_terminal)),
        ])
      }),
    ),
  ])
  |> json.to_string
}
