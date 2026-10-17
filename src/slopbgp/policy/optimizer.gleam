//// BGP Routing Policy Static Analysis & Optimization Engine
////
//// Analyzes, audits, and optimizes complex BGP routing policy chains:
//// - Detects shadowed / unreachable rules (e.g., following an unconditional terminal rule)
//// - Detects redundant / duplicate rules
//// - Identifies empty rules with no operations
//// - Computes policy complexity and rule execution efficiency
//// - Generates an optimized, pruned PolicyChain

import gleam/int
import gleam/json
import gleam/list
import gleam/string
import slopbgp/types.{
  type PolicyChain, type PolicyRule, ActionAccept, ActionReject, MatchAny,
  PolicyChain,
}

pub type PolicyIssue {
  IssueShadowedRule(rule_name: String, shadowed_by: String)
  IssueDuplicateRule(rule_name: String, duplicate_of: String)
  IssueEmptyRule(rule_name: String)
  IssueRedundantMatch(rule_name: String, match_desc: String)
}

pub type PolicyAuditReport {
  PolicyAuditReport(
    chain_name: String,
    total_rules_original: Int,
    total_rules_optimized: Int,
    complexity_score: Int,
    issues: List(PolicyIssue),
    recommendations: List(String),
    optimized_chain: PolicyChain,
  )
}

/// Audit and optimize a PolicyChain
pub fn audit_and_optimize(chain: PolicyChain) -> PolicyAuditReport {
  let #(cleaned_rules, issues, recs) =
    scan_rules(chain.rules, False, "", [], [], [])

  let complexity =
    list.fold(chain.rules, 0, fn(acc, r) {
      acc + 2 + list.length(r.matches) + list.length(r.actions)
    })

  let opt_chain = PolicyChain(..chain, rules: cleaned_rules)

  PolicyAuditReport(
    chain_name: chain.name,
    total_rules_original: list.length(chain.rules),
    total_rules_optimized: list.length(cleaned_rules),
    complexity_score: complexity,
    issues: issues,
    recommendations: recs,
    optimized_chain: opt_chain,
  )
}

fn scan_rules(
  rules: List(PolicyRule),
  seen_unconditional_term: Bool,
  unconditional_term_name: String,
  seen_rules_acc: List(PolicyRule),
  issues_acc: List(PolicyIssue),
  recs_acc: List(String),
) -> #(List(PolicyRule), List(PolicyIssue), List(String)) {
  case rules {
    [] -> #(
      list.reverse(seen_rules_acc),
      list.reverse(issues_acc),
      list.reverse(recs_acc),
    )
    [r, ..rest] -> {
      // 1. Check if already shadowed by previous unconditional terminal
      case seen_unconditional_term {
        True -> {
          let issue = IssueShadowedRule(r.name, unconditional_term_name)
          let rec =
            "Pruned shadowed rule \""
            <> r.name
            <> "\" which was unreachable due to preceding terminal rule \""
            <> unconditional_term_name
            <> "\""
          scan_rules(
            rest,
            seen_unconditional_term,
            unconditional_term_name,
            seen_rules_acc,
            [issue, ..issues_acc],
            [rec, ..recs_acc],
          )
        }
        False -> {
          // 2. Check if rule is empty
          case r.actions == [] {
            True -> {
              let issue = IssueEmptyRule(r.name)
              let rec =
                "Pruned empty rule \""
                <> r.name
                <> "\" with no actions configured"
              scan_rules(
                rest,
                seen_unconditional_term,
                unconditional_term_name,
                seen_rules_acc,
                [issue, ..issues_acc],
                [rec, ..recs_acc],
              )
            }
            False -> {
              // 3. Check for duplicates
              let is_dup =
                list.any(seen_rules_acc, fn(seen) {
                  seen.matches == r.matches && seen.actions == r.actions
                })
              case is_dup {
                True -> {
                  let issue =
                    IssueDuplicateRule(
                      r.name,
                      "earlier rule with identical matches/actions",
                    )
                  let rec =
                    "Pruned redundant duplicate rule \"" <> r.name <> "\""
                  scan_rules(
                    rest,
                    seen_unconditional_term,
                    unconditional_term_name,
                    seen_rules_acc,
                    [issue, ..issues_acc],
                    [rec, ..recs_acc],
                  )
                }
                False -> {
                  // 4. Check if this rule is unconditional and terminal
                  let is_uncond = r.matches == [] || r.matches == [MatchAny]
                  let has_term =
                    list.any(r.actions, fn(a) {
                      a == ActionAccept || a == ActionReject
                    })

                  case is_uncond && has_term {
                    True -> {
                      scan_rules(
                        rest,
                        True,
                        r.name,
                        [r, ..seen_rules_acc],
                        issues_acc,
                        recs_acc,
                      )
                    }
                    False -> {
                      scan_rules(
                        rest,
                        False,
                        "",
                        [r, ..seen_rules_acc],
                        issues_acc,
                        recs_acc,
                      )
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

/// Format the audit report for CLI output
pub fn format_audit_report(report: PolicyAuditReport) -> String {
  let issue_lines = case report.issues {
    [] -> "  None (Policy chain is optimal with 0 shadowed/redundant rules)"
    issues ->
      list.map(issues, fn(iss) {
        case iss {
          IssueShadowedRule(r, by) ->
            "  [!] Shadowed Rule: \""
            <> r
            <> "\" is unreachable (shadowed by \""
            <> by
            <> "\")"
          IssueDuplicateRule(r, of) ->
            "  [!] Duplicate Rule: \"" <> r <> "\" (identical to " <> of <> ")"
          IssueEmptyRule(r) ->
            "  [!] Empty Rule: \"" <> r <> "\" performs no action"
          IssueRedundantMatch(r, m) ->
            "  [!] Redundant Match in \"" <> r <> "\": " <> m
        }
      })
      |> string.join("\n")
  }

  let rec_lines = case report.recommendations {
    [] -> "  * Policy is already production-ready and lean."
    recs -> list.map(recs, fn(r) { "  * " <> r }) |> string.join("\n")
  }

  "┌────────────────────────────────────────────────────────┐\n"
  <> "│ SlopFilter Static Policy Optimizer & Audit Report      │\n"
  <> "├────────────────────────────────────────────────────────┤\n"
  <> "│ Policy Chain:      "
  <> string.pad_end(report.chain_name, 36, " ")
  <> "│\n"
  <> "│ Original Rules:    "
  <> string.pad_end(int.to_string(report.total_rules_original), 36, " ")
  <> "│\n"
  <> "│ Optimized Rules:   "
  <> string.pad_end(int.to_string(report.total_rules_optimized), 36, " ")
  <> "│\n"
  <> "│ Complexity Score:  "
  <> string.pad_end(int.to_string(report.complexity_score) <> " pts", 36, " ")
  <> "│\n"
  <> "├────────────────────────────────────────────────────────┤\n"
  <> "│ Policy Findings:                                       │\n"
  <> issue_lines
  <> "\n├────────────────────────────────────────────────────────┤\n"
  <> "│ Optimization Actions:                                  │\n"
  <> rec_lines
  <> "\n└────────────────────────────────────────────────────────┘"
}

/// Serialize audit report to JSON
pub fn audit_report_to_json(report: PolicyAuditReport) -> String {
  json.object([
    #("chain_name", json.string(report.chain_name)),
    #("total_rules_original", json.int(report.total_rules_original)),
    #("total_rules_optimized", json.int(report.total_rules_optimized)),
    #("complexity_score", json.int(report.complexity_score)),
    #(
      "issues",
      json.array(report.issues, fn(iss) {
        case iss {
          IssueShadowedRule(r, by) ->
            json.object([
              #("type", json.string("shadowed_rule")),
              #("rule", json.string(r)),
              #("shadowed_by", json.string(by)),
            ])
          IssueDuplicateRule(r, of) ->
            json.object([
              #("type", json.string("duplicate_rule")),
              #("rule", json.string(r)),
              #("duplicate_of", json.string(of)),
            ])
          IssueEmptyRule(r) ->
            json.object([
              #("type", json.string("empty_rule")),
              #("rule", json.string(r)),
            ])
          IssueRedundantMatch(r, m) ->
            json.object([
              #("type", json.string("redundant_match")),
              #("rule", json.string(r)),
              #("match", json.string(m)),
            ])
        }
      }),
    ),
    #("recommendations", json.array(report.recommendations, json.string)),
  ])
  |> json.to_string
}
