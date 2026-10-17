//// GitOps Fleet Config Drift Detection & Automated Reconciliation Engine
////
//// In continuous NetOps / GitOps workflows, the global network model
//// (slopnet_global.json) is the single source of truth for all routers.
//// This engine compares running or locally configured node states against
//// the derived model configuration, flags unauthorized drift (unmanaged peers,
//// altered timers, mismatched RRs or latency tags), and synthesizes
//// zero-downtime hot-reload reconciliation actions.

import gleam/dict.{type Dict}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import slopbgp/config.{type DaemonConfig}
import slopbgp/ip.{ip_to_string}
import slopbgp/netmodel/compiler.{compile_router_config}
import slopbgp/netmodel/model.{type GlobalNetworkModel}
import slopbgp/types.{type PeerConfig}

pub type DriftSeverity {
  DriftInSync
  DriftMinor
  DriftCritical
}

pub type DriftIssue {
  DriftMissingPeer(peer_id: String, expected_as: Int, expected_ip: String)
  DriftExtraneousPeer(peer_id: String, actual_as: Int, actual_ip: String)
  DriftMismatchedPeerAs(peer_id: String, expected_as: Int, actual_as: Int)
  DriftMismatchedPeerIp(peer_id: String, expected_ip: String, actual_ip: String)
  DriftMismatchedLatency(
    peer_id: String,
    expected_ms: Option(Int),
    actual_ms: Option(Int),
  )
  DriftMismatchedRrClient(peer_id: String, expected_rr: Bool, actual_rr: Bool)
  DriftMismatchedRouterId(expected_id: String, actual_id: String)
  DriftMismatchedAsn(expected_asn: Int, actual_asn: Int)
}

pub type NodeDriftReport {
  NodeDriftReport(
    node_id: String,
    hostname: String,
    severity: DriftSeverity,
    issues: List(DriftIssue),
    reconciliation_actions: List(String),
  )
}

pub type FleetDriftReport {
  FleetDriftReport(
    network_name: String,
    total_nodes: Int,
    in_sync_nodes: Int,
    drifted_nodes: Int,
    overall_severity: DriftSeverity,
    node_reports: List(NodeDriftReport),
  )
}

/// Detects configuration drift on a single router node
pub fn detect_node_drift(
  desired: DaemonConfig,
  live: DaemonConfig,
  node_id: String,
  hostname: String,
) -> NodeDriftReport {
  let mut_issues = []

  // 1. Check global router parameters
  let issues1 = case desired.asn != live.asn {
    True -> [DriftMismatchedAsn(desired.asn, live.asn), ..mut_issues]
    False -> mut_issues
  }

  let issues2 = case desired.router_id != live.router_id {
    True -> [
      DriftMismatchedRouterId(
        ip_to_string(desired.router_id),
        ip_to_string(live.router_id),
      ),
      ..issues1
    ]
    False -> issues1
  }

  // 2. Index peers by ID
  let desired_map: Dict(String, PeerConfig) =
    list.fold(desired.peers, dict.new(), fn(acc, p) {
      dict.insert(acc, p.id, p)
    })
  let live_map: Dict(String, PeerConfig) =
    list.fold(live.peers, dict.new(), fn(acc, p) { dict.insert(acc, p.id, p) })

  // 3. Find missing peers (in desired but not in live)
  let issues3 =
    dict.fold(desired_map, issues2, fn(acc, pid, p) {
      case dict.has_key(live_map, pid) {
        False -> [
          DriftMissingPeer(pid, p.remote_as, ip_to_string(p.remote_ip)),
          ..acc
        ]
        True -> acc
      }
    })

  // 4. Find extraneous / unmanaged peers (in live but not in desired)
  let issues4 =
    dict.fold(live_map, issues3, fn(acc, pid, p) {
      case dict.has_key(desired_map, pid) {
        False -> [
          DriftExtraneousPeer(pid, p.remote_as, ip_to_string(p.remote_ip)),
          ..acc
        ]
        True -> acc
      }
    })

  // 5. Find attribute mismatches on common peers
  let issues5 =
    dict.fold(desired_map, issues4, fn(acc, pid, des_p) {
      case dict.get(live_map, pid) {
        Error(_) -> acc
        Ok(live_p) -> {
          let cur = acc

          let cur = case des_p.remote_as != live_p.remote_as {
            True -> [
              DriftMismatchedPeerAs(pid, des_p.remote_as, live_p.remote_as),
              ..cur
            ]
            False -> cur
          }

          let cur = case des_p.remote_ip != live_p.remote_ip {
            True -> [
              DriftMismatchedPeerIp(
                pid,
                ip_to_string(des_p.remote_ip),
                ip_to_string(live_p.remote_ip),
              ),
              ..cur
            ]
            False -> cur
          }

          let cur = case des_p.dn42_latency != live_p.dn42_latency {
            True -> [
              DriftMismatchedLatency(
                pid,
                des_p.dn42_latency,
                live_p.dn42_latency,
              ),
              ..cur
            ]
            False -> cur
          }

          let cur = case
            des_p.route_reflector_client != live_p.route_reflector_client
          {
            True -> [
              DriftMismatchedRrClient(
                pid,
                des_p.route_reflector_client,
                live_p.route_reflector_client,
              ),
              ..cur
            ]
            False -> cur
          }

          cur
        }
      }
    })

  // Classify severity
  let severity = case issues5 {
    [] -> DriftInSync
    iss -> {
      let has_critical =
        list.any(iss, fn(i) {
          case i {
            DriftMissingPeer(_, _, _) -> True
            DriftExtraneousPeer(_, _, _) -> True
            DriftMismatchedPeerAs(_, _, _) -> True
            DriftMismatchedPeerIp(_, _, _) -> True
            DriftMismatchedAsn(_, _) -> True
            _ -> False
          }
        })
      case has_critical {
        True -> DriftCritical
        False -> DriftMinor
      }
    }
  }

  // Synthesize reconciliation actions
  let actions =
    list.map(issues5, fn(issue) {
      case issue {
        DriftMissingPeer(pid, rem_as, rem_ip) ->
          "slopbgpctl peer add "
          <> pid
          <> " "
          <> int.to_string(rem_as)
          <> " "
          <> rem_ip
        DriftExtraneousPeer(pid, _, _) ->
          "slopbgpctl peer drain "
          <> pid
          <> " && slopbgpctl peer remove "
          <> pid
        DriftMismatchedPeerAs(pid, expected, _) ->
          "slopbgpctl peer update "
          <> pid
          <> " --asn "
          <> int.to_string(expected)
        DriftMismatchedPeerIp(pid, expected, _) ->
          "slopbgpctl peer update " <> pid <> " --ip " <> expected
        DriftMismatchedLatency(pid, Some(lat), _) ->
          "slopbgpctl peer update "
          <> pid
          <> " --latency "
          <> int.to_string(lat)
        DriftMismatchedLatency(pid, None, _) ->
          "slopbgpctl peer update " <> pid <> " --no-latency"
        DriftMismatchedRrClient(pid, True, _) ->
          "slopbgpctl peer update " <> pid <> " --rr-client true"
        DriftMismatchedRrClient(pid, False, _) ->
          "slopbgpctl peer update " <> pid <> " --rr-client false"
        DriftMismatchedRouterId(expected, _) ->
          "slopbgpctl reload --router-id " <> expected
        DriftMismatchedAsn(expected, _) ->
          "slopbgpctl reload --asn " <> int.to_string(expected)
      }
    })

  NodeDriftReport(
    node_id: node_id,
    hostname: hostname,
    severity: severity,
    issues: issues5,
    reconciliation_actions: actions,
  )
}

/// Detects configuration drift across the entire fleet
pub fn detect_fleet_drift(
  model: GlobalNetworkModel,
  live_fleet: Dict(String, DaemonConfig),
) -> FleetDriftReport {
  let node_reports =
    list.map(model.routers, fn(r) {
      case compile_router_config(model, r.id) {
        Error(_) ->
          NodeDriftReport(
            node_id: r.id,
            hostname: r.hostname,
            severity: DriftCritical,
            issues: [],
            reconciliation_actions: ["# Error compiling desired model config"],
          )
        Ok(desired) -> {
          case dict.get(live_fleet, r.id) {
            Error(_) ->
              NodeDriftReport(
                node_id: r.id,
                hostname: r.hostname,
                severity: DriftCritical,
                issues: [
                  DriftMissingPeer(
                    "NODE_OFFLINE",
                    model.asn,
                    "No running state reported",
                  ),
                ],
                reconciliation_actions: [
                  "# Router node offline or unreachable via API",
                ],
              )
            Ok(live) -> detect_node_drift(desired, live, r.id, r.hostname)
          }
        }
      }
    })

  let in_sync_cnt =
    list.count(node_reports, fn(r) { r.severity == DriftInSync })
  let drifted_cnt = list.length(node_reports) - in_sync_cnt

  let overall_sev = case drifted_cnt == 0 {
    True -> DriftInSync
    False -> {
      let any_crit =
        list.any(node_reports, fn(r) { r.severity == DriftCritical })
      case any_crit {
        True -> DriftCritical
        False -> DriftMinor
      }
    }
  }

  FleetDriftReport(
    network_name: model.name,
    total_nodes: list.length(model.routers),
    in_sync_nodes: in_sync_cnt,
    drifted_nodes: drifted_cnt,
    overall_severity: overall_sev,
    node_reports: node_reports,
  )
}

/// Formats human-readable CLI report for operator inspection
pub fn format_fleet_drift_report(report: FleetDriftReport) -> String {
  let sev_str = case report.overall_severity {
    DriftInSync -> "IN_SYNC (All fleet routers match model 100%)"
    DriftMinor -> "MINOR_DRIFT (Non-forwarding parameter differences)"
    DriftCritical -> "CRITICAL_DRIFT (Topology or routing session divergence!)"
  }

  let lines = [
    "┌────────────────────────────────────────────────────────┐",
    "│ slopbgp GitOps Fleet Drift Detection Report            │",
    "├────────────────────────────────────────────────────────┤",
    "│ Network Name:      "
      <> string.pad_end(report.network_name, 36, " ")
      <> "│",
    "│ Total Nodes:       "
      <> string.pad_end(
      int.to_string(report.total_nodes) <> " routers",
      36,
      " ",
    )
      <> "│",
    "│ In-Sync Nodes:     "
      <> string.pad_end(
      int.to_string(report.in_sync_nodes) <> " nodes",
      36,
      " ",
    )
      <> "│",
    "│ Drifted Nodes:     "
      <> string.pad_end(
      int.to_string(report.drifted_nodes) <> " nodes",
      36,
      " ",
    )
      <> "│",
    "│ Fleet Status:      " <> string.pad_end(sev_str, 36, " ") <> "│",
    "├────────────────────────────────────────────────────────┤",
    "│ Node Drift Inspection:                                 │",
  ]

  let node_lines =
    list.map(report.node_reports, fn(nr) {
      let icon = case nr.severity {
        DriftInSync -> "  ✔ "
        DriftMinor -> "  ▲ "
        DriftCritical -> "  ✖ "
      }
      let status_txt = case nr.severity {
        DriftInSync -> "IN_SYNC"
        DriftMinor ->
          "MINOR_DRIFT (" <> int.to_string(list.length(nr.issues)) <> " issues)"
        DriftCritical ->
          "CRITICAL_DRIFT ("
          <> int.to_string(list.length(nr.issues))
          <> " issues)"
      }

      let header =
        icon <> nr.node_id <> " (" <> nr.hostname <> "): " <> status_txt
      let iss_strs =
        list.map(nr.issues, fn(iss) {
          case iss {
            DriftMissingPeer(p, rem_as, rem_ip) ->
              "    [-] MISSING_PEER: "
              <> p
              <> " (AS"
              <> int.to_string(rem_as)
              <> " @ "
              <> rem_ip
              <> ")"
            DriftExtraneousPeer(p, rem_as, rem_ip) ->
              "    [!] UNMANAGED_PEER: "
              <> p
              <> " (AS"
              <> int.to_string(rem_as)
              <> " @ "
              <> rem_ip
              <> ")"
            DriftMismatchedPeerAs(p, exp, act) ->
              "    [~] ASN_MISMATCH: "
              <> p
              <> " (expected AS"
              <> int.to_string(exp)
              <> ", actual AS"
              <> int.to_string(act)
              <> ")"
            DriftMismatchedPeerIp(p, exp, act) ->
              "    [~] IP_MISMATCH: "
              <> p
              <> " (expected "
              <> exp
              <> ", actual "
              <> act
              <> ")"
            DriftMismatchedLatency(p, exp, act) ->
              "    [~] LATENCY_TAG_MISMATCH: "
              <> p
              <> " (expected "
              <> opt_int_str(exp)
              <> ", actual "
              <> opt_int_str(act)
              <> ")"
            DriftMismatchedRrClient(p, exp, act) ->
              "    [~] RR_CLIENT_MISMATCH: "
              <> p
              <> " (expected "
              <> bool_str(exp)
              <> ", actual "
              <> bool_str(act)
              <> ")"
            DriftMismatchedRouterId(exp, act) ->
              "    [~] ROUTER_ID_MISMATCH: expected "
              <> exp
              <> ", actual "
              <> act
            DriftMismatchedAsn(exp, act) ->
              "    [~] ASN_MISMATCH: expected AS"
              <> int.to_string(exp)
              <> ", actual AS"
              <> int.to_string(act)
          }
        })
      string.join([header, ..iss_strs], "\n")
    })

  let footer = ["└────────────────────────────────────────────────────────┘"]

  string.join(list.flatten([lines, node_lines, footer]), "\n")
}

/// Generates executable bash script to reconcile all drifted nodes
pub fn generate_reconciliation_script(report: FleetDriftReport) -> String {
  let header = [
    "#!/usr/bin/env bash",
    "# slopbgp GitOps Automated Reconciliation Script",
    "# Network: " <> report.network_name,
    "set -euo pipefail",
    "",
  ]

  let actions =
    list.flat_map(report.node_reports, fn(nr) {
      case nr.reconciliation_actions {
        [] -> []
        acts -> [
          "# Reconciling node: " <> nr.node_id <> " (" <> nr.hostname <> ")",
          ..acts
        ]
      }
    })

  string.join(list.append(header, actions), "\n")
}

/// JSON serialization for GitOps CI/CD pipelines
pub fn fleet_drift_report_to_json(report: FleetDriftReport) -> String {
  json.object([
    #("network_name", json.string(report.network_name)),
    #("total_nodes", json.int(report.total_nodes)),
    #("in_sync_nodes", json.int(report.in_sync_nodes)),
    #("drifted_nodes", json.int(report.drifted_nodes)),
    #(
      "overall_severity",
      json.string(case report.overall_severity {
        DriftInSync -> "in_sync"
        DriftMinor -> "minor_drift"
        DriftCritical -> "critical_drift"
      }),
    ),
    #(
      "nodes",
      json.array(report.node_reports, fn(nr) {
        json.object([
          #("node_id", json.string(nr.node_id)),
          #("hostname", json.string(nr.hostname)),
          #(
            "severity",
            json.string(case nr.severity {
              DriftInSync -> "in_sync"
              DriftMinor -> "minor_drift"
              DriftCritical -> "critical_drift"
            }),
          ),
          #("issue_count", json.int(list.length(nr.issues))),
          #(
            "reconciliation_actions",
            json.array(nr.reconciliation_actions, json.string),
          ),
        ])
      }),
    ),
  ])
  |> json.to_string
}

fn opt_int_str(opt: Option(Int)) -> String {
  case opt {
    Some(i) -> int.to_string(i) <> "ms"
    None -> "none"
  }
}

fn bool_str(b: Bool) -> String {
  case b {
    True -> "true"
    False -> "false"
  }
}
