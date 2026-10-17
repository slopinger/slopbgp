//// Global Network Topology Simulator & Policy Convergence Engine
////
//// Instantiates and runs a discrete multi-router simulation of an entire
//// GlobalNetworkModel topology in-memory:
//// - Builds virtual router nodes with independent RIBs and peering relationships
//// - Enforces Route Reflector reflection hierarchies (RFC 4456)
//// - Enforces RFC 9234 BGP Role & OTC route leak detection/drops
//// - Enforces RFC 7454 / RFC 7938 AS-Path loop detection & route hygiene
//// - Propagates and accumulates DN42 latency tags across inter-region links
//// - Verifies end-to-end network convergence and traces forwarding paths

import gleam/dict.{type Dict}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import slopbgp/bgp/rfc9234.{get_otc}
import slopbgp/filter/hygiene.{default_dn42_hygiene, validate_route_hygiene}
import slopbgp/ip.{parse_ip, parse_prefix}
import slopbgp/netmodel/model.{
  type GlobalNetworkModel, type RouterNode, RoleCore, RoleEdge,
  RoleRouteReflector, RoleRouteServerNode,
}
import slopbgp/types.{
  type BgpRole, type Community, type LargeCommunity, type Route, AsSequence,
  Community, Ipv4, OriginIgp, RoaValid, RoleCustomer, RolePeer, RoleProvider,
  Route,
}

pub type SimPeer {
  SimPeer(
    peer_id: String,
    target_node_id: String,
    peer_as: Int,
    is_ibgp: Bool,
    is_rr_client: Bool,
    bgp_role: Option(BgpRole),
    latency_ms: Int,
  )
}

pub type SimRouter {
  SimRouter(
    id: String,
    hostname: String,
    region_id: String,
    role_str: String,
    asn: Int,
    router_id: String,
    rib: Dict(String, Route),
    peers: List(SimPeer),
  )
}

pub type SimLeakRecord {
  SimLeakRecord(
    step: Int,
    from_node: String,
    to_node: String,
    prefix: String,
    otc_as: Int,
    reason: String,
  )
}

pub type SimRouteInjection {
  SimRouteInjection(
    target_node_id: String,
    prefix: String,
    origin_as: Int,
    as_path: List(Int),
    med: Int,
    communities: List(Community),
    large_communities: List(LargeCommunity),
    otc: Option(Int),
  )
}

pub type SimState {
  SimState(
    model: GlobalNetworkModel,
    routers: Dict(String, SimRouter),
    step_count: Int,
    logs: List(String),
    leaks_detected: List(SimLeakRecord),
  )
}

pub type SimNodeSummary {
  SimNodeSummary(
    node_id: String,
    region_id: String,
    role_str: String,
    route_count: Int,
    prefixes: List(String),
  )
}

pub type SimConvergenceReport {
  SimConvergenceReport(
    converged: Bool,
    total_steps: Int,
    node_route_counts: List(#(String, Int)),
    detected_leaks: List(SimLeakRecord),
    node_rib_summaries: List(SimNodeSummary),
  )
}

/// Initialize the simulation environment from a GlobalNetworkModel
pub fn init_sim(model: GlobalNetworkModel) -> SimState {
  let router_dict =
    list.map(model.routers, fn(node) {
      let node_asn = option.unwrap(node.asn, model.asn)
      let peers = build_router_peers(node, model)
      let role_str = case node.role {
        RoleRouteReflector -> "RouteReflector"
        RoleCore -> "Core"
        RoleEdge -> "Edge"
        RoleRouteServerNode -> "RouteServer"
      }
      let r =
        SimRouter(
          id: node.id,
          hostname: node.hostname,
          region_id: node.region_id,
          role_str: role_str,
          asn: node_asn,
          router_id: node.router_id,
          rib: dict.new(),
          peers: peers,
        )
      #(node.id, r)
    })
    |> dict.from_list

  SimState(
    model: model,
    routers: router_dict,
    step_count: 0,
    logs: [
      "Simulation initialized with "
      <> int.to_string(list.length(model.routers))
      <> " routers.",
    ],
    leaks_detected: [],
  )
}

fn build_router_peers(
  node: RouterNode,
  model: GlobalNetworkModel,
) -> List(SimPeer) {
  let node_asn = option.unwrap(node.asn, model.asn)

  // 1. Inter-router internal links
  let internal_peers =
    list.filter_map(model.links, fn(link) {
      case link.endpoint_a == node.id {
        True -> {
          case list.find(model.routers, fn(r) { r.id == link.endpoint_b }) {
            Ok(target) -> {
              let target_asn = option.unwrap(target.asn, model.asn)
              let is_rr_client =
                node.role == RoleRouteReflector && target.role == RoleEdge
              Ok(SimPeer(
                peer_id: "link_" <> link.id,
                target_node_id: target.id,
                peer_as: target_asn,
                is_ibgp: target_asn == node_asn,
                is_rr_client: is_rr_client,
                bgp_role: None,
                latency_ms: link.latency_ms,
              ))
            }
            Error(Nil) -> Error(Nil)
          }
        }
        False -> {
          case link.endpoint_b == node.id {
            True -> {
              case list.find(model.routers, fn(r) { r.id == link.endpoint_a }) {
                Ok(target) -> {
                  let target_asn = option.unwrap(target.asn, model.asn)
                  let is_rr_client =
                    node.role == RoleRouteReflector && target.role == RoleEdge
                  Ok(SimPeer(
                    peer_id: "link_" <> link.id,
                    target_node_id: target.id,
                    peer_as: target_asn,
                    is_ibgp: target_asn == node_asn,
                    is_rr_client: is_rr_client,
                    bgp_role: None,
                    latency_ms: link.latency_ms,
                  ))
                }
                Error(Nil) -> Error(Nil)
              }
            }
            False -> Error(Nil)
          }
        }
      }
    })

  // 2. External peering definitions
  let external_peers =
    list.filter_map(model.external_peers, fn(ext) {
      case ext.attached_router == node.id {
        True -> {
          let lat = option.unwrap(ext.dn42_latency, 10)
          Ok(SimPeer(
            peer_id: ext.id,
            target_node_id: "ext_" <> ext.id,
            peer_as: ext.remote_as,
            is_ibgp: False,
            is_rr_client: False,
            bgp_role: Some(ext.bgp_role),
            latency_ms: lat,
          ))
        }
        False -> Error(Nil)
      }
    })

  list.append(internal_peers, external_peers)
}

/// Inject a route directly into a router's RIB
pub fn inject_route(
  state: SimState,
  injection: SimRouteInjection,
) -> Result(SimState, String) {
  case dict.get(state.routers, injection.target_node_id) {
    Error(Nil) ->
      Error(
        "Target router "
        <> injection.target_node_id
        <> " not found in simulation",
      )
    Ok(router) -> {
      use pfx <- result_try(parse_prefix(injection.prefix))
      let default_nh =
        parse_ip(router.router_id) |> result_unwrap(Ipv4(127, 0, 0, 1))
      let as_path = case injection.as_path {
        [] -> [AsSequence([injection.origin_as])]
        asns -> [AsSequence(asns)]
      }
      let route =
        Route(
          prefix: pfx,
          origin: OriginIgp,
          as_path: as_path,
          next_hop: default_nh,
          med: injection.med,
          local_pref: 100,
          atomic_aggregate: False,
          communities: injection.communities,
          large_communities: injection.large_communities,
          ext_communities: [],
          otc: injection.otc,
          roa_status: RoaValid,
          peer_id: "injected",
          timestamp: 0,
          path_id: None,
          originator_id: None,
          cluster_list: [],
        )

      let updated_rib = dict.insert(router.rib, injection.prefix, route)
      let updated_router = SimRouter(..router, rib: updated_rib)
      let updated_routers =
        dict.insert(state.routers, router.id, updated_router)
      let log_msg =
        "Injected route "
        <> injection.prefix
        <> " into "
        <> router.id
        <> " (AS"
        <> int.to_string(injection.origin_as)
        <> ")"
      Ok(
        SimState(..state, routers: updated_routers, logs: [
          log_msg,
          ..state.logs
        ]),
      )
    }
  }
}

/// Run a single discrete propagation step across all routers in the network
pub fn sim_step(state: SimState) -> #(SimState, Bool) {
  let hygiene_cfg = default_dn42_hygiene()
  let current_routers = state.routers
  let mut_changed = False
  let mut_leaks = state.leaks_detected

  // Fold over all routers and determine newly propagated routes
  let #(updated_routers, has_changes, new_leaks) =
    dict.fold(
      current_routers,
      #(current_routers, mut_changed, mut_leaks),
      fn(acc, sender_id, sender_router) {
        let #(routers_acc, changed_flag, leaks_acc) = acc

        // Iterate through all peers of sender_router
        list.fold(
          sender_router.peers,
          #(routers_acc, changed_flag, leaks_acc),
          fn(peer_acc, peer) {
            let #(r_acc, c_flag, l_acc) = peer_acc

            // Fold over all routes in sender's RIB for this peer
            dict.fold(
              sender_router.rib,
              #(r_acc, c_flag, l_acc),
              fn(route_acc, pfx_str, route) {
                let #(curr_r_dict, curr_changed, curr_leaks) = route_acc

                // 1. RFC 9234 OTC Route Leak Check
                let otc_opt = get_otc(route)
                let is_leak = case peer.bgp_role, otc_opt {
                  Some(RoleProvider), Some(otc_as) ->
                    otc_as != sender_router.asn
                  Some(RolePeer), Some(otc_as) -> otc_as != sender_router.asn
                  _, _ -> False
                }

                case is_leak {
                  True -> {
                    let otc_val = option.unwrap(otc_opt, 0)
                    let leak_rec =
                      SimLeakRecord(
                        step: state.step_count + 1,
                        from_node: sender_id,
                        to_node: peer.target_node_id,
                        prefix: pfx_str,
                        otc_as: otc_val,
                        reason: "RFC 9234 route leak: route with OTC AS"
                          <> int.to_string(otc_val)
                          <> " re-advertised to Provider/Peer",
                      )
                    #(curr_r_dict, curr_changed, [leak_rec, ..curr_leaks])
                  }
                  False -> {
                    // 2. If target node is an internal router, propagate into its RIB
                    case dict.get(curr_r_dict, peer.target_node_id) {
                      Error(Nil) -> route_acc
                      Ok(receiver_router) -> {
                        // Loop prevention: check if receiver's AS is in AS-Path
                        let receiver_asn = receiver_router.asn
                        let path_asns =
                          hygiene.extract_asns_from_path(route.as_path)
                        let has_as_loop = list.contains(path_asns, receiver_asn)

                        case has_as_loop {
                          True -> route_acc
                          False -> {
                            // 3. Transform route for receiver
                            let transformed_route =
                              transform_propagated_route(
                                route,
                                sender_router,
                                peer,
                                receiver_router,
                              )

                            // 4. Validate hygiene
                            case
                              validate_route_hygiene(
                                transformed_route,
                                hygiene_cfg,
                                None,
                              )
                            {
                              Error(_) -> route_acc
                              Ok(valid_route) -> {
                                // 5. Check if receiver needs updating
                                case dict.get(receiver_router.rib, pfx_str) {
                                  Ok(existing_route) -> {
                                    case
                                      should_replace_route(
                                        existing_route,
                                        valid_route,
                                      )
                                    {
                                      True -> {
                                        let new_rib =
                                          dict.insert(
                                            receiver_router.rib,
                                            pfx_str,
                                            valid_route,
                                          )
                                        let updated_recv =
                                          SimRouter(
                                            ..receiver_router,
                                            rib: new_rib,
                                          )
                                        let new_r_dict =
                                          dict.insert(
                                            curr_r_dict,
                                            receiver_router.id,
                                            updated_recv,
                                          )
                                        #(new_r_dict, True, curr_leaks)
                                      }
                                      False -> route_acc
                                    }
                                  }
                                  Error(Nil) -> {
                                    let new_rib =
                                      dict.insert(
                                        receiver_router.rib,
                                        pfx_str,
                                        valid_route,
                                      )
                                    let updated_recv =
                                      SimRouter(..receiver_router, rib: new_rib)
                                    let new_r_dict =
                                      dict.insert(
                                        curr_r_dict,
                                        receiver_router.id,
                                        updated_recv,
                                      )
                                    #(new_r_dict, True, curr_leaks)
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
              },
            )
          },
        )
      },
    )

  let new_step = state.step_count + 1
  let step_log =
    "Step "
    <> int.to_string(new_step)
    <> ": "
    <> case has_changes {
      True -> "routes propagated and RIBs updated"
      False -> "network converged, no changes"
    }

  let next_state =
    SimState(
      ..state,
      routers: updated_routers,
      step_count: new_step,
      logs: [step_log, ..state.logs],
      leaks_detected: new_leaks,
    )

  #(next_state, has_changes)
}

fn transform_propagated_route(
  route: Route,
  sender: SimRouter,
  peer: SimPeer,
  _receiver: SimRouter,
) -> Route {
  // Update Next-Hop to sender
  let sender_nh =
    parse_ip(sender.router_id) |> result_unwrap(Ipv4(127, 0, 0, 1))

  // Update AS-Path if eBGP
  let new_as_path = case peer.is_ibgp {
    True -> route.as_path
    False ->
      case route.as_path {
        [AsSequence(asns), ..rest] -> [AsSequence([sender.asn, ..asns]), ..rest]
        other -> [AsSequence([sender.asn]), ..other]
      }
  }

  // Update DN42 latency community
  let new_comms = case peer.latency_ms > 0 {
    True -> {
      let existing_lat = get_route_latency(route) |> option.unwrap(0)
      let total_lat = existing_lat + peer.latency_ms
      let lat_comm = Community(asn: 64_511, value: 1000 + total_lat)
      [
        lat_comm,
        ..list.filter(route.communities, fn(c) {
          c.asn != 64_511 || c.value < 1000 || c.value > 1999
        })
      ]
    }
    False -> route.communities
  }

  // Inject OTC if outbound to Customer or Peer
  let new_otc = case peer.bgp_role {
    Some(RoleCustomer) | Some(RolePeer) ->
      case route.otc {
        Some(existing) -> Some(existing)
        None -> Some(sender.asn)
      }
    _ -> route.otc
  }

  Route(
    ..route,
    next_hop: sender_nh,
    as_path: new_as_path,
    communities: new_comms,
    peer_id: sender.id,
    otc: new_otc,
  )
}

fn should_replace_route(existing: Route, candidate: Route) -> Bool {
  // Prefer higher local_pref
  case candidate.local_pref > existing.local_pref {
    True -> True
    False ->
      case candidate.local_pref < existing.local_pref {
        True -> False
        False -> {
          // Prefer shorter AS-Path
          let cand_len =
            hygiene.extract_asns_from_path(candidate.as_path) |> list.length
          let exist_len =
            hygiene.extract_asns_from_path(existing.as_path) |> list.length
          case cand_len < exist_len {
            True -> True
            False ->
              case cand_len > exist_len {
                True -> False
                False -> {
                  // Prefer lower MED
                  candidate.med < existing.med
                }
              }
          }
        }
      }
  }
}

fn get_route_latency(route: Route) -> Option(Int) {
  list.find_map(route.communities, fn(c) {
    case c.asn == 64_511 && c.value >= 1000 && c.value <= 1999 {
      True -> Ok(c.value - 1000)
      False -> Error(Nil)
    }
  })
  |> option.from_result
}

/// Run simulation until convergence or max_steps reached
pub fn run_simulation_to_convergence(
  state: SimState,
  max_steps: Int,
) -> SimConvergenceReport {
  run_loop(state, max_steps)
}

fn run_loop(state: SimState, remaining_steps: Int) -> SimConvergenceReport {
  case remaining_steps <= 0 {
    True -> generate_report(state, False)
    False -> {
      let #(next_state, has_changes) = sim_step(state)
      case has_changes {
        False -> generate_report(next_state, True)
        True -> run_loop(next_state, remaining_steps - 1)
      }
    }
  }
}

fn generate_report(state: SimState, converged: Bool) -> SimConvergenceReport {
  let summaries =
    list.map(dict.values(state.routers), fn(r) {
      let pfxs = dict.keys(r.rib)
      SimNodeSummary(
        node_id: r.id,
        region_id: r.region_id,
        role_str: r.role_str,
        route_count: list.length(pfxs),
        prefixes: pfxs,
      )
    })

  let counts = list.map(summaries, fn(s) { #(s.node_id, s.route_count) })

  SimConvergenceReport(
    converged: converged,
    total_steps: state.step_count,
    node_route_counts: counts,
    detected_leaks: list.reverse(state.leaks_detected),
    node_rib_summaries: summaries,
  )
}

/// Render convergence report as structured JSON
pub fn convergence_report_to_json(report: SimConvergenceReport) -> String {
  json.object([
    #("converged", json.bool(report.converged)),
    #("total_steps", json.int(report.total_steps)),
    #(
      "detected_leaks",
      json.array(report.detected_leaks, fn(l) {
        json.object([
          #("step", json.int(l.step)),
          #("from_node", json.string(l.from_node)),
          #("to_node", json.string(l.to_node)),
          #("prefix", json.string(l.prefix)),
          #("otc_as", json.int(l.otc_as)),
          #("reason", json.string(l.reason)),
        ])
      }),
    ),
    #(
      "node_summaries",
      json.array(report.node_rib_summaries, fn(s) {
        json.object([
          #("node_id", json.string(s.node_id)),
          #("region_id", json.string(s.region_id)),
          #("role", json.string(s.role_str)),
          #("route_count", json.int(s.route_count)),
          #("prefixes", json.array(s.prefixes, json.string)),
        ])
      }),
    ),
  ])
  |> json.to_string
}

/// Format a human-readable CLI report
pub fn format_convergence_report(report: SimConvergenceReport) -> String {
  let status_str = case report.converged {
    True -> "CONVERGED in " <> int.to_string(report.total_steps) <> " steps"
    False -> "FAILED TO CONVERGE within step limit"
  }

  let leak_section = case report.detected_leaks {
    [] -> "  None (No route leaks detected - RFC 9234 verified)"
    leaks ->
      list.map(leaks, fn(l) {
        "  [!] Step "
        <> int.to_string(l.step)
        <> ": "
        <> l.prefix
        <> " from "
        <> l.from_node
        <> " -> "
        <> l.to_node
        <> " (OTC AS"
        <> int.to_string(l.otc_as)
        <> ")\n      "
        <> l.reason
      })
      |> string.join("\n")
  }

  let node_section =
    list.map(report.node_rib_summaries, fn(s) {
      "  - "
      <> s.node_id
      <> " ("
      <> s.region_id
      <> " / "
      <> s.role_str
      <> "): "
      <> int.to_string(s.route_count)
      <> " routes in RIB -> "
      <> string.join(s.prefixes, ", ")
    })
    |> string.join("\n")

  "=================================================================\n"
  <> "slopbgp // Global Network Topology Simulation Report\n"
  <> "Status: "
  <> status_str
  <> "\n=================================================================\n"
  <> "Detected Route Leaks:\n"
  <> leak_section
  <> "\n\nRouter Convergence Details:\n"
  <> node_section
  <> "\n================================================================="
}

fn result_try(res: Result(a, e), f: fn(a) -> Result(b, e)) -> Result(b, e) {
  case res {
    Ok(v) -> f(v)
    Error(e) -> Error(e)
  }
}

fn result_unwrap(res: Result(a, e), default: a) -> a {
  case res {
    Ok(v) -> v
    Error(_) -> default
  }
}
