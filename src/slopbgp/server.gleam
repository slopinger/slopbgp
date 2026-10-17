import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import simplifile
import slopbgp/bgp/damping.{
  type DampingTable, default_damping_config,
  get_damped_routes as damping_get_damped, new_table as new_damping_table,
  register_flap,
}
import slopbgp/bgp/fsm.{EventHoldTimerExpires, EventKeepaliveTimerExpires}
import slopbgp/bgp/graceful_shutdown.{apply_graceful_shutdown_outbound}
import slopbgp/bgp/message.{encode_message}
import slopbgp/config.{type DaemonConfig}
import slopbgp/dn42/roa.{parse_roa_content}
import slopbgp/fib/kernel.{type FibEntry, type FibState, new_fib, sync_fib}
import slopbgp/metrics/prometheus.{DaemonMetricsData, render_prometheus_metrics}
import slopbgp/net/socket.{now, send}
import slopbgp/peer.{
  type PeerHandle, PeerHandle, extract_routes_from_update, handle_peer_event,
  new_peer, process_fsm_actions,
}
import slopbgp/policy/filter.{dn42_default_import_policy, filter_inbound_route}
import slopbgp/rib/rib.{
  type Rib, get_all_routes, insert_route, new_rib, prepare_outbound_route,
  withdraw_all_from_peer, withdraw_route,
}
import slopbgp/routeserver/routeserver
import slopbgp/types.{
  type BgpMessage, type DampedRoute, type DampingConfig, type FlowspecRule,
  type PeerConfig, type PeerStats, type PolicyChain, type RoaEntry, type Route,
  AttrAsPath, AttrCommunities, AttrLargeCommunities, AttrLocalPref, AttrMed,
  AttrNextHop, AttrOrigin, MsgUpdate, PeerStats, StateEstablished,
}

pub type ServerState {
  ServerState(
    config: DaemonConfig,
    peers: Dict(String, PeerHandle),
    rib: Rib,
    fib: FibState,
    roa_table: List(RoaEntry),
    started_at: Int,
    event_log: List(String),
    damping_table: DampingTable,
    damping_config: DampingConfig,
    flowspec_rules: List(FlowspecRule),
    drained_peers: List(String),
    import_policy: PolicyChain,
  )
}

pub fn new_server(config: DaemonConfig) -> ServerState {
  let initial_fib = new_fib(config.fib_table)
  let initial_rib = new_rib()
  let state0 =
    ServerState(
      config: config,
      peers: dict.new(),
      rib: initial_rib,
      fib: initial_fib,
      roa_table: [],
      started_at: now(),
      event_log: ["[init] slopbgp server initialized"],
      damping_table: new_damping_table(),
      damping_config: default_damping_config(),
      flowspec_rules: [],
      drained_peers: [],
      import_policy: dn42_default_import_policy(),
    )

  // Load configured peers
  let state_with_peers =
    list.fold(config.peers, state0, fn(acc, p_cfg) { add_peer(acc, p_cfg) })

  // Load ROA tables if files exist
  load_roa_tables(state_with_peers)
}

pub fn add_peer(state: ServerState, config: PeerConfig) -> ServerState {
  let handle = new_peer(config)
  let updated_peers = dict.insert(state.peers, config.id, handle)
  let log_entry =
    "[peer] Added peer "
    <> config.id
    <> " (AS"
    <> int.to_string(config.remote_as)
    <> ")"
  ServerState(..state, peers: updated_peers, event_log: [
    log_entry,
    ..state.event_log
  ])
}

pub fn load_roa_tables(state: ServerState) -> ServerState {
  let v4_content = case simplifile.read(state.config.roa_v4_path) {
    Ok(c) -> c
    Error(_) -> ""
  }
  let v6_content = case simplifile.read(state.config.roa_v6_path) {
    Ok(c) -> c
    Error(_) -> ""
  }
  let v4_entries = parse_roa_content(v4_content)
  let v6_entries = parse_roa_content(v6_content)
  let all_entries = list.append(v4_entries, v6_entries)
  let count = list.length(all_entries)
  let log_entry =
    "[roa] Loaded " <> int.to_string(count) <> " ROA validation entries"
  ServerState(..state, roa_table: all_entries, event_log: [
    log_entry,
    ..state.event_log
  ])
}

pub fn tick_server(state: ServerState, now_time: Int) -> ServerState {
  // Check timers and connections for each peer
  let #(updated_peers, updated_rib, new_logs) =
    dict.fold(
      state.peers,
      #(state.peers, state.rib, []),
      fn(acc, peer_id, peer_handle) {
        let #(p_dict, curr_rib, logs) = acc

        // Check keepalive timer
        let is_estab = peer_handle.fsm.state == StateEstablished
        let ka_interval = peer_handle.fsm.negotiated_hold_time / 3
        let need_ka =
          is_estab
          && ka_interval > 0
          && now_time - peer_handle.last_keepalive_sent >= ka_interval

        let #(p_after_ka, log_ka) = case need_ka {
          True -> {
            let #(p_ev, actions) =
              handle_peer_event(
                peer_handle,
                EventKeepaliveTimerExpires,
                now_time,
              )
            let #(p_done, _) = process_fsm_actions(p_ev, actions, now_time)
            #(p_done, ["[ka] Sent keepalive to " <> peer_id])
          }
          False -> #(peer_handle, [])
        }

        // Check hold timer
        let hold_timeout = peer_handle.fsm.negotiated_hold_time
        let hold_expired =
          is_estab
          && hold_timeout > 0
          && now_time - p_after_ka.last_keepalive_received > hold_timeout

        case hold_expired {
          True -> {
            let #(p_ev, actions) =
              handle_peer_event(p_after_ka, EventHoldTimerExpires, now_time)
            let #(p_done, _) = process_fsm_actions(p_ev, actions, now_time)
            let rib_cleaned = withdraw_all_from_peer(curr_rib, peer_id)
            let log_hold = [
              "[hold] Hold timer expired for peer " <> peer_id,
              ..log_ka
            ]
            #(
              dict.insert(p_dict, peer_id, p_done),
              rib_cleaned,
              list.append(log_hold, logs),
            )
          }
          False -> {
            #(
              dict.insert(p_dict, peer_id, p_after_ka),
              curr_rib,
              list.append(log_ka, logs),
            )
          }
        }
      },
    )

  // Synchronize best routes to FIB
  let best_routes = get_all_routes(updated_rib)
  let updated_fib = sync_fib(state.fib, best_routes)

  ServerState(
    ..state,
    peers: updated_peers,
    rib: updated_rib,
    fib: updated_fib,
    event_log: list.append(new_logs, state.event_log),
  )
}

pub fn ingest_peer_update(
  state: ServerState,
  peer_id: String,
  update_msg: BgpMessage,
  now_time: Int,
) -> ServerState {
  case dict.get(state.peers, peer_id) {
    Error(_) -> state
    Ok(peer_handle) -> {
      let #(raw_learned, withdrawn) =
        extract_routes_from_update(
          update_msg,
          peer_id,
          peer_handle.config.remote_ip,
          state.roa_table,
          now_time,
        )

      // Filter inbound learned routes with Policy Engine and Drain mode
      let is_drained = list.contains(state.drained_peers, peer_id)
      let learned =
        list.filter_map(raw_learned, fn(route) {
          let initial = case is_drained {
            True -> types.Route(..route, local_pref: 0)
            False -> route
          }
          case filter_inbound_route(initial, state.import_policy) {
            Ok(r) -> Ok(r)
            Error(_) -> Error(Nil)
          }
        })

      // Insert learned routes into RIB
      let #(rib_after_learn, new_best_routes) =
        list.fold(learned, #(state.rib, []), fn(acc, route) {
          let #(curr_rib, bests) = acc
          let #(upd_rib, opt_changed) = insert_route(curr_rib, route)
          case opt_changed {
            Some(changed) -> #(upd_rib, [changed, ..bests])
            None -> #(upd_rib, bests)
          }
        })

      // Withdraw routes from RIB and record RFC 2439 flap damping penalties
      let #(rib_final, upd_damping) =
        list.fold(
          withdrawn,
          #(rib_after_learn, state.damping_table),
          fn(acc, prefix) {
            let #(curr_rib, d_tab) = acc
            let #(upd_rib, _) = withdraw_route(curr_rib, peer_id, prefix)
            let #(new_d_tab, _) =
              register_flap(
                d_tab,
                peer_id,
                prefix,
                now_time,
                state.damping_config,
              )
            #(upd_rib, new_d_tab)
          },
        )

      // Propagate changed best routes to other peers (Adj-RIB-Out)
      let state_propagated =
        propagate_routes_to_peers(
          ServerState(..state, rib: rib_final, damping_table: upd_damping),
          new_best_routes,
          peer_id,
        )

      // Update peer statistics
      let updated_stats =
        PeerStats(
          ..peer_handle.stats,
          prefixes_received: peer_handle.stats.prefixes_received
            + list.length(learned)
            - list.length(withdrawn),
          updates_received: peer_handle.stats.updates_received + 1,
        )
      let updated_peer = PeerHandle(..peer_handle, stats: updated_stats)
      let updated_peers = dict.insert(state.peers, peer_id, updated_peer)

      let log_msg =
        "[update] Peer "
        <> peer_id
        <> " announced "
        <> int.to_string(list.length(learned))
        <> " routes, withdrew "
        <> int.to_string(list.length(withdrawn))

      ServerState(..state_propagated, peers: updated_peers, event_log: [
        log_msg,
        ..state_propagated.event_log
      ])
    }
  }
}

fn propagate_routes_to_peers(
  state: ServerState,
  routes_to_send: List(Route),
  origin_peer_id: String,
) -> ServerState {
  case routes_to_send {
    [] -> state
    _ -> {
      dict.fold(state.peers, state, fn(acc, target_peer_id, target_peer) {
        case target_peer_id == origin_peer_id {
          True -> acc
          False -> {
            case target_peer.fsm.state == StateEstablished {
              False -> acc
              True -> {
                let target_is_drained =
                  list.contains(acc.drained_peers, target_peer_id)

                // Prepare outbound routes for this peer (RFC 7947 Route Server or standard eBGP/iBGP)
                let outbound_routes =
                  list.filter_map(routes_to_send, fn(r) {
                    let maybe_prepared = case
                      target_peer.config.route_server_client
                    {
                      True ->
                        routeserver.prepare_routeserver_outbound_route(
                          r,
                          target_peer.config.remote_as,
                          target_peer.config.local_as,
                        )
                      False ->
                        prepare_outbound_route(
                          r,
                          target_peer.config,
                          target_peer.config.local_ip,
                        )
                    }

                    case maybe_prepared {
                      Some(prepared) -> {
                        // RFC 8326 Graceful Shutdown: attach community & drop local_pref if drained
                        case target_is_drained {
                          True -> Ok(apply_graceful_shutdown_outbound(prepared))
                          False -> Ok(prepared)
                        }
                      }
                      None -> Error(Nil)
                    }
                  })

                case outbound_routes {
                  [] -> acc
                  [first, ..] -> {
                    // Group routes by path attributes and send UPDATE
                    let update =
                      MsgUpdate(
                        withdrawn: [],
                        attributes: [
                          AttrOrigin(first.origin),
                          AttrAsPath(first.as_path),
                          AttrNextHop(first.next_hop),
                          AttrMed(first.med),
                          AttrLocalPref(first.local_pref),
                          AttrCommunities(first.communities),
                          AttrLargeCommunities(first.large_communities),
                        ],
                        nlri: list.map(outbound_routes, fn(r) { r.prefix }),
                      )
                    let msg_bytes = encode_message(update)
                    case target_peer.socket {
                      Some(sock) -> {
                        let _ = send(sock, msg_bytes)
                        let updated_stats =
                          PeerStats(
                            ..target_peer.stats,
                            prefixes_advertised: target_peer.stats.prefixes_advertised
                              + list.length(outbound_routes),
                            updates_sent: target_peer.stats.updates_sent + 1,
                          )
                        let upd_peer =
                          PeerHandle(..target_peer, stats: updated_stats)
                        let upd_peers =
                          dict.insert(acc.peers, target_peer_id, upd_peer)
                        ServerState(..acc, peers: upd_peers)
                      }
                      None -> acc
                    }
                  }
                }
              }
            }
          }
        }
      })
    }
  }
}

/// Drain a peer session gracefully (RFC 8326 Graceful Shutdown)
pub fn drain_peer(state: ServerState, peer_id: String) -> ServerState {
  case list.contains(state.drained_peers, peer_id) {
    True -> state
    False -> {
      let updated_drained = [peer_id, ..state.drained_peers]
      let log_msg = "[drain] Peer " <> peer_id <> " entered graceful drain mode"
      ServerState(..state, drained_peers: updated_drained, event_log: [
        log_msg,
        ..state.event_log
      ])
    }
  }
}

/// Undrain a peer session, restoring normal priority
pub fn undrain_peer(state: ServerState, peer_id: String) -> ServerState {
  let updated_drained = list.filter(state.drained_peers, fn(p) { p != peer_id })
  let log_msg = "[undrain] Peer " <> peer_id <> " exited drain mode (restored)"
  ServerState(..state, drained_peers: updated_drained, event_log: [
    log_msg,
    ..state.event_log
  ])
}

pub fn is_peer_drained(state: ServerState, peer_id: String) -> Bool {
  list.contains(state.drained_peers, peer_id)
}

/// Add an RFC 5575 / RFC 8955 Flowspec rule
pub fn add_flowspec_rule(
  state: ServerState,
  rule: FlowspecRule,
) -> ServerState {
  let updated_rules = [rule, ..state.flowspec_rules]
  let log_msg = "[flowspec] Added rule " <> rule.id
  ServerState(..state, flowspec_rules: updated_rules, event_log: [
    log_msg,
    ..state.event_log
  ])
}

/// Remove a Flowspec rule by ID
pub fn delete_flowspec_rule(
  state: ServerState,
  rule_id: String,
) -> ServerState {
  let updated_rules =
    list.filter(state.flowspec_rules, fn(r) { r.id != rule_id })
  let log_msg = "[flowspec] Deleted rule " <> rule_id
  ServerState(..state, flowspec_rules: updated_rules, event_log: [
    log_msg,
    ..state.event_log
  ])
}

pub fn get_flowspec_rules(state: ServerState) -> List(FlowspecRule) {
  state.flowspec_rules
}

pub fn get_damped_routes(
  state: ServerState,
  now_time: Int,
) -> List(DampedRoute) {
  damping_get_damped(state.damping_table, now_time, state.damping_config)
}

pub fn get_prometheus_metrics(state: ServerState) -> String {
  let metrics_data =
    DaemonMetricsData(
      asn: state.config.asn,
      router_id: state.config.router_id,
      peers: get_peer_stats_list(state),
      routes: get_all_routes(state.rib),
      fib_count: list.length(get_fib_routes(state)),
      roa_count: list.length(state.roa_table),
      flowspec_rules: state.flowspec_rules,
      damped_routes: get_damped_routes(state, now()),
    )
  render_prometheus_metrics(metrics_data)
}

pub fn get_peer_stats_list(state: ServerState) -> List(PeerStats) {
  dict.values(state.peers)
  |> list.map(fn(p) {
    let is_drained = list.contains(state.drained_peers, p.config.id)
    PeerStats(..p.stats, drained: is_drained)
  })
}

pub fn get_all_active_routes(state: ServerState) -> List(Route) {
  get_all_routes(state.rib)
}

pub fn get_fib_routes(state: ServerState) -> List(FibEntry) {
  kernel.get_installed_entries(state.fib)
}

/// Dynamically remove a peer and flush all its advertised routes from Loc-RIB
pub fn remove_peer(state: ServerState, peer_id: String) -> ServerState {
  let upd_rib = withdraw_all_from_peer(state.rib, peer_id)
  let updated_peers = dict.delete(state.peers, peer_id)
  let log_entry =
    "[peer] Removed peer " <> peer_id <> ", flushed routes from Loc-RIB"
  ServerState(..state, rib: upd_rib, peers: updated_peers, event_log: [
    log_entry,
    ..state.event_log
  ])
}

/// Dynamically reload daemon configuration without tearing down unaffected sessions
pub fn reload_config(
  state: ServerState,
  new_config: DaemonConfig,
) -> #(ServerState, List(String)) {
  let existing_ids = dict.keys(state.peers)
  let new_ids = list.map(new_config.peers, fn(p) { p.id })

  // Find added and removed peers
  let added_peers =
    list.filter(new_config.peers, fn(p) { !list.contains(existing_ids, p.id) })
  let removed_ids =
    list.filter(existing_ids, fn(id) { !list.contains(new_ids, id) })

  // Add new peers
  let state_with_added =
    list.fold(added_peers, state, fn(acc, p_cfg) { add_peer(acc, p_cfg) })

  // Gracefully close and remove defunct peers
  let state_with_removed =
    list.fold(removed_ids, state_with_added, fn(acc, rem_id) {
      remove_peer(acc, rem_id)
    })

  let events = [
    "[reload] Configuration reloaded",
    "[reload] Added " <> int.to_string(list.length(added_peers)) <> " new peers",
    "[reload] Removed " <> int.to_string(list.length(removed_ids)) <> " peers",
  ]

  let updated_state =
    ServerState(
      ..state_with_removed,
      config: new_config,
      event_log: list.append(events, state_with_removed.event_log),
    )

  #(updated_state, events)
}
