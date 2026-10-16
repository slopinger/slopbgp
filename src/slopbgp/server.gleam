import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import simplifile
import slopbgp/bgp/fsm.{EventHoldTimerExpires, EventKeepaliveTimerExpires}
import slopbgp/bgp/message.{encode_message}
import slopbgp/config.{type DaemonConfig}
import slopbgp/dn42/roa.{parse_roa_content}
import slopbgp/fib/kernel.{type FibEntry, type FibState, new_fib, sync_fib}
import slopbgp/net/socket.{now, send}
import slopbgp/peer.{
  type PeerHandle, PeerHandle, extract_routes_from_update, handle_peer_event,
  new_peer, process_fsm_actions,
}
import slopbgp/rib/rib.{
  type Rib, get_all_routes, insert_route, new_rib, prepare_outbound_route,
  withdraw_all_from_peer, withdraw_route,
}
import slopbgp/types.{
  type BgpMessage, type PeerConfig, type PeerStats, type RoaEntry, type Route,
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
      let #(learned, withdrawn) =
        extract_routes_from_update(
          update_msg,
          peer_id,
          peer_handle.config.remote_ip,
          state.roa_table,
          now_time,
        )

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

      // Withdraw routes from RIB
      let rib_final =
        list.fold(withdrawn, rib_after_learn, fn(curr_rib, prefix) {
          let #(upd_rib, _) = withdraw_route(curr_rib, peer_id, prefix)
          upd_rib
        })

      // Propagate changed best routes to other peers (Adj-RIB-Out)
      let state_propagated =
        propagate_routes_to_peers(
          ServerState(..state, rib: rib_final),
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
                // Prepare outbound routes for this peer
                let outbound_routes =
                  list.filter_map(routes_to_send, fn(r) {
                    case
                      prepare_outbound_route(
                        r,
                        target_peer.config,
                        target_peer.config.local_ip,
                      )
                    {
                      Some(prepared) -> Ok(prepared)
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

pub fn get_peer_stats_list(state: ServerState) -> List(PeerStats) {
  dict.values(state.peers)
  |> list.map(fn(p) { p.stats })
}

pub fn get_all_active_routes(state: ServerState) -> List(Route) {
  get_all_routes(state.rib)
}

pub fn get_fib_routes(state: ServerState) -> List(FibEntry) {
  kernel.get_installed_entries(state.fib)
}
