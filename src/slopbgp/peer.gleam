import gleam/list
import gleam/option.{None, Some}
import slopbgp/bgp/fsm.{
  type FsmAction, type FsmEvent, type FsmSession, ActionCloseTcp, ActionConnect,
  ActionNone, ActionProcessRouteRefresh, ActionProcessUpdate,
  ActionResetHoldTimer, ActionSendKeepalive, ActionSendNotification,
  ActionSendOpen, ActionSessionEstablished, ActionStartHoldTimer,
  ActionStartKeepaliveTimer, EventTcpConnected, EventTcpFailed, handle_event,
  new_session,
}
import slopbgp/bgp/message.{encode_keepalive, encode_notification, encode_open}
import slopbgp/dn42/filter.{is_bogon, is_valid_dn42_network}
import slopbgp/dn42/roa.{extract_origin_asn, validate_route}
import slopbgp/ip.{ip_to_string}
import slopbgp/net/socket.{type Socket, close, connect, send}
import slopbgp/types.{
  type BgpCapability, type BgpMessage, type IpAddress, type IpPrefix,
  type PeerConfig, type PeerStats, type RoaEntry, type Route, AfiIpv4, AfiIpv6,
  AttrAsPath, AttrClusterList, AttrCommunities, AttrExtendedCommunities,
  AttrLargeCommunities, AttrLocalPref, AttrMed, AttrMpReachNlri,
  AttrMpUnreachNlri, AttrNextHop, AttrOnlyToCustomer, AttrOrigin,
  AttrOriginatorId, CapAddPath, CapEnhancedRouteRefresh, CapExtendedMessage,
  CapExtendedNextHop, CapFourOctetAsn, CapGracefulRestart, CapMultiProtocol,
  CapRouteRefresh, MsgUpdate, OriginIncomplete, PeerStats, RoaNotFound, Route,
  SafiUnicast, StateIdle,
}

pub type PeerHandle {
  PeerHandle(
    config: PeerConfig,
    fsm: FsmSession,
    stats: PeerStats,
    socket: option.Option(Socket),
    buffer: BitArray,
    last_keepalive_sent: Int,
    last_keepalive_received: Int,
  )
}

pub fn new_peer(config: PeerConfig) -> PeerHandle {
  let fsm =
    new_session(
      config.id,
      config.local_as,
      config.local_ip,
      config.remote_as,
      config.hold_time,
    )
  let stats =
    PeerStats(
      id: config.id,
      name: config.name,
      remote_as: config.remote_as,
      state: StateIdle,
      uptime_seconds: 0,
      prefixes_received: 0,
      prefixes_advertised: 0,
      updates_received: 0,
      updates_sent: 0,
      keepalives_received: 0,
      keepalives_sent: 0,
      last_error: None,
      last_shutdown_communication: None,
      drained: False,
    )
  PeerHandle(
    config: config,
    fsm: fsm,
    stats: stats,
    socket: option.None,
    buffer: <<>>,
    last_keepalive_sent: 0,
    last_keepalive_received: 0,
  )
}

pub fn default_capabilities(config: PeerConfig) -> List(BgpCapability) {
  let caps = [
    CapFourOctetAsn(config.local_as),
    CapRouteRefresh,
    CapEnhancedRouteRefresh,
    CapExtendedMessage,
    CapGracefulRestart(0, 120, [
      #(AfiIpv4, SafiUnicast, 0),
      #(AfiIpv6, SafiUnicast, 0),
    ]),
  ]

  let with_mp_v4 = case config.enable_ipv4 {
    True -> [CapMultiProtocol(AfiIpv4, SafiUnicast), ..caps]
    False -> caps
  }

  let with_mp_v6 = case config.enable_ipv6 {
    True -> [CapMultiProtocol(AfiIpv6, SafiUnicast), ..with_mp_v4]
    False -> with_mp_v4
  }

  let with_enh = case config.extended_next_hop {
    True -> [CapExtendedNextHop(AfiIpv4, SafiUnicast, AfiIpv6), ..with_mp_v6]
    False -> with_mp_v6
  }

  case config.add_path_rx, config.add_path_tx {
    False, False -> with_enh
    _, _ -> [
      CapAddPath(AfiIpv4, SafiUnicast, config.add_path_tx, config.add_path_rx),
      CapAddPath(AfiIpv6, SafiUnicast, config.add_path_tx, config.add_path_rx),
      ..with_enh
    ]
  }
}

pub fn process_fsm_actions(
  peer: PeerHandle,
  actions: List(FsmAction),
  now_time: Int,
) -> #(PeerHandle, List(BgpMessage)) {
  list.fold(actions, #(peer, []), fn(acc, action) {
    let #(p, msgs) = acc
    case action {
      ActionConnect -> {
        case p.config.passive {
          True -> #(p, msgs)
          False -> {
            let host = ip_to_string(p.config.remote_ip)
            case connect(host, p.config.port, 5000) {
              Ok(sock) -> {
                let #(p_conn, act_conn) =
                  handle_peer_event(p, EventTcpConnected, now_time)
                let p_with_sock = PeerHandle(..p_conn, socket: Some(sock))
                let #(final_p, new_msgs) =
                  process_fsm_actions(p_with_sock, act_conn, now_time)
                #(final_p, list.append(msgs, new_msgs))
              }
              Error(err) -> {
                let #(p_fail, act_fail) =
                  handle_peer_event(p, EventTcpFailed, now_time)
                let p_err =
                  PeerHandle(
                    ..p_fail,
                    stats: PeerStats(..p_fail.stats, last_error: Some(err)),
                  )
                let #(final_p, new_msgs) =
                  process_fsm_actions(p_err, act_fail, now_time)
                #(final_p, list.append(msgs, new_msgs))
              }
            }
          }
        }
      }

      ActionSendOpen -> {
        let caps = default_capabilities(p.config)
        let open_bytes =
          encode_open(
            4,
            p.config.local_as,
            p.config.hold_time,
            p.config.local_ip,
            caps,
          )
        case p.socket {
          Some(sock) -> {
            let _ = send(sock, open_bytes)
            #(p, msgs)
          }
          None -> #(p, msgs)
        }
      }

      ActionSendKeepalive -> {
        let ka_bytes = encode_keepalive()
        case p.socket {
          Some(sock) -> {
            let _ = send(sock, ka_bytes)
            let updated_stats =
              PeerStats(..p.stats, keepalives_sent: p.stats.keepalives_sent + 1)
            #(
              PeerHandle(
                ..p,
                stats: updated_stats,
                last_keepalive_sent: now_time,
              ),
              msgs,
            )
          }
          None -> #(p, msgs)
        }
      }

      ActionSendNotification(code, subcode, data) -> {
        let notif_bytes = encode_notification(code, subcode, data)
        case p.socket {
          Some(sock) -> {
            let _ = send(sock, notif_bytes)
            #(p, msgs)
          }
          None -> #(p, msgs)
        }
      }

      ActionCloseTcp -> {
        case p.socket {
          Some(sock) -> close(sock)
          None -> Nil
        }
        #(PeerHandle(..p, socket: None, buffer: <<>>), msgs)
      }

      ActionProcessUpdate(update_msg) -> {
        let updated_stats =
          PeerStats(..p.stats, updates_received: p.stats.updates_received + 1)
        #(PeerHandle(..p, stats: updated_stats), [update_msg, ..msgs])
      }

      ActionProcessRouteRefresh(refresh_msg) -> {
        #(p, [refresh_msg, ..msgs])
      }

      ActionResetHoldTimer -> {
        #(
          PeerHandle(
            ..p,
            last_keepalive_received: now_time,
            stats: PeerStats(
              ..p.stats,
              keepalives_received: p.stats.keepalives_received + 1,
            ),
          ),
          msgs,
        )
      }

      ActionSessionEstablished -> {
        let updated_stats = PeerStats(..p.stats, state: types.StateEstablished)
        #(PeerHandle(..p, stats: updated_stats), msgs)
      }

      ActionStartHoldTimer(_) | ActionStartKeepaliveTimer(_) | ActionNone -> {
        #(p, msgs)
      }
    }
  })
}

pub fn handle_peer_event(
  peer: PeerHandle,
  event: FsmEvent,
  _now_time: Int,
) -> #(PeerHandle, List(FsmAction)) {
  let #(new_fsm, actions) = handle_event(peer.fsm, event)
  let updated_stats = PeerStats(..peer.stats, state: new_fsm.state)
  #(PeerHandle(..peer, fsm: new_fsm, stats: updated_stats), actions)
}

pub fn extract_routes_from_update(
  msg: BgpMessage,
  peer_id: String,
  default_next_hop: IpAddress,
  roa_table: List(RoaEntry),
  now_time: Int,
) -> #(List(Route), List(IpPrefix)) {
  case msg {
    MsgUpdate(withdrawn, attrs, nlri) -> {
      // Extract common attributes
      let origin = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrOrigin(o) -> Ok(o)
            _ -> Error(Nil)
          }
        })
      {
        Ok(o) -> o
        Error(_) -> OriginIncomplete
      }

      let as_path = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrAsPath(segs) -> Ok(segs)
            _ -> Error(Nil)
          }
        })
      {
        Ok(segs) -> segs
        Error(_) -> []
      }

      let next_hop = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrNextHop(ip) -> Ok(ip)
            _ -> Error(Nil)
          }
        })
      {
        Ok(ip) -> ip
        Error(_) -> default_next_hop
      }

      let med = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrMed(m) -> Ok(m)
            _ -> Error(Nil)
          }
        })
      {
        Ok(m) -> m
        Error(_) -> 0
      }

      let local_pref = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrLocalPref(p) -> Ok(p)
            _ -> Error(Nil)
          }
        })
      {
        Ok(p) -> p
        Error(_) -> 100
      }

      let comms = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrCommunities(c) -> Ok(c)
            _ -> Error(Nil)
          }
        })
      {
        Ok(c) -> c
        Error(_) -> []
      }

      let large_comms = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrLargeCommunities(lc) -> Ok(lc)
            _ -> Error(Nil)
          }
        })
      {
        Ok(lc) -> lc
        Error(_) -> []
      }

      let ext_comms = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrExtendedCommunities(ec) -> Ok(ec)
            _ -> Error(Nil)
          }
        })
      {
        Ok(ec) -> ec
        Error(_) -> []
      }

      let otc =
        list.find_map(attrs, fn(a) {
          case a {
            AttrOnlyToCustomer(asn) -> Ok(asn)
            _ -> Error(Nil)
          }
        })
        |> option.from_result

      let originator_id =
        list.find_map(attrs, fn(a) {
          case a {
            AttrOriginatorId(id) -> Ok(id)
            _ -> Error(Nil)
          }
        })
        |> option.from_result

      let cluster_list = case
        list.find_map(attrs, fn(a) {
          case a {
            AttrClusterList(cls) -> Ok(cls)
            _ -> Error(Nil)
          }
        })
      {
        Ok(cls) -> cls
        Error(_) -> []
      }

      let origin_asn = extract_origin_asn(as_path)

      // 1. Process standard IPv4 NLRI
      let standard_routes =
        list.filter_map(nlri, fn(prefix) {
          case is_valid_dn42_network(prefix) && !is_bogon(prefix) {
            False -> Error(Nil)
            True -> {
              let roa_status = case origin_asn {
                Some(asn) -> validate_route(prefix, asn, roa_table)
                None -> RoaNotFound
              }
              Ok(Route(
                prefix: prefix,
                origin: origin,
                as_path: as_path,
                next_hop: next_hop,
                med: med,
                local_pref: local_pref,
                atomic_aggregate: False,
                communities: comms,
                large_communities: large_comms,
                ext_communities: ext_comms,
                otc: otc,
                roa_status: roa_status,
                peer_id: peer_id,
                timestamp: now_time,
                path_id: None,
                originator_id: originator_id,
                cluster_list: cluster_list,
              ))
            }
          }
        })

      // 2. Process MP_REACH_NLRI (IPv6 & Extended Next Hop IPv4)
      let mp_routes =
        list.fold(attrs, [], fn(acc, attr) {
          case attr {
            AttrMpReachNlri(_afi, _safi, nhs, mp_nlri) -> {
              let nh = case nhs {
                [first, ..] -> first
                [] -> default_next_hop
              }
              let valid_mp =
                list.filter_map(mp_nlri, fn(prefix) {
                  case is_valid_dn42_network(prefix) && !is_bogon(prefix) {
                    False -> Error(Nil)
                    True -> {
                      let roa_status = case origin_asn {
                        Some(asn) -> validate_route(prefix, asn, roa_table)
                        None -> RoaNotFound
                      }
                      Ok(Route(
                        prefix: prefix,
                        origin: origin,
                        as_path: as_path,
                        next_hop: nh,
                        med: med,
                        local_pref: local_pref,
                        atomic_aggregate: False,
                        communities: comms,
                        large_communities: large_comms,
                        ext_communities: ext_comms,
                        otc: otc,
                        roa_status: roa_status,
                        peer_id: peer_id,
                        timestamp: now_time,
                        path_id: None,
                        originator_id: originator_id,
                        cluster_list: cluster_list,
                      ))
                    }
                  }
                })
              list.append(acc, valid_mp)
            }
            _ -> acc
          }
        })

      // 3. Process MP_UNREACH_NLRI
      let mp_withdrawn =
        list.fold(attrs, [], fn(acc, attr) {
          case attr {
            AttrMpUnreachNlri(_afi, _safi, mp_w) -> list.append(acc, mp_w)
            _ -> acc
          }
        })

      let all_learned_routes = list.append(standard_routes, mp_routes)
      let all_withdrawn = list.append(withdrawn, mp_withdrawn)

      #(all_learned_routes, all_withdrawn)
    }

    _ -> #([], [])
  }
}
