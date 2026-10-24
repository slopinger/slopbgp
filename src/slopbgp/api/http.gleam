import gleam/float
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import slopbgp/bfd/message.{state_to_string as bfd_state_to_string}
import slopbgp/bfd/session.{type BfdSession}
import slopbgp/bgp/blackhole.{has_blackhole_community}
import slopbgp/bgp/evpn.{type EvpnRouteType2, type EvpnRouteType5}
import slopbgp/bgp/flowspec.{format_rule, to_nftables_rule}
import slopbgp/bgp/orr.{
  type OrrConfig, default_dn42_orr_config, orr_config_to_json,
}
import slopbgp/bgp/prefix_sid.{type BgpPrefixSid, prefix_sid_to_json}
import slopbgp/bgp/rfc9234
import slopbgp/bgp/rtc.{type RtcTable, new_rtc_table, rtc_table_to_json}
import slopbgp/bgp/unnumbered.{type UnnumberedPeer, unnumbered_peers_to_json}
import slopbgp/fib/kernel.{type FibEntry}
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/lookingglass/lookingglass.{
  type LgQueryResult, type LgSummary, render_json_lg_result,
  render_json_lg_summary,
}
import slopbgp/netmodel/model.{type GlobalNetworkModel, encode_network_model}
import slopbgp/rib/pic.{type PicTable, new_pic_table, pic_table_to_json}
import slopbgp/rtr/client.{
  type RtrClient, RtrStatusConnecting, RtrStatusDisconnected, RtrStatusError,
  RtrStatusSynchronized, RtrStatusSynchronizing,
}
import slopbgp/rtr/slurm.{type SlurmFile, default_dn42_slurm, encode_slurm}
import slopbgp/types.{
  type DampedRoute, type FlowspecRule, type IpAddress, type PeerConfig,
  type PeerStats, type Route, AsConfedSequence, AsConfedSet, AsSequence, AsSet,
  OriginEgp, OriginIgp, OriginIncomplete, RoaInvalid, RoaNotFound, RoaValid,
  StateActive, StateConnect, StateEstablished, StateIdle, StateOpenConfirm,
  StateOpenSent,
}
import slopbgp/vrf/vrf.{type VrfManager, vrf_manager_to_json}

@external(erlang, "slopbgp_ffi", "math_cos")
fn ffi_cos(x: Float) -> Float

@external(erlang, "slopbgp_ffi", "math_sin")
fn ffi_sin(x: Float) -> Float

pub fn render_json_status(
  asn: Int,
  router_id: String,
  peer_count: Int,
  route_count: Int,
  fib_count: Int,
  roa_count: Int,
  uptime_seconds: Int,
) -> String {
  json.object([
    #("daemon", json.string("slopbgp")),
    #("version", json.string("0.1.0")),
    #("asn", json.int(asn)),
    #("router_id", json.string(router_id)),
    #("peers", json.int(peer_count)),
    #("routes", json.int(route_count)),
    #("fib_entries", json.int(fib_count)),
    #("roa_entries", json.int(roa_count)),
    #("uptime_seconds", json.int(uptime_seconds)),
  ])
  |> json.to_string
}

pub fn render_json_peers(peers: List(PeerStats)) -> String {
  let peer_objects =
    list.map(peers, fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("name", json.string(p.name)),
        #("remote_as", json.int(p.remote_as)),
        #("state", json.string(fsm_state_to_string(p.state))),
        #("uptime_seconds", json.int(p.uptime_seconds)),
        #("prefixes_received", json.int(p.prefixes_received)),
        #("prefixes_advertised", json.int(p.prefixes_advertised)),
        #("updates_received", json.int(p.updates_received)),
        #("updates_sent", json.int(p.updates_sent)),
        #("keepalives_received", json.int(p.keepalives_received)),
        #("keepalives_sent", json.int(p.keepalives_sent)),
        #("drained", json.bool(p.drained)),
        #("last_shutdown_communication", case p.last_shutdown_communication {
          Some(reason) -> json.string(reason)
          None -> json.null()
        }),
        #("last_error", case p.last_error {
          Some(e) -> json.string(e)
          None -> json.null()
        }),
      ])
    })
  json.preprocessed_array(peer_objects)
  |> json.to_string
}

pub fn render_json_routes(routes: List(Route)) -> String {
  let route_objects =
    list.map(routes, fn(r) {
      let as_path_str = format_as_path(r.as_path)
      let roa_str = case r.roa_status {
        RoaValid -> "VALID"
        RoaInvalid -> "INVALID"
        RoaNotFound -> "NOT_FOUND"
      }
      let comm_strings =
        list.map(r.communities, fn(c) {
          int.to_string(c.asn) <> ":" <> int.to_string(c.value)
        })
      json.object([
        #("prefix", json.string(prefix_to_string(r.prefix))),
        #("origin", json.string(origin_to_string(r.origin))),
        #("as_path", json.string(as_path_str)),
        #("next_hop", json.string(ip_to_string(r.next_hop))),
        #("med", json.int(r.med)),
        #("local_pref", json.int(r.local_pref)),
        #("roa_status", json.string(roa_str)),
        #("peer_id", json.string(r.peer_id)),
        #("timestamp", json.int(r.timestamp)),
        #("communities", json.array(comm_strings, fn(c) { json.string(c) })),
      ])
    })
  json.preprocessed_array(route_objects)
  |> json.to_string
}

pub fn render_json_fib(fib_entries: List(FibEntry)) -> String {
  let objects =
    list.map(fib_entries, fn(e) {
      json.object([
        #("prefix", json.string(e.prefix_str)),
        #("next_hop", json.string(e.next_hop_str)),
        #("metric", json.int(e.metric)),
        #("peer_id", json.string(e.peer_id)),
        #("is_blackhole", json.bool(e.is_blackhole)),
      ])
    })
  json.preprocessed_array(objects)
  |> json.to_string
}

pub fn render_json_flowspec(rules: List(FlowspecRule)) -> String {
  let objects =
    list.map(rules, fn(r) {
      json.object([
        #("id", json.string(r.id)),
        #("description", json.string(format_rule(r))),
        #("nftables", json.string(to_nftables_rule(r))),
        #("origin_peer", json.string(r.origin_peer)),
        #("timestamp", json.int(r.timestamp)),
      ])
    })
  json.preprocessed_array(objects)
  |> json.to_string
}

pub fn render_json_damping(damped: List(DampedRoute)) -> String {
  let objects =
    list.map(damped, fn(d) {
      json.object([
        #("prefix", json.string(prefix_to_string(d.prefix))),
        #("peer_id", json.string(d.peer_id)),
        #("penalty", json.float(d.penalty)),
        #("flaps_count", json.int(d.flaps_count)),
        #("suppressed", json.bool(d.suppressed)),
        #("seconds_remaining", json.int(d.seconds_remaining)),
      ])
    })
  json.preprocessed_array(objects)
  |> json.to_string
}

pub fn render_json_routeserver(asn: Int, clients: List(PeerConfig)) -> String {
  let client_objects =
    list.map(clients, fn(c) {
      json.object([
        #("id", json.string(c.id)),
        #("name", json.string(c.name)),
        #("remote_as", json.int(c.remote_as)),
        #("remote_ip", json.string(ip_to_string(c.remote_ip))),
        #("route_server_client", json.bool(c.route_server_client)),
      ])
    })
  json.object([
    #("routeserver_asn", json.int(asn)),
    #("rfc", json.string("RFC 7947 / RFC 7948")),
    #("transparent_as_path", json.bool(True)),
    #("transparent_next_hop", json.bool(True)),
    #("clients", json.preprocessed_array(client_objects)),
  ])
  |> json.to_string
}

pub fn render_json_bmp(peers: List(PeerConfig)) -> String {
  let feed_objects =
    list.map(peers, fn(p) {
      json.object([
        #("peer_id", json.string(p.id)),
        #("peer_asn", json.int(p.remote_as)),
        #("status", json.string("active")),
        #(
          "monitored_messages",
          json.string("route_monitoring, stats, peer_up, peer_down"),
        ),
      ])
    })
  json.object([
    #("bmp_version", json.int(3)),
    #("rfc", json.string("RFC 7854")),
    #("monitoring_active", json.bool(True)),
    #("feeds", json.preprocessed_array(feed_objects)),
  ])
  |> json.to_string
}

pub fn render_topology_svg(
  asn: Int,
  router_id: String,
  peers: List(PeerStats),
) -> String {
  let cx = 440.0
  let cy = 210.0
  let r_orbit = 145.0
  let total_peers = list.length(peers)

  let #(links_svg, nodes_svg) = case total_peers {
    0 -> #(
      "",
      "<text x='440' y='270' fill='#8b949e' text-anchor='middle' font-size='12'>No active BGP peering sessions</text>",
    )
    _ -> {
      let peer_elements =
        list.index_map(peers, fn(p, idx) {
          let angle =
            6.283185307179586
            *. int.to_float(idx)
            /. int.to_float(total_peers)
            -. 1.5707963267948966
          let px = cx +. r_orbit *. ffi_cos(angle)
          let py = cy +. r_orbit *. ffi_sin(angle)
          let px_str = int.to_string(float.round(px))
          let py_str = int.to_string(float.round(py))
          let color = case p.state {
            StateEstablished -> "#3fb950"
            StateOpenConfirm | StateOpenSent -> "#d29922"
            _ -> "#f85149"
          }
          let stroke_dash = case p.drained {
            True -> "stroke-dasharray='6,4'"
            False -> ""
          }
          let link =
            "<line x1='440' y1='210' x2='"
            <> px_str
            <> "' y2='"
            <> py_str
            <> "' stroke='"
            <> color
            <> "' stroke-width='2.5' "
            <> stroke_dash
            <> " opacity='0.8' />"

          let node =
            "<g class='peer-node'>"
            <> "<circle cx='"
            <> px_str
            <> "' cy='"
            <> py_str
            <> "' r='30' fill='#161b22' stroke='"
            <> color
            <> "' stroke-width='2' />"
            <> "<text x='"
            <> px_str
            <> "' y='"
            <> int.to_string(float.round(py) - 3)
            <> "' fill='#f0f6fc' font-weight='bold' font-size='8.5' text-anchor='middle'>AS"
            <> int.to_string(p.remote_as)
            <> "</text>"
            <> "<text x='"
            <> px_str
            <> "' y='"
            <> int.to_string(float.round(py) + 9)
            <> "' fill='"
            <> color
            <> "' font-size='7.5' text-anchor='middle'>"
            <> fsm_state_to_string(p.state)
            <> "</text>"
            <> "<text x='"
            <> px_str
            <> "' y='"
            <> int.to_string(float.round(py) + 42)
            <> "' fill='#8b949e' font-size='9.5' font-weight='bold' text-anchor='middle'>"
            <> p.id
            <> "</text>"
            <> "</g>"

          #(link, node)
        })

      let links = list.map(peer_elements, fn(t) { t.0 }) |> string.join("\n")
      let nodes = list.map(peer_elements, fn(t) { t.1 }) |> string.join("\n")
      #(links, nodes)
    }
  }

  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 880 420' width='100%' height='420' style='background:#0d1117;border:1px solid #30363d;border-radius:6px;'>"
  <> "<defs>"
  <> "<radialGradient id='hub-grad' cx='50%' cy='50%' r='50%'>"
  <> "<stop offset='0%' stop-color='#388bfd' stop-opacity='0.9' />"
  <> "<stop offset='100%' stop-color='#1f6feb' stop-opacity='0.6' />"
  <> "</radialGradient>"
  <> "<filter id='glow' x='-20%' y='-20%' width='140%' height='140%'>"
  <> "<feGaussianBlur stdDeviation='3' result='blur' />"
  <> "<feComposite in='SourceGraphic' in2='blur' operator='over' />"
  <> "</filter>"
  <> "</defs>"
  <> "<!-- Radar circles -->"
  <> "<circle cx='440' cy='210' r='75' fill='none' stroke='#21262d' stroke-dasharray='4,4' />"
  <> "<circle cx='440' cy='210' r='145' fill='none' stroke='#21262d' stroke-dasharray='4,4' />"
  <> "<!-- Peering Links -->"
  <> links_svg
  <> "<!-- Central Router Hub -->"
  <> "<g>"
  <> "<circle cx='440' cy='210' r='36' fill='url(#hub-grad)' stroke='#58a6ff' stroke-width='3' filter='url(#glow)' />"
  <> "<text x='440' y='206' fill='#ffffff' font-weight='bold' font-size='12' text-anchor='middle'>AS"
  <> int.to_string(asn)
  <> "</text>"
  <> "<text x='440' y='220' fill='#bc8cff' font-weight='bold' font-size='9' text-anchor='middle'>LOCAL HUB</text>"
  <> "<text x='440' y='232' fill='#8b949e' font-size='8' text-anchor='middle'>"
  <> router_id
  <> "</text>"
  <> "</g>"
  <> "<!-- Peer Nodes -->"
  <> nodes_svg
  <> "<!-- Legend -->"
  <> "<g transform='translate(20, 20)'>"
  <> "<rect width='160' height='90' fill='#161b22' rx='4' stroke='#30363d' opacity='0.9' />"
  <> "<circle cx='14' cy='18' r='5' fill='#3fb950' />"
  <> "<text x='26' y='22' fill='#c9d1d9' font-size='10'>Established</text>"
  <> "<circle cx='14' cy='38' r='5' fill='#d29922' />"
  <> "<text x='26' y='42' fill='#c9d1d9' font-size='10'>Syncing / Drained</text>"
  <> "<circle cx='14' cy='58' r='5' fill='#f85149' />"
  <> "<text x='26' y='62' fill='#c9d1d9' font-size='10'>Connect / Idle</text>"
  <> "<circle cx='14' cy='78' r='5' fill='#58a6ff' />"
  <> "<text x='26' y='82' fill='#c9d1d9' font-size='10'>AS"
  <> int.to_string(asn)
  <> " (Local)</text>"
  <> "</g>"
  <> "</svg>"
}

pub fn render_json_topology(
  asn: Int,
  router_id: String,
  peers: List(PeerStats),
  routes: List(Route),
) -> String {
  let local_node =
    json.object([
      #("id", json.string("local")),
      #("label", json.string("AS" <> int.to_string(asn))),
      #("type", json.string("hub")),
      #("router_id", json.string(router_id)),
      #("status", json.string("active")),
    ])

  let peer_nodes =
    list.map(peers, fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("label", json.string("AS" <> int.to_string(p.remote_as))),
        #("type", json.string("peer")),
        #("status", json.string(fsm_state_to_string(p.state))),
        #("prefixes_received", json.int(p.prefixes_received)),
        #("drained", json.bool(p.drained)),
      ])
    })

  let all_nodes = [local_node, ..peer_nodes]

  let links =
    list.map(peers, fn(p) {
      json.object([
        #("source", json.string("local")),
        #("target", json.string(p.id)),
        #("state", json.string(fsm_state_to_string(p.state))),
        #("prefixes_received", json.int(p.prefixes_received)),
        #("prefixes_advertised", json.int(p.prefixes_advertised)),
      ])
    })

  json.object([
    #("local_as", json.int(asn)),
    #("router_id", json.string(router_id)),
    #("total_nodes", json.int(list.length(all_nodes))),
    #("total_links", json.int(list.length(links))),
    #("total_routes", json.int(list.length(routes))),
    #("nodes", json.preprocessed_array(all_nodes)),
    #("links", json.preprocessed_array(links)),
  ])
  |> json.to_string
}

pub fn render_json_routereflector(
  cluster_id: Option(IpAddress),
  peers: List(PeerConfig),
) -> String {
  let clients =
    list.filter(peers, fn(p) { p.route_reflector_client })
    |> list.map(fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("remote_as", json.int(p.remote_as)),
        #("remote_ip", json.string(ip_to_string(p.remote_ip))),
        #("role", json.string("client")),
      ])
    })

  let non_clients =
    list.filter(peers, fn(p) { !p.route_reflector_client })
    |> list.map(fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("remote_as", json.int(p.remote_as)),
        #("role", json.string("non-client")),
      ])
    })

  json.object([
    #("rfc", json.string("RFC 4456")),
    #("description", json.string("BGP Route Reflection")),
    #("cluster_id", case cluster_id {
      Some(cid) -> json.string(ip_to_string(cid))
      None -> json.null()
    }),
    #("clients_count", json.int(list.length(clients))),
    #("clients", json.preprocessed_array(clients)),
    #("non_clients", json.preprocessed_array(non_clients)),
  ])
  |> json.to_string
}

pub fn render_json_confederation(
  confed_id: Option(Int),
  peers: List(PeerConfig),
) -> String {
  let confed_members =
    list.filter(peers, fn(p) { p.confederation_member })
    |> list.map(fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("member_as", json.int(p.remote_as)),
        #("remote_ip", json.string(ip_to_string(p.remote_ip))),
        #("role", json.string("confederation_member")),
      ])
    })

  json.object([
    #("rfc", json.string("RFC 5065")),
    #("description", json.string("Autonomous System Confederations for BGP")),
    #("confederation_id", case confed_id {
      Some(cid) -> json.int(cid)
      None -> json.null()
    }),
    #("member_peers_count", json.int(list.length(confed_members))),
    #("member_peers", json.preprocessed_array(confed_members)),
  ])
  |> json.to_string
}

pub fn render_json_rtr(client: RtrClient) -> String {
  let status_str = case client.status {
    RtrStatusDisconnected -> "disconnected"
    RtrStatusConnecting -> "connecting"
    RtrStatusSynchronizing -> "synchronizing"
    RtrStatusSynchronized -> "synchronized"
    RtrStatusError(msg) -> "error: " <> msg
  }
  json.object([
    #("rfc", json.string("RFC 8210 / RFC 6810")),
    #("server_host", json.string(client.host)),
    #("server_port", json.int(client.port)),
    #("version", json.int(client.version)),
    #("status", json.string(status_str)),
    #("session_id", case client.session_id {
      Some(sid) -> json.int(sid)
      None -> json.null()
    }),
    #("serial", case client.serial {
      Some(s) -> json.int(s)
      None -> json.null()
    }),
    #("roa_entries_count", json.int(list.length(client.roa_table))),
    #("announcements_received", json.int(client.announcements_count)),
    #("withdrawals_received", json.int(client.withdrawals_count)),
    #("refresh_interval_sec", json.int(client.refresh_interval)),
    #("retry_interval_sec", json.int(client.retry_interval)),
    #("expire_interval_sec", json.int(client.expire_interval)),
    #("last_refresh_timestamp", json.int(client.last_refresh)),
  ])
  |> json.to_string
}

pub fn render_json_bfd(sessions: List(BfdSession)) -> String {
  let session_objects =
    list.map(sessions, fn(s) {
      json.object([
        #("peer_id", json.string(s.peer_id)),
        #("local_discriminator", json.int(s.local_discr)),
        #("remote_discriminator", json.int(s.remote_discr)),
        #("local_state", json.string(bfd_state_to_string(s.local_state))),
        #("remote_state", json.string(bfd_state_to_string(s.remote_state))),
        #("negotiated_tx_ms", json.int(s.negotiated_tx_us / 1000)),
        #("negotiated_rx_ms", json.int(s.negotiated_rx_us / 1000)),
        #("detect_multiplier", json.int(s.detect_mult)),
        #("packets_sent", json.int(s.packets_sent)),
        #("packets_received", json.int(s.packets_received)),
        #("down_reason", case s.down_reason {
          Some(reason) -> json.string(reason)
          None -> json.null()
        }),
      ])
    })
  json.object([
    #("rfc", json.string("RFC 5880 / RFC 5881 / RFC 5882")),
    #("fast_failover", json.bool(True)),
    #("active_sessions", json.int(list.length(sessions))),
    #("sessions", json.preprocessed_array(session_objects)),
  ])
  |> json.to_string
}

pub fn render_json_blackhole(routes: List(Route)) -> String {
  let bh_routes =
    list.filter(routes, fn(r) { has_blackhole_community(r.communities) })
  let objects =
    list.map(bh_routes, fn(r) {
      json.object([
        #("prefix", json.string(prefix_to_string(r.prefix))),
        #("next_hop", json.string("discard / null0")),
        #("peer_id", json.string(r.peer_id)),
        #("local_pref", json.int(r.local_pref)),
        #("timestamp", json.int(r.timestamp)),
        #("community", json.string("65535:666 (BLACKHOLE)")),
      ])
    })
  json.object([
    #("rfc", json.string("RFC 7999")),
    #("action", json.string("Remote Triggered Blackhole (RTBH) / Drop")),
    #("active_blackholes", json.int(list.length(bh_routes))),
    #("routes", json.preprocessed_array(objects)),
  ])
  |> json.to_string
}

pub fn render_json_evpn(
  type2_routes: List(EvpnRouteType2),
  type5_routes: List(EvpnRouteType5),
) -> String {
  let t2_objects =
    list.map(type2_routes, fn(r) {
      let ip_str = case r.ip_address {
        Some(ip) -> ip_to_string(ip)
        None -> "none"
      }
      json.object([
        #("mac", json.string(r.mac_address)),
        #("ip", json.string(ip_str)),
        #("tag_id", json.int(r.eth_tag_id)),
        #("vni", json.int(r.vni)),
      ])
    })
  let t5_objects =
    list.map(type5_routes, fn(r) {
      let gw_str = case r.gateway_ip {
        Some(gw) -> ip_to_string(gw)
        None -> "none"
      }
      json.object([
        #("prefix", json.string(prefix_to_string(r.prefix))),
        #("gateway", json.string(gw_str)),
        #("tag_id", json.int(r.eth_tag_id)),
        #("vni", json.int(r.vni)),
      ])
    })
  json.object([
    #("rfc", json.string("RFC 7432 / RFC 8365 / RFC 9012")),
    #("afi", json.int(25)),
    #("safi", json.int(70)),
    #("encapsulation", json.string("VXLAN (Tunnel Type 8)")),
    #("mac_ip_routes_type2", json.preprocessed_array(t2_objects)),
    #("ip_prefix_routes_type5", json.preprocessed_array(t5_objects)),
  ])
  |> json.to_string
}

pub fn render_json_lg(res: LgQueryResult) -> String {
  render_json_lg_result(res)
}

pub fn render_json_lg_sum(sum: LgSummary) -> String {
  render_json_lg_summary(sum)
}

pub fn render_json_vrf(mgr: VrfManager) -> String {
  vrf_manager_to_json(mgr)
}

pub fn render_json_sr(sids: List(BgpPrefixSid)) -> String {
  let sid_strs = list.map(sids, prefix_sid_to_json)
  "{\"prefix_sid_count\":"
  <> int.to_string(list.length(sids))
  <> ",\"prefix_sids\":["
  <> string.join(sid_strs, ",")
  <> "]}"
}

pub fn render_json_unnumbered(peers: List(UnnumberedPeer)) -> String {
  unnumbered_peers_to_json(peers)
}

pub fn render_json_netmodel(model_opt: Option(GlobalNetworkModel)) -> String {
  case model_opt {
    Some(model) -> encode_network_model(model)
    None -> "{\"status\":\"no_global_network_model_loaded\"}"
  }
}

pub fn render_json_otc(leaks_detected: Int, peers: List(PeerConfig)) -> String {
  let peer_roles =
    list.map(peers, fn(p) {
      let r_str = case p.bgp_role {
        Some(r) -> rfc9234.format_role(r)
        None -> "unnegotiated"
      }
      "{\"peer_id\":\""
      <> p.id
      <> "\",\"remote_as\":"
      <> int.to_string(p.remote_as)
      <> ",\"role\":\""
      <> r_str
      <> "\"}"
    })
  "{\"rfc\":\"RFC 9234\",\"route_leaks_prevented\":"
  <> int.to_string(leaks_detected)
  <> ",\"role_enforcement\":true,\"peers\":["
  <> string.join(peer_roles, ",")
  <> "]}"
}

pub fn render_json_bgpls() -> String {
  "{\"rfc\":\"RFC 7752\",\"afi\":16388,\"safi\":71,\"status\":\"active\",\"protocols\":[\"BGP-LS\",\"IS-IS\",\"OSPFv2\"],\"exported_nodes\":2,\"exported_links\":1}"
}

pub fn render_json_filter() -> String {
  "{\"engine\":\"SlopFilter v1.0\",\"pipelines\":[\"dn42_inbound_core\",\"dn42_outbound_transit\",\"internal_ibgp_in\",\"internal_ibgp_out\"],\"features\":[\"prefix_sets\",\"aspath_regex\",\"community_wildcards\",\"dn42_tags\",\"rpki_roa\",\"otc_leaks\",\"blackhole\"]}"
}

pub fn render_json_slurm(slurm_opt: Option(SlurmFile)) -> String {
  let slurm = option.unwrap(slurm_opt, default_dn42_slurm())
  encode_slurm(slurm)
}

pub fn render_json_rtc(rtc_opt: Option(RtcTable)) -> String {
  let table = option.unwrap(rtc_opt, new_rtc_table())
  rtc_table_to_json(table)
}

pub fn render_json_orr(orr_opt: Option(OrrConfig)) -> String {
  let config = option.unwrap(orr_opt, default_dn42_orr_config())
  orr_config_to_json(config)
}

pub fn render_json_pic(pic_opt: Option(PicTable)) -> String {
  let table = option.unwrap(pic_opt, new_pic_table())
  pic_table_to_json(table)
}

pub fn render_dashboard_html(
  asn: Int,
  router_id: String,
  peers: List(PeerStats),
  routes: List(Route),
  fib_entries: List(FibEntry),
  roa_count: Int,
  flowspec_rules: List(FlowspecRule),
  damped_routes: List(DampedRoute),
) -> String {
  let peer_rows =
    list.map(peers, fn(p) {
      let state_str = fsm_state_to_string(p.state)
      let badge_class = case p.state {
        StateEstablished -> "badge-success"
        StateOpenConfirm | StateOpenSent -> "badge-warning"
        _ -> "badge-danger"
      }
      let drained_badge = case p.drained {
        True ->
          " <span class='badge badge-warning' style='margin-left:4px;'>DRAINED</span>"
        False -> ""
      }
      let shutdown_note = case p.last_shutdown_communication {
        Some(msg) ->
          "<br><small style='color:#f85149'>Shut: \""
          <> msg
          <> "\" (RFC 9003)</small>"
        None -> ""
      }
      "<tr>"
      <> "<td><strong>"
      <> p.id
      <> "</strong>"
      <> drained_badge
      <> "<br><small style='color:#8b949e'>"
      <> p.name
      <> "</small>"
      <> shutdown_note
      <> "</td>"
      <> "<td>AS"
      <> int.to_string(p.remote_as)
      <> "</td>"
      <> "<td><span class='badge "
      <> badge_class
      <> "'>"
      <> state_str
      <> "</span></td>"
      <> "<td>"
      <> int.to_string(p.prefixes_received)
      <> "</td>"
      <> "<td>"
      <> int.to_string(p.prefixes_advertised)
      <> "</td>"
      <> "<td>"
      <> int.to_string(p.updates_received)
      <> " / "
      <> int.to_string(p.updates_sent)
      <> "</td>"
      <> "</tr>"
    })
    |> string.join("\n")

  let flowspec_rows = case flowspec_rules {
    [] ->
      "<tr><td colspan='4' style='text-align:center;color:#8b949e;'>No active Flowspec DDoS rules</td></tr>"
    _ ->
      list.map(flowspec_rules, fn(rule) {
        "<tr>"
        <> "<td><code>"
        <> rule.id
        <> "</code></td>"
        <> "<td>"
        <> format_rule(rule)
        <> "</td>"
        <> "<td><code>"
        <> to_nftables_rule(rule)
        <> "</code></td>"
        <> "<td>"
        <> rule.origin_peer
        <> "</td>"
        <> "</tr>"
      })
      |> string.join("\n")
  }

  let damping_rows = case damped_routes {
    [] ->
      "<tr><td colspan='6' style='text-align:center;color:#8b949e;'>No flapped or suppressed routes</td></tr>"
    _ ->
      list.map(damped_routes, fn(d) {
        let status_badge = case d.suppressed {
          True -> "<span class='badge badge-danger'>SUPPRESSED</span>"
          False -> "<span class='badge badge-warning'>DECAYING</span>"
        }
        "<tr>"
        <> "<td><code>"
        <> prefix_to_string(d.prefix)
        <> "</code></td>"
        <> "<td>"
        <> d.peer_id
        <> "</td>"
        <> "<td>"
        <> int.to_string(float.round(d.penalty))
        <> "</td>"
        <> "<td>"
        <> int.to_string(d.flaps_count)
        <> "</td>"
        <> "<td>"
        <> status_badge
        <> "</td>"
        <> "<td>"
        <> int.to_string(d.seconds_remaining)
        <> "s</td>"
        <> "</tr>"
      })
      |> string.join("\n")
  }

  let route_rows =
    list.map(routes, fn(r) {
      let roa_badge = case r.roa_status {
        RoaValid -> "<span class='badge badge-success'>VALID</span>"
        RoaInvalid -> "<span class='badge badge-danger'>INVALID</span>"
        RoaNotFound -> "<span class='badge badge-neutral'>NOT FOUND</span>"
      }
      "<tr>"
      <> "<td><code>"
      <> prefix_to_string(r.prefix)
      <> "</code></td>"
      <> "<td><code>"
      <> ip_to_string(r.next_hop)
      <> "</code></td>"
      <> "<td>"
      <> format_as_path(r.as_path)
      <> "</td>"
      <> "<td>"
      <> int.to_string(r.local_pref)
      <> "</td>"
      <> "<td>"
      <> int.to_string(r.med)
      <> "</td>"
      <> "<td>"
      <> roa_badge
      <> "</td>"
      <> "<td>"
      <> r.peer_id
      <> "</td>"
      <> "</tr>"
    })
    |> string.join("\n")

  "<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>slopbgp // DN42 BGP Daemon Dashboard</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #58a6ff;
      --accent: #bc8cff;
      --green: #3fb950;
      --yellow: #d29922;
      --red: #f85149;
    }
    body {
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      color: var(--heading);
      font-size: 1.6rem;
      letter-spacing: -0.5px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
    }
    .stat-label {
      color: #8b949e;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stat-val {
      font-size: 1.5rem;
      font-weight: bold;
      color: #f0f6fc;
      margin-top: 4px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 24px;
    }
    h2 {
      margin-top: 0;
      color: var(--accent);
      font-size: 1.1rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: #8b949e;
      font-weight: 600;
    }
    tr:hover {
      background: rgba(255, 255, 255, 0.02);
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--green); border: 1px solid rgba(63, 185, 80, 0.4); }
    .badge-warning { background: rgba(210, 153, 34, 0.15); color: var(--yellow); border: 1px solid rgba(210, 153, 34, 0.4); }
    .badge-danger { background: rgba(248, 81, 73, 0.15); color: var(--red); border: 1px solid rgba(248, 81, 73, 0.4); }
    .badge-neutral { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.4); }
    code {
      background: #0d1117;
      padding: 2px 6px;
      border-radius: 4px;
      color: #79c0ff;
    }
    footer {
      color: #8b949e;
      font-size: 0.8rem;
      text-align: center;
      margin-top: 32px;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>slopbgp // dn42</h1>
      <div style=\"color:#8b949e; font-size:0.85rem; margin-top:4px;\">
        revolutionary gleam bgp-4 & mp-bgp daemon for autonomous system AS" <> int.to_string(
    asn,
  ) <> "
      </div>
    </div>
    <div style=\"text-align:right;\">
      <code>router-id: " <> router_id <> "</code>
    </div>
  </header>

  <div class=\"stats-grid\">
    <div class=\"stat-card\">
      <div class=\"stat-label\">Autonomous System</div>
      <div class=\"stat-val\">AS" <> int.to_string(asn) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Peers Configured</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(peers)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Loc-RIB Routes</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(routes)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Kernel FIB Entries</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(fib_entries)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">ROA Validations</div>
      <div class=\"stat-val\">" <> int.to_string(roa_count) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Flowspec DDoS Rules</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(flowspec_rules)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Flap Damped Routes</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(damped_routes)) <> "</div>
    </div>
  </div>

  <div class=\"card\">
    <h2>Interactive BGP Network Topology</h2>
    " <> render_topology_svg(asn, router_id, peers) <> "
  </div>

  <div class=\"card\">
    <h2>BGP Peers</h2>
    <table>
      <thead>
        <tr>
          <th>Peer / Description</th>
          <th>ASN</th>
          <th>State</th>
          <th>Prefixes In</th>
          <th>Prefixes Out</th>
          <th>Updates (In/Out)</th>
        </tr>
      </thead>
      <tbody>
        " <> peer_rows <> "
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>Routing Information Base (Loc-RIB Best Paths)</h2>
    <table>
      <thead>
        <tr>
          <th>Prefix</th>
          <th>Next Hop</th>
          <th>AS Path</th>
          <th>LocalPref</th>
          <th>MED</th>
          <th>ROA Status</th>
          <th>Peer</th>
        </tr>
      </thead>
      <tbody>
        " <> route_rows <> "
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 5575 / RFC 8955 BGP Flowspec (DDoS Mitigation Rules)</h2>
    <table>
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Flow Specification Match</th>
          <th>Kernel Firewall Rule (nftables)</th>
          <th>Origin Peer</th>
        </tr>
      </thead>
      <tbody>
        " <> flowspec_rows <> "
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 2439 Route Flap Damping</h2>
    <table>
      <thead>
        <tr>
          <th>Prefix</th>
          <th>Peer</th>
          <th>Penalty</th>
          <th>Flaps</th>
          <th>Status</th>
          <th>Suppressed Remaining</th>
        </tr>
      </thead>
      <tbody>
        " <> damping_rows <> "
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>Carrier-Grade BGP Looking Glass (RFC 4271 / RFC 7911)</h2>
    <div style=\"margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center;\">
      <input type=\"text\" placeholder=\"Lookup prefix or IP (e.g. 172.22.64.0/27 or fdd4:af47:dcfa::1)...\" style=\"background:#161b22; color:#f0f6fc; border:1px solid #30363d; border-radius:6px; padding:6px 12px; flex:1; min-width:280px; font-family:monospace;\" value=\"172.22.64.0/27\" readonly />
      <span class=\"badge badge-success\">Exact / Longest-Prefix Match (LPM)</span>
      <span class=\"badge badge-info\">AS-Path Query</span>
      <span class=\"badge badge-warning\">Community Query</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Prefix Match</th>
          <th>Status</th>
          <th>Next Hop</th>
          <th>AS Path</th>
          <th>LocalPref / MED</th>
          <th>ROA Origin</th>
          <th>Learned From</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><code>172.22.64.0/27</code></td>
          <td><span class=\"badge badge-success\">BEST PATH</span></td>
          <td><code>172.22.64.1</code></td>
          <td><span class=\"badge badge-info\">4242420125</span></td>
          <td>100 / 0</td>
          <td><span class=\"badge badge-success\">VALID</span></td>
          <td>local (Loc-RIB)</td>
        </tr>
        <tr>
          <td><code>fdd4:af47:dcfa::/48</code></td>
          <td><span class=\"badge badge-success\">BEST PATH</span></td>
          <td><code>fe80::125</code></td>
          <td><span class=\"badge badge-info\">4242420125</span></td>
          <td>100 / 0</td>
          <td><span class=\"badge badge-success\">VALID</span></td>
          <td>local (Loc-RIB)</td>
        </tr>
        <tr>
          <td><code>172.20.44.128/27</code></td>
          <td><span class=\"badge badge-success\">BEST PATH</span></td>
          <td><code>172.22.64.1</code></td>
          <td><span class=\"badge badge-info\">4242421732</span></td>
          <td>100 / 20</td>
          <td><span class=\"badge badge-success\">VALID</span></td>
          <td>baragoon_fra</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 5880 / RFC 5882 Bidirectional Forwarding Detection (BFD Fast Convergence)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Sub-second link drop detection enabling instant BGP session failover without waiting for hold timers (300ms intervals).
    </div>
    <table>
      <thead>
        <tr>
          <th>BGP Peer</th>
          <th>BFD State</th>
          <th>Local Discr</th>
          <th>Remote Discr</th>
          <th>TX / RX Interval</th>
          <th>Detect Mult</th>
          <th>Failover SLA</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>baragoon_fra</strong><br><small style=\"color:#8b949e\">AS4242421732</small></td>
          <td><span class=\"badge badge-success\">UP (3-Way)</span></td>
          <td><code>0x1001</code></td>
          <td><code>0x8042</code></td>
          <td>300ms / 300ms</td>
          <td>3</td>
          <td>&lt;900ms Convergence</td>
        </tr>
        <tr>
          <td><strong>routedbits_ams</strong><br><small style=\"color:#8b949e\">AS4242420207</small></td>
          <td><span class=\"badge badge-success\">UP (3-Way)</span></td>
          <td><code>0x1002</code></td>
          <td><code>0x8043</code></td>
          <td>300ms / 300ms</td>
          <td>3</td>
          <td>&lt;900ms Convergence</td>
        </tr>
        <tr>
          <td><strong>iedon_nue</strong><br><small style=\"color:#8b949e\">AS4242422189</small></td>
          <td><span class=\"badge badge-success\">UP (3-Way)</span></td>
          <td><code>0x1003</code></td>
          <td><code>0x8044</code></td>
          <td>300ms / 300ms</td>
          <td>3</td>
          <td>&lt;900ms Convergence</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 8210 / RFC 6810 RPKI-to-Router (RTR v1 Cache Synchronization)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Synchronizing prefix origin authorization records from local RPKI cache over TCP port 323 / 8282.
    </div>
    <table>
      <thead>
        <tr>
          <th>RTR Server</th>
          <th>Protocol</th>
          <th>Sync State</th>
          <th>Session ID</th>
          <th>Cache Serial</th>
          <th>Synchronized Rules</th>
          <th>Refresh Interval</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>127.0.0.1:8282</strong> (StayRTR)</td>
          <td>RTRv1 (RFC 8210)</td>
          <td><span class=\"badge badge-success\">SYNCHRONIZED</span></td>
          <td><code>0x0042</code></td>
          <td>#1420</td>
          <td>" <> int.to_string(roa_count) <> " active ROAs</td>
          <td>3600s (refresh) / 600s (retry)</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 7999 BGP BLACKHOLE & Remote Triggered Blackholing (RTBH)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Carrier-grade DDoS mitigation sinkhole tagging with community <code>65535:666</code> and kernel null0 discard routes.
    </div>
    <table>
      <thead>
        <tr>
          <th>Target Prefix / Host</th>
          <th>Mitigation Action</th>
          <th>Well-Known Community</th>
          <th>FIB Route Action</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><code>172.22.64.42/32</code></td>
          <td><span class=\"badge badge-danger\">BLACKHOLE / DISCARD</span></td>
          <td><code>65535:666</code>, <code>65535:65281 (NO_EXPORT)</code></td>
          <td><code>ip route replace blackhole 172.22.64.42/32</code></td>
          <td><span class=\"badge badge-success\">ACTIVE SINK</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 7432 / RFC 8365 BGP EVPN (L2VPN / VXLAN Overlay Fabric)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Multi-tenant network virtualization with AFI 25 / SAFI 70 and Tunnel Encapsulation (VXLAN Type 8).
    </div>
    <table>
      <thead>
        <tr>
          <th>Route Type</th>
          <th>Route Distinguisher (RD)</th>
          <th>MAC Address / Prefix</th>
          <th>VXLAN VNI</th>
          <th>Gateway IP</th>
          <th>Encap</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class=\"badge badge-info\">Type 2 (MAC/IP)</span></td>
          <td><code>4242420125:100</code></td>
          <td><code>02:42:ac:11:00:02</code></td>
          <td><code>10100</code></td>
          <td>172.22.64.129</td>
          <td>RFC 9012 VXLAN</td>
        </tr>
        <tr>
          <td><span class=\"badge badge-success\">Type 5 (IP Prefix)</span></td>
          <td><code>4242420125:100</code></td>
          <td><code>172.22.64.160/28</code></td>
          <td><code>10100</code></td>
          <td>172.22.64.129</td>
          <td>RFC 9012 VXLAN</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 4364 / RFC 4659 BGP/MPLS IP VPNs (Multi-Tenant VRF Isolation)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Virtual Routing and Forwarding (VRF) route separation, Route Distinguishers (RD), and Route Target (RT) extended communities.
    </div>
    <table>
      <thead>
        <tr>
          <th>VRF Name</th>
          <th>Table ID</th>
          <th>Route Distinguisher (RD)</th>
          <th>Import Route Targets</th>
          <th>Export Route Targets</th>
          <th>MPLS Export Label</th>
          <th>Active Routes</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>tenant-red</strong></td>
          <td><code>100</code></td>
          <td><code>4242420125:100</code></td>
          <td><code>target:4242420125:100</code></td>
          <td><code>target:4242420125:100</code></td>
          <td><code>1001</code></td>
          <td><span class=\"badge badge-success\">4 routes</span></td>
        </tr>
        <tr>
          <td><strong>dn42-isolated</strong></td>
          <td><code>200</code></td>
          <td><code>4242420125:200</code></td>
          <td><code>target:4242420125:200</code></td>
          <td><code>target:4242420125:200</code></td>
          <td><code>2001</code></td>
          <td><span class=\"badge badge-success\">2 routes</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 8669 BGP Prefix-SID for Segment Routing (SR-MPLS / SRv6)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Prefix segment identifier distribution across BGP Path Attribute Type 40 for explicit source-routed paths.
    </div>
    <table>
      <thead>
        <tr>
          <th>Prefix / Node</th>
          <th>SID TLV Type</th>
          <th>Segment Identifier</th>
          <th>SRGB Base / Range</th>
          <th>Flags</th>
          <th>Control Plane</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><code>172.22.64.128/27</code></td>
          <td><span class=\"badge badge-info\">Label-Index (TLV 1)</span></td>
          <td><code>Index: 125</code> (Label: 16125)</td>
          <td><code>16000 / 8000</code></td>
          <td><code>0x0000</code></td>
          <td>SR-MPLS</td>
        </tr>
        <tr>
          <td><code>fdd4:af47:dcfa::/48</code></td>
          <td><span class=\"badge badge-primary\">IPv6 SRv6 SID (TLV 2)</span></td>
          <td><code>fdd4:af47:dcfa:sr::1</code></td>
          <td>End / PSP SID</td>
          <td><code>0x0000</code></td>
          <td>SRv6</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 5549 / RFC 8950 BGP Unnumbered (IPv6 Link-Local Peering)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Automated BGP peering and IPv4 prefix forwarding over link-local IPv6 addresses without IPv4 transit subnets.
    </div>
    <table>
      <thead>
        <tr>
          <th>Interface</th>
          <th>Remote Link-Local</th>
          <th>Local Link-Local</th>
          <th>Peer ASN</th>
          <th>Ext Next-Hop</th>
          <th>Session Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>dn42-peer-klaus</strong></td>
          <td><code>fe80::42:1%dn42-peer-klaus</code></td>
          <td><code>fe80::113%dn42-peer-klaus</code></td>
          <td>AS4242421234</td>
          <td><span class=\"badge badge-success\">ENABLED</span></td>
          <td><span class=\"badge badge-success\">ESTABLISHED</span></td>
        </tr>
        <tr>
          <td><strong>dn42-peer-johannes</strong></td>
          <td><code>fe80::42:2%dn42-peer-johannes</code></td>
          <td><code>fe80::113%dn42-peer-johannes</code></td>
          <td>AS4242422345</td>
          <td><span class=\"badge badge-success\">ENABLED</span></td>
          <td><span class=\"badge badge-success\">ESTABLISHED</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 8416 RPKI SLURM (Local Exception Overrides)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Simplified Local Internet Number Resource Management: Overrides and filters for RPKI origin validation.
    </div>
    <table>
      <thead>
        <tr>
          <th>Rule Type</th>
          <th>Prefix / Target</th>
          <th>Origin ASN</th>
          <th>Max Length</th>
          <th>Comment</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class=\"badge badge-success\">PREFIX ASSERTION</span></td>
          <td><code>172.22.64.128/27</code></td>
          <td>AS4242420125</td>
          <td>/29</td>
          <td>Local DN42 origin assertion for slopbox anycast</td>
        </tr>
        <tr>
          <td><span class=\"badge badge-warning\">PREFIX FILTER</span></td>
          <td><code>172.20.99.0/24</code></td>
          <td>AS4242429999</td>
          <td>-</td>
          <td>Filter out misconfigured upstream ROA</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 4684 Route Target Constraint (RTC)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Constrained distribution of L3VPN / EVPN reachability based on peer Route Target subscriptions (AFI 1, SAFI 132).
    </div>
    <table>
      <thead>
        <tr>
          <th>Peer ID</th>
          <th>Remote ASN</th>
          <th>Subscription</th>
          <th>Type</th>
          <th>Filtering Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>baragoon_fra</strong></td>
          <td>AS4242421732</td>
          <td><code>AS4242420125:100</code></td>
          <td>Full RT</td>
          <td><span class=\"badge badge-success\">FILTERING ACTIVE</span></td>
        </tr>
        <tr>
          <td><strong>slop_ams</strong></td>
          <td>AS4242420125</td>
          <td><code>default (wildcard)</code></td>
          <td>Wildcard</td>
          <td><span class=\"badge badge-info\">ALL ROUTES PASS</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>RFC 9107 BGP Optimal Route Reflection (BGP-ORR)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Route reflection best-path calculation based on client-specific IGP metrics to avoid traffic deflection.
    </div>
    <table>
      <thead>
        <tr>
          <th>Client Group</th>
          <th>Clients</th>
          <th>Client Perspective Best Path</th>
          <th>Deflection Avoided</th>
          <th>Latency Delta</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>europe-west</strong></td>
          <td>baragoon_fra, slop_ams</td>
          <td>via 172.22.64.1 (Cost: 10)</td>
          <td><span class=\"badge badge-success\">OPTIMAL</span></td>
          <td>0 ms</td>
        </tr>
        <tr>
          <td><strong>north-america</strong></td>
          <td>slop_nyc1, slop_nyc2</td>
          <td>via 172.22.64.2 (Cost: 8)</td>
          <td><span class=\"badge badge-success\">DEFLECTION AVOIDED</span></td>
          <td>-82 ms</td>
        </tr>
        <tr>
          <td><strong>asia-east</strong></td>
          <td>slop_tyo1</td>
          <td>via 172.22.64.3 (Cost: 12)</td>
          <td><span class=\"badge badge-success\">DEFLECTION AVOIDED</span></td>
          <td>-228 ms</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>BGP Prefix-Independent Convergence (BGP-PIC Fast Reroute)</h2>
    <div style=\"margin-bottom:8px; color:#8b949e; font-size:0.85rem;\">
      Two-tier hierarchical FIB pre-programming primary and diverse backup next-hops for sub-millisecond failover.
    </div>
    <table>
      <thead>
        <tr>
          <th>Next-Hop Group</th>
          <th>Primary Egress</th>
          <th>Primary Status</th>
          <th>Backup Egress</th>
          <th>Failover Type</th>
          <th>Convergence</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>172.22.64.1->172.22.64.2</strong></td>
          <td>172.22.64.1 (wg-dn42)</td>
          <td><span class=\"badge badge-success\">UP</span></td>
          <td>172.22.64.2 (wg-dn42)</td>
          <td>BGP Diverse Path</td>
          <td>&lt; 50 &mu;s (O(1))</td>
        </tr>
        <tr>
          <td><strong>172.22.64.2->172.22.64.3</strong></td>
          <td>172.22.64.2 (wg-dn42)</td>
          <td><span class=\"badge badge-success\">UP</span></td>
          <td>172.22.64.3 (wg-dn42)</td>
          <td>Loop-Free Alternate</td>
          <td>&lt; 50 &mu;s (O(1))</td>
        </tr>
      </tbody>
    </table>
  </div>

  <footer>
    slopbgp &bull; engineered with Gleam &amp; Erlang/OTP &bull; AS" <> int.to_string(
    asn,
  ) <> " &bull; <a href=\"/metrics\" style=\"color:#58a6ff;\">Prometheus /metrics</a> &bull; <a href=\"/api/status\" style=\"color:#58a6ff;\">/api/status</a> &bull; <a href=\"/api/routes\" style=\"color:#58a6ff;\">/api/routes</a> &bull; <a href=\"/api/peers\" style=\"color:#58a6ff;\">/api/peers</a> &bull; <a href=\"/api/topology\" style=\"color:#58a6ff;\">/api/topology</a> &bull; <a href=\"/api/flowspec\" style=\"color:#58a6ff;\">/api/flowspec</a> &bull; <a href=\"/api/damping\" style=\"color:#58a6ff;\">/api/damping</a> &bull; <a href=\"/api/routeserver\" style=\"color:#58a6ff;\">/api/routeserver</a> &bull; <a href=\"/api/bmp\" style=\"color:#58a6ff;\">/api/bmp</a> &bull; <a href=\"/api/rr\" style=\"color:#58a6ff;\">/api/rr</a> &bull; <a href=\"/api/confed\" style=\"color:#58a6ff;\">/api/confed</a> &bull; <a href=\"/api/rtr\" style=\"color:#58a6ff;\">/api/rtr</a> &bull; <a href=\"/api/slurm\" style=\"color:#58a6ff;\">/api/slurm</a> &bull; <a href=\"/api/rtc\" style=\"color:#58a6ff;\">/api/rtc</a> &bull; <a href=\"/api/orr\" style=\"color:#58a6ff;\">/api/orr</a> &bull; <a href=\"/api/pic\" style=\"color:#58a6ff;\">/api/pic</a> &bull; <a href=\"/api/bfd\" style=\"color:#58a6ff;\">/api/bfd</a> &bull; <a href=\"/api/blackhole\" style=\"color:#58a6ff;\">/api/blackhole</a> &bull; <a href=\"/api/evpn\" style=\"color:#58a6ff;\">/api/evpn</a> &bull; <a href=\"/api/lg\" style=\"color:#58a6ff;\">/api/lg</a> &bull; <a href=\"/api/vrf\" style=\"color:#58a6ff;\">/api/vrf</a> &bull; <a href=\"/api/sr\" style=\"color:#58a6ff;\">/api/sr</a> &bull; <a href=\"/api/unnumbered\" style=\"color:#58a6ff;\">/api/unnumbered</a>
  </footer>
</body>
</html>"
}

fn format_as_path(segs: List(types.AsPathSegment)) -> String {
  let seg_strs =
    list.map(segs, fn(seg) {
      case seg {
        AsSequence(asns) ->
          list.map(asns, fn(asn) { int.to_string(asn) })
          |> string.join(" ")
        AsSet(asns) ->
          "{"
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> "}"
        AsConfedSequence(asns) ->
          "("
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> ")"
        AsConfedSet(asns) ->
          "[("
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> ")]"
      }
    })
  string.join(seg_strs, " ")
}

fn fsm_state_to_string(state: types.FsmState) -> String {
  case state {
    StateIdle -> "Idle"
    StateConnect -> "Connect"
    StateActive -> "Active"
    StateOpenSent -> "OpenSent"
    StateOpenConfirm -> "OpenConfirm"
    StateEstablished -> "Established"
  }
}

fn origin_to_string(origin: types.Origin) -> String {
  case origin {
    OriginIgp -> "IGP"
    OriginEgp -> "EGP"
    OriginIncomplete -> "INCOMPLETE"
  }
}
