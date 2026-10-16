import gleam/int
import gleam/list
import gleam/string
import slopbgp/ip.{ipv4_to_string}
import slopbgp/types.{
  type DampedRoute, type FlowspecRule, type IpAddress, type PeerStats,
  type Route, Ipv4, StateActive, StateConnect, StateEstablished, StateIdle,
  StateOpenConfirm, StateOpenSent,
}

pub type DaemonMetricsData {
  DaemonMetricsData(
    asn: Int,
    router_id: IpAddress,
    peers: List(PeerStats),
    routes: List(Route),
    fib_count: Int,
    roa_count: Int,
    flowspec_rules: List(FlowspecRule),
    damped_routes: List(DampedRoute),
  )
}

pub fn render_prometheus_metrics(data: DaemonMetricsData) -> String {
  let router_id_str = case data.router_id {
    Ipv4(_, _, _, _) -> ipv4_to_string(data.router_id)
    _ -> "0.0.0.0"
  }

  let established_count =
    list.count(data.peers, fn(p) { p.state == StateEstablished })

  let #(v4_routes, v6_routes) =
    list.fold(data.routes, #(0, 0), fn(acc, r) {
      let #(v4, v6) = acc
      case r.prefix.address {
        Ipv4(_, _, _, _) -> #(v4 + 1, v6)
        _ -> #(v4, v6 + 1)
      }
    })

  let suppressed_count = list.count(data.damped_routes, fn(d) { d.suppressed })

  let lines = [
    "# HELP slopbgp_info SlopBGP daemon metadata",
    "# TYPE slopbgp_info gauge",
    "slopbgp_info{version=\"0.1.0\",asn=\""
      <> int.to_string(data.asn)
      <> "\",router_id=\""
      <> router_id_str
      <> "\"} 1",
    "",
    "# HELP slopbgp_peers_total Total number of configured peers",
    "# TYPE slopbgp_peers_total gauge",
    "slopbgp_peers_total " <> int.to_string(list.length(data.peers)),
    "",
    "# HELP slopbgp_peers_established Total number of established BGP peering sessions",
    "# TYPE slopbgp_peers_established gauge",
    "slopbgp_peers_established " <> int.to_string(established_count),
    "",
    "# HELP slopbgp_peer_state BGP FSM state of each peer (0=Idle, 1=Connect, 2=Active, 3=OpenSent, 4=OpenConfirm, 5=Established)",
    "# TYPE slopbgp_peer_state gauge",
  ]

  let peer_state_lines =
    list.map(data.peers, fn(p) {
      let state_val = case p.state {
        StateIdle -> 0
        StateConnect -> 1
        StateActive -> 2
        StateOpenSent -> 3
        StateOpenConfirm -> 4
        StateEstablished -> 5
      }
      "slopbgp_peer_state{peer=\""
      <> p.id
      <> "\",remote_as=\""
      <> int.to_string(p.remote_as)
      <> "\"} "
      <> int.to_string(state_val)
    })

  let peer_prefixes_rx =
    list.map(data.peers, fn(p) {
      "slopbgp_peer_prefixes_received_total{peer=\""
      <> p.id
      <> "\"} "
      <> int.to_string(p.prefixes_received)
    })

  let peer_prefixes_tx =
    list.map(data.peers, fn(p) {
      "slopbgp_peer_prefixes_advertised_total{peer=\""
      <> p.id
      <> "\"} "
      <> int.to_string(p.prefixes_advertised)
    })

  let peer_uptime =
    list.map(data.peers, fn(p) {
      "slopbgp_peer_uptime_seconds{peer=\""
      <> p.id
      <> "\"} "
      <> int.to_string(p.uptime_seconds)
    })

  let peer_updates_rx =
    list.map(data.peers, fn(p) {
      "slopbgp_peer_updates_received_total{peer=\""
      <> p.id
      <> "\"} "
      <> int.to_string(p.updates_received)
    })

  let global_metrics = [
    "",
    "# HELP slopbgp_loc_rib_routes_total Number of converged routes in Loc-RIB",
    "# TYPE slopbgp_loc_rib_routes_total gauge",
    "slopbgp_loc_rib_routes_total{family=\"ipv4\"} " <> int.to_string(v4_routes),
    "slopbgp_loc_rib_routes_total{family=\"ipv6\"} " <> int.to_string(v6_routes),
    "",
    "# HELP slopbgp_fib_routes_installed Routes installed into kernel FIB table",
    "# TYPE slopbgp_fib_routes_installed gauge",
    "slopbgp_fib_routes_installed " <> int.to_string(data.fib_count),
    "",
    "# HELP slopbgp_roa_rules_total Total ROA rules loaded into memory",
    "# TYPE slopbgp_roa_rules_total gauge",
    "slopbgp_roa_rules_total " <> int.to_string(data.roa_count),
    "",
    "# HELP slopbgp_flowspec_rules_total Active BGP Flowspec DDoS mitigation rules",
    "# TYPE slopbgp_flowspec_rules_total gauge",
    "slopbgp_flowspec_rules_total "
      <> int.to_string(list.length(data.flowspec_rules)),
    "",
    "# HELP slopbgp_damped_routes_total Routes tracked under RFC 2439 Flap Damping",
    "# TYPE slopbgp_damped_routes_total gauge",
    "slopbgp_damped_routes_total "
      <> int.to_string(list.length(data.damped_routes)),
    "",
    "# HELP slopbgp_suppressed_routes_total Routes currently suppressed due to flapping",
    "# TYPE slopbgp_suppressed_routes_total gauge",
    "slopbgp_suppressed_routes_total " <> int.to_string(suppressed_count),
  ]

  let all_sections =
    list.flatten([
      lines,
      peer_state_lines,
      [
        "",
        "# HELP slopbgp_peer_prefixes_received_total Prefixes received per peer",
        "# TYPE slopbgp_peer_prefixes_received_total counter",
      ],
      peer_prefixes_rx,
      [
        "",
        "# HELP slopbgp_peer_prefixes_advertised_total Prefixes advertised per peer",
        "# TYPE slopbgp_peer_prefixes_advertised_total counter",
      ],
      peer_prefixes_tx,
      [
        "",
        "# HELP slopbgp_peer_uptime_seconds Peer session uptime in seconds",
        "# TYPE slopbgp_peer_uptime_seconds gauge",
      ],
      peer_uptime,
      [
        "",
        "# HELP slopbgp_peer_updates_received_total BGP UPDATE messages received per peer",
        "# TYPE slopbgp_peer_updates_received_total counter",
      ],
      peer_updates_rx,
      global_metrics,
      [""],
    ])

  string.join(all_sections, "\n")
}
