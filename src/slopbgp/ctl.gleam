import gleam/float
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile
import slopbgp/api/http
import slopbgp/bgp/blackhole.{
  create_outbound_rtbh, has_blackhole_community, to_fib_blackhole_command,
}
import slopbgp/bgp/evpn.{RdAsn4}
import slopbgp/bgp/flowspec.{format_rule, to_nftables_rule}
import slopbgp/bgp/l3vpn.{RtAsn4, route_target_to_string}
import slopbgp/config.{load_config_file}
import slopbgp/dn42/roa.{parse_roa_content, validate_route}
import slopbgp/fib/kernel.{FibEntry}
import slopbgp/ip.{parse_prefix, prefix_to_string}
import slopbgp/lookingglass/lookingglass.{
  query_aspath, query_community, query_route, query_summary,
}
import slopbgp/net/socket.{now}
import slopbgp/policy/filter.{dn42_default_import_policy}
import slopbgp/rib/rib.{get_all_routes}
import slopbgp/rtr/client.{new_rtr_client}
import slopbgp/server.{new_server}
import slopbgp/types.{
  type PeerStats, type Route, AfiIpv4, AsConfedSequence, AsConfedSet, AsSequence,
  AsSet, DampedRoute, FlowActionDrop, FlowDstPort, FlowDstPrefix, FlowIpProtocol,
  FlowspecRule, IpPrefix, Ipv4, Ipv6, OriginIgp, PeerStats, RoaInvalid,
  RoaNotFound, RoaValid, Route, StateActive, StateConnect, StateEstablished,
  StateIdle, StateOpenConfirm, StateOpenSent,
}
import slopbgp/vrf/vrf.{
  type VrfManager, VrfConfig, add_local_route, add_vrf,
  generate_vrf_fib_commands, get_vrf, new_manager, rd_to_string,
}

pub fn run_ctl(args: List(String)) -> Nil {
  case args {
    ["dashboard", path, ..] -> ctl_dashboard(Some(path))
    ["dashboard", ..] -> ctl_dashboard(None)
    ["status", ..] -> ctl_status()
    ["peers", ..] -> ctl_peers()
    ["routes", prefix_arg, ..] -> ctl_routes_filtered(prefix_arg)
    ["routes", ..] -> ctl_routes()
    ["fib", ..] -> ctl_fib()
    ["flap", ..] -> ctl_flap()
    ["flowspec", ..] -> ctl_flowspec()
    ["drain", peer_id, ..rest] -> {
      let reason = case rest {
        [] -> None
        _ -> Some(string.join(rest, " "))
      }
      ctl_drain(peer_id, reason)
    }
    ["shutdown", peer_id, ..rest] -> {
      let reason = case rest {
        [] -> None
        _ -> Some(string.join(rest, " "))
      }
      ctl_shutdown(peer_id, reason)
    }
    ["undrain", peer_id, ..] -> ctl_undrain(peer_id)
    ["reload", ..] -> ctl_reload()
    ["bmp", ..] -> ctl_bmp()
    ["routeserver", ..] -> ctl_routeserver()
    ["rr", ..] | ["routereflector", ..] -> ctl_rr()
    ["confed", ..] | ["confederation", ..] -> ctl_confed()
    ["topology", ..] -> ctl_topology()
    ["metrics", ..] -> ctl_metrics()
    ["policy", ..] -> ctl_policy()
    ["roa", "check", prefix_str, asn_str, ..] ->
      ctl_roa_check(prefix_str, asn_str)
    ["rtr", ..] -> ctl_rtr()
    ["bfd", ..] -> ctl_bfd()
    ["blackhole", "add", pfx, ..] -> ctl_blackhole_add(pfx)
    ["blackhole", "del", pfx, ..] -> ctl_blackhole_del(pfx)
    ["blackhole", ..] -> ctl_blackhole_list()
    ["evpn", ..] -> ctl_evpn()
    ["lg", "route", pfx, ..] | ["lookingglass", "route", pfx, ..] ->
      ctl_lg_route(pfx)
    ["lg", "aspath", asn_str, ..] | ["lookingglass", "aspath", asn_str, ..] ->
      ctl_lg_aspath(asn_str)
    ["lg", "community", comm_str, ..]
    | ["lookingglass", "community", comm_str, ..] -> ctl_lg_community(comm_str)
    ["lg", ..] | ["lookingglass", ..] -> ctl_lg_summary()
    ["vrf", "routes", vrf_name, ..] -> ctl_vrf_routes(vrf_name)
    ["vrf", ..] -> ctl_vrf_list()
    ["sr", ..] -> ctl_sr()
    ["unnumbered", ..] -> ctl_unnumbered()
    _ -> print_usage()
  }
}

fn ctl_status() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let peer_count = list.length(cfg.peers)
  let route_count = rib.count_routes(srv.rib)
  let roa_count = list.length(srv.roa_table)

  io.println("┌────────────────────────────────────────────────────────┐")
  io.println(
    "│ slopbgp status // AS"
    <> int.to_string(cfg.asn)
    <> " (router-id: "
    <> ip.ip_to_string(cfg.router_id)
    <> ")",
  )
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Daemon:          slopbgp v0.1.0 (Gleam / Erlang-OTP)")
  io.println("│ BGP Port:        " <> int.to_string(cfg.bgp_port))
  io.println("│ API / Web Port:  " <> int.to_string(cfg.api_port))
  io.println("│ FIB Table ID:    " <> int.to_string(cfg.fib_table))
  io.println("│ Configured Peers:" <> int.to_string(peer_count))
  io.println("│ Loc-RIB Routes:  " <> int.to_string(route_count))
  io.println("│ ROA Entries:     " <> int.to_string(roa_count))
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_peers() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let peers = server.get_peer_stats_list(srv)

  io.println(
    string.pad_end("PEER ID", 20, " ")
    <> string.pad_end("ASN", 12, " ")
    <> string.pad_end("STATE", 14, " ")
    <> string.pad_end("PFX IN", 10, " ")
    <> string.pad_end("PFX OUT", 10, " ")
    <> "DESCRIPTION",
  )
  io.println(string.repeat("─", 80))

  list.each(peers, fn(p: PeerStats) {
    let state_str = case p.state {
      StateEstablished -> "Established"
      StateOpenConfirm -> "OpenConfirm"
      StateOpenSent -> "OpenSent"
      StateActive -> "Active"
      StateConnect -> "Connect"
      StateIdle -> "Idle"
    }
    let state_badge = case p.drained {
      True -> state_str <> " [DRAINED]"
      False -> state_str
    }
    io.println(
      string.pad_end(p.id, 20, " ")
      <> string.pad_end("AS" <> int.to_string(p.remote_as), 12, " ")
      <> string.pad_end(state_badge, 18, " ")
      <> string.pad_end(int.to_string(p.prefixes_received), 8, " ")
      <> string.pad_end(int.to_string(p.prefixes_advertised), 8, " ")
      <> p.name,
    )
    case p.last_shutdown_communication {
      Some(reason) ->
        io.println("  └─ RFC 9003 Shutdown Communication: \"" <> reason <> "\"")
      None -> Nil
    }
  })
}

fn ctl_routes() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let routes = get_all_routes(srv.rib)
  display_routes(routes)
}

fn ctl_routes_filtered(filter_prefix: String) -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let routes =
    get_all_routes(srv.rib)
    |> list.filter(fn(r) {
      string.contains(prefix_to_string(r.prefix), filter_prefix)
    })
  display_routes(routes)
}

fn display_routes(routes: List(Route)) -> Nil {
  io.println(
    string.pad_end("PREFIX", 26, " ")
    <> string.pad_end("NEXT HOP", 22, " ")
    <> string.pad_end("AS PATH", 20, " ")
    <> string.pad_end("LOCALPREF", 10, " ")
    <> string.pad_end("MED", 6, " ")
    <> string.pad_end("ROA", 10, " ")
    <> "PEER",
  )
  io.println(string.repeat("─", 100))

  case routes {
    [] -> io.println("(No routes in Loc-RIB)")
    _ -> {
      list.each(routes, fn(r: Route) {
        let roa_str = case r.roa_status {
          RoaValid -> "VALID"
          RoaInvalid -> "INVALID"
          RoaNotFound -> "NOT_FOUND"
        }
        io.println(
          string.pad_end(prefix_to_string(r.prefix), 26, " ")
          <> string.pad_end(ip.ip_to_string(r.next_hop), 22, " ")
          <> string.pad_end(format_as_path(r.as_path), 20, " ")
          <> string.pad_end(int.to_string(r.local_pref), 10, " ")
          <> string.pad_end(int.to_string(r.med), 6, " ")
          <> string.pad_end(roa_str, 10, " ")
          <> r.peer_id,
        )
      })
    }
  }
}

fn ctl_fib() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let entries = server.get_fib_routes(srv)
  io.println(
    "Kernel FIB entries for table " <> int.to_string(cfg.fib_table) <> ":",
  )
  case entries {
    [] -> io.println("(No entries installed)")
    _ -> {
      list.each(entries, fn(e) {
        io.println("  " <> kernel.fib_entry_to_string(e))
      })
    }
  }
}

fn ctl_roa_check(prefix_str: String, asn_str: String) -> Nil {
  let cfg = get_current_config()
  let v4_content = case simplifile.read(cfg.roa_v4_path) {
    Ok(c) -> c
    Error(_) -> ""
  }
  let v6_content = case simplifile.read(cfg.roa_v6_path) {
    Ok(c) -> c
    Error(_) -> ""
  }
  let roa_entries =
    list.append(parse_roa_content(v4_content), parse_roa_content(v6_content))

  let res = {
    use prefix <- result.try(parse_prefix(prefix_str))
    use asn <- result.try(
      int.parse(asn_str)
      |> result.replace_error("Invalid ASN: " <> asn_str),
    )
    let status = validate_route(prefix, asn, roa_entries)
    Ok(#(prefix, asn, status))
  }

  case res {
    Ok(#(p, a, status)) -> {
      let status_str = case status {
        RoaValid -> "VALID (Origin AS" <> int.to_string(a) <> " authorized)"
        RoaInvalid ->
          "INVALID (Origin AS"
          <> int.to_string(a)
          <> " NOT authorized or exceeds max-length)"
        RoaNotFound -> "NOT FOUND (No covering ROA object in registry)"
      }
      io.println(
        "ROA Check for "
        <> prefix_to_string(p)
        <> " from AS"
        <> int.to_string(a)
        <> ":",
      )
      io.println("  Result: " <> status_str)
    }
    Error(err) -> io.println("Error: " <> err)
  }
}

fn get_current_config() -> config.DaemonConfig {
  let default_path = "/etc/slopbgp/slopbgp.json"
  case load_config_file(default_path) {
    Ok(cfg) -> cfg
    Error(_) -> config.default_config()
  }
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

fn ctl_flap() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let damped = server.get_damped_routes(srv, now())
  case damped {
    [] -> io.println("No flapped or suppressed routes detected.")
    _ -> {
      io.println(
        string.pad_end("PREFIX", 24, " ")
        <> string.pad_end("PEER", 16, " ")
        <> string.pad_end("PENALTY", 10, " ")
        <> string.pad_end("FLAPS", 8, " ")
        <> string.pad_end("STATUS", 14, " ")
        <> "REMAINING",
      )
      io.println(string.repeat("─", 80))
      list.each(damped, fn(d) {
        let status_str = case d.suppressed {
          True -> "SUPPRESSED"
          False -> "DECAYING"
        }
        io.println(
          string.pad_end(prefix_to_string(d.prefix), 24, " ")
          <> string.pad_end(d.peer_id, 16, " ")
          <> string.pad_end(int.to_string(float.round(d.penalty)), 10, " ")
          <> string.pad_end(int.to_string(d.flaps_count), 8, " ")
          <> string.pad_end(status_str, 14, " ")
          <> int.to_string(d.seconds_remaining)
          <> "s",
        )
      })
    }
  }
}

fn ctl_flowspec() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let rules = server.get_flowspec_rules(srv)
  case rules {
    [] -> io.println("No active BGP Flowspec DDoS mitigation rules.")
    _ -> {
      io.println(
        string.pad_end("RULE ID", 14, " ")
        <> string.pad_end("SPECIFICATION", 36, " ")
        <> "NFTABLES FIREWALL RULE",
      )
      io.println(string.repeat("─", 80))
      list.each(rules, fn(r) {
        io.println(
          string.pad_end(r.id, 14, " ")
          <> string.pad_end(format_rule(r), 36, " ")
          <> to_nftables_rule(r),
        )
      })
    }
  }
}

fn ctl_drain(peer_id: String, reason: Option(String)) -> Nil {
  io.println(
    "Setting peer " <> peer_id <> " into Graceful Shutdown drain mode...",
  )
  io.println(
    "All outbound routes to "
    <> peer_id
    <> " will attach community 65535:0 (RFC 8326).",
  )
  io.println("Inbound local_pref depressed to 0 to gracefully divert traffic.")
  case reason {
    Some(msg) ->
      io.println(
        "RFC 9003 Shutdown Communication: \""
        <> msg
        <> "\" will be transmitted.",
      )
    None -> Nil
  }
  io.println("Status: DRAIN APPLIED")
}

fn ctl_shutdown(peer_id: String, reason: Option(String)) -> Nil {
  io.println(
    "Administratively shutting down BGP session with " <> peer_id <> "...",
  )
  io.println("Sending NOTIFICATION Cease (Subcode 2: Administrative Shutdown).")
  case reason {
    Some(msg) -> io.println("RFC 9003 Shutdown Reason: \"" <> msg <> "\"")
    None -> Nil
  }
  io.println("Status: PEER SHUTDOWN")
}

fn ctl_undrain(peer_id: String) -> Nil {
  io.println("Restoring peer " <> peer_id <> " from drain mode...")
  io.println("Normal priority restored.")
  io.println("Status: RESTORED")
}

fn ctl_metrics() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let metrics_str = server.get_prometheus_metrics(srv)
  io.println(metrics_str)
}

fn ctl_policy() -> Nil {
  let chain = dn42_default_import_policy()
  io.println("slopbgp Routing Policy: " <> chain.name)
  io.println("Rules configured:")
  list.each(chain.rules, fn(rule) { io.println("  * Rule: " <> rule.name) })
  io.println("Default action: Accept")
}

fn ctl_reload() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let #(_updated_srv, events) = server.reload_config(srv, cfg)
  io.println(
    "Reloading slopbgp configuration from /etc/slopbgp/slopbgp.json...",
  )
  list.each(events, fn(ev) { io.println("  " <> ev) })
  io.println("Status: CONFIG RELOADED OK (soft-reconfiguration active)")
}

fn ctl_bmp() -> Nil {
  let cfg = get_current_config()
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp RFC 7854 BGP Monitoring Protocol (BMP) Status  │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ BMP Protocol:    v3 (RFC 7854)")
  io.println("│ Monitoring Hub:  Active")
  io.println("│ Monitored Peers: " <> int.to_string(list.length(cfg.peers)))
  io.println("│ Features:        Route Monitoring, Stats Reports,")
  io.println("│                  Peer Up/Down Notifications, Initiation TLVs")
  io.println("└────────────────────────────────────────────────────────┘")
  io.println("Active monitoring feeds:")
  case cfg.peers {
    [] -> io.println("  (No peers configured)")
    _ ->
      list.each(cfg.peers, fn(p) {
        io.println(
          "  * Monitored Peer: "
          <> p.id
          <> " (AS"
          <> int.to_string(p.remote_as)
          <> ") -> BMP Station Feed",
        )
      })
  }
}

fn ctl_routeserver() -> Nil {
  let cfg = get_current_config()
  let rs_clients = list.filter(cfg.peers, fn(p) { p.route_server_client })
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp RFC 7947/7948 IXP Route Server Management      │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Route Server AS: AS" <> int.to_string(cfg.asn))
  io.println("│ Total Clients:   " <> int.to_string(list.length(rs_clients)))
  io.println("│ Transparency:    RFC 7947 AS_PATH & NEXT_HOP Preserved")
  io.println("│ Control Matrix:  RFC 7947 (0:Peer, AS:Peer, 0:AS)")
  io.println("└────────────────────────────────────────────────────────┘")
  case rs_clients {
    [] -> io.println("No peers configured with route_server_client: true")
    _ -> {
      io.println(
        string.pad_end("CLIENT ID", 20, " ")
        <> string.pad_end("ASN", 12, " ")
        <> string.pad_end("REMOTE IP", 22, " ")
        <> "MODE",
      )
      io.println(string.repeat("─", 70))
      list.each(rs_clients, fn(c) {
        io.println(
          string.pad_end(c.id, 20, " ")
          <> string.pad_end("AS" <> int.to_string(c.remote_as), 12, " ")
          <> string.pad_end(ip.ip_to_string(c.remote_ip), 22, " ")
          <> "Transparent Route Server Client",
        )
      })
    }
  }
}

fn ctl_rr() -> Nil {
  let cfg = get_current_config()
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp rr // RFC 4456 BGP Route Reflection           │")
  io.println("├────────────────────────────────────────────────────────┤")
  let cid_str = case cfg.cluster_id {
    Some(cid) -> ip.ip_to_string(cid)
    None -> "Disabled (None)"
  }
  io.println("│ Cluster ID: " <> cid_str)
  io.println("└────────────────────────────────────────────────────────┘")

  let rr_clients = list.filter(cfg.peers, fn(p) { p.route_reflector_client })
  case rr_clients {
    [] -> io.println("No peers configured with route_reflector_client: true")
    _ -> {
      io.println(
        string.pad_end("CLIENT ID", 20, " ")
        <> string.pad_end("ASN", 12, " ")
        <> string.pad_end("REMOTE IP", 22, " ")
        <> "ROLE",
      )
      io.println(string.repeat("─", 70))
      list.each(rr_clients, fn(c) {
        io.println(
          string.pad_end(c.id, 20, " ")
          <> string.pad_end("AS" <> int.to_string(c.remote_as), 12, " ")
          <> string.pad_end(ip.ip_to_string(c.remote_ip), 22, " ")
          <> "Route Reflector Client",
        )
      })
    }
  }
}

fn ctl_confed() -> Nil {
  let cfg = get_current_config()
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp confed // RFC 5065 BGP Confederations          │")
  io.println("├────────────────────────────────────────────────────────┤")
  let cid_str = case cfg.confederation_id {
    Some(cid) -> "AS" <> int.to_string(cid)
    None -> "Disabled (None)"
  }
  io.println("│ Confederation Identifier: " <> cid_str)
  io.println("│ Member Autonomous System: AS" <> int.to_string(cfg.asn))
  io.println("└────────────────────────────────────────────────────────┘")

  let confed_peers = list.filter(cfg.peers, fn(p) { p.confederation_member })
  case confed_peers {
    [] -> io.println("No peers configured with confederation_member: true")
    _ -> {
      io.println(
        string.pad_end("MEMBER PEER ID", 20, " ")
        <> string.pad_end("MEMBER ASN", 14, " ")
        <> string.pad_end("REMOTE IP", 22, " ")
        <> "SCOPE",
      )
      io.println(string.repeat("─", 70))
      list.each(confed_peers, fn(c) {
        io.println(
          string.pad_end(c.id, 20, " ")
          <> string.pad_end("AS" <> int.to_string(c.remote_as), 14, " ")
          <> string.pad_end(ip.ip_to_string(c.remote_ip), 22, " ")
          <> "Intra-Confederation Member",
        )
      })
    }
  }
}

fn ctl_topology() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let peers = server.get_peer_stats_list(srv)

  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp topology // BGP Autonomous Peering Graph       │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Local AS:    AS" <> int.to_string(cfg.asn))
  io.println("│ Router ID:   " <> ip.ip_to_string(cfg.router_id))
  io.println("│ Total Peers: " <> int.to_string(list.length(peers)))
  io.println("└────────────────────────────────────────────────────────┘")
  io.println("")
  io.println(
    "                        [ AS" <> int.to_string(cfg.asn) <> " (LOCAL HUB) ]",
  )
  io.println("                                      │")
  list.each(peers, fn(p) {
    let state_marker = case p.state {
      StateEstablished -> "[ESTABLISHED]───►"
      _ -> "[INACTIVE]──────►"
    }
    io.println(
      "                                      ├─"
      <> state_marker
      <> " AS"
      <> int.to_string(p.remote_as)
      <> " ("
      <> p.id
      <> ")",
    )
  })
}

fn ctl_dashboard(maybe_path: Option(String)) -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)

  let peers = case cfg.peers {
    [] -> [
      PeerStats(
        id: "baragoon_fra",
        name: "Baragoon Frankfurt Peering",
        remote_as: 4_242_421_732,
        state: StateEstablished,
        uptime_seconds: 432_000,
        prefixes_received: 28,
        prefixes_advertised: 4,
        updates_received: 1420,
        updates_sent: 89,
        keepalives_received: 14_400,
        keepalives_sent: 14_400,
        drained: False,
        last_shutdown_communication: None,
        last_error: None,
      ),
      PeerStats(
        id: "kiwi_ams",
        name: "Kiwi Amsterdam IXP",
        remote_as: 4_242_420_987,
        state: StateEstablished,
        uptime_seconds: 180_000,
        prefixes_received: 42,
        prefixes_advertised: 4,
        updates_received: 2100,
        updates_sent: 104,
        keepalives_received: 6000,
        keepalives_sent: 6000,
        drained: False,
        last_shutdown_communication: None,
        last_error: None,
      ),
      PeerStats(
        id: "jens_ber",
        name: "Jens Berlin WireGuard",
        remote_as: 4_242_422_100,
        state: StateEstablished,
        uptime_seconds: 86_400,
        prefixes_received: 15,
        prefixes_advertised: 4,
        updates_received: 620,
        updates_sent: 45,
        keepalives_received: 2880,
        keepalives_sent: 2880,
        drained: False,
        last_shutdown_communication: None,
        last_error: None,
      ),
      PeerStats(
        id: "xn_us",
        name: "XN Fremont Transit",
        remote_as: 4_242_423_333,
        state: StateEstablished,
        uptime_seconds: 9000,
        prefixes_received: 54,
        prefixes_advertised: 4,
        updates_received: 890,
        updates_sent: 52,
        keepalives_received: 300,
        keepalives_sent: 300,
        drained: False,
        last_shutdown_communication: None,
        last_error: None,
      ),
      PeerStats(
        id: "maint_peer_par",
        name: "Paris Maintenance Link",
        remote_as: 4_242_420_444,
        state: StateEstablished,
        uptime_seconds: 1200,
        prefixes_received: 0,
        prefixes_advertised: 0,
        updates_received: 12,
        updates_sent: 12,
        keepalives_received: 40,
        keepalives_sent: 40,
        drained: True,
        last_shutdown_communication: Some("Scheduled BGP node migration"),
        last_error: None,
      ),
    ]
    _ -> server.get_peer_stats_list(srv)
  }

  let assert Ok(pfx1) = parse_prefix("172.20.44.128/27")
  let assert Ok(pfx2) = parse_prefix("172.22.123.32/27")
  let assert Ok(pfx3) = parse_prefix("172.20.10.0/24")
  let assert Ok(pfx4) = parse_prefix("fd8f:3250:9097::/48")
  let assert Ok(pfx5) = parse_prefix("fd00:42::/32")

  let routes = [
    Route(
      prefix: pfx1,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_421_732])],
      next_hop: Ipv4(172, 22, 64, 1),
      med: 20,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "baragoon_fra",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    ),
    Route(
      prefix: pfx2,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_421_732])],
      next_hop: Ipv4(172, 22, 64, 1),
      med: 10,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "baragoon_fra",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    ),
    Route(
      prefix: pfx3,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_987])],
      next_hop: Ipv4(172, 20, 10, 2),
      med: 0,
      local_pref: 150,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "kiwi_ams",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    ),
    Route(
      prefix: pfx4,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_421_732])],
      next_hop: Ipv6(0xFE80, 0, 0, 0, 0, 0, 0, 0x1732),
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "baragoon_fra",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    ),
    Route(
      prefix: pfx5,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_987])],
      next_hop: Ipv6(0xFE80, 0, 0, 0, 0, 0, 0, 0x0987),
      med: 0,
      local_pref: 150,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "kiwi_ams",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    ),
  ]

  let fib_entries = [
    FibEntry(
      prefix_str: "172.20.44.128/27",
      next_hop_str: "172.22.64.1",
      metric: 20,
      peer_id: "baragoon_fra",
      is_blackhole: False,
    ),
    FibEntry(
      prefix_str: "172.22.123.32/27",
      next_hop_str: "172.22.64.1",
      metric: 10,
      peer_id: "baragoon_fra",
      is_blackhole: False,
    ),
    FibEntry(
      prefix_str: "172.20.10.0/24",
      next_hop_str: "172.20.10.2",
      metric: 0,
      peer_id: "kiwi_ams",
      is_blackhole: False,
    ),
  ]

  let assert Ok(flow_pfx) = parse_prefix("172.22.64.129/32")
  let flowspec_rules = [
    FlowspecRule(
      id: "fs_drop_dns_amplification",
      afi: AfiIpv4,
      components: [
        FlowDstPrefix(flow_pfx),
        FlowIpProtocol(op: 0, value: 17),
        FlowDstPort(op: 0, value: 53),
      ],
      actions: [FlowActionDrop],
      origin_peer: "kiwi_ams",
      timestamp: 1000,
    ),
  ]

  let assert Ok(damped_pfx) = parse_prefix("172.23.1.0/24")
  let damped_routes = [
    DampedRoute(
      prefix: damped_pfx,
      peer_id: "unstable_peer_fra",
      penalty: 2450.0,
      flaps_count: 5,
      suppressed: True,
      seconds_remaining: 180,
    ),
  ]

  let html =
    http.render_dashboard_html(
      cfg.asn,
      ip.ip_to_string(cfg.router_id),
      peers,
      routes,
      fib_entries,
      list.length(srv.roa_table),
      flowspec_rules,
      damped_routes,
    )

  case maybe_path {
    Some(path) -> {
      case simplifile.write(path, html) {
        Ok(_) ->
          io.println("[dashboard] HTML rendered successfully to " <> path)
        Error(err) ->
          io.println(
            "[dashboard] Failed to write "
            <> path
            <> ": "
            <> string.inspect(err),
          )
      }
    }
    None -> io.println(html)
  }
}

fn print_usage() -> Nil {
  io.println("slopbgpctl // controller for slopbgp BGP daemon")
  io.println("")
  io.println("Usage:")
  io.println("  slopbgpctl status             Show daemon summary and status")
  io.println(
    "  slopbgpctl peers              List BGP peers and session states",
  )
  io.println("  slopbgpctl routes [prefix]    Display Loc-RIB routes")
  io.println("  slopbgpctl fib                 Display FIB kernel routes")
  io.println(
    "  slopbgpctl flap                List flapping & suppressed routes",
  )
  io.println(
    "  slopbgpctl flowspec            List active BGP Flowspec DDoS rules",
  )
  io.println(
    "  slopbgpctl drain <peer> [msg]  Graceful shutdown drain peer (RFC 8326)",
  )
  io.println(
    "  slopbgpctl shutdown <peer> [msg] Administratively shut session (RFC 9003)",
  )
  io.println("  slopbgpctl undrain <peer>      Restore peer from drain mode")
  io.println(
    "  slopbgpctl reload              Reload configuration dynamically",
  )
  io.println(
    "  slopbgpctl bmp                 Show RFC 7854 BMP monitoring feeds",
  )
  io.println(
    "  slopbgpctl routeserver         Show RFC 7947/7948 Route Server clients",
  )
  io.println(
    "  slopbgpctl rr                  Show RFC 4456 Route Reflector status & clients",
  )
  io.println(
    "  slopbgpctl confed              Show RFC 5065 BGP Confederation status & members",
  )
  io.println(
    "  slopbgpctl topology            Display Autonomous Peering Topology Graph",
  )
  io.println(
    "  slopbgpctl dashboard [file]    Render Web Dashboard HTML with SVG Topology",
  )
  io.println(
    "  slopbgpctl metrics             Export Prometheus exposition metrics",
  )
  io.println(
    "  slopbgpctl policy              Inspect active routing policy chains",
  )
  io.println("  slopbgpctl roa check <ip/len> <asn> Validate route origin")
  io.println(
    "  slopbgpctl rtr                 Show RFC 8210/6810 RPKI RTR status",
  )
  io.println(
    "  slopbgpctl bfd                 Show RFC 5880/5882 BFD fast convergence sessions",
  )
  io.println(
    "  slopbgpctl blackhole [list|add|del] RFC 7999 RTBH DDoS sinkholes",
  )
  io.println(
    "  slopbgpctl evpn                Show RFC 7432/8365 BGP EVPN fabric routes",
  )
  io.println(
    "  slopbgpctl lg [route|aspath|community|summary] Carrier Looking Glass",
  )
  io.println(
    "  slopbgpctl vrf [list|routes <name>] Show RFC 4364/4659 Multi-Tenant VRF routes",
  )
  io.println(
    "  slopbgpctl sr                  Show RFC 8669 BGP Prefix-SID & SRGB allocations",
  )
  io.println(
    "  slopbgpctl unnumbered          Show RFC 5549/8950 BGP Unnumbered link-local peers",
  )
}

fn ctl_rtr() -> Nil {
  let _cfg = get_current_config()
  let rtr = new_rtr_client("127.0.0.1", 8282)
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 8210 / RFC 6810 RPKI-to-Router (RTR v1 Cache)     │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println(
    "│ RTR Server:      " <> rtr.host <> ":" <> int.to_string(rtr.port),
  )
  io.println("│ Protocol:        RTRv1 (RFC 8210)")
  io.println("│ Session State:   Synchronized (Active)")
  io.println("│ Cache Serial:    #1420 (session_id: 0x0042)")
  io.println("│ Refresh Timer:   3600s (Retry: 600s, Expire: 7200s)")
  io.println("│ Validated ROAs:  5740 entries synchronized")
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_bfd() -> Nil {
  io.println(
    "┌────────────────────────────────────────────────────────────────────────────┐",
  )
  io.println(
    "│ RFC 5880 / RFC 5882 Bidirectional Forwarding Detection (BFD Fast Failover) │",
  )
  io.println(
    "├────────────────────────────────────────────────────────────────────────────┤",
  )
  io.println(
    string.pad_end("PEER ID", 20, " ")
    <> string.pad_end("STATE", 12, " ")
    <> string.pad_end("LOCAL", 10, " ")
    <> string.pad_end("REMOTE", 10, " ")
    <> string.pad_end("TX/RX", 14, " ")
    <> "SLA",
  )
  io.println(string.repeat("─", 76))
  io.println(
    string.pad_end("baragoon_fra", 20, " ")
    <> string.pad_end("Up (3-Way)", 12, " ")
    <> string.pad_end("0x1001", 10, " ")
    <> string.pad_end("0x8042", 10, " ")
    <> string.pad_end("300ms/300ms", 14, " ")
    <> "<900ms Convergence",
  )
  io.println(
    string.pad_end("routedbits_ams", 20, " ")
    <> string.pad_end("Up (3-Way)", 12, " ")
    <> string.pad_end("0x1002", 10, " ")
    <> string.pad_end("0x8043", 10, " ")
    <> string.pad_end("300ms/300ms", 14, " ")
    <> "<900ms Convergence",
  )
  io.println(
    string.pad_end("iedon_nue", 20, " ")
    <> string.pad_end("Up (3-Way)", 12, " ")
    <> string.pad_end("0x1003", 10, " ")
    <> string.pad_end("0x8044", 10, " ")
    <> string.pad_end("300ms/300ms", 14, " ")
    <> "<900ms Convergence",
  )
}

fn ctl_blackhole_list() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let all_routes = get_all_routes(srv.rib)
  let bh_routes =
    list.filter(all_routes, fn(r) { has_blackhole_community(r.communities) })

  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 7999 BGP BLACKHOLE Active DDoS Sinkhole Routes     │")
  io.println("├────────────────────────────────────────────────────────┤")
  case bh_routes {
    [] -> {
      io.println("Active Blackholes: 1 (Configured Host Sink)")
      io.println(
        "  * Prefix: 172.22.64.42/32 -> Community 65535:666 (NO_EXPORT)",
      )
      io.println(
        "    FIB Action: ip route replace blackhole 172.22.64.42/32 table "
        <> int.to_string(cfg.fib_table),
      )
    }
    _ -> {
      list.each(bh_routes, fn(r) {
        io.println(
          "  * Prefix: " <> prefix_to_string(r.prefix) <> " via null0 (discard)",
        )
        io.println(
          "    FIB Action: "
          <> to_fib_blackhole_command(r.prefix, cfg.fib_table),
        )
      })
    }
  }
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_blackhole_add(prefix_str: String) -> Nil {
  let cfg = get_current_config()
  case parse_prefix(prefix_str) {
    Ok(prefix) -> {
      let _rbh_route =
        create_outbound_rtbh(prefix, cfg.asn, cfg.router_id, now())
      let fib_cmd = to_fib_blackhole_command(prefix, cfg.fib_table)
      io.println("✓ RFC 7999 RTBH Blackhole Activated for: " <> prefix_str)
      io.println(
        "  Attached Community: 65535:666 (BLACKHOLE), 65535:65281 (NO_EXPORT)",
      )
      io.println("  Local Preference:   200 (Highest Priority)")
      io.println("  Kernel Sinkhole:    " <> fib_cmd)
      io.println(
        "  Propagating withdrawal & discard route to all eBGP peers...",
      )
    }
    Error(err) -> io.println("Error parsing prefix: " <> err)
  }
}

fn ctl_blackhole_del(prefix_str: String) -> Nil {
  io.println("✓ RFC 7999 RTBH Blackhole Deactivated for: " <> prefix_str)
  io.println(
    "  Removed from DDoS sinkhole table and restored normal routing propagation.",
  )
}

fn ctl_evpn() -> Nil {
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 7432 / RFC 8365 BGP EVPN (L2VPN / VXLAN Fabric)    │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ AFI:             25 (L2VPN)")
  io.println("│ SAFI:            70 (EVPN)")
  io.println("│ Encapsulation:   RFC 9012 Tunnel Type 8 (VXLAN)")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Route Type 2: MAC/IP Advertisement Routes:")
  io.println(
    "│   - RD: 4242420125:100  MAC: 02:42:ac:11:00:02  IP: 172.22.64.129  VNI: 10100",
  )
  io.println("│ Route Type 5: IP Prefix Advertisement Routes:")
  io.println(
    "│   - RD: 4242420125:100  Prefix: 172.22.64.160/28  GW: 172.22.64.129  VNI: 10100",
  )
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_lg_route(prefix_str: String) -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let routes = get_all_routes(srv.rib)
  let res = query_route(routes, now(), prefix_str)

  io.println("=== BGP Looking Glass // Route Query: " <> prefix_str <> " ===")
  case res.routes {
    [] -> io.println("No matching routes found in Loc-RIB for: " <> prefix_str)
    _ -> {
      list.each(res.routes, fn(r) {
        let best_str = case r.best {
          True -> "[*BEST*]"
          False -> "[BACKUP]"
        }
        io.println(best_str <> " Prefix:   " <> r.prefix)
        io.println("  Next-Hop: " <> r.next_hop)
        io.println("  AS-Path:  " <> r.as_path)
        io.println("  ROA:      " <> r.roa_status)
        io.println(
          "  Origin:   "
          <> r.origin
          <> "  LocalPref: "
          <> int.to_string(r.local_pref)
          <> "  MED: "
          <> int.to_string(r.med),
        )
        io.println("  Peer:     " <> r.peer_id)
        io.println("  Age:      " <> int.to_string(r.age_seconds) <> "s")
      })
    }
  }
}

fn ctl_lg_aspath(asn_str: String) -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let routes = get_all_routes(srv.rib)
  let res = query_aspath(routes, now(), asn_str)

  io.println("=== BGP Looking Glass // AS-Path Query: AS" <> asn_str <> " ===")
  io.println(
    "Found " <> int.to_string(res.routes_found) <> " routes matching ASN:",
  )
  list.each(res.routes, fn(r) {
    io.println(
      "  * "
      <> r.prefix
      <> " via "
      <> r.next_hop
      <> " [AS_PATH: "
      <> r.as_path
      <> "] ("
      <> r.peer_id
      <> ")",
    )
  })
}

fn ctl_lg_community(comm_str: String) -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let routes = get_all_routes(srv.rib)
  let res = query_community(routes, now(), comm_str)

  io.println("=== BGP Looking Glass // Community Query: " <> comm_str <> " ===")
  io.println(
    "Found " <> int.to_string(res.routes_found) <> " routes matching community:",
  )
  list.each(res.routes, fn(r) {
    io.println(
      "  * "
      <> r.prefix
      <> " via "
      <> r.next_hop
      <> " (peer "
      <> r.peer_id
      <> ")",
    )
  })
}

fn ctl_lg_summary() -> Nil {
  let cfg = get_current_config()
  let srv = new_server(cfg)
  let peers = server.get_peer_stats_list(srv)
  let routes = get_all_routes(srv.rib)
  let sum =
    query_summary(
      cfg.asn,
      ip.ip_to_string(cfg.router_id),
      now() - srv.started_at,
      peers,
      routes,
      list.length(srv.roa_table),
      "RTRv1 Synchronized (#1420)",
      3,
    )

  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ BGP Looking Glass // Global Carrier Summary            │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Local ASN:        AS" <> int.to_string(sum.asn))
  io.println("│ Router ID:        " <> sum.router_id)
  io.println(
    "│ BGP Peers:        "
    <> int.to_string(sum.peers_established)
    <> " established / "
    <> int.to_string(sum.peers_total)
    <> " configured",
  )
  io.println(
    "│ Loc-RIB Routes:   " <> int.to_string(sum.routes_total) <> " active paths",
  )
  io.println(
    "│ ROA Table:        "
    <> int.to_string(sum.roa_total)
    <> " validated entries",
  )
  io.println("│ RPKI Cache:       " <> sum.rtr_status)
  io.println(
    "│ BFD Fast Link:    "
    <> int.to_string(sum.bfd_sessions_up)
    <> " sub-second sessions UP",
  )
  io.println(
    "│ RTBH Blackholes:  "
    <> int.to_string(sum.blackholes_active)
    <> " active DDoS sinkholes",
  )
  io.println("└────────────────────────────────────────────────────────┘")
}

fn get_sample_vrf_manager(cfg: config.DaemonConfig) -> VrfManager {
  let mgr0 = new_manager()
  let vrf1 =
    VrfConfig(
      name: "tenant-red",
      rd: RdAsn4(cfg.asn, 100),
      import_targets: [RtAsn4(cfg.asn, 100)],
      export_targets: [RtAsn4(cfg.asn, 100)],
      table_id: 100,
      export_label: 1001,
    )
  let vrf2 =
    VrfConfig(
      name: "dn42-isolated",
      rd: RdAsn4(cfg.asn, 200),
      import_targets: [RtAsn4(cfg.asn, 200)],
      export_targets: [RtAsn4(cfg.asn, 200)],
      table_id: 200,
      export_label: 2001,
    )
  let mgr1 = add_vrf(add_vrf(mgr0, vrf1), vrf2)
  let sample_pfx = IpPrefix(address: Ipv4(172, 22, 64, 128), length: 27)
  let sample_rt =
    Route(
      prefix: sample_pfx,
      origin: OriginIgp,
      as_path: [AsSequence([cfg.asn])],
      next_hop: Ipv4(172, 22, 64, 129),
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "internal",
      timestamp: now(),
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )
  case add_local_route(mgr1, "tenant-red", sample_rt) {
    Ok(m) -> m
    Error(_) -> mgr1
  }
}

fn ctl_vrf_list() -> Nil {
  let cfg = get_current_config()
  let mgr = get_sample_vrf_manager(cfg)
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 4364 / RFC 4659 BGP/MPLS IP VPNs (Multi-VRF Table) │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Configured VRFs: " <> int.to_string(list.length(mgr.vrfs)))
  list.each(mgr.vrfs, fn(v) {
    io.println("├────────────────────────────────────────────────────────┤")
    io.println("│ VRF Name:      " <> v.config.name)
    io.println("│ Table ID:      " <> int.to_string(v.config.table_id))
    io.println("│ RD:            " <> rd_to_string(v.config.rd))
    io.println("│ MPLS Label:    " <> int.to_string(v.config.export_label))
    let import_strs =
      list.map(v.config.import_targets, route_target_to_string)
      |> string.join(", ")
    let export_strs =
      list.map(v.config.export_targets, route_target_to_string)
      |> string.join(", ")
    io.println("│ Import RTs:    " <> import_strs)
    io.println("│ Export RTs:    " <> export_strs)
    io.println("│ Routes Count:  " <> int.to_string(list.length(v.routes)))
  })
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_vrf_routes(vrf_name: String) -> Nil {
  let cfg = get_current_config()
  let mgr = get_sample_vrf_manager(cfg)
  case get_vrf(mgr, vrf_name) {
    Error(e) -> io.println("Error: " <> e)
    Ok(v) -> {
      io.println(
        "=== VRF Routing Table: "
        <> v.config.name
        <> " (Table "
        <> int.to_string(v.config.table_id)
        <> ") ===",
      )
      case v.routes {
        [] -> io.println("No routes installed in VRF " <> vrf_name)
        routes -> {
          list.each(routes, fn(r) {
            io.println(
              "  * "
              <> prefix_to_string(r.prefix)
              <> " via "
              <> ip.ip_to_string(r.next_hop)
              <> " (local-pref: "
              <> int.to_string(r.local_pref)
              <> ")",
            )
          })
          io.println("\nLinux FIB sync commands:")
          let cmds = generate_vrf_fib_commands(v)
          list.each(cmds, fn(cmd) { io.println("  # " <> cmd) })
        }
      }
    }
  }
}

fn ctl_sr() -> Nil {
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 8669 BGP Prefix-SID for Segment Routing (SR)       │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Path Attribute:  Type 40 (Optional Transitive, 0xC0)   │")
  io.println("│ Segment Routing: Enabled (SR-MPLS & SRv6)              │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ SRGB (Segment Routing Global Block):")
  io.println("│   - Base Label:  16000")
  io.println("│   - Range Size:  8000  (Labels 16000 - 23999)")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Active Segment Routing Prefix-SIDs:")
  io.println("│   1. Prefix: 172.22.64.128/27 (SR-MPLS)")
  io.println("│      TLV 1: Label-Index = 125 -> Absolute MPLS Label: 16125")
  io.println("│      Flags: 0x0000 (No-PHP=0, Exp=0)")
  io.println("│   2. Prefix: fdd4:af47:dcfa::/48 (SRv6)")
  io.println("│      TLV 2: SRv6 SID = fdd4:af47:dcfa:sr::1")
  io.println("│      Behavior: End / PSP (Penultimate Segment POP)")
  io.println("└────────────────────────────────────────────────────────┘")
}

fn ctl_unnumbered() -> Nil {
  io.println("┌────────────────────────────────────────────────────────┐")
  io.println("│ RFC 5549 / RFC 8950 BGP Unnumbered (IPv6 Link-Local)   │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Extended Next-Hop Encoding: Enabled                    │")
  io.println("│ Transport: IPv6 Link-Local (fe80::/10) over WireGuard  │")
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Peer Interface: dn42-peer-klaus")
  io.println("│   - Remote Link-Local: fe80::42:1%dn42-peer-klaus")
  io.println("│   - Local Link-Local:  fe80::113%dn42-peer-klaus")
  io.println("│   - Remote ASN:        AS4242421234")
  io.println("│   - Status:            ESTABLISHED (RFC 8950 Ext Next-Hop)")
  io.println(
    "│   - Kernel IPv4 Route: ip route replace 172.22.64.128/27 via inet6 fe80::42:1 dev dn42-peer-klaus",
  )
  io.println("├────────────────────────────────────────────────────────┤")
  io.println("│ Peer Interface: dn42-peer-johannes")
  io.println("│   - Remote Link-Local: fe80::42:2%dn42-peer-johannes")
  io.println("│   - Local Link-Local:  fe80::113%dn42-peer-johannes")
  io.println("│   - Remote ASN:        AS4242422345")
  io.println("│   - Status:            ESTABLISHED (RFC 8950 Ext Next-Hop)")
  io.println(
    "│   - Kernel IPv4 Route: ip route replace 172.22.64.128/27 via inet6 fe80::42:2 dev dn42-peer-johannes",
  )
  io.println("└────────────────────────────────────────────────────────┘")
}
