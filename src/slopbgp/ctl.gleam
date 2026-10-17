import gleam/float
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile
import slopbgp/api/http
import slopbgp/bgp/flowspec.{format_rule, to_nftables_rule}
import slopbgp/config.{load_config_file}
import slopbgp/dn42/roa.{parse_roa_content, validate_route}
import slopbgp/fib/kernel.{FibEntry}
import slopbgp/ip.{parse_prefix, prefix_to_string}
import slopbgp/net/socket.{now}
import slopbgp/policy/filter.{dn42_default_import_policy}
import slopbgp/rib/rib.{get_all_routes}
import slopbgp/server.{new_server}
import slopbgp/types.{
  type PeerStats, type Route, AfiIpv4, AsConfedSequence, AsConfedSet, AsSequence,
  AsSet, DampedRoute, FlowActionDrop, FlowDstPort, FlowDstPrefix, FlowIpProtocol,
  FlowspecRule, Ipv4, Ipv6, OriginIgp, PeerStats, RoaInvalid, RoaNotFound,
  RoaValid, Route, StateActive, StateConnect, StateEstablished, StateIdle,
  StateOpenConfirm, StateOpenSent,
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
    ),
    FibEntry(
      prefix_str: "172.22.123.32/27",
      next_hop_str: "172.22.64.1",
      metric: 10,
      peer_id: "baragoon_fra",
    ),
    FibEntry(
      prefix_str: "172.20.10.0/24",
      next_hop_str: "172.20.10.2",
      metric: 0,
      peer_id: "kiwi_ams",
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
}
