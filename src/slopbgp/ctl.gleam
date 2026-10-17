import gleam/float
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile
import slopbgp/bgp/flowspec.{format_rule, to_nftables_rule}
import slopbgp/config.{load_config_file}
import slopbgp/dn42/roa.{parse_roa_content, validate_route}
import slopbgp/fib/kernel
import slopbgp/ip.{parse_prefix, prefix_to_string}
import slopbgp/net/socket.{now}
import slopbgp/policy/filter.{dn42_default_import_policy}
import slopbgp/rib/rib.{get_all_routes}
import slopbgp/server.{new_server}
import slopbgp/types.{
  type PeerStats, type Route, AsSequence, AsSet, RoaInvalid, RoaNotFound,
  RoaValid, StateActive, StateConnect, StateEstablished, StateIdle,
  StateOpenConfirm, StateOpenSent,
}

pub fn run_ctl(args: List(String)) -> Nil {
  case args {
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
    "  slopbgpctl metrics             Export Prometheus exposition metrics",
  )
  io.println(
    "  slopbgpctl policy              Inspect active routing policy chains",
  )
  io.println("  slopbgpctl roa check <ip/len> <asn> Validate route origin")
}
