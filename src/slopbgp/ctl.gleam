import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import simplifile
import slopbgp/config.{load_config_file}
import slopbgp/dn42/roa.{parse_roa_content, validate_route}
import slopbgp/fib/kernel
import slopbgp/ip.{parse_prefix, prefix_to_string}
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
    io.println(
      string.pad_end(p.id, 20, " ")
      <> string.pad_end("AS" <> int.to_string(p.remote_as), 12, " ")
      <> string.pad_end(state_str, 14, " ")
      <> string.pad_end(int.to_string(p.prefixes_received), 10, " ")
      <> string.pad_end(int.to_string(p.prefixes_advertised), 10, " ")
      <> p.name,
    )
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
  io.println("  slopbgpctl roa check <ip/len> <asn> Validate route origin")
}
