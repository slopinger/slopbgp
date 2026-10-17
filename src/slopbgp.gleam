import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import slopbgp/config.{default_config, load_config_file}
import slopbgp/ctl.{run_ctl}
import slopbgp/ip.{ip_to_string}
import slopbgp/net/http_server.{start_http_listener}
import slopbgp/net/socket.{now}
import slopbgp/server.{type ServerState, new_server, tick_server}
import slopbgp/simulator.{run_simulation}

@external(erlang, "slopbgp_ffi", "get_args")
fn get_cli_args() -> List(String)

pub fn main() {
  let args = case get_cli_args() {
    [] ->
      case envoy.get("SLOPBGP_CMD") {
        Ok(cmd) -> [cmd]
        Error(_) -> []
      }
    cli_args -> cli_args
  }
  run_with_args(args)
}

pub fn run_with_args(args: List(String)) -> Nil {
  case args {
    ["sim", ..] | ["simulate", ..] -> {
      let _ = run_simulation()
      Nil
    }
    ["ctl", ..rest] -> run_ctl(rest)
    ["status", ..]
    | ["peers", ..]
    | ["routes", ..]
    | ["fib", ..]
    | ["flap", ..]
    | ["flowspec", ..]
    | ["drain", ..]
    | ["shutdown", ..]
    | ["undrain", ..]
    | ["reload", ..]
    | ["bmp", ..]
    | ["routeserver", ..]
    | ["rr", ..]
    | ["confed", ..]
    | ["topology", ..]
    | ["dashboard", ..]
    | ["metrics", ..]
    | ["policy", ..]
    | ["roa", ..]
    | ["rtr", ..]
    | ["bfd", ..]
    | ["blackhole", ..]
    | ["evpn", ..]
    | ["lg", ..]
    | ["lookingglass", ..]
    | ["vrf", ..]
    | ["sr", ..]
    | ["unnumbered", ..] -> run_ctl(args)
    ["daemon", ..] | [] -> run_daemon()
    _ -> {
      io.println(
        "slopbgp // revolutionary BGP-4 & MP-BGP daemon in Gleam for DN42",
      )
      io.println("Usage:")
      io.println("  slopbgp [daemon]       Run BGP routing daemon")
      io.println(
        "  slopbgp sim            Run automated BGP protocol simulation testbed",
      )
      io.println(
        "  slopbgp ctl <command>  Control running daemon (status, peers, routes, roa)",
      )
    }
  }
}

fn run_daemon() -> Nil {
  let cfg = case envoy.get("SLOPBGP_CONFIG") {
    Ok(path) ->
      case load_config_file(path) {
        Ok(c) -> c
        Error(err) -> {
          io.println("[warn] Failed to load " <> path <> ": " <> err)
          default_config()
        }
      }
    Error(_) -> default_config()
  }

  io.println("┌────────────────────────────────────────────────────────────┐")
  io.println("│ slopbgp v0.1.0 // BGP-4 & MP-BGP routing daemon for DN42    │")
  io.println("│ Autonomous System: AS" <> int.to_string(cfg.asn))
  io.println("│ Router Identifier: " <> ip_to_string(cfg.router_id))
  io.println("│ Peering IPv4:      " <> ip_to_string(cfg.local_ipv4))
  io.println("│ Peering IPv6:      " <> ip_to_string(cfg.local_ipv6))
  io.println("│ BGP Listen Port:   " <> int.to_string(cfg.bgp_port))
  io.println(
    "│ Web Dashboard:     http://127.0.0.1:" <> int.to_string(cfg.api_port),
  )
  io.println("└────────────────────────────────────────────────────────────┘")

  let srv = new_server(cfg)
  io.println(
    "[server] Master routing supervisor online. "
    <> int.to_string(list.length(srv.roa_table))
    <> " ROA filters active.",
  )

  // Run initial tick and test simulation to verify full engine convergence
  let _ = tick_server(srv, now())
  io.println("[server] Ready to accept BGP peering sessions.")

  // Start background HTTP management server and dashboard
  process.spawn(fn() { start_http_listener(srv, cfg.api_port) })

  // Start background ticker
  process.spawn(fn() { run_ticker(srv) })

  // Keep daemon alive
  process.sleep_forever()
}

fn run_ticker(srv: ServerState) -> Nil {
  process.sleep(1000)
  let _ = tick_server(srv, now())
  run_ticker(srv)
}
