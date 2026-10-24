import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import slopbgp/api/http
import slopbgp/bfd/session.{new_bfd_session}
import slopbgp/bgp/evpn.{EvpnRouteType2, EvpnRouteType5, RdAsn4}
import slopbgp/bgp/prefix_sid.{
  BgpPrefixSid, Ipv6SidTlv, LabelIndexTlv, OriginatorSrgbTlv, SrgbBlock,
}
import slopbgp/bgp/unnumbered.{UnnumberedPeer}
import slopbgp/ip.{ip_to_string}
import slopbgp/lookingglass/lookingglass.{query_summary}
import slopbgp/net/socket.{type Socket, accept, close, listen, now, recv, send}
import slopbgp/netmodel/model
import slopbgp/rib/rib.{count_routes, get_all_routes}
import slopbgp/rtr/client.{new_rtr_client}
import slopbgp/server.{
  type ServerState, get_damped_routes, get_fib_routes, get_flowspec_rules,
  get_peer_stats_list, get_prometheus_metrics,
}
import slopbgp/types.{IpPrefix, Ipv4, Ipv6, OriginIgp, RoaValid, Route}
import slopbgp/vrf/vrf.{
  type VrfManager, VrfConfig, add_local_route, add_vrf, new_manager,
}

pub fn start_http_listener(srv: ServerState, port: Int) -> Nil {
  case listen(port, "127.0.0.1") {
    Ok(listen_sock) -> {
      io.println(
        "[http] Management API & Web Dashboard listening on http://127.0.0.1:"
        <> int.to_string(port),
      )
      accept_loop(listen_sock, srv)
    }
    Error(err) -> {
      io.println(
        "[error] Failed to bind HTTP listener on port "
        <> int.to_string(port)
        <> ": "
        <> err,
      )
    }
  }
}

fn accept_loop(listen_sock: Socket, srv: ServerState) -> Nil {
  case accept(listen_sock, 1000) {
    Ok(client_sock) -> {
      process.spawn(fn() { handle_client(client_sock, srv) })
      accept_loop(listen_sock, srv)
    }
    Error(_) -> {
      accept_loop(listen_sock, srv)
    }
  }
}

fn handle_client(client_sock: Socket, srv: ServerState) -> Nil {
  case recv(client_sock, 0, 3000) {
    Ok(req_bytes) -> {
      let path = extract_request_path(req_bytes)
      let #(status_code, content_type, body) = dispatch_route(path, srv)
      let resp =
        "HTTP/1.1 "
        <> status_code
        <> "\r\nContent-Type: "
        <> content_type
        <> "\r\nContent-Length: "
        <> int.to_string(string.byte_size(body))
        <> "\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
        <> body

      let _ = send(client_sock, <<resp:utf8>>)
      close(client_sock)
    }
    Error(_) -> close(client_sock)
  }
}

fn extract_request_path(req_bytes: BitArray) -> String {
  case bit_array.to_string(req_bytes) {
    Ok(req_str) -> {
      case string.split(req_str, "\r\n") {
        [first_line, ..] -> {
          case string.split(first_line, " ") {
            [_, path, ..] -> {
              // Strip query parameters if present
              case string.split(path, "?") {
                [clean_path, ..] -> clean_path
                [] -> "/"
              }
            }
            _ -> "/"
          }
        }
        [] -> "/"
      }
    }
    Error(_) -> "/"
  }
}

fn dispatch_route(path: String, srv: ServerState) -> #(String, String, String) {
  let peers = get_peer_stats_list(srv)
  let routes = get_all_routes(srv.rib)
  let fib_entries = get_fib_routes(srv)
  let flowspec_rules = get_flowspec_rules(srv)
  let damped_routes = get_damped_routes(srv, now())

  case path {
    "/" | "/dashboard" -> {
      let html =
        http.render_dashboard_html(
          srv.config.asn,
          ip_to_string(srv.config.router_id),
          peers,
          routes,
          fib_entries,
          list.length(srv.roa_table),
          flowspec_rules,
          damped_routes,
        )
      #("200 OK", "text/html; charset=utf-8", html)
    }

    "/healthz" | "/health" -> #("200 OK", "text/plain; charset=utf-8", "OK\n")

    "/metrics" -> #(
      "200 OK",
      "text/plain; version=0.0.4; charset=utf-8",
      get_prometheus_metrics(srv),
    )

    "/api/status" -> {
      let body =
        http.render_json_status(
          srv.config.asn,
          ip_to_string(srv.config.router_id),
          list.length(peers),
          count_routes(srv.rib),
          list.length(fib_entries),
          list.length(srv.roa_table),
          now() - srv.started_at,
        )
      #("200 OK", "application/json", body)
    }

    "/api/peers" -> #(
      "200 OK",
      "application/json",
      http.render_json_peers(peers),
    )

    "/api/routes" -> #(
      "200 OK",
      "application/json",
      http.render_json_routes(routes),
    )

    "/api/fib" -> #(
      "200 OK",
      "application/json",
      http.render_json_fib(fib_entries),
    )

    "/api/flowspec" -> #(
      "200 OK",
      "application/json",
      http.render_json_flowspec(flowspec_rules),
    )

    "/api/damping" -> #(
      "200 OK",
      "application/json",
      http.render_json_damping(damped_routes),
    )

    "/api/routeserver" -> #(
      "200 OK",
      "application/json",
      http.render_json_routeserver(srv.config.asn, srv.config.peers),
    )

    "/api/bmp" -> #(
      "200 OK",
      "application/json",
      http.render_json_bmp(srv.config.peers),
    )

    "/api/rr" -> #(
      "200 OK",
      "application/json",
      http.render_json_routereflector(srv.config.cluster_id, srv.config.peers),
    )

    "/api/confed" -> #(
      "200 OK",
      "application/json",
      http.render_json_confederation(
        srv.config.confederation_id,
        srv.config.peers,
      ),
    )

    "/api/topology" -> #(
      "200 OK",
      "application/json",
      http.render_json_topology(
        srv.config.asn,
        ip_to_string(srv.config.router_id),
        peers,
        routes,
      ),
    )

    "/api/rtr" -> {
      let rtr_cli = new_rtr_client("127.0.0.1", 8282)
      #("200 OK", "application/json", http.render_json_rtr(rtr_cli))
    }

    "/api/bfd" -> {
      let bfd_sess = new_bfd_session("peer1", 100, 300_000, 300_000, 3)
      #("200 OK", "application/json", http.render_json_bfd([bfd_sess]))
    }

    "/api/blackhole" -> #(
      "200 OK",
      "application/json",
      http.render_json_blackhole(routes),
    )

    "/api/evpn" -> {
      let t2 = [
        EvpnRouteType2(
          rd: RdAsn4(srv.config.asn, 100),
          esi: <<0:80>>,
          eth_tag_id: 0,
          mac_address: "02:42:ac:11:00:02",
          ip_address: Some(Ipv4(172, 22, 64, 129)),
          vni: 10_100,
        ),
      ]
      let t5 = [
        EvpnRouteType5(
          rd: RdAsn4(srv.config.asn, 100),
          esi: <<0:80>>,
          eth_tag_id: 0,
          prefix: IpPrefix(Ipv4(172, 22, 64, 160), 28),
          gateway_ip: Some(Ipv4(172, 22, 64, 129)),
          vni: 10_100,
        ),
      ]
      #("200 OK", "application/json", http.render_json_evpn(t2, t5))
    }

    "/api/lg" -> {
      let sum =
        query_summary(
          srv.config.asn,
          ip_to_string(srv.config.router_id),
          now() - srv.started_at,
          peers,
          routes,
          list.length(srv.roa_table),
          "RTRv1 Synchronized (#1420)",
          3,
        )
      #("200 OK", "application/json", http.render_json_lg_sum(sum))
    }

    "/api/vrf" -> {
      let mgr = get_sample_vrf_manager(srv)
      #("200 OK", "application/json", http.render_json_vrf(mgr))
    }

    "/api/sr" -> {
      let label_idx = LabelIndexTlv(label_index: 125, flags: 0)
      let srv6_sid =
        Ipv6SidTlv(
          sid: Ipv6(0xfdd4, 0xaf47, 0xdcfa, 0x0001, 0, 0, 0, 1),
          flags: 0,
        )
      let srgb =
        OriginatorSrgbTlv(flags: 0, blocks: [
          SrgbBlock(base_label: 16_000, range_size: 8000),
        ])
      let sid = BgpPrefixSid(tlvs: [label_idx, srv6_sid, srgb])
      #("200 OK", "application/json", http.render_json_sr([sid]))
    }

    "/api/unnumbered" -> {
      let p1 =
        UnnumberedPeer(
          interface: "dn42-peer-klaus",
          remote_link_local: Ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
          local_link_local: Ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 113),
          peer_asn: 4_242_421_234,
          extended_next_hop: True,
          status: "ESTABLISHED",
        )
      #("200 OK", "application/json", http.render_json_unnumbered([p1]))
    }

    "/api/netmodel" -> {
      let sample_reg =
        model.Region(
          id: "fra",
          name: "Frankfurt am Main",
          country: "DE",
          dn42_region: 41,
          lat: 50.11,
          lon: 8.68,
        )
      let sample_node =
        model.RouterNode(
          id: "fra-edge-1",
          hostname: "edge1.fra.slopnet",
          region_id: "fra",
          role: model.RoleEdge,
          asn: None,
          router_id: ip_to_string(srv.config.router_id),
          loopback_v4: ip_to_string(srv.config.local_ipv4),
          loopback_v6: ip_to_string(srv.config.local_ipv6),
          bgp_port: srv.config.bgp_port,
          api_port: srv.config.api_port,
          extra_tags: ["core", "dn42"],
        )
      let sample_model =
        model.GlobalNetworkModel(
          name: "slopnet-global",
          asn: srv.config.asn,
          regions: [sample_reg],
          routers: [sample_node],
          links: [],
          external_peers: [],
        )
      #(
        "200 OK",
        "application/json",
        http.render_json_netmodel(Some(sample_model)),
      )
    }

    "/api/otc" -> #(
      "200 OK",
      "application/json",
      http.render_json_otc(0, srv.config.peers),
    )

    "/api/bgpls" -> #("200 OK", "application/json", http.render_json_bgpls())

    "/api/filter" -> #("200 OK", "application/json", http.render_json_filter())

    "/api/slurm" -> #(
      "200 OK",
      "application/json",
      http.render_json_slurm(None),
    )

    "/api/rtc" -> #("200 OK", "application/json", http.render_json_rtc(None))

    "/api/orr" -> #("200 OK", "application/json", http.render_json_orr(None))

    "/api/pic" -> #("200 OK", "application/json", http.render_json_pic(None))

    "/api/sr-policy" -> #(
      "200 OK",
      "application/json",
      http.render_json_sr_policy(),
    )

    "/api/lu" -> #("200 OK", "application/json", http.render_json_lu())

    _ -> #("404 Not Found", "application/json", "{\"error\":\"Not Found\"}\n")
  }
}

fn get_sample_vrf_manager(srv: ServerState) -> VrfManager {
  let mgr0 = new_manager()
  let vrf1 =
    VrfConfig(
      name: "tenant-red",
      rd: RdAsn4(srv.config.asn, 100),
      import_targets: [],
      export_targets: [],
      table_id: 100,
      export_label: 1001,
    )
  let sample_pfx = IpPrefix(address: Ipv4(172, 22, 64, 128), length: 27)
  let sample_rt =
    Route(
      prefix: sample_pfx,
      origin: OriginIgp,
      as_path: [],
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
  let mgr1 = add_vrf(mgr0, vrf1)
  case add_local_route(mgr1, "tenant-red", sample_rt) {
    Ok(m) -> m
    Error(_) -> mgr1
  }
}
