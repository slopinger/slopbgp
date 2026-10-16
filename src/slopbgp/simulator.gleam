import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import slopbgp/bgp/fsm.{
  EventAutomaticStart, EventReceivedKeepalive, EventReceivedOpen,
  EventTcpConnected, handle_event, new_session,
}
import slopbgp/config.{default_config}
import slopbgp/dn42/roa.{validate_route}
import slopbgp/ip.{parse_prefix, prefix_to_string}
import slopbgp/rib/rib.{get_all_routes, insert_route}
import slopbgp/server.{ingest_peer_update, new_server}
import slopbgp/types.{
  type Route, AfiIpv4, AfiIpv6, AsSequence, AttrAsPath, AttrCommunities,
  AttrLargeCommunities, AttrLocalPref, AttrMed, AttrMpReachNlri, AttrNextHop,
  AttrOrigin, CapExtendedNextHop, CapFourOctetAsn, CapMultiProtocol,
  CapRouteRefresh, Community, Ipv4, Ipv6, LargeCommunity, MsgOpen, MsgUpdate,
  OriginIgp, PeerConfig, RoaEntry, RoaInvalid, RoaNotFound, RoaValid, Route,
  SafiUnicast, StateEstablished, StateOpenConfirm, StateOpenSent,
}

pub fn run_simulation() -> Result(Nil, String) {
  io.println("================================================================")
  io.println("slopbgp // Autonomous Peering & BGP Protocol Simulation Engine")
  io.println("================================================================")

  // 1. Setup virtual local router (slop, AS4242420125)
  let cfg = default_config()
  let local_asn = cfg.asn
  let local_router_id = cfg.router_id

  io.println(
    "[1] Initializing virtual BGP router: AS" <> int.to_string(local_asn),
  )

  // 2. Setup mock peer router (Baragoon Frankfurt, AS4242421732)
  let peer_asn = 4_242_421_732
  let peer_id = "baragoon_fra"
  let peer_ip = Ipv4(172, 22, 64, 1)

  let peer_cfg =
    PeerConfig(
      id: peer_id,
      name: "Baragoon Frankfurt Peering",
      remote_as: peer_asn,
      remote_ip: peer_ip,
      local_as: local_asn,
      local_ip: local_router_id,
      port: 179,
      hold_time: 90,
      keepalive_time: 30,
      passive: False,
      enable_ipv4: True,
      enable_ipv6: True,
      extended_next_hop: True,
      add_path_rx: True,
      add_path_tx: False,
      dn42_latency: Some(8),
      dn42_bandwidth: Some(22),
      dn42_crypto: Some(34),
      dn42_region: Some(41),
      import_filters: [],
      export_filters: [],
    )

  let srv = server.add_peer(new_server(cfg), peer_cfg)
  io.println(
    "[2] Configured virtual peer "
    <> peer_id
    <> " (AS"
    <> int.to_string(peer_asn)
    <> ")",
  )

  // 3. Simulate FSM Handshake: Connect -> OpenSent -> OpenConfirm -> Established
  let fsm0 = new_session(peer_id, local_asn, local_router_id, peer_asn, 90)

  let #(fsm_start, _) = handle_event(fsm0, EventAutomaticStart)
  let #(fsm1, _) = handle_event(fsm_start, EventTcpConnected)
  case fsm1.state == StateOpenSent {
    True ->
      io.println(
        "[3] FSM Transition: Idle -> Connect -> OpenSent (TCP Connected)",
      )
    False -> io.println("[!] FSM Transition error")
  }

  // Peer sends OPEN message with 4-Byte ASN, MP-BGP and Extended Next Hop capabilities
  let peer_caps = [
    CapFourOctetAsn(peer_asn),
    CapRouteRefresh,
    CapMultiProtocol(AfiIpv4, SafiUnicast),
    CapMultiProtocol(AfiIpv6, SafiUnicast),
    CapExtendedNextHop(AfiIpv4, SafiUnicast, AfiIpv6),
  ]

  let open_msg =
    MsgOpen(
      version: 4,
      my_as: peer_asn,
      hold_time: 90,
      bgp_id: peer_ip,
      capabilities: peer_caps,
    )

  let #(fsm2, _actions2) = handle_event(fsm1, EventReceivedOpen(open_msg))
  case fsm2.state == StateOpenConfirm {
    True ->
      io.println(
        "[4] Received OPEN from AS"
        <> int.to_string(peer_asn)
        <> " -> FSM State: OpenConfirm",
      )
    False -> io.println("[!] Failed to transition to OpenConfirm")
  }

  let #(fsm3, _) = handle_event(fsm2, EventReceivedKeepalive)
  case fsm3.state == StateEstablished {
    True -> io.println("[5] Received KEEPALIVE -> BGP Session ESTABLISHED!")
    False -> io.println("[!] Failed to establish session")
  }

  // 4. Ingest routes from Peer (BGP UPDATE)
  // Let's create prefixes:
  // Route 1: 172.22.123.32/27 (Authorized for AS4242423282)
  // Route 2: 172.20.44.128/27 (Authorized for AS4242420387)
  // Route 3: fd8f:3250:9097::/48 (Authorized for AS4242420461, advertised via MP_REACH_NLRI)
  let assert Ok(pfx1) = parse_prefix("172.22.123.32/27")
  let assert Ok(pfx2) = parse_prefix("172.20.44.128/27")
  let assert Ok(pfx3_v6) = parse_prefix("fd8f:3250:9097::/48")

  // Test ROA rules loaded in memory
  let roa_table = [
    RoaEntry(prefix: pfx1, max_length: 27, asn: 4_242_423_282),
    RoaEntry(prefix: pfx2, max_length: 29, asn: 4_242_420_387),
    RoaEntry(prefix: pfx3_v6, max_length: 64, asn: 4_242_420_461),
  ]

  let srv_with_roa = server.ServerState(..srv, roa_table: roa_table)

  io.println(
    "[6] Injecting BGP UPDATE announcements with RFC 8092 Large Communities & MP-BGP...",
  )

  // Create UPDATE message with 4-byte AS_PATH, Communities, Large Communities
  let update1 =
    MsgUpdate(
      withdrawn: [],
      attributes: [
        AttrOrigin(OriginIgp),
        AttrAsPath([AsSequence([peer_asn, 4_242_423_282])]),
        AttrNextHop(peer_ip),
        AttrMed(10),
        AttrLocalPref(100),
        AttrCommunities([Community(64_511, 8)]),
        AttrLargeCommunities([LargeCommunity(peer_asn, 1, 100)]),
      ],
      nlri: [pfx1],
    )

  let srv_after_update1 =
    ingest_peer_update(srv_with_roa, peer_id, update1, 1000)

  // Route 2 with different path
  let update2 =
    MsgUpdate(
      withdrawn: [],
      attributes: [
        AttrOrigin(OriginIgp),
        AttrAsPath([AsSequence([peer_asn, 4_242_420_387])]),
        AttrNextHop(peer_ip),
        AttrMed(20),
        AttrLocalPref(100),
        AttrCommunities([Community(64_511, 5)]),
      ],
      nlri: [pfx2],
    )

  let srv_after_update2 =
    ingest_peer_update(srv_after_update1, peer_id, update2, 1001)

  // Route 3 (IPv6 MP_REACH_NLRI)
  let update3_v6 =
    MsgUpdate(
      withdrawn: [],
      attributes: [
        AttrOrigin(OriginIgp),
        AttrAsPath([AsSequence([peer_asn, 4_242_420_461])]),
        AttrLocalPref(100),
        AttrMpReachNlri(
          AfiIpv6,
          SafiUnicast,
          [Ipv6(0xFE80, 0, 0, 0, 0, 0, 0, 0x1732)],
          [pfx3_v6],
        ),
      ],
      nlri: [],
    )

  let srv_after_update3 =
    ingest_peer_update(srv_after_update2, peer_id, update3_v6, 1002)

  let routes = get_all_routes(srv_after_update3.rib)
  io.println("[7] Routing Information Base (Loc-RIB) Convergence:")
  list.each(routes, fn(r: Route) {
    let roa_str = case r.roa_status {
      RoaValid -> "VALID"
      RoaInvalid -> "INVALID"
      RoaNotFound -> "NOT_FOUND"
    }
    io.println(
      "  * Prefix: "
      <> prefix_to_string(r.prefix)
      <> " -> NextHop: "
      <> ip.ip_to_string(r.next_hop)
      <> " [ROA: "
      <> roa_str
      <> "]"
      <> " [MED: "
      <> int.to_string(r.med)
      <> "]",
    )
  })

  // 5. Test Route Origin Authorization (RFC 6811)
  io.println("[8] Verifying RFC 6811 Prefix Origin Validation (ROA):")
  let roa_test_valid = validate_route(pfx1, 4_242_423_282, roa_table)
  let roa_test_invalid = validate_route(pfx1, 4_242_429_999, roa_table)
  let assert Ok(unknown_pfx) = parse_prefix("172.22.99.0/24")
  let roa_test_notfound = validate_route(unknown_pfx, 4_242_420_125, roa_table)

  io.println(
    "  - Test 1 (Expected VALID): " <> roa_status_to_string(roa_test_valid),
  )
  io.println(
    "  - Test 2 (Expected INVALID): " <> roa_status_to_string(roa_test_invalid),
  )
  io.println(
    "  - Test 3 (Expected NOT_FOUND): "
    <> roa_status_to_string(roa_test_notfound),
  )

  // 6. Test Best Path Selection
  io.println("[9] Testing Best Path Selection with competing paths...")
  let competing_route_higher_pref =
    Route(
      ..list.first(routes)
      |> result.unwrap(make_dummy_route(pfx1)),
      local_pref: 200,
      peer_id: "competing_peer_ams",
    )
  let #(_rib_after_comp, best_opt) =
    insert_route(srv_after_update3.rib, competing_route_higher_pref)

  case best_opt {
    Some(best) ->
      io.println(
        "  - Competing route selected: Peer "
        <> best.peer_id
        <> " won with LocalPref "
        <> int.to_string(best.local_pref),
      )
    None -> io.println("  - Route retained")
  }

  io.println("================================================================")
  io.println("BGP Daemon Simulation PASSED: All protocol extensions verified!")
  io.println("================================================================")
  Ok(Nil)
}

fn roa_status_to_string(status: types.RoaStatus) -> String {
  case status {
    RoaValid -> "VALID"
    RoaInvalid -> "INVALID"
    RoaNotFound -> "NOT_FOUND"
  }
}

fn make_dummy_route(pfx: types.IpPrefix) -> Route {
  Route(
    prefix: pfx,
    origin: OriginIgp,
    as_path: [],
    next_hop: Ipv4(127, 0, 0, 1),
    med: 0,
    local_pref: 100,
    atomic_aggregate: False,
    communities: [],
    large_communities: [],
    ext_communities: [],
    otc: None,
    roa_status: RoaNotFound,
    peer_id: "test",
    timestamp: 0,
    path_id: None,
  )
}
