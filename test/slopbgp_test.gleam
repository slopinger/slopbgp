import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import gleeunit/should
import slopbgp/api/http
import slopbgp/bfd/message as bfd_msg
import slopbgp/bfd/session as bfd_session
import slopbgp/bgp/attributes.{decode_attributes, encode_attributes}
import slopbgp/bgp/bgpls
import slopbgp/bgp/blackhole
import slopbgp/bgp/capabilities.{decode_capabilities, encode_capability}
import slopbgp/bgp/confederation
import slopbgp/bgp/damping.{default_damping_config, evaluate_flap, record_flap}
import slopbgp/bgp/evpn
import slopbgp/bgp/flowspec.{
  decode_action_community, decode_flowspec_nlri, encode_action_community,
  encode_flowspec_nlri, format_rule, to_nftables_rule,
}
import slopbgp/bgp/fsm.{
  EventAutomaticStart, EventReceivedKeepalive, EventReceivedOpen,
  EventTcpConnected, handle_event, new_session,
}
import slopbgp/bgp/graceful_shutdown.{
  apply_graceful_shutdown_inbound, apply_graceful_shutdown_outbound,
  graceful_shutdown_community, has_graceful_shutdown,
}
import slopbgp/bgp/l3vpn
import slopbgp/bgp/message.{decode_message, encode_message}
import slopbgp/bgp/prefix_sid
import slopbgp/bgp/rfc8212
import slopbgp/bgp/rfc9234
import slopbgp/bgp/routereflector
import slopbgp/bgp/shutdown_communication.{
  decode_shutdown_communication, encode_shutdown_communication,
  format_cease_subcode, make_shutdown_notification,
}
import slopbgp/bgp/unnumbered
import slopbgp/bmp/message as bmp_message
import slopbgp/config
import slopbgp/dn42/filter.{is_bogon, is_valid_dn42_network}
import slopbgp/dn42/roa.{parse_roa_line, validate_route}
import slopbgp/filter/hygiene
import slopbgp/filter/pipeline as slop_pipeline
import slopbgp/ip.{
  decode_prefixes_ipv4, encode_prefix, ip_to_string, is_prefix_contained,
  parse_ip, parse_prefix, prefix_to_string,
}
import slopbgp/lookingglass/lookingglass as lg
import slopbgp/metrics/prometheus.{DaemonMetricsData, render_prometheus_metrics}
import slopbgp/netmodel/compiler as net_compiler
import slopbgp/netmodel/model as net_model
import slopbgp/netmodel/sim as net_sim
import slopbgp/netmodel/validator as net_validator
import slopbgp/policy/filter as policy_filter
import slopbgp/rib/rib.{compare_routes, insert_route, new_rib, withdraw_route}
import slopbgp/routeserver/routeserver
import slopbgp/rtr/client as rtr_client
import slopbgp/rtr/message as rtr_msg
import slopbgp/server
import slopbgp/simulator.{run_simulation}
import slopbgp/types.{
  type Route, ActionAccept, ActionPrependAs, ActionSetLocalPref, AfiIpv4,
  AfiIpv6, AsConfedSequence, AsConfedSet, AsSequence, AttrAsPath,
  AttrClusterList, AttrCommunities, AttrLargeCommunities, AttrLocalPref, AttrMed,
  AttrMpReachNlri, AttrNextHop, AttrOrigin, AttrOriginatorId, BmpMsgInitiation,
  BmpMsgPeerDown, BmpMsgRouteMonitoring, BmpMsgStatsReport, BmpMsgTermination,
  BmpPeerHeader, BmpStatCounter, CapAddPath, CapBgpRole, CapEnhancedRouteRefresh,
  CapExtendedMessage, CapExtendedNextHop, CapFourOctetAsn, CapMultiProtocol,
  CapRouteRefresh, Community, FlowActionDrop, FlowDstPort, FlowDstPrefix,
  FlowIpProtocol, FlowLabel, FlowNextHeader, FlowSrcPrefix, FlowspecRule,
  IpPrefix, Ipv4, Ipv6, LargeCommunity, MatchAsPathContains, MsgKeepalive,
  MsgNotification, MsgOpen, MsgRouteRefresh, OriginIgp, PeerConfig, PolicyChain,
  PolicyRule, RoaInvalid, RoaNotFound, RoaValid, RoleCustomer, RolePeer,
  RoleProvider, RoleRouteServer, RoleRouteServerClient, Route, SafiUnicast,
  StateConnect, StateEstablished, StateOpenConfirm, StateOpenSent,
}
import slopbgp/vrf/vrf

pub fn main() {
  gleeunit.main()
}

// 1. IP and Prefix Tests
pub fn ip_parsing_test() {
  let assert Ok(v4) = parse_ip("172.22.64.129")
  ip_to_string(v4) |> should.equal("172.22.64.129")

  let assert Ok(v6) = parse_ip("fdd4:af47:dcfa::1")
  ip_to_string(v6) |> should.equal("fdd4:af47:dcfa:0:0:0:0:1")

  let assert Ok(p4) = parse_prefix("172.22.64.128/27")
  prefix_to_string(p4) |> should.equal("172.22.64.128/27")

  let assert Ok(child) = parse_prefix("172.22.64.130/32")
  is_prefix_contained(child, p4) |> should.equal(True)

  let assert Ok(outside) = parse_prefix("172.22.65.0/24")
  is_prefix_contained(outside, p4) |> should.equal(False)
}

// 2. Prefix Wire Encoding / Decoding (RFC 4271 & RFC 7911 ADD-PATH)
pub fn prefix_wire_encoding_test() {
  let assert Ok(pfx) = parse_prefix("172.20.0.0/14")
  let bin = encode_prefix(pfx, None)
  let assert Ok(decoded) = decode_prefixes_ipv4(bin, False)
  let assert [#(dec_pfx, opt_id)] = decoded
  dec_pfx |> should.equal(pfx)
  opt_id |> should.equal(None)

  // Test with ADD-PATH path identifier
  let bin_path_id = encode_prefix(pfx, Some(42))
  let assert Ok(decoded_path_id) = decode_prefixes_ipv4(bin_path_id, True)
  let assert [#(dec_pfx2, opt_id2)] = decoded_path_id
  dec_pfx2 |> should.equal(pfx)
  opt_id2 |> should.equal(Some(42))
}

// 3. Capabilities Negotiation (RFC 5492, 6793, 4760, 8950, 7911, 4724, 8654, 9234)
pub fn capabilities_roundtrip_test() {
  let caps = [
    CapFourOctetAsn(4_242_420_125),
    CapRouteRefresh,
    CapEnhancedRouteRefresh,
    CapExtendedMessage,
    CapMultiProtocol(AfiIpv4, SafiUnicast),
    CapMultiProtocol(AfiIpv6, SafiUnicast),
    CapExtendedNextHop(AfiIpv4, SafiUnicast, AfiIpv6),
    CapBgpRole(RoleCustomer),
    CapAddPath(AfiIpv4, SafiUnicast, True, True),
  ]

  let bin =
    list.fold(caps, <<>>, fn(acc, c) {
      <<acc:bits, { encode_capability(c) }:bits>>
    })
  let decoded = decode_capabilities(bin)
  list.length(decoded) |> should.equal(list.length(caps))
}

// 4. Path Attributes Encoding / Decoding (RFC 4271, 8092, 4760, 8950)
pub fn path_attributes_roundtrip_test() {
  let segs = [AsSequence([4_242_420_125, 4_242_421_732])]
  let comms = [Community(64_511, 8)]
  let large_comms = [LargeCommunity(4_242_420_125, 1, 100)]
  let assert Ok(pfx_v6) = parse_prefix("fd8f:3250:9097::/48")

  let attrs = [
    AttrOrigin(OriginIgp),
    AttrAsPath(segs),
    AttrNextHop(Ipv4(172, 22, 64, 1)),
    AttrMed(15),
    AttrLocalPref(120),
    AttrCommunities(comms),
    AttrLargeCommunities(large_comms),
    AttrMpReachNlri(AfiIpv6, SafiUnicast, [Ipv6(0xFE80, 0, 0, 0, 0, 0, 0, 1)], [
      pfx_v6,
    ]),
  ]

  let bin = encode_attributes(attrs)
  let assert Ok(decoded) = decode_attributes(bin, False)
  list.length(decoded) |> should.equal(list.length(attrs))
}

// 5. BGP Messages Roundtrip (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH)
pub fn bgp_messages_test() {
  // KEEPALIVE
  let ka = MsgKeepalive
  let ka_bytes = encode_message(ka)
  let assert Ok(#(dec_ka, <<>>)) = decode_message(ka_bytes, False)
  dec_ka |> should.equal(MsgKeepalive)

  // NOTIFICATION
  let notif = MsgNotification(2, 2, <<1:8>>)
  let notif_bytes = encode_message(notif)
  let assert Ok(#(dec_notif, <<>>)) = decode_message(notif_bytes, False)
  dec_notif |> should.equal(notif)

  // ROUTE-REFRESH (RFC 2918 & 7313)
  let rr = MsgRouteRefresh(AfiIpv6, 1, SafiUnicast)
  let rr_bytes = encode_message(rr)
  let assert Ok(#(dec_rr, <<>>)) = decode_message(rr_bytes, False)
  dec_rr |> should.equal(rr)

  // OPEN
  let open_msg =
    MsgOpen(
      version: 4,
      my_as: 4_242_420_125,
      hold_time: 90,
      bgp_id: Ipv4(172, 22, 64, 129),
      capabilities: [CapFourOctetAsn(4_242_420_125)],
    )
  let open_bytes = encode_message(open_msg)
  let assert Ok(#(dec_open, <<>>)) = decode_message(open_bytes, False)
  case dec_open {
    MsgOpen(ver, asn, hold, id, _) -> {
      ver |> should.equal(4)
      asn |> should.equal(4_242_420_125)
      hold |> should.equal(90)
      id |> should.equal(Ipv4(172, 22, 64, 129))
    }
    _ -> should.fail()
  }
}

// 6. Finite State Machine Tests (RFC 4271 §8)
pub fn fsm_transitions_test() {
  let session =
    new_session(
      "test_peer",
      4_242_420_125,
      Ipv4(172, 22, 64, 129),
      4_242_421_732,
      90,
    )

  // Automatic Start -> StateConnect
  let #(s0, _) = handle_event(session, EventAutomaticStart)
  s0.state |> should.equal(StateConnect)

  // Connect -> StateOpenSent
  let #(s1, _) = handle_event(s0, EventTcpConnected)
  s1.state |> should.equal(StateOpenSent)

  // Receive Open
  let open_in =
    MsgOpen(
      version: 4,
      my_as: 4_242_421_732,
      hold_time: 90,
      bgp_id: Ipv4(172, 22, 64, 1),
      capabilities: [CapFourOctetAsn(4_242_421_732)],
    )
  let #(s2, _) = handle_event(s1, EventReceivedOpen(open_in))
  s2.state |> should.equal(StateOpenConfirm)

  // Receive Keepalive -> Established
  let #(s3, _) = handle_event(s2, EventReceivedKeepalive)
  s3.state |> should.equal(StateEstablished)
}

// 7. DN42 Filtering & Bogon Detection
pub fn dn42_filters_test() {
  let assert Ok(dn42_v4) = parse_prefix("172.22.64.128/27")
  is_valid_dn42_network(dn42_v4) |> should.equal(True)
  is_bogon(dn42_v4) |> should.equal(False)

  let assert Ok(dn42_v6) = parse_prefix("fdd4:af47:dcfa::/48")
  is_valid_dn42_network(dn42_v6) |> should.equal(True)
  is_bogon(dn42_v6) |> should.equal(False)

  let assert Ok(default_route) = parse_prefix("0.0.0.0/0")
  is_bogon(default_route) |> should.equal(True)

  let assert Ok(google_dns) = parse_prefix("8.8.8.0/24")
  is_valid_dn42_network(google_dns) |> should.equal(False)
}

// 8. DN42 ROA Parsing & RFC 6811 Validation
pub fn roa_validation_test() {
  let line = "route 172.22.123.32/27 max 27 as 4242423282;"
  let assert Ok(entry) = parse_roa_line(line)
  entry.asn |> should.equal(4_242_423_282)
  entry.max_length |> should.equal(27)

  let table = [entry]
  let assert Ok(pfx) = parse_prefix("172.22.123.32/27")

  // Valid
  validate_route(pfx, 4_242_423_282, table) |> should.equal(RoaValid)

  // Invalid ASN
  validate_route(pfx, 4_242_429_999, table) |> should.equal(RoaInvalid)

  // Not found
  let assert Ok(other_pfx) = parse_prefix("172.20.1.0/24")
  validate_route(other_pfx, 4_242_423_282, table) |> should.equal(RoaNotFound)
}

// 9. RIB Best Path Decision Algorithm
pub fn rib_decision_process_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.0/24")

  let r1 =
    Route(
      prefix: pfx,
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
      peer_id: "peer1",
      timestamp: 100,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  // r2 has higher local_pref
  let r2 = Route(..r1, local_pref: 150, peer_id: "peer2")

  compare_routes(r2, r1) |> should.equal(True)
  compare_routes(r1, r2) |> should.equal(False)

  let rib0 = new_rib()
  let #(rib1, best1) = insert_route(rib0, r1)
  best1 |> should.equal(Some(r1))

  let #(rib2, best2) = insert_route(rib1, r2)
  best2 |> should.equal(Some(r2))

  // Withdraw r2 -> r1 becomes best again
  let #(_rib3, best3) = withdraw_route(rib2, "peer2", pfx)
  best3 |> should.equal(Some(r1))
}

// 10. Simulation test
pub fn full_simulation_test() {
  let res = run_simulation()
  res |> should.equal(Ok(Nil))
}

// 11. RFC 8326 Graceful Shutdown Tests
pub fn graceful_shutdown_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let clean_route =
    Route(
      prefix: pfx,
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
      peer_id: "peer_de",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  has_graceful_shutdown(clean_route) |> should.equal(False)

  // Applying outbound graceful shutdown attaches community 65535:0 and local_pref 0
  let drained_route = apply_graceful_shutdown_outbound(clean_route)
  has_graceful_shutdown(drained_route) |> should.equal(True)
  drained_route.local_pref |> should.equal(0)
  list.contains(drained_route.communities, graceful_shutdown_community())
  |> should.equal(True)

  // Inbound reception of drained route depresses local_pref to 0
  let inbound_drained = apply_graceful_shutdown_inbound(drained_route)
  inbound_drained.local_pref |> should.equal(0)
}

// 12. RFC 2439 Route Flap Damping Tests
pub fn flap_damping_test() {
  let cfg = default_damping_config()
  let assert Ok(_pfx) = parse_prefix("172.20.50.0/24")

  // Initial flap at t=0
  let h1 = record_flap(None, 0, cfg)
  h1.penalty |> should.equal(1000.0)
  h1.flaps_count |> should.equal(1)
  h1.suppressed |> should.equal(False)

  // Flap again shortly at t=10
  let h2 = record_flap(Some(h1), 10, cfg)
  h2.flaps_count |> should.equal(2)
  h2.suppressed |> should.equal(False)

  // Third flap at t=20 exceeds suppress threshold (2000.0) -> suppressed!
  let h3 = record_flap(Some(h2), 20, cfg)
  h3.flaps_count |> should.equal(3)
  h3.suppressed |> should.equal(True)

  // After 1800s (2 half-lives), penalty decays below reuse_threshold (750) -> suppression lifted
  let h4 = evaluate_flap(h3, 20 + 1800, cfg)
  h4.suppressed |> should.equal(False)
}

// 13. RFC 5575 / RFC 8955 BGP Flowspec Tests
pub fn flowspec_test() {
  let assert Ok(pfx) = parse_prefix("172.20.10.0/24")
  let components = [
    FlowDstPrefix(pfx),
    FlowIpProtocol(0x01, 6),
    FlowDstPort(0x01, 80),
  ]

  let wire_bin = encode_flowspec_nlri(components)
  let assert <<_len:8, payload:bits>> = wire_bin
  let assert Ok(decoded_comps) = decode_flowspec_nlri(payload, AfiIpv4)
  list.length(decoded_comps) |> should.equal(3)

  let rule =
    FlowspecRule(
      id: "ddos-drop-http",
      afi: AfiIpv4,
      components: components,
      actions: [FlowActionDrop],
      origin_peer: "peer_fra",
      timestamp: 1000,
    )

  let rule_str = format_rule(rule)
  string.contains(rule_str, "dst 172.20.10.0/24") |> should.equal(True)
  string.contains(rule_str, "proto tcp") |> should.equal(True)
  string.contains(rule_str, "dport 80") |> should.equal(True)
  string.contains(rule_str, "DROP") |> should.equal(True)

  let nft_rule = to_nftables_rule(rule)
  string.contains(nft_rule, "nft add rule inet filter input")
  |> should.equal(True)
  string.contains(nft_rule, "ip daddr 172.20.10.0/24") |> should.equal(True)
  string.contains(nft_rule, "ip protocol tcp th dport 80 drop")
  |> should.equal(True)

  let ext_comm = encode_action_community(FlowActionDrop, 4_242_420_125)
  let assert Ok(action) = decode_action_community(ext_comm)
  action |> should.equal(FlowActionDrop)
}

// 14. Routing Policy Engine Tests
pub fn routing_policy_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let r =
    Route(
      prefix: pfx,
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
      peer_id: "peer_baragoon",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let custom_policy =
    PolicyChain(name: "prefer_baragoon", default_action: ActionAccept, rules: [
      PolicyRule(
        name: "boost_baragoon",
        matches: [MatchAsPathContains(4_242_421_732)],
        actions: [
          ActionSetLocalPref(250),
          ActionPrependAs(4_242_420_125, 1),
        ],
      ),
    ])

  let #(accepted, modified): #(Bool, Route) =
    policy_filter.evaluate_chain(r, custom_policy)
  accepted |> should.equal(True)
  modified.local_pref |> should.equal(250)
  modified.as_path
  |> should.equal([AsSequence([4_242_420_125, 4_242_421_732])])

  // DN42 Default Policy rejects bogons
  let assert Ok(bogon) = parse_prefix("192.168.1.0/24")
  let bogon_route = Route(..r, prefix: bogon)
  case
    policy_filter.filter_inbound_route(
      bogon_route,
      policy_filter.dn42_default_import_policy(),
    )
  {
    Error(_) -> True
    Ok(_) -> False
  }
  |> should.equal(True)
}

// 15. Prometheus Metrics Rendering Tests
pub fn prometheus_metrics_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let r =
    Route(
      prefix: pfx,
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
      peer_id: "peer1",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let data =
    DaemonMetricsData(
      asn: 4_242_420_125,
      router_id: Ipv4(172, 22, 64, 129),
      peers: [],
      routes: [r],
      fib_count: 1,
      roa_count: 5000,
      flowspec_rules: [],
      damped_routes: [],
    )

  let metrics = render_prometheus_metrics(data)
  string.contains(metrics, "slopbgp_info{version=\"0.1.0\",asn=\"4242420125\"")
  |> should.equal(True)
  string.contains(metrics, "slopbgp_loc_rib_routes_total{family=\"ipv4\"} 1")
  |> should.equal(True)
  string.contains(metrics, "slopbgp_fib_routes_installed 1")
  |> should.equal(True)
  string.contains(metrics, "slopbgp_roa_rules_total 5000")
  |> should.equal(True)
}

// 16. RFC 9003 Extended Administrative Shutdown Communication Tests
pub fn administrative_shutdown_communication_test() {
  let reason = "Scheduled fiber maintenance until 04:00 UTC"
  let encoded = encode_shutdown_communication(reason)

  // Verify decoded reason matches original
  let assert Ok(decoded) = decode_shutdown_communication(encoded)
  decoded |> should.equal(reason)

  // Empty string encoding
  let empty_encoded = encode_shutdown_communication("")
  empty_encoded |> should.equal(<<0:8>>)
  case decode_shutdown_communication(empty_encoded) {
    Error(_) -> True
    Ok(_) -> False
  }
  |> should.equal(True)

  // Cease subcode formatting
  format_cease_subcode(2)
  |> should.equal("Administrative Shutdown (RFC 9003)")
  format_cease_subcode(4)
  |> should.equal("Administrative Reset (RFC 9003)")

  // Notification generation and wire roundtrip
  let notif = make_shutdown_notification(2, reason)
  let raw = encode_message(notif)
  let assert Ok(#(decoded_msg, _)) = decode_message(raw, False)
  case decoded_msg {
    MsgNotification(code, subcode, data) -> {
      code |> should.equal(6)
      subcode |> should.equal(2)
      let assert Ok(parsed_reason) = decode_shutdown_communication(data)
      parsed_reason |> should.equal(reason)
    }
    _ -> panic as "Expected MsgNotification"
  }
}

// 17. RFC 8956 IPv6 Flowspec Dissemination Tests
pub fn flowspec_ipv6_test() {
  let assert Ok(dst_v6) = parse_prefix("fd00::/48")
  let assert Ok(src_v6) = parse_prefix("fd42:d42::/48")
  let comps = [
    FlowDstPrefix(dst_v6),
    FlowSrcPrefix(src_v6),
    FlowNextHeader(0, 6),
    FlowDstPort(0, 80),
    FlowLabel(0, 12_345),
  ]

  let binary_nlri = encode_flowspec_nlri(comps)
  let assert <<_len:8, payload:bits>> = binary_nlri
  let assert Ok(decoded_comps) = decode_flowspec_nlri(payload, AfiIpv6)
  list.length(decoded_comps) |> should.equal(5)

  let rule =
    FlowspecRule(
      id: "fs-v6-ddos",
      afi: AfiIpv6,
      components: comps,
      actions: [FlowActionDrop],
      origin_peer: "peer_v6",
      timestamp: 2000,
    )

  let formatted = format_rule(rule)
  string.contains(formatted, "dst fd00:0:0:0:0:0:0:0/48") |> should.equal(True)
  string.contains(formatted, "nexthdr tcp") |> should.equal(True)
  string.contains(formatted, "flowlabel 12345") |> should.equal(True)
  string.contains(formatted, "DROP") |> should.equal(True)

  let nft = to_nftables_rule(rule)
  string.contains(nft, "nft add rule ip6 filter input") |> should.equal(True)
  string.contains(nft, "ip6 daddr fd00:0:0:0:0:0:0:0/48") |> should.equal(True)
  string.contains(nft, "ip6 saddr fd42:d42:0:0:0:0:0:0/48")
  |> should.equal(True)
  string.contains(nft, "ip6 nexthdr tcp") |> should.equal(True)
  string.contains(nft, "th dport 80") |> should.equal(True)
  string.contains(nft, "ip6 flowlabel 12345") |> should.equal(True)
  string.contains(nft, "drop") |> should.equal(True)
}

// 18. RFC 7854 BGP Monitoring Protocol (BMP) Tests
pub fn bmp_protocol_test() {
  let peer_hdr =
    BmpPeerHeader(
      peer_type: 0,
      is_ipv6: False,
      is_post_policy: False,
      peer_distinguisher: <<0:64>>,
      peer_ip: Ipv4(172, 22, 64, 1),
      peer_as: 4_242_421_732,
      peer_bgp_id: Ipv4(172, 22, 64, 1),
      timestamp_sec: 1_700_000_000,
      timestamp_usec: 500_000,
    )

  // 1. Peer Header Roundtrip
  let hdr_bin = bmp_message.encode_peer_header(peer_hdr)
  let assert Ok(#(decoded_hdr, _)) = bmp_message.decode_peer_header(hdr_bin)
  decoded_hdr.peer_as |> should.equal(4_242_421_732)
  decoded_hdr.timestamp_sec |> should.equal(1_700_000_000)
  decoded_hdr.is_ipv6 |> should.equal(False)

  // 2. BMP Initiation Message
  let init_msg =
    BmpMsgInitiation("arch-router", "slopbgp v0.1.0 on Erlang/OTP BEAM")
  let init_bytes = bmp_message.encode_bmp_message(init_msg)
  let assert Ok(decoded_init) = bmp_message.decode_bmp_message(init_bytes)
  case decoded_init {
    BmpMsgInitiation(name, descr) -> {
      name |> should.equal("arch-router")
      descr |> should.equal("slopbgp v0.1.0 on Erlang/OTP BEAM")
    }
    _ -> panic as "Expected BmpMsgInitiation"
  }

  // 3. BMP Route Monitoring Message (encapsulating BGP UPDATE)
  let dummy_update = <<0:16, 0:16>>
  let rm_msg = BmpMsgRouteMonitoring(peer_hdr, dummy_update)
  let rm_bytes = bmp_message.encode_bmp_message(rm_msg)
  let assert Ok(decoded_rm) = bmp_message.decode_bmp_message(rm_bytes)
  case decoded_rm {
    BmpMsgRouteMonitoring(p, upd) -> {
      p.peer_as |> should.equal(4_242_421_732)
      upd |> should.equal(dummy_update)
    }
    _ -> panic as "Expected BmpMsgRouteMonitoring"
  }

  // 4. BMP Statistics Report Message
  let counters = [
    BmpStatCounter(bmp_message.stat_rejected_prefixes, 42),
    BmpStatCounter(bmp_message.stat_loc_rib_routes, 1250),
  ]
  let stats_msg = BmpMsgStatsReport(peer_hdr, counters)
  let stats_bytes = bmp_message.encode_bmp_message(stats_msg)
  let assert Ok(decoded_stats) = bmp_message.decode_bmp_message(stats_bytes)
  case decoded_stats {
    BmpMsgStatsReport(p, c_list) -> {
      p.peer_as |> should.equal(4_242_421_732)
      list.length(c_list) |> should.equal(2)
      let assert [c1, c2] = c_list
      c1.stat_type |> should.equal(bmp_message.stat_rejected_prefixes)
      c1.value |> should.equal(42)
      c2.stat_type |> should.equal(bmp_message.stat_loc_rib_routes)
      c2.value |> should.equal(1250)
    }
    _ -> panic as "Expected BmpMsgStatsReport"
  }

  // 5. BMP Peer Down Notification
  let down_msg = BmpMsgPeerDown(peer_hdr, 1, None)
  let down_bytes = bmp_message.encode_bmp_message(down_msg)
  let assert Ok(decoded_down) = bmp_message.decode_bmp_message(down_bytes)
  case decoded_down {
    BmpMsgPeerDown(p, reason, _) -> {
      p.peer_as |> should.equal(4_242_421_732)
      reason |> should.equal(1)
    }
    _ -> panic as "Expected BmpMsgPeerDown"
  }

  // 6. BMP Termination Message
  let term_msg = BmpMsgTermination(0, "Administrative maintenance")
  let term_bytes = bmp_message.encode_bmp_message(term_msg)
  let assert Ok(decoded_term) = bmp_message.decode_bmp_message(term_bytes)
  case decoded_term {
    BmpMsgTermination(code, str) -> {
      code |> should.equal(0)
      str |> should.equal("Administrative maintenance")
    }
    _ -> panic as "Expected BmpMsgTermination"
  }
}

// 19. RFC 7947 & RFC 7948 Internet Exchange Point (IXP) Route Server Tests
pub fn route_server_operations_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let rs_asn = 4_242_429_999
  let client_a_asn = 4_242_421_111
  let client_b_asn = 4_242_422_222
  let origin_nh = Ipv4(172, 22, 64, 50)

  let base_route =
    Route(
      prefix: pfx,
      origin: OriginIgp,
      as_path: [AsSequence([client_a_asn])],
      next_hop: origin_nh,
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "client_a",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  // 1. Transparent AS_PATH forwarding & NEXT_HOP preservation
  let assert Some(out_b) =
    routeserver.prepare_routeserver_outbound_route(
      base_route,
      client_b_asn,
      rs_asn,
    )
  // AS_PATH is not prepended with rs_asn!
  out_b.as_path |> should.equal([AsSequence([client_a_asn])])
  // Next-hop is untouched!
  out_b.next_hop |> should.equal(origin_nh)

  // 2. RFC 7947 Community Filtering: Do not announce to client B (0:client_b_asn)
  let blocked_route =
    routeserver.add_rs_control_community(
      base_route,
      rs_asn,
      routeserver.RsDoNotAnnounce(client_b_asn),
    )
  routeserver.is_route_permitted_for_client(blocked_route, client_b_asn, rs_asn)
  |> should.equal(False)
  // Still permitted to other clients
  routeserver.is_route_permitted_for_client(
    blocked_route,
    4_242_423_333,
    rs_asn,
  )
  |> should.equal(True)

  // 3. Selective announcement: Announce ONLY to client B (rs_asn:client_b_asn)
  let selective_route =
    routeserver.add_rs_control_community(
      base_route,
      rs_asn,
      routeserver.RsAnnounceOnly(client_b_asn),
    )
  // Permitted to client B
  routeserver.is_route_permitted_for_client(
    selective_route,
    client_b_asn,
    rs_asn,
  )
  |> should.equal(True)
  // Blocked for all other clients
  routeserver.is_route_permitted_for_client(
    selective_route,
    4_242_423_333,
    rs_asn,
  )
  |> should.equal(False)

  // 4. Do not announce to ANY client (0:rs_asn)
  let holdback_route =
    routeserver.add_rs_control_community(
      base_route,
      rs_asn,
      routeserver.RsDoNotAnnounceAny,
    )
  routeserver.is_route_permitted_for_client(
    holdback_route,
    client_b_asn,
    rs_asn,
  )
  |> should.equal(False)
  routeserver.is_route_permitted_for_client(
    holdback_route,
    4_242_423_333,
    rs_asn,
  )
  |> should.equal(False)

  // 5. Control communities are stripped when prepared for delivery
  let assert Some(clean_out) =
    routeserver.prepare_routeserver_outbound_route(
      selective_route,
      client_b_asn,
      rs_asn,
    )
  list.contains(clean_out.communities, Community(rs_asn, client_b_asn))
  |> should.equal(False)
  list.contains(
    clean_out.large_communities,
    LargeCommunity(rs_asn, 1, client_b_asn),
  )
  |> should.equal(False)
}

// 20. Route Server REST API, BMP REST API & Dynamic Config Reload Tests
pub fn routeserver_api_and_dynamic_reload_test() {
  let base_cfg = config.default_config()
  let client_cfg =
    PeerConfig(
      id: "rs_peer_1",
      name: "RS Client One",
      remote_as: 4_242_421_999,
      remote_ip: Ipv4(172, 20, 10, 2),
      local_as: base_cfg.asn,
      local_ip: base_cfg.router_id,
      port: 179,
      hold_time: 90,
      keepalive_time: 30,
      passive: False,
      enable_ipv4: True,
      enable_ipv6: True,
      extended_next_hop: True,
      add_path_rx: True,
      add_path_tx: False,
      dn42_latency: None,
      dn42_bandwidth: None,
      dn42_crypto: None,
      dn42_region: None,
      import_filters: [],
      export_filters: [],
      route_server_client: True,
      route_reflector_client: False,
      confederation_member: False,
      bgp_role: None,
    )

  // 1. Test render_json_routeserver
  let rs_json = http.render_json_routeserver(base_cfg.asn, [client_cfg])
  string.contains(rs_json, "RFC 7947") |> should.equal(True)
  string.contains(rs_json, "rs_peer_1") |> should.equal(True)
  string.contains(rs_json, "transparent_as_path") |> should.equal(True)

  // 2. Test render_json_bmp
  let bmp_json = http.render_json_bmp([client_cfg])
  string.contains(bmp_json, "RFC 7854") |> should.equal(True)
  string.contains(bmp_json, "route_monitoring") |> should.equal(True)

  // 3. Test dynamic reload
  let srv = server.new_server(base_cfg)
  let new_cfg = config.DaemonConfig(..base_cfg, peers: [client_cfg])
  let #(srv_reloaded, events) = server.reload_config(srv, new_cfg)
  list.length(events) |> should.equal(3)
  server.get_peer_stats_list(srv_reloaded)
  |> list.any(fn(p) { p.id == "rs_peer_1" })
  |> should.equal(True)

  // 4. Test peer removal via reload
  let empty_cfg = config.DaemonConfig(..base_cfg, peers: [])
  let #(srv_cleared, _events2) = server.reload_config(srv_reloaded, empty_cfg)
  server.get_peer_stats_list(srv_cleared)
  |> list.any(fn(p) { p.id == "rs_peer_1" })
  |> should.equal(False)
}

// 21. RFC 4456 BGP Route Reflection Tests
pub fn route_reflection_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let my_router_id = Ipv4(172, 20, 10, 1)
  let my_cluster_id = Ipv4(172, 20, 10, 1)
  let sender_router_id = Ipv4(172, 20, 10, 2)
  let other_router_id = Ipv4(172, 20, 10, 3)

  let base_route =
    Route(
      prefix: pfx,
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
      peer_id: "peer_rr_client",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  // 1. Loop detection
  let route_with_orig_loop =
    Route(..base_route, originator_id: Some(my_router_id))
  routereflector.is_originator_loop(route_with_orig_loop, my_router_id)
  |> should.equal(True)
  routereflector.is_originator_loop(base_route, my_router_id)
  |> should.equal(False)

  let route_with_cluster_loop =
    Route(..base_route, cluster_list: [my_cluster_id, other_router_id])
  routereflector.is_cluster_loop(route_with_cluster_loop, my_cluster_id)
  |> should.equal(True)
  routereflector.is_cluster_loop(base_route, my_cluster_id)
  |> should.equal(False)

  // 2. Reflection propagation rules per RFC 4456 Section 8
  // Non-client to non-client: NEVER reflect
  routereflector.should_reflect_to_peer(False, False, False)
  |> should.equal(False)

  // Non-client to client: MUST reflect
  routereflector.should_reflect_to_peer(False, True, False)
  |> should.equal(True)

  // Client to non-client: MUST reflect
  routereflector.should_reflect_to_peer(True, False, False)
  |> should.equal(True)

  // Client to client: MUST reflect
  routereflector.should_reflect_to_peer(True, True, False)
  |> should.equal(True)

  // eBGP to any: MUST propagate
  routereflector.should_reflect_to_peer(False, False, True)
  |> should.equal(True)

  // 3. Route reflection modification
  let reflected =
    routereflector.reflect_route(base_route, my_cluster_id, sender_router_id)
  reflected.originator_id |> should.equal(Some(sender_router_id))
  reflected.cluster_list |> should.equal([my_cluster_id])

  // If originator_id was already present, it is preserved
  let pre_existing_orig = Ipv4(172, 20, 10, 99)
  let route_with_orig =
    Route(..base_route, originator_id: Some(pre_existing_orig))
  let reflected2 =
    routereflector.reflect_route(
      route_with_orig,
      my_cluster_id,
      sender_router_id,
    )
  reflected2.originator_id |> should.equal(Some(pre_existing_orig))
  reflected2.cluster_list |> should.equal([my_cluster_id])

  // 4. Decision process tie breakers (RFC 4456)
  // Shorter cluster_list wins
  let r_short_clusters = Route(..base_route, cluster_list: [Ipv4(1, 1, 1, 1)])
  let r_long_clusters =
    Route(..base_route, cluster_list: [Ipv4(1, 1, 1, 1), Ipv4(2, 2, 2, 2)])
  compare_routes(r_short_clusters, r_long_clusters) |> should.equal(True)
  compare_routes(r_long_clusters, r_short_clusters) |> should.equal(False)

  // Smaller originator_id wins
  let r_low_orig = Route(..base_route, originator_id: Some(Ipv4(10, 0, 0, 1)))
  let r_high_orig = Route(..base_route, originator_id: Some(Ipv4(10, 0, 0, 2)))
  compare_routes(r_low_orig, r_high_orig) |> should.equal(True)
  compare_routes(r_high_orig, r_low_orig) |> should.equal(False)

  // 5. Wire encoding and decoding of ORIGINATOR_ID and CLUSTER_LIST
  let attrs = [
    AttrOriginatorId(my_router_id),
    AttrClusterList([my_cluster_id, other_router_id]),
  ]
  let enc = encode_attributes(attrs)
  let assert Ok(dec_attrs) = decode_attributes(enc, False)
  dec_attrs |> should.equal(attrs)
}

// 22. RFC 5065 BGP Confederations Tests
pub fn confederation_test() {
  let member_as1 = 4_242_421_111
  let member_as2 = 4_242_422_222
  let confed_id = 4_242_420_000
  let local_ip = Ipv4(172, 20, 10, 1)

  // 1. Confederation loop detection
  let path_with_confed_loop = [
    AsConfedSequence([member_as1, member_as2]),
    AsSequence([4_242_420_125]),
  ]
  confederation.has_confed_loop(path_with_confed_loop, member_as1)
  |> should.equal(True)
  confederation.has_confed_loop(path_with_confed_loop, member_as2)
  |> should.equal(True)
  confederation.has_confed_loop(path_with_confed_loop, 4_242_429_999)
  |> should.equal(False)

  let path_with_confed_set = [AsConfedSet([member_as1])]
  confederation.has_confed_loop(path_with_confed_set, member_as1)
  |> should.equal(True)

  // 2. Effective AS_PATH length (confed segments excluded per RFC 5065 Section 5.3)
  let path_with_confed = [
    AsConfedSequence([member_as1, member_as2]),
    AsConfedSet([member_as1]),
    AsSequence([4_242_420_125, 4_242_421_732]),
  ]
  confederation.effective_as_path_length(path_with_confed)
  |> should.equal(2)

  // 3. Intra-confederation route preparation
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let base_route =
    Route(
      prefix: pfx,
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
      peer_id: "peer_confed_1",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let intra_route =
    confederation.prepare_confed_outbound_route(
      base_route,
      True,
      member_as1,
      confed_id,
      local_ip,
    )
  // Local member AS prepended into AS_CONFED_SEQUENCE
  intra_route.as_path
  |> should.equal([
    AsConfedSequence([member_as1]),
    AsSequence([4_242_421_732]),
  ])
  // Next-hop and MED are preserved
  intra_route.next_hop |> should.equal(Ipv4(172, 22, 64, 1))
  intra_route.med |> should.equal(10)

  // 4. External boundary route preparation (to eBGP outside confederation)
  let external_route =
    confederation.prepare_confed_outbound_route(
      intra_route,
      False,
      member_as1,
      confed_id,
      local_ip,
    )
  // Confed segments stripped, public Confederation Identifier prepended
  external_route.as_path
  |> should.equal([AsSequence([confed_id, 4_242_421_732])])
  // Next-hop updated to local IP
  external_route.next_hop |> should.equal(local_ip)

  // 5. Wire encoding and decoding of Confederation segments (Types 3 and 4)
  let confed_attrs = [
    AttrAsPath([
      AsConfedSequence([member_as1, member_as2]),
      AsConfedSet([member_as1]),
      AsSequence([4_242_420_125]),
    ]),
  ]
  let enc = encode_attributes(confed_attrs)
  let assert Ok(dec_attrs) = decode_attributes(enc, False)
  dec_attrs |> should.equal(confed_attrs)
}

// 23. RFC 8212 Default External BGP Route Propagation Behavior Tests
pub fn rfc8212_test() {
  let assert Ok(pfx) = parse_prefix("172.22.64.128/27")
  let r =
    Route(
      prefix: pfx,
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
      peer_id: "ebgp_peer",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  rfc8212.is_ebgp(4_242_420_125, 4_242_421_732) |> should.equal(True)
  rfc8212.is_ebgp(4_242_420_125, 4_242_420_125) |> should.equal(False)

  // Inbound eBGP route without explicit policy rejected when enforce is True
  case rfc8212.evaluate_rfc8212_inbound(r, True, False, True) {
    Error(_) -> True
    Ok(_) -> False
  }
  |> should.equal(True)

  // Inbound eBGP route with explicit policy accepted
  case rfc8212.evaluate_rfc8212_inbound(r, True, True, True) {
    Ok(_) -> True
    Error(_) -> False
  }
  |> should.equal(True)

  // Inbound iBGP route without policy accepted (RFC 8212 applies to eBGP)
  case rfc8212.evaluate_rfc8212_inbound(r, False, False, True) {
    Ok(_) -> True
    Error(_) -> False
  }
  |> should.equal(True)

  // Outbound eBGP route without export policy denied
  rfc8212.evaluate_rfc8212_outbound(r, True, False, True)
  |> should.equal(False)

  // Outbound eBGP route with export policy permitted
  rfc8212.evaluate_rfc8212_outbound(r, True, True, True)
  |> should.equal(True)
}

// 24. Interactive SVG Network Topology Map and REST Endpoints Tests
pub fn topology_and_rest_endpoints_test() {
  let base_cfg = config.default_config()
  let srv = server.new_server(base_cfg)
  let peers = server.get_peer_stats_list(srv)
  let routes = server.get_all_active_routes(srv)

  // 1. Test render_topology_svg
  let svg = http.render_topology_svg(base_cfg.asn, "172.20.10.1", peers)
  string.contains(svg, "<svg") |> should.equal(True)
  string.contains(svg, "AS4242420125") |> should.equal(True)
  string.contains(svg, "LOCAL HUB") |> should.equal(True)
  string.contains(svg, "radar") |> should.equal(False)
  string.contains(svg, "</svg>") |> should.equal(True)

  // 2. Test render_json_topology
  let topo_json =
    http.render_json_topology(base_cfg.asn, "172.20.10.1", peers, routes)
  string.contains(topo_json, "\"local_as\":4242420125") |> should.equal(True)
  string.contains(topo_json, "\"nodes\":") |> should.equal(True)
  string.contains(topo_json, "\"links\":") |> should.equal(True)

  // 3. Test render_json_routereflector
  let rr_peer =
    PeerConfig(
      id: "peer_rr1",
      name: "RR Client 1",
      remote_as: 4_242_420_125,
      remote_ip: Ipv4(172, 20, 10, 2),
      local_as: base_cfg.asn,
      local_ip: base_cfg.router_id,
      port: 179,
      hold_time: 90,
      keepalive_time: 30,
      passive: False,
      enable_ipv4: True,
      enable_ipv6: True,
      extended_next_hop: True,
      add_path_rx: True,
      add_path_tx: False,
      dn42_latency: None,
      dn42_bandwidth: None,
      dn42_crypto: None,
      dn42_region: None,
      import_filters: [],
      export_filters: [],
      route_server_client: False,
      route_reflector_client: True,
      confederation_member: False,
      bgp_role: None,
    )
  let rr_json =
    http.render_json_routereflector(Some(Ipv4(172, 20, 10, 1)), [rr_peer])
  string.contains(rr_json, "RFC 4456") |> should.equal(True)
  string.contains(rr_json, "172.20.10.1") |> should.equal(True)
  string.contains(rr_json, "\"clients_count\":1") |> should.equal(True)

  // 4. Test render_json_confederation
  let confed_peer =
    PeerConfig(
      ..rr_peer,
      route_reflector_client: False,
      confederation_member: True,
    )
  let confed_json =
    http.render_json_confederation(Some(4_242_420_000), [confed_peer])
  string.contains(confed_json, "RFC 5065") |> should.equal(True)
  string.contains(confed_json, "4242420000") |> should.equal(True)
  string.contains(confed_json, "\"member_peers_count\":1")
  |> should.equal(True)
}

// 25. RFC 8210 & RFC 6810 RPKI-to-Router (RTR) Protocol Tests
pub fn rtr_protocol_test() {
  // 1. Reset Query Roundtrip
  let reset_pdu = rtr_msg.RtrResetQuery(version: 1)
  let reset_bytes = rtr_msg.encode_rtr_pdu(reset_pdu)
  let assert Ok(#(dec_reset, _)) = rtr_msg.decode_rtr_pdu(reset_bytes)
  case dec_reset {
    rtr_msg.RtrResetQuery(v) -> v |> should.equal(1)
    _ -> panic as "Expected RtrResetQuery"
  }

  // 2. IPv4 Prefix Announcement PDU
  let ipv4_pdu =
    rtr_msg.RtrIpv4Prefix(
      version: 1,
      flags: 1,
      prefix_len: 27,
      max_len: 27,
      prefix: Ipv4(172, 22, 64, 128),
      asn: 4_242_420_125,
    )
  let ipv4_bytes = rtr_msg.encode_rtr_pdu(ipv4_pdu)
  let assert Ok(#(dec_ipv4, _)) = rtr_msg.decode_rtr_pdu(ipv4_bytes)
  case dec_ipv4 {
    rtr_msg.RtrIpv4Prefix(v, flags, plen, mlen, p, asn) -> {
      v |> should.equal(1)
      flags |> should.equal(1)
      plen |> should.equal(27)
      mlen |> should.equal(27)
      p |> should.equal(Ipv4(172, 22, 64, 128))
      asn |> should.equal(4_242_420_125)
    }
    _ -> panic as "Expected RtrIpv4Prefix"
  }

  // 3. IPv6 Prefix Announcement PDU
  let ipv6_pdu =
    rtr_msg.RtrIpv6Prefix(
      version: 1,
      flags: 1,
      prefix_len: 48,
      max_len: 48,
      prefix: Ipv6(0xfd8f, 0x3250, 0x9097, 0, 0, 0, 0, 0),
      asn: 4_242_420_125,
    )
  let ipv6_bytes = rtr_msg.encode_rtr_pdu(ipv6_pdu)
  let assert Ok(#(dec_ipv6, _)) = rtr_msg.decode_rtr_pdu(ipv6_bytes)
  case dec_ipv6 {
    rtr_msg.RtrIpv6Prefix(_, flags, plen, mlen, _, asn) -> {
      flags |> should.equal(1)
      plen |> should.equal(48)
      mlen |> should.equal(48)
      asn |> should.equal(4_242_420_125)
    }
    _ -> panic as "Expected RtrIpv6Prefix"
  }

  // 4. End of Data PDU
  let eod_pdu =
    rtr_msg.RtrEndOfData(
      version: 1,
      session_id: 42,
      serial: 101,
      refresh_sec: 3600,
      retry_sec: 600,
      expire_sec: 7200,
    )
  let eod_bytes = rtr_msg.encode_rtr_pdu(eod_pdu)
  let assert Ok(#(dec_eod, _)) = rtr_msg.decode_rtr_pdu(eod_bytes)
  case dec_eod {
    rtr_msg.RtrEndOfData(_, sid, serial, ref, ret, exp) -> {
      sid |> should.equal(42)
      serial |> should.equal(101)
      ref |> should.equal(3600)
      ret |> should.equal(600)
      exp |> should.equal(7200)
    }
    _ -> panic as "Expected RtrEndOfData"
  }

  // 5. RTR Client State Machine Integration
  let client0 = rtr_client.new_rtr_client("127.0.0.1", 8282)
  client0.status |> should.equal(rtr_client.RtrStatusDisconnected)

  let cache_resp = rtr_msg.RtrCacheResponse(version: 1, session_id: 42)
  let #(client1, _) = rtr_client.process_pdu(client0, cache_resp, 1000)
  client1.status |> should.equal(rtr_client.RtrStatusSynchronizing)
  client1.session_id |> should.equal(Some(42))

  // Ingest IPv4 announcement
  let #(client2, _) = rtr_client.process_pdu(client1, ipv4_pdu, 1000)
  list.length(client2.roa_table) |> should.equal(1)
  client2.announcements_count |> should.equal(1)

  // Ingest End of Data
  let #(client3, _) = rtr_client.process_pdu(client2, eod_pdu, 1000)
  client3.status |> should.equal(rtr_client.RtrStatusSynchronized)
  client3.serial |> should.equal(Some(101))

  // Ingest IPv4 withdrawal
  let ipv4_withdraw =
    rtr_msg.RtrIpv4Prefix(
      version: 1,
      flags: 0,
      prefix_len: 27,
      max_len: 27,
      prefix: Ipv4(172, 22, 64, 128),
      asn: 4_242_420_125,
    )
  let #(client4, _) = rtr_client.process_pdu(client3, ipv4_withdraw, 1000)
  list.length(client4.roa_table) |> should.equal(0)
  client4.withdrawals_count |> should.equal(1)
}

// 26. RFC 5880 / RFC 5882 BFD for BGP Protocol Tests
pub fn bfd_protocol_test() {
  // 1. BFD Control Packet Encode/Decode Roundtrip
  let pkt =
    bfd_msg.BfdPacket(
      version: 1,
      diag: 0,
      state: bfd_msg.BfdDown,
      poll: True,
      final: False,
      control_plane_independent: False,
      auth_present: False,
      demand: False,
      multipoint: False,
      detect_mult: 3,
      my_discriminator: 0x1001,
      your_discriminator: 0,
      desired_min_tx_us: 300_000,
      required_min_rx_us: 300_000,
      required_min_echo_us: 0,
    )
  let pkt_bytes = bfd_msg.encode_bfd_packet(pkt)
  let assert Ok(dec_pkt) = bfd_msg.decode_bfd_packet(pkt_bytes)
  dec_pkt.version |> should.equal(1)
  dec_pkt.state |> should.equal(bfd_msg.BfdDown)
  dec_pkt.poll |> should.equal(True)
  dec_pkt.my_discriminator |> should.equal(0x1001)
  dec_pkt.desired_min_tx_us |> should.equal(300_000)
  dec_pkt.detect_mult |> should.equal(3)

  // 2. BFD 3-Way Handshake Session State Machine
  let sess0 =
    bfd_session.new_bfd_session("peer_fra", 0x1001, 300_000, 300_000, 3)
  sess0.local_state |> should.equal(bfd_msg.BfdDown)

  // Peer receives Down from remote with remote discr 0x8042 -> transitions to Init
  let remote_down =
    bfd_msg.BfdPacket(
      version: 1,
      diag: 0,
      state: bfd_msg.BfdDown,
      poll: False,
      final: False,
      control_plane_independent: False,
      auth_present: False,
      demand: False,
      multipoint: False,
      detect_mult: 3,
      my_discriminator: 0x8042,
      your_discriminator: 0x1001,
      desired_min_tx_us: 300_000,
      required_min_rx_us: 300_000,
      required_min_echo_us: 0,
    )
  let #(sess1, actions1) =
    bfd_session.handle_packet(sess0, remote_down, 1_000_000)
  sess1.local_state |> should.equal(bfd_msg.BfdInit)
  sess1.remote_discr |> should.equal(0x8042)
  list.length(actions1) |> should.equal(1)

  // Peer receives Init or Up from remote -> transitions to Up
  let remote_up =
    bfd_msg.BfdPacket(
      version: 1,
      diag: 0,
      state: bfd_msg.BfdUp,
      poll: False,
      final: False,
      control_plane_independent: False,
      auth_present: False,
      demand: False,
      multipoint: False,
      detect_mult: 3,
      my_discriminator: 0x8042,
      your_discriminator: 0x1001,
      desired_min_tx_us: 300_000,
      required_min_rx_us: 300_000,
      required_min_echo_us: 0,
    )
  let #(sess2, _) = bfd_session.handle_packet(sess1, remote_up, 1_200_000)
  sess2.local_state |> should.equal(bfd_msg.BfdUp)

  // 3. Sub-second Detection Timer Expiration & Instant BGP Drop Signal
  // detect_mult = 3, negotiated_rx = 300ms => timeout = 900ms
  // At now = 2_200_000 us (elapsed 1,000,000 us > 900,000 us), must trip!
  let #(sess3, actions3) = bfd_session.check_timer(sess2, 2_200_000)
  sess3.local_state |> should.equal(bfd_msg.BfdDown)
  sess3.diag |> should.equal(1)
  // Control Detection Time Expired
  let has_bgp_down =
    list.any(actions3, fn(act) {
      case act {
        bfd_session.BfdActionSignalBgpDown(p_id, _) -> p_id == "peer_fra"
        _ -> False
      }
    })
  has_bgp_down |> should.equal(True)
}

// 27. RFC 7999 BGP BLACKHOLE & RTBH Tests
pub fn blackhole_rtbh_test() {
  let bh_comm = blackhole.blackhole_community()
  bh_comm.asn |> should.equal(65_535)
  bh_comm.value |> should.equal(666)

  let assert Ok(pfx32) = parse_prefix("172.22.64.42/32")
  let assert Ok(pfx24) = parse_prefix("172.22.64.0/24")

  let r0 =
    Route(
      prefix: pfx32,
      origin: OriginIgp,
      as_path: [],
      next_hop: Ipv4(172, 22, 64, 1),
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "peer_fra",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  // Tagging
  let r_tagged = blackhole.tag_blackhole(r0)
  blackhole.has_blackhole_community(r_tagged.communities) |> should.equal(True)

  // Untagging
  let r_untagged = blackhole.untag_blackhole(r_tagged)
  blackhole.has_blackhole_community(r_untagged.communities)
  |> should.equal(False)

  // Inbound RTBH Processing: /32 host route accepted and next-hop rewritten to 127.0.0.1
  let assert Ok(r_sink) = blackhole.process_inbound_rtbh(r_tagged, True)
  r_sink.next_hop |> should.equal(Ipv4(127, 0, 0, 1))

  // Inbound RTBH Processing: /24 non-host route rejected
  let r_non_host = Route(..r_tagged, prefix: pfx24)
  let non_host_res = blackhole.process_inbound_rtbh(r_non_host, True)
  case non_host_res {
    Error(msg) -> string.contains(msg, "host route") |> should.equal(True)
    _ -> panic as "Expected error for non-host route"
  }

  // Outbound RTBH Route Generation
  let out_rtbh =
    blackhole.create_outbound_rtbh(
      pfx32,
      4_242_420_125,
      Ipv4(172, 22, 64, 129),
      2000,
    )
  blackhole.has_blackhole_community(out_rtbh.communities) |> should.equal(True)
  out_rtbh.local_pref |> should.equal(200)

  // FIB Kernel Command Generation
  let fib_cmd = blackhole.to_fib_blackhole_command(pfx32, 42)
  fib_cmd |> should.equal("ip route replace blackhole 172.22.64.42/32 table 42")
}

// 28. RFC 7432 / RFC 8365 BGP EVPN Protocol Tests
pub fn evpn_protocol_test() {
  // 1. Route Distinguisher (RD) Type 2 (4-Octet ASN)
  let rd = evpn.RdAsn4(4_242_420_125, 100)
  let rd_bytes = evpn.encode_rd(rd)
  let assert Ok(dec_rd) = evpn.decode_rd(rd_bytes)
  dec_rd |> should.equal(rd)

  // 2. MAC Address formatting & hex parsing
  let mac_str = "02:42:ac:11:00:02"
  let mac_bytes = evpn.mac_to_bytes(mac_str)
  let restored_mac = evpn.bytes_to_mac(mac_bytes)
  restored_mac |> should.equal(mac_str)

  // 3. EVPN Route Type 2 (MAC/IP Advertisement)
  let r2 =
    evpn.EvpnRouteType2(
      rd: rd,
      esi: <<0:80>>,
      eth_tag_id: 0,
      mac_address: mac_str,
      ip_address: Some(Ipv4(172, 22, 64, 129)),
      vni: 10_100,
    )
  let r2_bytes = evpn.encode_evpn_route_type2(r2)
  let assert Ok(#(dec_r2_nlri, _)) = evpn.decode_evpn_nlri(r2_bytes)
  case dec_r2_nlri {
    evpn.EvpnMacIp(parsed_r2) -> {
      parsed_r2.mac_address |> should.equal(mac_str)
      parsed_r2.ip_address |> should.equal(Some(Ipv4(172, 22, 64, 129)))
      parsed_r2.vni |> should.equal(10_100)
    }
    _ -> panic as "Expected EvpnMacIp"
  }

  // 4. EVPN Route Type 5 (IP Prefix)
  let assert Ok(evpn_pfx) = parse_prefix("172.22.64.160/28")
  let r5 =
    evpn.EvpnRouteType5(
      rd: rd,
      esi: <<0:80>>,
      eth_tag_id: 0,
      prefix: evpn_pfx,
      gateway_ip: Some(Ipv4(172, 22, 64, 129)),
      vni: 10_100,
    )
  let r5_bytes = evpn.encode_evpn_route_type5(r5)
  let assert Ok(#(dec_r5_nlri, _)) = evpn.decode_evpn_nlri(r5_bytes)
  case dec_r5_nlri {
    evpn.EvpnPrefix(parsed_r5) -> {
      parsed_r5.prefix.length |> should.equal(28)
      parsed_r5.gateway_ip |> should.equal(Some(Ipv4(172, 22, 64, 129)))
      parsed_r5.vni |> should.equal(10_100)
    }
    _ -> panic as "Expected EvpnPrefix"
  }

  // 5. VXLAN Tunnel Encapsulation Extended Community (RFC 9012)
  let vxlan_encap = evpn.vxlan_tunnel_encap_community()
  vxlan_encap.type_code |> should.equal(0x03)
  vxlan_encap.sub_type |> should.equal(0x0C)
}

// 29. Carrier-Grade BGP Looking Glass Tests
pub fn looking_glass_test() {
  let assert Ok(pfx1) = parse_prefix("172.22.64.0/27")
  let assert Ok(pfx2) = parse_prefix("172.20.44.128/27")
  let assert Ok(_pfx_more_spec) = parse_prefix("172.22.64.128/28")

  let r1 =
    Route(
      prefix: pfx1,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_125])],
      next_hop: Ipv4(172, 22, 64, 1),
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [Community(65_535, 666)],
      large_communities: [LargeCommunity(4_242_420_125, 1, 1)],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "local_rib",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let r2 =
    Route(
      prefix: pfx2,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_421_732, 4_242_420_000])],
      next_hop: Ipv4(172, 22, 64, 2),
      med: 20,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [Community(64_500, 100)],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "baragoon_fra",
      timestamp: 1050,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let routes = [r1, r2]

  // 1. Exact Prefix Match
  let res_exact = lg.query_route(routes, 1100, "172.22.64.0/27")
  res_exact.routes_found |> should.equal(1)
  case res_exact.routes {
    [first, ..] -> {
      first.prefix |> should.equal("172.22.64.0/27")
      first.is_blackhole |> should.equal(True)
      first.best |> should.equal(True)
    }
    [] -> panic as "Expected exact match"
  }

  // 2. Longest Prefix Match (LPM) with Host IP
  let res_lpm = lg.query_route(routes, 1100, "172.22.64.5")
  res_lpm.routes_found |> should.equal(1)

  // 3. AS-Path Query
  let res_as = lg.query_aspath(routes, 1100, "4242421732")
  res_as.routes_found |> should.equal(1)
  case res_as.routes {
    [first, ..] -> first.peer_id |> should.equal("baragoon_fra")
    [] -> panic as "Expected AS path match"
  }

  // 4. Community Query
  let res_comm = lg.query_community(routes, 1100, "65535:666")
  res_comm.routes_found |> should.equal(1)

  // 5. Looking Glass Summary & JSON
  let sum =
    lg.query_summary(
      4_242_420_125,
      "172.22.64.129",
      3600,
      [],
      routes,
      5740,
      "Synchronized",
      3,
    )
  sum.blackholes_active |> should.equal(1)
  let sum_json = lg.render_json_lg_summary(sum)
  string.contains(sum_json, "4242420125") |> should.equal(True)
  string.contains(sum_json, "\"blackholes_active\":1") |> should.equal(True)

  // 6. Test http module JSON renderers
  let rtr_cli = rtr_client.new_rtr_client("127.0.0.1", 8282)
  let rtr_json = http.render_json_rtr(rtr_cli)
  string.contains(rtr_json, "RFC 8210") |> should.equal(True)

  let bfd_sess = bfd_session.new_bfd_session("peer1", 100, 300_000, 300_000, 3)
  let bfd_json = http.render_json_bfd([bfd_sess])
  string.contains(bfd_json, "RFC 5880") |> should.equal(True)

  let bh_json = http.render_json_blackhole(routes)
  string.contains(bh_json, "RFC 7999") |> should.equal(True)
  string.contains(bh_json, "65535:666") |> should.equal(True)
}

// 30. RFC 4364 / RFC 4659 BGP/MPLS IP Virtual Private Networks (L3VPN)
pub fn l3vpn_rfc4364_test() {
  // Test Route Targets
  let rt_asn2 = l3vpn.RtAsn2(42_424, 100)
  let ext_asn2 = l3vpn.encode_route_target(rt_asn2)
  let assert Ok(dec_asn2) = l3vpn.decode_route_target(ext_asn2)
  dec_asn2 |> should.equal(rt_asn2)

  let rt_ipv4 = l3vpn.RtIpv4(Ipv4(172, 22, 64, 1), 100)
  let ext_ipv4 = l3vpn.encode_route_target(rt_ipv4)
  let assert Ok(dec_ipv4) = l3vpn.decode_route_target(ext_ipv4)
  dec_ipv4 |> should.equal(rt_ipv4)

  let rt_asn4 = l3vpn.RtAsn4(4_242_420_125, 200)
  let ext_asn4 = l3vpn.encode_route_target(rt_asn4)
  let assert Ok(dec_asn4) = l3vpn.decode_route_target(ext_asn4)
  dec_asn4 |> should.equal(rt_asn4)

  // Route Target string parsing
  let assert Ok(parsed_rt1) = l3vpn.parse_route_target("target:4242420125:200")
  parsed_rt1 |> should.equal(rt_asn4)
  let assert Ok(parsed_rt2) = l3vpn.parse_route_target("172.22.64.1:100")
  parsed_rt2 |> should.equal(rt_ipv4)

  // Test Route Origin (Site of Origin)
  let soo = l3vpn.SooAsn4(4_242_420_125, 500)
  let ext_soo = l3vpn.encode_route_origin(soo)
  let assert Ok(dec_soo) = l3vpn.decode_route_origin(ext_soo)
  dec_soo |> should.equal(soo)

  // Test 24-bit MPLS Label encoding & decoding
  let label_bytes = l3vpn.encode_mpls_label(1001, True)
  let assert Ok(#(dec_label, is_bottom)) = l3vpn.decode_mpls_label(label_bytes)
  dec_label |> should.equal(1001)
  is_bottom |> should.equal(True)

  // Test VPN-IPv4 NLRI wire roundtrip
  let v4_route =
    l3vpn.MplsVpnRoute(
      rd: evpn.RdAsn4(4_242_420_125, 100),
      label: 1001,
      prefix: IpPrefix(Ipv4(10, 100, 1, 0), 24),
    )
  let nlri_v4_bin = l3vpn.encode_vpn_nlri(v4_route)
  let assert Ok(decoded_v4_routes) = l3vpn.decode_vpn_nlri(nlri_v4_bin, False)
  case decoded_v4_routes {
    [d_route] -> {
      d_route.rd |> should.equal(v4_route.rd)
      d_route.label |> should.equal(1001)
      d_route.prefix |> should.equal(v4_route.prefix)
    }
    _ -> panic as "Expected single VPN-IPv4 route"
  }

  // Test VPN-IPv6 NLRI wire roundtrip
  let v6_prefix = IpPrefix(Ipv6(0xfdd4, 0xaf47, 0xdcfa, 0x0001, 0, 0, 0, 0), 64)
  let v6_route =
    l3vpn.MplsVpnRoute(
      rd: evpn.RdAsn4(4_242_420_125, 200),
      label: 2001,
      prefix: v6_prefix,
    )
  let nlri_v6_bin = l3vpn.encode_vpn_nlri(v6_route)
  let assert Ok(decoded_v6_routes) = l3vpn.decode_vpn_nlri(nlri_v6_bin, True)
  case decoded_v6_routes {
    [d_v6] -> {
      d_v6.rd |> should.equal(v6_route.rd)
      d_v6.label |> should.equal(2001)
      d_v6.prefix |> should.equal(v6_prefix)
    }
    _ -> panic as "Expected single VPN-IPv6 route"
  }
}

// 31. Multi-Tenant VRF Isolation & Routing Engine Tests
pub fn vrf_isolation_test() {
  let mgr0 = vrf.new_manager()
  let vrf_red =
    vrf.VrfConfig(
      name: "tenant-red",
      rd: evpn.RdAsn4(4_242_420_125, 100),
      import_targets: [l3vpn.RtAsn4(4_242_420_125, 100)],
      export_targets: [l3vpn.RtAsn4(4_242_420_125, 100)],
      table_id: 100,
      export_label: 1001,
    )
  let vrf_blue =
    vrf.VrfConfig(
      name: "tenant-blue",
      rd: evpn.RdAsn4(4_242_420_125, 200),
      import_targets: [l3vpn.RtAsn4(4_242_420_125, 200)],
      export_targets: [l3vpn.RtAsn4(4_242_420_125, 200)],
      table_id: 200,
      export_label: 2001,
    )

  let mgr1 = vrf.add_vrf(vrf.add_vrf(mgr0, vrf_red), vrf_blue)
  list.length(vrf.list_vrfs(mgr1)) |> should.equal(2)

  // Create an inbound BGP VPN route carrying target:4242420125:100 (for tenant-red)
  let rt_ext = l3vpn.encode_route_target(l3vpn.RtAsn4(4_242_420_125, 100))
  let base_route =
    Route(
      prefix: IpPrefix(Ipv4(10, 100, 1, 0), 24),
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_125])],
      next_hop: Ipv4(172, 22, 64, 129),
      med: 0,
      local_pref: 150,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [rt_ext],
      otc: None,
      roa_status: RoaValid,
      peer_id: "edge_peer",
      timestamp: 1000,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )
  let vpn_route =
    l3vpn.MplsVpnRoute(
      rd: evpn.RdAsn4(4_242_420_125, 100),
      label: 1001,
      prefix: base_route.prefix,
    )

  let mgr2 = vrf.import_vpn_route(mgr1, vpn_route, base_route)

  // Verify tenant-red received the route
  let assert Ok(red_table) = vrf.get_vrf(mgr2, "tenant-red")
  list.length(red_table.routes) |> should.equal(1)
  case red_table.routes {
    [r] -> {
      r.prefix |> should.equal(base_route.prefix)
      r.local_pref |> should.equal(150)
    }
    _ -> panic as "Expected route in tenant-red"
  }

  // Verify tenant-blue did NOT receive the route (perfect tenant separation)
  let assert Ok(blue_table) = vrf.get_vrf(mgr2, "tenant-blue")
  list.length(blue_table.routes) |> should.equal(0)

  // Test route export from VRF
  let #(exp_vpn_route, exp_exts) = vrf.export_vrf_route(red_table, base_route)
  exp_vpn_route.label |> should.equal(1001)
  exp_vpn_route.rd |> should.equal(vrf_red.rd)
  list.length(exp_exts) |> should.equal(1)

  // Test Linux FIB command generation
  let fib_cmds = vrf.generate_vrf_fib_commands(red_table)
  case fib_cmds {
    [cmd] -> {
      string.contains(
        cmd,
        "ip route replace 10.100.1.0/24 via 172.22.64.129 table 100",
      )
      |> should.equal(True)
    }
    _ -> panic as "Expected 1 FIB command"
  }

  // Test JSON rendering
  let json_str = vrf.vrf_manager_to_json(mgr2)
  string.contains(json_str, "tenant-red") |> should.equal(True)
  string.contains(json_str, "tenant-blue") |> should.equal(True)
}

// 32. RFC 8669 BGP Prefix-SID for Segment Routing (SR-MPLS / SRv6)
pub fn prefix_sid_rfc8669_test() {
  let label_idx_tlv = prefix_sid.LabelIndexTlv(label_index: 125, flags: 0)
  let srv6_ip = Ipv6(0xfdd4, 0xaf47, 0xdcfa, 0x0001, 0, 0, 0, 1)
  let srv6_tlv = prefix_sid.Ipv6SidTlv(sid: srv6_ip, flags: 0)
  let srgb_tlv =
    prefix_sid.OriginatorSrgbTlv(flags: 0, blocks: [
      prefix_sid.SrgbBlock(base_label: 16_000, range_size: 8000),
    ])

  let sid = prefix_sid.BgpPrefixSid(tlvs: [label_idx_tlv, srv6_tlv, srgb_tlv])

  // Wire encoding
  let attr_bin = prefix_sid.encode_prefix_sid(sid)
  // Verify BGP Path Attribute header: 0xC0 (Flags), 40 (Attribute Type 40), 16-bit Length
  let assert <<0xC0:8, 40:8, len:16, payload:bits>> = attr_bin
  len |> should.equal(43)

  // Wire decoding
  let assert Ok(decoded_sid) = prefix_sid.decode_prefix_sid(payload)
  list.length(decoded_sid.tlvs) |> should.equal(3)

  case decoded_sid.tlvs {
    [t1, t2, t3] -> {
      t1 |> should.equal(label_idx_tlv)
      t2 |> should.equal(srv6_tlv)
      t3 |> should.equal(srgb_tlv)
    }
    _ -> panic as "Expected 3 TLVs"
  }

  // JSON rendering
  let json_str = prefix_sid.prefix_sid_to_json(sid)
  string.contains(json_str, "label_index") |> should.equal(True)
  string.contains(json_str, "125") |> should.equal(True)
  string.contains(json_str, "srv6_sid") |> should.equal(True)
  string.contains(json_str, "16000") |> should.equal(True)
}

// 33. RFC 5549 / RFC 8950 BGP Unnumbered (IPv6 Link-Local Peering)
pub fn unnumbered_rfc5549_test() {
  let link_local = Ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 1)
  let global_v6 = Ipv6(0xfdd4, 0xaf47, 0xdcfa, 0, 0, 0, 0, 1)
  let v4_addr = Ipv4(172, 22, 64, 1)

  // Link local check
  unnumbered.is_link_local(link_local) |> should.equal(True)
  unnumbered.is_link_local(global_v6) |> should.equal(False)
  unnumbered.is_link_local(v4_addr) |> should.equal(False)

  // Scoped link-local string
  let scoped =
    unnumbered.format_scoped_link_local(link_local, "dn42-peer-klaus")
  scoped |> should.equal("fe80:0:0:0:0:0:0:1%dn42-peer-klaus")

  // Kernel unnumbered route formatting
  let pfx_v4 = IpPrefix(Ipv4(172, 22, 64, 128), 27)
  let cmd_v4 =
    unnumbered.format_kernel_unnumbered_route(
      pfx_v4,
      link_local,
      "dn42-peer-klaus",
    )
  cmd_v4
  |> should.equal(
    "ip route replace 172.22.64.128/27 via inet6 fe80:0:0:0:0:0:0:1 dev dn42-peer-klaus",
  )

  let pfx_v6 = IpPrefix(Ipv6(0xfdd4, 0xaf47, 0xdcfa, 0, 0, 0, 0, 0), 48)
  let cmd_v6 =
    unnumbered.format_kernel_unnumbered_route(
      pfx_v6,
      link_local,
      "dn42-peer-klaus",
    )
  cmd_v6
  |> should.equal(
    "ip -6 route replace fdd4:af47:dcfa:0:0:0:0:0/48 via fe80:0:0:0:0:0:0:1 dev dn42-peer-klaus",
  )

  // Peer JSON serialization
  let peer =
    unnumbered.UnnumberedPeer(
      interface: "dn42-peer-klaus",
      remote_link_local: link_local,
      local_link_local: Ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 113),
      peer_asn: 4_242_421_234,
      extended_next_hop: True,
      status: "ESTABLISHED",
    )
  let json_peers = unnumbered.unnumbered_peers_to_json([peer])
  string.contains(json_peers, "dn42-peer-klaus") |> should.equal(True)
  string.contains(json_peers, "4242421234") |> should.equal(True)
  string.contains(json_peers, "ESTABLISHED") |> should.equal(True)
}

// 34. RFC 9234 BGP Role Negotiation and Only to Customer (OTC) Route Leak Prevention Tests
pub fn rfc9234_role_and_otc_leak_test() {
  // 1. Role pair compatibility validation
  rfc9234.validate_role_pair(RoleProvider, RoleCustomer)
  |> should.equal(Ok(Nil))
  rfc9234.validate_role_pair(RoleCustomer, RoleProvider)
  |> should.equal(Ok(Nil))
  rfc9234.validate_role_pair(RoleRouteServer, RoleRouteServerClient)
  |> should.equal(Ok(Nil))
  rfc9234.validate_role_pair(RoleRouteServerClient, RoleRouteServer)
  |> should.equal(Ok(Nil))
  rfc9234.validate_role_pair(RolePeer, RolePeer) |> should.equal(Ok(Nil))

  // Invalid role pairings should result in error
  let invalid_res1 = rfc9234.validate_role_pair(RoleProvider, RoleProvider)
  case invalid_res1 {
    Error(msg) -> string.contains(msg, "Role mismatch") |> should.equal(True)
    Ok(_) -> panic as "Provider <-> Provider should fail"
  }
  let invalid_res2 = rfc9234.validate_role_pair(RoleCustomer, RoleCustomer)
  case invalid_res2 {
    Error(msg) -> string.contains(msg, "Role mismatch") |> should.equal(True)
    Ok(_) -> panic as "Customer <-> Customer should fail"
  }

  // 2. Inbound route leak detection
  let test_route =
    Route(
      prefix: IpPrefix(Ipv4(172, 22, 100, 0), 24),
      next_hop: Ipv4(172, 22, 64, 1),
      as_path: [AsSequence([4_242_421_111])],
      origin: OriginIgp,
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      originator_id: None,
      cluster_list: [],
      peer_id: "peer_de_fra",
      timestamp: 1000,
      path_id: None,
      roa_status: RoaValid,
      otc: Some(4_242_429_999),
    )

  // Received from a lateral Peer where ingress AS (4242421111) != OTC AS (4242429999) -> LEAK!
  let leak_eval =
    rfc9234.evaluate_inbound_otc(test_route, 4_242_421_111, RolePeer)
  case leak_eval {
    Error(err) ->
      string.contains(err, "route leak detected") |> should.equal(True)
    Ok(_) -> panic as "Should detect route leak"
  }

  // Received from a lateral Peer where ingress AS matches OTC AS -> Valid
  let matching_route = Route(..test_route, otc: Some(4_242_421_111))
  rfc9234.evaluate_inbound_otc(matching_route, 4_242_421_111, RolePeer)
  |> should.equal(Ok(matching_route))

  // Received from Provider without OTC -> Provider OTC is attached
  let no_otc_route = Route(..test_route, otc: None)
  let prov_eval =
    rfc9234.evaluate_inbound_otc(no_otc_route, 4_242_420_001, RoleProvider)
  let assert Ok(tagged_route) = prov_eval
  tagged_route.otc |> should.equal(Some(4_242_420_001))

  // 3. Outbound route leak prevention
  // Advertising to Customer without OTC -> attaches local AS
  let out_eval =
    rfc9234.evaluate_outbound_otc(no_otc_route, 4_242_420_125, RoleCustomer)
  out_eval.otc |> should.equal(Some(4_242_420_125))

  // Advertising to Customer with existing OTC -> preserved
  let out_preserved =
    rfc9234.evaluate_outbound_otc(test_route, 4_242_420_125, RoleCustomer)
  out_preserved.otc |> should.equal(Some(4_242_429_999))
}

// 35. RFC 7752 BGP Link-State (BGP-LS) Tests
pub fn bgp_ls_rfc7752_test() {
  // 1. Node Descriptor roundtrip
  let node_desc =
    bgpls.BgpLsNodeDescriptor(
      asn: 4_242_420_125,
      ls_id: 1,
      igp_router_id: "fra-edge-01",
    )
  let node_bin = bgpls.encode_node_descriptor(node_desc)
  let assert Ok(dec_node) = bgpls.decode_node_descriptor(node_bin)
  dec_node.asn |> should.equal(4_242_420_125)
  dec_node.ls_id |> should.equal(1)
  dec_node.igp_router_id |> should.equal("fra-edge-01")

  // 2. Link Descriptor roundtrip
  let link_desc =
    bgpls.BgpLsLinkDescriptor(
      local_id: 10,
      remote_id: 20,
      local_ip: Some(Ipv4(172, 22, 64, 1)),
      remote_ip: Some(Ipv4(172, 22, 64, 2)),
    )
  let link_bin = bgpls.encode_link_descriptor(link_desc)
  let dec_link = bgpls.decode_link_descriptor(link_bin)
  dec_link.local_id |> should.equal(10)
  dec_link.remote_id |> should.equal(20)
  dec_link.local_ip |> should.equal(Some(Ipv4(172, 22, 64, 1)))
  dec_link.remote_ip |> should.equal(Some(Ipv4(172, 22, 64, 2)))

  // 3. Node NLRI roundtrip
  let node_nlri =
    bgpls.LsNodeNlri(protocol_id: 7, identifier: 42, node: node_desc)
  let nlri_bin = bgpls.encode_bgp_ls_nlri(node_nlri)
  let assert Ok(dec_nlri) = bgpls.decode_bgp_ls_nlri(nlri_bin)
  case dec_nlri {
    bgpls.LsNodeNlri(proto, id, n) -> {
      proto |> should.equal(7)
      id |> should.equal(42)
      n.igp_router_id |> should.equal("fra-edge-01")
    }
    _ -> panic as "Expected LsNodeNlri"
  }

  // 4. BGP-LS Attributes roundtrip
  let ls_attrs =
    bgpls.BgpLsAttributes(
      node_name: Some("frankfurt-core-router"),
      igp_metric: Some(15),
      te_metric: Some(25),
      max_bandwidth_bytes: Some(125_000_000.0),
      admin_group: Some(0x00000001),
    )
  let attr_bin = bgpls.encode_bgp_ls_attributes(ls_attrs)
  let dec_attrs = bgpls.decode_bgp_ls_attributes(attr_bin)
  dec_attrs.node_name |> should.equal(Some("frankfurt-core-router"))
  dec_attrs.igp_metric |> should.equal(Some(15))
  dec_attrs.te_metric |> should.equal(Some(25))
  dec_attrs.admin_group |> should.equal(Some(0x00000001))
}

// 36. SlopFilter Expressive BGP Routing Policy Pipeline Tests
pub fn slopfilter_pipeline_test() {
  let base_route =
    Route(
      prefix: IpPrefix(Ipv4(172, 22, 64, 0), 27),
      next_hop: Ipv4(172, 22, 64, 1),
      as_path: [AsSequence([4_242_421_732])],
      origin: OriginIgp,
      med: 10,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [Community(asn: 64_511, value: 1015)],
      large_communities: [LargeCommunity(4_242_420_125, 1, 10)],
      ext_communities: [],
      originator_id: None,
      cluster_list: [],
      peer_id: "baragoon_fra",
      timestamp: 12_345,
      path_id: None,
      roa_status: RoaValid,
      otc: None,
    )

  // 1. Condition Matching Tests
  // Prefix exact vs longer
  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchPrefix(
      IpPrefix(Ipv4(172, 22, 64, 0), 27),
      slop_pipeline.PrefixExact,
    ),
  )
  |> should.equal(True)

  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchPrefix(
      IpPrefix(Ipv4(172, 22, 0, 0), 16),
      slop_pipeline.PrefixLonger,
    ),
  )
  |> should.equal(True)

  // AS-Path regex
  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchAsPathRegex("^4242421732$"),
  )
  |> should.equal(True)

  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchAsPathRegex("_9999_"),
  )
  |> should.equal(False)

  // DN42 latency matching
  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchDn42Latency(20),
  )
  |> should.equal(True)

  slop_pipeline.matches_condition(
    base_route,
    slop_pipeline.MatchDn42Latency(10),
  )
  |> should.equal(False)

  // 2. Full Multi-Stage Policy Pipeline Execution
  let pipeline =
    slop_pipeline.FilterPipeline(
      name: "dn42_inbound_core",
      rules: [
        // Rule 1: Drop bogons
        slop_pipeline.FilterRule(
          name: "drop_bogons",
          matches: [slop_pipeline.MatchDn42Bogon],
          actions: [slop_pipeline.ActionReject("Bogon or Non-DN42 route")],
        ),
        // Rule 2: Low-latency fast path bonus
        slop_pipeline.FilterRule(
          name: "low_latency_boost",
          matches: [slop_pipeline.MatchDn42Latency(25)],
          actions: [
            slop_pipeline.ActionAddLocalPref(50),
            slop_pipeline.ActionDn42TagBandwidth(1000),
            slop_pipeline.ActionDn42TagCrypto(41),
            slop_pipeline.ActionNextRule,
          ],
        ),
        // Rule 3: Final acceptance
        slop_pipeline.FilterRule(
          name: "accept_dn42",
          matches: [slop_pipeline.MatchAny],
          actions: [slop_pipeline.ActionAccept],
        ),
      ],
      default_action: slop_pipeline.ActionReject("Default drop"),
    )

  let result = slop_pipeline.execute_pipeline(pipeline, base_route)
  result.accepted |> should.equal(True)
  result.route.local_pref |> should.equal(150)
  result.applied_rules
  |> should.equal(["low_latency_boost", "accept_dn42"])

  // Check bandwidth and crypto communities were added
  let has_bw =
    list.any(result.route.communities, fn(c) {
      c.asn == 64_511 && c.value == 28
    })
  has_bw |> should.equal(True)

  let has_crypto =
    list.any(result.route.communities, fn(c) {
      c.asn == 64_511 && c.value == 41
    })
  has_crypto |> should.equal(True)

  // Test Blackhole action
  let bh_pipeline =
    slop_pipeline.FilterPipeline(
      name: "mitigation",
      rules: [
        slop_pipeline.FilterRule(
          name: "blackhole_ddos",
          matches: [slop_pipeline.MatchAny],
          actions: [slop_pipeline.ActionBlackhole, slop_pipeline.ActionAccept],
        ),
      ],
      default_action: slop_pipeline.ActionReject("drop"),
    )
  let bh_result = slop_pipeline.execute_pipeline(bh_pipeline, base_route)
  let has_bh_comm =
    list.any(bh_result.route.communities, fn(c) {
      c.asn == 65_535 && c.value == 666
    })
  has_bh_comm |> should.equal(True)
}

// 37. Unified Global Network Model Decoding, Validation, and Router Config Derivation Tests
pub fn global_network_model_compiler_test() {
  let model_json =
    "{\n"
    <> "  \"name\": \"slopnet-global\",\n"
    <> "  \"asn\": 4242420125,\n"
    <> "  \"regions\": [\n"
    <> "    {\"id\": \"fra\", \"name\": \"Frankfurt\", \"country\": \"DE\", \"dn42_region\": 41, \"lat\": 50.11, \"lon\": 8.68},\n"
    <> "    {\"id\": \"ams\", \"name\": \"Amsterdam\", \"country\": \"NL\", \"dn42_region\": 42, \"lat\": 52.37, \"lon\": 4.89}\n"
    <> "  ],\n"
    <> "  \"routers\": [\n"
    <> "    {\n"
    <> "      \"id\": \"fra-rr-1\",\n"
    <> "      \"hostname\": \"rr1.fra.slopnet\",\n"
    <> "      \"region_id\": \"fra\",\n"
    <> "      \"role\": \"route_reflector\",\n"
    <> "      \"router_id\": \"172.22.64.1\",\n"
    <> "      \"loopback_v4\": \"172.22.64.1\",\n"
    <> "      \"loopback_v6\": \"fdd4:af47:dcfa::1\",\n"
    <> "      \"bgp_port\": 179,\n"
    <> "      \"api_port\": 9179\n"
    <> "    },\n"
    <> "    {\n"
    <> "      \"id\": \"fra-edge-1\",\n"
    <> "      \"hostname\": \"edge1.fra.slopnet\",\n"
    <> "      \"region_id\": \"fra\",\n"
    <> "      \"role\": \"edge\",\n"
    <> "      \"router_id\": \"172.22.64.2\",\n"
    <> "      \"loopback_v4\": \"172.22.64.2\",\n"
    <> "      \"loopback_v6\": \"fdd4:af47:dcfa::2\",\n"
    <> "      \"bgp_port\": 179,\n"
    <> "      \"api_port\": 9179\n"
    <> "    }\n"
    <> "  ],\n"
    <> "  \"links\": [\n"
    <> "    {\n"
    <> "      \"id\": \"link-fra-core\",\n"
    <> "      \"endpoint_a\": \"fra-rr-1\",\n"
    <> "      \"endpoint_b\": \"fra-edge-1\",\n"
    <> "      \"link_type\": \"wireguard\",\n"
    <> "      \"cost\": 10,\n"
    <> "      \"latency_ms\": 2,\n"
    <> "      \"bandwidth_mbps\": 1000,\n"
    <> "      \"bfd\": true,\n"
    <> "      \"ip_a\": \"172.22.64.10\",\n"
    <> "      \"ip_b\": \"172.22.64.11\"\n"
    <> "    }\n"
    <> "  ],\n"
    <> "  \"external_peers\": [\n"
    <> "    {\n"
    <> "      \"id\": \"peer-baragoon\",\n"
    <> "      \"name\": \"Baragoon Frankfurt\",\n"
    <> "      \"attached_router\": \"fra-edge-1\",\n"
    <> "      \"remote_as\": 4242421732,\n"
    <> "      \"remote_ip\": \"172.22.64.120\",\n"
    <> "      \"bgp_role\": \"peer\",\n"
    <> "      \"bfd\": true,\n"
    <> "      \"dn42_latency\": 8,\n"
    <> "      \"dn42_bandwidth\": 1000\n"
    <> "    }\n"
    <> "  ]\n"
    <> "}"

  // 1. JSON decoding
  let assert Ok(model) = net_model.decode_network_model(model_json)
  model.name |> should.equal("slopnet-global")
  model.asn |> should.equal(4_242_420_125)
  list.length(model.regions) |> should.equal(2)
  list.length(model.routers) |> should.equal(2)
  list.length(model.links) |> should.equal(1)
  list.length(model.external_peers) |> should.equal(1)

  // 2. Topology validation (valid model has 0 errors)
  let errors = net_validator.validate_network_model(model)
  list.length(errors) |> should.equal(0)

  // Test validation detects errors when router references invalid region
  let broken_router =
    net_model.RouterNode(
      id: "broken-1",
      hostname: "broken.net",
      region_id: "unknown-pop",
      role: net_model.RoleEdge,
      asn: None,
      router_id: "172.22.64.99",
      loopback_v4: "172.22.64.99",
      loopback_v6: "fdd4::99",
      bgp_port: 179,
      api_port: 9179,
      extra_tags: [],
    )
  let broken_model =
    net_model.GlobalNetworkModel(..model, routers: [
      broken_router,
      ..model.routers
    ])
  let broken_errors = net_validator.validate_network_model(broken_model)
  list.length(broken_errors) |> should.equal(1)

  // 3. Compiler derives edge router config
  let assert Ok(edge_cfg) =
    net_compiler.compile_router_config(model, "fra-edge-1")
  edge_cfg.asn |> should.equal(4_242_420_125)
  edge_cfg.router_id |> should.equal(Ipv4(172, 22, 64, 2))
  edge_cfg.cluster_id |> should.equal(None)
  // Should have 2 peers: 1 iBGP link to fra-rr-1 and 1 external peer to baragoon
  list.length(edge_cfg.peers) |> should.equal(2)

  let assert Ok(ibgp_peer) =
    list.find(edge_cfg.peers, fn(p) { p.id == "ibgp_fra-rr-1" })
  ibgp_peer.remote_as |> should.equal(4_242_420_125)
  ibgp_peer.dn42_latency |> should.equal(Some(2))
  ibgp_peer.dn42_bandwidth |> should.equal(Some(1000))
  ibgp_peer.dn42_crypto |> should.equal(Some(41))

  let assert Ok(ext_peer) =
    list.find(edge_cfg.peers, fn(p) { p.id == "peer-baragoon" })
  ext_peer.remote_as |> should.equal(4_242_421_732)
  ext_peer.bgp_role |> should.equal(Some(RolePeer))

  // 4. Compiler derives Route Reflector config
  let assert Ok(rr_cfg) = net_compiler.compile_router_config(model, "fra-rr-1")
  rr_cfg.cluster_id |> should.equal(Some(Ipv4(172, 22, 64, 1)))
  let assert Ok(rr_client_peer) =
    list.find(rr_cfg.peers, fn(p) { p.id == "ibgp_fra-edge-1" })
  rr_client_peer.route_reflector_client |> should.equal(True)

  // 5. Native JSON config generation
  let edge_json = net_compiler.daemon_config_to_json(edge_cfg)
  string.contains(edge_json, "172.22.64.2") |> should.equal(True)
  string.contains(edge_json, "ibgp_fra-rr-1") |> should.equal(True)
  string.contains(edge_json, "peer-baragoon") |> should.equal(True)

  // 6. Graphviz DOT and Mermaid topology graph generation
  let dot = net_compiler.to_graphviz_dot(model)
  string.contains(dot, "graph \"slopnet-global\"") |> should.equal(True)
  string.contains(dot, "subgraph \"cluster_fra\"") |> should.equal(True)

  let mermaid = net_compiler.to_mermaid_graph(model)
  string.contains(mermaid, "flowchart LR") |> should.equal(True)
  string.contains(mermaid, "subgraph fra") |> should.equal(True)
  string.contains(mermaid, "fra-rr-1 <-->|2ms| fra-edge-1")
  |> should.equal(True)
}

// 38. RFC 7938 / RFC 7454 BGP Route Hygiene & Bogon/Martian Filter Engine
pub fn bgp_route_hygiene_test() {
  // 1. Martian ASN detection
  hygiene.is_martian_asn(0) |> should.equal(True)
  hygiene.is_martian_asn(23_456) |> should.equal(True)
  hygiene.is_martian_asn(64_500) |> should.equal(True)
  hygiene.is_martian_asn(65_535) |> should.equal(True)
  hygiene.is_martian_asn(65_540) |> should.equal(True)
  hygiene.is_martian_asn(4_294_967_295) |> should.equal(True)
  hygiene.is_martian_asn(4_242_421_732) |> should.equal(False)

  // 2. Bogon prefix detection (RFC 6890)
  let assert Ok(p_loop) = parse_prefix("127.0.0.1/32")
  let assert Ok(p_cgnat) = parse_prefix("100.64.1.0/24")
  let assert Ok(p_mc) = parse_prefix("224.0.0.1/32")
  let assert Ok(p_v6_doc) = parse_prefix("2001:db8::/32")
  let assert Ok(p_v6_ll) = parse_prefix("fe80::1/128")
  let assert Ok(p_dn42) = parse_prefix("172.20.99.0/24")
  let assert Ok(p_dn42_v6) = parse_prefix("fd42:d42:1732::/48")

  hygiene.is_bogon_prefix(p_loop) |> should.equal(True)
  hygiene.is_bogon_prefix(p_cgnat) |> should.equal(True)
  hygiene.is_bogon_prefix(p_mc) |> should.equal(True)
  hygiene.is_bogon_prefix(p_v6_doc) |> should.equal(True)
  hygiene.is_bogon_prefix(p_v6_ll) |> should.equal(True)

  // 3. DN42 address space compliance
  hygiene.is_valid_dn42_space(p_dn42) |> should.equal(True)
  hygiene.is_valid_dn42_space(p_dn42_v6) |> should.equal(True)
  hygiene.is_valid_dn42_space(p_loop) |> should.equal(False)

  // 4. Validate route hygiene
  let cfg = hygiene.default_dn42_hygiene()
  let valid_rt =
    Route(
      prefix: p_dn42,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_001, 4_242_420_002])],
      next_hop: Ipv4(172, 20, 10, 1),
      med: 10,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "peer1",
      timestamp: 0,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  // Valid DN42 route passes
  hygiene.validate_route_hygiene(valid_rt, cfg, Some(4_242_420_001))
  |> should.be_ok

  // First-AS mismatch rejected
  hygiene.validate_route_hygiene(valid_rt, cfg, Some(4_242_429_999))
  |> should.be_error

  // Excessive prepending rejected
  let prepended_rt =
    Route(..valid_rt, as_path: [AsSequence(list.repeat(4_242_420_001, 8))])
  hygiene.validate_route_hygiene(prepended_rt, cfg, Some(4_242_420_001))
  |> should.be_error

  // Martian ASN in path rejected
  let martian_rt =
    Route(..valid_rt, as_path: [AsSequence([4_242_420_001, 0, 4_242_420_002])])
  hygiene.validate_route_hygiene(martian_rt, cfg, Some(4_242_420_001))
  |> should.be_error
}

// 39. SlopFilter Route Hygiene Pipeline Integration
pub fn slopfilter_hygiene_pipeline_test() {
  let assert Ok(p_bogon) = parse_prefix("10.0.0.0/8")
  let assert Ok(p_dn42) = parse_prefix("172.20.50.0/24")
  let cfg = hygiene.default_dn42_hygiene()

  let bogon_rt =
    Route(
      prefix: p_bogon,
      origin: OriginIgp,
      as_path: [AsSequence([4_242_420_001])],
      next_hop: Ipv4(10, 0, 0, 1),
      med: 0,
      local_pref: 100,
      atomic_aggregate: False,
      communities: [],
      large_communities: [],
      ext_communities: [],
      otc: None,
      roa_status: RoaValid,
      peer_id: "peer1",
      timestamp: 0,
      path_id: None,
      originator_id: None,
      cluster_list: [],
    )

  let clean_rt = Route(..bogon_rt, prefix: p_dn42)

  let pipeline =
    slop_pipeline.FilterPipeline(
      name: "hygiene_filter",
      rules: [
        slop_pipeline.FilterRule(
          name: "drop_hygiene_violations",
          matches: [slop_pipeline.MatchHygieneViolation(cfg)],
          actions: [slop_pipeline.ActionReject("Route hygiene violation")],
        ),
      ],
      default_action: slop_pipeline.ActionAccept,
    )

  let res_bogon = slop_pipeline.execute_pipeline(pipeline, bogon_rt)
  res_bogon.accepted |> should.equal(False)

  let res_clean = slop_pipeline.execute_pipeline(pipeline, clean_rt)
  res_clean.accepted |> should.equal(True)
}

// 40. Multi-Router Global Network Topology Simulation & Convergence Engine
pub fn global_network_model_simulation_test() {
  let reg_eu = net_model.Region("eu", "Frankfurt", "DE", 41, 50.11, 8.68)
  let reg_us = net_model.Region("us", "New York", "US", 42, 40.71, -74.0)

  let r_core1 =
    net_model.RouterNode(
      id: "fra-core1",
      hostname: "fra-core1.slopnet",
      region_id: "eu",
      role: net_model.RoleRouteReflector,
      asn: None,
      router_id: "172.20.10.1",
      loopback_v4: "172.20.10.1/32",
      loopback_v6: "fd42::1/128",
      bgp_port: 179,
      api_port: 8787,
      extra_tags: [],
    )
  let r_edge1 =
    net_model.RouterNode(
      id: "fra-edge1",
      hostname: "fra-edge1.slopnet",
      region_id: "eu",
      role: net_model.RoleEdge,
      asn: None,
      router_id: "172.20.10.11",
      loopback_v4: "172.20.10.11/32",
      loopback_v6: "fd42::11/128",
      bgp_port: 179,
      api_port: 8788,
      extra_tags: [],
    )
  let r_nyc1 =
    net_model.RouterNode(
      id: "nyc-core1",
      hostname: "nyc-core1.slopnet",
      region_id: "us",
      role: net_model.RoleRouteReflector,
      asn: None,
      router_id: "172.20.20.1",
      loopback_v4: "172.20.20.1/32",
      loopback_v6: "fd42::21/128",
      bgp_port: 179,
      api_port: 8789,
      extra_tags: [],
    )

  let link_fra =
    net_model.InterRouterLink(
      id: "fra_internal",
      endpoint_a: "fra-core1",
      endpoint_b: "fra-edge1",
      link_type: net_model.LinkWireGuard,
      cost: 10,
      latency_ms: 2,
      bandwidth_mbps: 1000,
      bfd: True,
      ip_a: "172.20.10.1",
      ip_b: "172.20.10.11",
    )
  let link_wan =
    net_model.InterRouterLink(
      id: "wan_transatlantic",
      endpoint_a: "fra-core1",
      endpoint_b: "nyc-core1",
      link_type: net_model.LinkWireGuard,
      cost: 75,
      latency_ms: 70,
      bandwidth_mbps: 1000,
      bfd: True,
      ip_a: "172.20.10.1",
      ip_b: "172.20.20.1",
    )

  let model =
    net_model.GlobalNetworkModel(
      name: "slopnet-test",
      asn: 4_242_421_732,
      regions: [reg_eu, reg_us],
      routers: [r_core1, r_edge1, r_nyc1],
      links: [link_fra, link_wan],
      external_peers: [],
    )

  let init_state = net_sim.init_sim(model)
  let injection =
    net_sim.SimRouteInjection(
      target_node_id: "fra-edge1",
      prefix: "172.20.77.0/24",
      origin_as: 4_242_420_001,
      as_path: [4_242_420_001],
      med: 10,
      communities: [],
      large_communities: [],
      otc: None,
    )

  let assert Ok(injected_state) = net_sim.inject_route(init_state, injection)
  let report = net_sim.run_simulation_to_convergence(injected_state, 10)

  // Network must converge in discrete simulation steps
  report.converged |> should.equal(True)
  report.total_steps |> should.equal(3)
  list.length(report.detected_leaks) |> should.equal(0)

  // Every router in the network must have the route
  let assert Ok(fra_core_summary) =
    list.find(report.node_rib_summaries, fn(s) { s.node_id == "fra-core1" })
  fra_core_summary.route_count |> should.equal(1)

  let assert Ok(nyc_core_summary) =
    list.find(report.node_rib_summaries, fn(s) { s.node_id == "nyc-core1" })
  nyc_core_summary.route_count |> should.equal(1)

  // Report JSON serialization check
  let json_rep = net_sim.convergence_report_to_json(report)
  string.contains(json_rep, "\"converged\":true") |> should.equal(True)
  string.contains(json_rep, "172.20.77.0/24") |> should.equal(True)

  // Report CLI formatting check
  let cli_rep = net_sim.format_convergence_report(report)
  string.contains(cli_rep, "Status: CONVERGED in 3 steps") |> should.equal(True)
}

// 41. RFC 9234 Route Leak Detection in Multi-Router Topology Simulation
pub fn global_network_simulation_route_leak_test() {
  let reg = net_model.Region("eu", "Frankfurt", "DE", 41, 50.11, 8.68)
  let r_edge =
    net_model.RouterNode(
      id: "fra-edge",
      hostname: "edge.slopnet",
      region_id: "eu",
      role: net_model.RoleEdge,
      asn: None,
      router_id: "172.20.10.1",
      loopback_v4: "172.20.10.1/32",
      loopback_v6: "fd42::1/128",
      bgp_port: 179,
      api_port: 8787,
      extra_tags: [],
    )
  let ext_provider =
    net_model.ExternalPeerDef(
      id: "peer-upstream",
      name: "Upstream Transit",
      attached_router: "fra-edge",
      remote_as: 4_242_420_099,
      remote_ip: "172.22.1.1",
      local_ip: None,
      port: 179,
      bgp_role: RoleProvider,
      import_policies: [],
      export_policies: [],
      bfd: False,
      dn42_latency: None,
      dn42_bandwidth: None,
      dn42_crypto: None,
    )

  let model =
    net_model.GlobalNetworkModel(
      name: "slopnet-leak-test",
      asn: 4_242_421_732,
      regions: [reg],
      routers: [r_edge],
      links: [],
      external_peers: [ext_provider],
    )

  let init_state = net_sim.init_sim(model)

  // Route learned from another peer/provider with OTC AS4242420088
  let leak_injection =
    net_sim.SimRouteInjection(
      target_node_id: "fra-edge",
      prefix: "172.20.88.0/24",
      origin_as: 4_242_420_001,
      as_path: [4_242_420_088, 4_242_420_001],
      med: 0,
      communities: [],
      large_communities: [],
      otc: Some(4_242_420_088),
    )

  let assert Ok(injected) = net_sim.inject_route(init_state, leak_injection)
  let #(stepped, _) = net_sim.sim_step(injected)

  // The simulator must catch the attempt to leak this OTC route to RoleProvider
  list.length(stepped.leaks_detected) |> should.equal(1)
  let assert [leak] = stepped.leaks_detected
  leak.otc_as |> should.equal(4_242_420_088)
  string.contains(leak.reason, "RFC 9234 route leak") |> should.equal(True)
}
