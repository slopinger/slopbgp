import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import gleeunit/should
import slopbgp/api/http
import slopbgp/bgp/attributes.{decode_attributes, encode_attributes}
import slopbgp/bgp/capabilities.{decode_capabilities, encode_capability}
import slopbgp/bgp/damping.{default_damping_config, evaluate_flap, record_flap}
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
import slopbgp/bgp/message.{decode_message, encode_message}
import slopbgp/bgp/shutdown_communication.{
  decode_shutdown_communication, encode_shutdown_communication,
  format_cease_subcode, make_shutdown_notification,
}
import slopbgp/bmp/message as bmp_message
import slopbgp/config
import slopbgp/dn42/filter.{is_bogon, is_valid_dn42_network}
import slopbgp/dn42/roa.{parse_roa_line, validate_route}
import slopbgp/ip.{
  decode_prefixes_ipv4, encode_prefix, ip_to_string, is_prefix_contained,
  parse_ip, parse_prefix, prefix_to_string,
}
import slopbgp/metrics/prometheus.{DaemonMetricsData, render_prometheus_metrics}
import slopbgp/policy/filter as policy_filter
import slopbgp/rib/rib.{compare_routes, insert_route, new_rib, withdraw_route}
import slopbgp/routeserver/routeserver
import slopbgp/server
import slopbgp/simulator.{run_simulation}
import slopbgp/types.{
  type Route, ActionAccept, ActionPrependAs, ActionSetLocalPref, AfiIpv4,
  AfiIpv6, AsSequence, AttrAsPath, AttrCommunities, AttrLargeCommunities,
  AttrLocalPref, AttrMed, AttrMpReachNlri, AttrNextHop, AttrOrigin,
  BmpMsgInitiation, BmpMsgPeerDown, BmpMsgRouteMonitoring, BmpMsgStatsReport,
  BmpMsgTermination, BmpPeerHeader, BmpStatCounter, CapAddPath, CapBgpRole,
  CapEnhancedRouteRefresh, CapExtendedMessage, CapExtendedNextHop,
  CapFourOctetAsn, CapMultiProtocol, CapRouteRefresh, Community, FlowActionDrop,
  FlowDstPort, FlowDstPrefix, FlowIpProtocol, FlowLabel, FlowNextHeader,
  FlowSrcPrefix, FlowspecRule, Ipv4, Ipv6, LargeCommunity, MatchAsPathContains,
  MsgKeepalive, MsgNotification, MsgOpen, MsgRouteRefresh, OriginIgp, PeerConfig,
  PolicyChain, PolicyRule, RoaInvalid, RoaNotFound, RoaValid, RoleCustomer,
  Route, SafiUnicast, StateConnect, StateEstablished, StateOpenConfirm,
  StateOpenSent,
}

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
