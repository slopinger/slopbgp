import gleam/list
import gleam/option.{None, Some}
import gleeunit
import gleeunit/should
import slopbgp/bgp/attributes.{decode_attributes, encode_attributes}
import slopbgp/bgp/capabilities.{decode_capabilities, encode_capability}
import slopbgp/bgp/fsm.{
  EventAutomaticStart, EventReceivedKeepalive, EventReceivedOpen,
  EventTcpConnected, handle_event, new_session,
}
import slopbgp/bgp/message.{decode_message, encode_message}
import slopbgp/dn42/filter.{is_bogon, is_valid_dn42_network}
import slopbgp/dn42/roa.{parse_roa_line, validate_route}
import slopbgp/ip.{
  decode_prefixes_ipv4, encode_prefix, ip_to_string, is_prefix_contained,
  parse_ip, parse_prefix, prefix_to_string,
}
import slopbgp/rib/rib.{compare_routes, insert_route, new_rib, withdraw_route}
import slopbgp/simulator.{run_simulation}
import slopbgp/types.{
  AfiIpv4, AfiIpv6, AsSequence, AttrAsPath, AttrCommunities,
  AttrLargeCommunities, AttrLocalPref, AttrMed, AttrMpReachNlri, AttrNextHop,
  AttrOrigin, CapAddPath, CapBgpRole, CapEnhancedRouteRefresh,
  CapExtendedMessage, CapExtendedNextHop, CapFourOctetAsn, CapMultiProtocol,
  CapRouteRefresh, Community, Ipv4, Ipv6, LargeCommunity, MsgKeepalive,
  MsgNotification, MsgOpen, MsgRouteRefresh, OriginIgp, RoaInvalid, RoaNotFound,
  RoaValid, RoleCustomer, Route, SafiUnicast, StateConnect, StateEstablished,
  StateOpenConfirm, StateOpenSent,
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
