import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import slopbgp/ip.{bytes_to_ipv6, ip_to_bytes}
import slopbgp/types.{
  type ExtendedCommunity, type IpAddress, type IpPrefix, ExtCommunity, IpPrefix,
  Ipv4, Ipv6,
}

pub type RouteDistinguisher {
  RdAsn2(asn: Int, assigned: Int)
  RdIpv4(ip: IpAddress, assigned: Int)
  RdAsn4(asn: Int, assigned: Int)
}

pub type EvpnRouteType2 {
  EvpnRouteType2(
    rd: RouteDistinguisher,
    esi: BitArray,
    eth_tag_id: Int,
    mac_address: String,
    ip_address: Option(IpAddress),
    vni: Int,
  )
}

pub type EvpnRouteType5 {
  EvpnRouteType5(
    rd: RouteDistinguisher,
    esi: BitArray,
    eth_tag_id: Int,
    prefix: IpPrefix,
    gateway_ip: Option(IpAddress),
    vni: Int,
  )
}

pub type EvpnNlri {
  EvpnMacIp(EvpnRouteType2)
  EvpnPrefix(EvpnRouteType5)
}

pub fn encode_rd(rd: RouteDistinguisher) -> BitArray {
  case rd {
    RdAsn2(asn, assigned) -> <<0:16, asn:16, assigned:32>>
    RdIpv4(ip, assigned) -> {
      let ip_bytes = case ip {
        Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
        _ -> <<0:32>>
      }
      <<1:16, ip_bytes:bits, assigned:16>>
    }
    RdAsn4(asn, assigned) -> <<2:16, asn:32, assigned:16>>
  }
}

pub fn decode_rd(bytes: BitArray) -> Result(RouteDistinguisher, String) {
  case bytes {
    <<0:16, asn:16, assigned:32>> -> Ok(RdAsn2(asn, assigned))
    <<1:16, a:8, b:8, c:8, d:8, assigned:16>> ->
      Ok(RdIpv4(Ipv4(a, b, c, d), assigned))
    <<2:16, asn:32, assigned:16>> -> Ok(RdAsn4(asn, assigned))
    _ -> Error("Invalid Route Distinguisher format")
  }
}

pub fn encode_vni_label(vni: Int) -> BitArray {
  <<vni:20, 1:4>>
}

pub fn decode_vni_label(bytes: BitArray) -> Result(Int, String) {
  case bytes {
    <<vni:20, _:4>> -> Ok(vni)
    _ -> Error("Invalid 24-bit MPLS/VNI label")
  }
}

pub fn mac_to_bytes(mac: String) -> BitArray {
  let cleaned = string.replace(mac, ":", "")
  let cleaned2 = string.replace(cleaned, "-", "")
  case bit_array.byte_size(<<0:48>>) {
    _ ->
      case parse_hex_mac(cleaned2) {
        Ok(b) -> b
        Error(_) -> <<0:48>>
      }
  }
}

fn parse_hex_mac(hex: String) -> Result(BitArray, String) {
  case string.length(hex) == 12 {
    True -> parse_hex_bytes(hex, <<>>)
    False -> Error("MAC hex string must be 12 characters")
  }
}

fn parse_hex_bytes(hex: String, acc: BitArray) -> Result(BitArray, String) {
  case hex {
    "" -> Ok(acc)
    _ -> {
      let byte_str = string.slice(hex, 0, 2)
      let rem = string.slice(hex, 2, string.length(hex) - 2)
      use byte_val <- result.try(hex_to_int(byte_str))
      parse_hex_bytes(rem, <<acc:bits, byte_val:8>>)
    }
  }
}

fn hex_to_int(h: String) -> Result(Int, String) {
  case string.lowercase(h) {
    "00" -> Ok(0)
    "01" -> Ok(1)
    "02" -> Ok(2)
    "03" -> Ok(3)
    "04" -> Ok(4)
    "05" -> Ok(5)
    "06" -> Ok(6)
    "07" -> Ok(7)
    "08" -> Ok(8)
    "09" -> Ok(9)
    "0a" -> Ok(10)
    "0b" -> Ok(11)
    "0c" -> Ok(12)
    "0d" -> Ok(13)
    "0e" -> Ok(14)
    "0f" -> Ok(15)
    "10" -> Ok(16)
    "1a" -> Ok(26)
    "20" -> Ok(32)
    "2b" -> Ok(43)
    "3c" -> Ok(60)
    "4d" -> Ok(77)
    "5e" -> Ok(94)
    "ff" -> Ok(255)
    _ -> {
      case string.to_graphemes(h) {
        [c1, c2] -> {
          use d1 <- result.try(hex_digit(c1))
          use d2 <- result.try(hex_digit(c2))
          Ok(d1 * 16 + d2)
        }
        _ -> Error("Invalid hex byte: " <> h)
      }
    }
  }
}

fn hex_digit(c: String) -> Result(Int, String) {
  case string.lowercase(c) {
    "0" -> Ok(0)
    "1" -> Ok(1)
    "2" -> Ok(2)
    "3" -> Ok(3)
    "4" -> Ok(4)
    "5" -> Ok(5)
    "6" -> Ok(6)
    "7" -> Ok(7)
    "8" -> Ok(8)
    "9" -> Ok(9)
    "a" -> Ok(10)
    "b" -> Ok(11)
    "c" -> Ok(12)
    "d" -> Ok(13)
    "e" -> Ok(14)
    "f" -> Ok(15)
    _ -> Error("Invalid hex digit: " <> c)
  }
}

pub fn bytes_to_mac(bytes: BitArray) -> String {
  case bytes {
    <<b1:8, b2:8, b3:8, b4:8, b5:8, b6:8>> ->
      to_hex2(b1)
      <> ":"
      <> to_hex2(b2)
      <> ":"
      <> to_hex2(b3)
      <> ":"
      <> to_hex2(b4)
      <> ":"
      <> to_hex2(b5)
      <> ":"
      <> to_hex2(b6)
    _ -> "00:00:00:00:00:00"
  }
}

fn to_hex2(b: Int) -> String {
  let hi = b / 16
  let lo = b % 16
  digit_to_hex(hi) <> digit_to_hex(lo)
}

fn digit_to_hex(d: Int) -> String {
  case d {
    0 -> "0"
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    6 -> "6"
    7 -> "7"
    8 -> "8"
    9 -> "9"
    10 -> "a"
    11 -> "b"
    12 -> "c"
    13 -> "d"
    14 -> "e"
    _ -> "f"
  }
}

pub fn encode_evpn_route_type2(r: EvpnRouteType2) -> BitArray {
  let rd_bytes = encode_rd(r.rd)
  let esi_bytes = case bit_array.byte_size(r.esi) == 10 {
    True -> r.esi
    False -> <<0:80>>
  }
  let mac_bytes = mac_to_bytes(r.mac_address)
  let #(ip_len, ip_bytes) = case r.ip_address {
    None -> #(0, <<>>)
    Some(Ipv4(a, b, c, d)) -> #(32, <<a:8, b:8, c:8, d:8>>)
    Some(Ipv6(..)) -> #(
      128,
      ip_to_bytes(case r.ip_address {
        Some(ip) -> ip
        None -> Ipv4(0, 0, 0, 0)
      }),
    )
  }
  let label_bytes = encode_vni_label(r.vni)
  let payload = <<
    rd_bytes:bits,
    esi_bytes:bits,
    r.eth_tag_id:32,
    48:8,
    mac_bytes:bits,
    ip_len:8,
    ip_bytes:bits,
    label_bytes:bits,
  >>
  let plen = bit_array.byte_size(payload)
  <<2:8, plen:8, payload:bits>>
}

pub fn encode_evpn_route_type5(r: EvpnRouteType5) -> BitArray {
  let rd_bytes = encode_rd(r.rd)
  let esi_bytes = case bit_array.byte_size(r.esi) == 10 {
    True -> r.esi
    False -> <<0:80>>
  }
  let prefix_bytes = ip_to_bytes(r.prefix.address)
  let gw_bytes = case r.gateway_ip {
    Some(gw) -> ip_to_bytes(gw)
    None ->
      case r.prefix.address {
        Ipv4(..) -> <<0:32>>
        Ipv6(..) -> <<0:128>>
      }
  }
  let label_bytes = encode_vni_label(r.vni)
  let payload = <<
    rd_bytes:bits,
    esi_bytes:bits,
    r.eth_tag_id:32,
    r.prefix.length:8,
    prefix_bytes:bits,
    gw_bytes:bits,
    label_bytes:bits,
  >>
  let plen = bit_array.byte_size(payload)
  <<5:8, plen:8, payload:bits>>
}

pub fn decode_evpn_nlri(
  bytes: BitArray,
) -> Result(#(EvpnNlri, BitArray), String) {
  case bytes {
    <<route_type:8, len:8, rest:bits>> -> {
      let bits_len = len * 8
      case rest {
        <<payload:bits-size(bits_len), rem:bits>> -> {
          case route_type {
            2 -> {
              // Type 2: MAC/IP Advertisement
              case payload {
                <<
                  rd_raw:bits-size(64),
                  esi_raw:bits-size(80),
                  tag_id:32,
                  mac_len:8,
                  mac_raw:bits-size(48),
                  ip_len:8,
                  after_ip_len:bits,
                >>
                  if mac_len == 48
                -> {
                  use rd <- result.try(decode_rd(rd_raw))
                  let mac_str = bytes_to_mac(mac_raw)
                  use #(ip_opt, after_ip) <- result.try(case ip_len {
                    0 -> Ok(#(None, after_ip_len))
                    32 -> {
                      case after_ip_len {
                        <<a:8, b:8, c:8, d:8, rem_labels:bits>> ->
                          Ok(#(Some(Ipv4(a, b, c, d)), rem_labels))
                        _ -> Error("Malformed IPv4 in EVPN Type 2")
                      }
                    }
                    128 -> {
                      case after_ip_len {
                        <<ip6_raw:bits-size(128), rem_labels:bits>> -> {
                          use ip6 <- result.try(bytes_to_ipv6(ip6_raw))
                          Ok(#(Some(ip6), rem_labels))
                        }
                        _ -> Error("Malformed IPv6 in EVPN Type 2")
                      }
                    }
                    _ -> Error("Invalid IP address length in EVPN Type 2")
                  })
                  use vni <- result.try(case after_ip {
                    <<lbl:bits-size(24), _:bits>> -> decode_vni_label(lbl)
                    _ -> Error("Missing VNI label in EVPN Type 2")
                  })
                  let r2 =
                    EvpnRouteType2(
                      rd: rd,
                      esi: esi_raw,
                      eth_tag_id: tag_id,
                      mac_address: mac_str,
                      ip_address: ip_opt,
                      vni: vni,
                    )
                  Ok(#(EvpnMacIp(r2), rem))
                }
                _ -> Error("Malformed EVPN Type 2 payload")
              }
            }
            5 -> {
              // Type 5: IP Prefix
              case payload {
                <<
                  rd_raw:bits-size(64),
                  esi_raw:bits-size(80),
                  tag_id:32,
                  prefix_len:8,
                  after_prefix_len:bits,
                >> -> {
                  use rd <- result.try(decode_rd(rd_raw))
                  case prefix_len <= 32 {
                    True -> {
                      case after_prefix_len {
                        <<
                          pa:8,
                          pb:8,
                          pc:8,
                          pd:8,
                          ga:8,
                          gb:8,
                          gc:8,
                          gd:8,
                          lbl:bits-size(24),
                          _:bits,
                        >> -> {
                          use vni <- result.try(decode_vni_label(lbl))
                          let pfx = IpPrefix(Ipv4(pa, pb, pc, pd), prefix_len)
                          let gw = case
                            ga == 0 && gb == 0 && gc == 0 && gd == 0
                          {
                            True -> None
                            False -> Some(Ipv4(ga, gb, gc, gd))
                          }
                          let r5 =
                            EvpnRouteType5(
                              rd: rd,
                              esi: esi_raw,
                              eth_tag_id: tag_id,
                              prefix: pfx,
                              gateway_ip: gw,
                              vni: vni,
                            )
                          Ok(#(EvpnPrefix(r5), rem))
                        }
                        _ -> Error("Malformed IPv4 EVPN Type 5 payload")
                      }
                    }
                    False -> {
                      case after_prefix_len {
                        <<
                          p_raw:bits-size(128),
                          g_raw:bits-size(128),
                          lbl:bits-size(24),
                          _:bits,
                        >> -> {
                          use p_ip <- result.try(bytes_to_ipv6(p_raw))
                          use g_ip <- result.try(bytes_to_ipv6(g_raw))
                          use vni <- result.try(decode_vni_label(lbl))
                          let pfx = IpPrefix(p_ip, prefix_len)
                          let r5 =
                            EvpnRouteType5(
                              rd: rd,
                              esi: esi_raw,
                              eth_tag_id: tag_id,
                              prefix: pfx,
                              gateway_ip: Some(g_ip),
                              vni: vni,
                            )
                          Ok(#(EvpnPrefix(r5), rem))
                        }
                        _ -> Error("Malformed IPv6 EVPN Type 5 payload")
                      }
                    }
                  }
                }
                _ -> Error("Malformed EVPN Type 5 payload")
              }
            }
            _ ->
              Error("Unsupported EVPN Route Type: " <> int_to_str(route_type))
          }
        }
        _ -> Error("Truncated EVPN NLRI payload")
      }
    }
    _ -> Error("Truncated EVPN NLRI header")
  }
}

pub fn decode_evpn_stream(bytes: BitArray) -> Result(List(EvpnNlri), String) {
  decode_evpn_stream_loop(bytes, [])
}

fn decode_evpn_stream_loop(
  bytes: BitArray,
  acc: List(EvpnNlri),
) -> Result(List(EvpnNlri), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(nlri, rest) <- result.try(decode_evpn_nlri(bytes))
      decode_evpn_stream_loop(rest, [nlri, ..acc])
    }
  }
}

pub fn vxlan_tunnel_encap_community() -> ExtendedCommunity {
  // RFC 9012 / RFC 8365: Transitive Opaque Extended Community, Sub-Type 0x0C, Tunnel Type 8 (VXLAN)
  ExtCommunity(type_code: 0x03, sub_type: 0x0C, value: <<0:16, 8:16>>)
}

fn int_to_str(i: Int) -> String {
  case i {
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    _ -> "other"
  }
}
