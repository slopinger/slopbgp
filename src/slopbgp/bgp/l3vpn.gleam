import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import slopbgp/bgp/evpn.{type RouteDistinguisher, decode_rd, encode_rd}
import slopbgp/ip.{bytes_to_ipv4, bytes_to_ipv6, ip_to_string}
import slopbgp/types.{
  type ExtendedCommunity, type IpAddress, type IpPrefix, ExtCommunity, IpPrefix,
  Ipv4, Ipv6,
}

// RFC 4364 BGP/MPLS IP Virtual Private Networks (VPNv4)
// RFC 4659 BGP-MPLS IP VPN Extension for IPv6 (VPNv6)

pub type RouteTarget {
  RtAsn2(asn: Int, assigned: Int)
  RtIpv4(ip: IpAddress, assigned: Int)
  RtAsn4(asn: Int, assigned: Int)
}

pub type RouteOrigin {
  SooAsn2(asn: Int, assigned: Int)
  SooIpv4(ip: IpAddress, assigned: Int)
  SooAsn4(asn: Int, assigned: Int)
}

pub type MplsVpnRoute {
  MplsVpnRoute(rd: RouteDistinguisher, label: Int, prefix: IpPrefix)
}

// --- Route Target (Extended Community Subtype 0x02) ---

pub fn encode_route_target(rt: RouteTarget) -> ExtendedCommunity {
  case rt {
    RtAsn2(asn, assigned) -> {
      let val = <<asn:16, assigned:32>>
      ExtCommunity(0x00, 0x02, val)
    }
    RtIpv4(ip, assigned) -> {
      let ip_bytes = case ip {
        Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
        _ -> <<0:32>>
      }
      let val = <<ip_bytes:bits, assigned:16>>
      ExtCommunity(0x01, 0x02, val)
    }
    RtAsn4(asn, assigned) -> {
      let val = <<asn:32, assigned:16>>
      ExtCommunity(0x02, 0x02, val)
    }
  }
}

pub fn decode_route_target(
  ext: ExtendedCommunity,
) -> Result(RouteTarget, String) {
  case ext.type_code, ext.sub_type, ext.value {
    0x00, 0x02, <<asn:16, assigned:32>> -> Ok(RtAsn2(asn, assigned))
    0x01, 0x02, <<a:8, b:8, c:8, d:8, assigned:16>> ->
      Ok(RtIpv4(Ipv4(a, b, c, d), assigned))
    0x02, 0x02, <<asn:32, assigned:16>> -> Ok(RtAsn4(asn, assigned))
    _, _, _ -> Error("Not a valid Route Target extended community")
  }
}

pub fn route_target_to_string(rt: RouteTarget) -> String {
  case rt {
    RtAsn2(asn, assigned) ->
      "target:" <> int.to_string(asn) <> ":" <> int.to_string(assigned)
    RtIpv4(ip, assigned) ->
      "target:" <> ip_to_string(ip) <> ":" <> int.to_string(assigned)
    RtAsn4(asn, assigned) ->
      "target:" <> int.to_string(asn) <> ":" <> int.to_string(assigned)
  }
}

pub fn parse_route_target(str: String) -> Result(RouteTarget, String) {
  let cleaned = case string.starts_with(str, "target:") {
    True -> string.drop_start(str, 7)
    False -> str
  }
  case string.split(cleaned, ":") {
    [first, second] -> {
      case int.parse(first), int.parse(second) {
        Ok(asn), Ok(assigned) -> {
          case asn > 65_535 {
            True -> Ok(RtAsn4(asn, assigned))
            False -> Ok(RtAsn2(asn, assigned))
          }
        }
        _, _ -> {
          // Check if first is IPv4
          case string.split(first, ".") {
            [a, b, c, d] -> {
              case
                int.parse(a),
                int.parse(b),
                int.parse(c),
                int.parse(d),
                int.parse(second)
              {
                Ok(a), Ok(b), Ok(c), Ok(d), Ok(assigned) ->
                  Ok(RtIpv4(Ipv4(a, b, c, d), assigned))
                _, _, _, _, _ -> Error("Invalid Route Target format: " <> str)
              }
            }
            _ -> Error("Invalid Route Target format: " <> str)
          }
        }
      }
    }
    _ -> Error("Expected format target:ASN:NN or target:IP:NN, got " <> str)
  }
}

// --- Route Origin (Site of Origin - Subtype 0x03) ---

pub fn encode_route_origin(soo: RouteOrigin) -> ExtendedCommunity {
  case soo {
    SooAsn2(asn, assigned) -> {
      let val = <<asn:16, assigned:32>>
      ExtCommunity(0x00, 0x03, val)
    }
    SooIpv4(ip, assigned) -> {
      let ip_bytes = case ip {
        Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
        _ -> <<0:32>>
      }
      let val = <<ip_bytes:bits, assigned:16>>
      ExtCommunity(0x01, 0x03, val)
    }
    SooAsn4(asn, assigned) -> {
      let val = <<asn:32, assigned:16>>
      ExtCommunity(0x02, 0x03, val)
    }
  }
}

pub fn decode_route_origin(
  ext: ExtendedCommunity,
) -> Result(RouteOrigin, String) {
  case ext.type_code, ext.sub_type, ext.value {
    0x00, 0x03, <<asn:16, assigned:32>> -> Ok(SooAsn2(asn, assigned))
    0x01, 0x03, <<a:8, b:8, c:8, d:8, assigned:16>> ->
      Ok(SooIpv4(Ipv4(a, b, c, d), assigned))
    0x02, 0x03, <<asn:32, assigned:16>> -> Ok(SooAsn4(asn, assigned))
    _, _, _ -> Error("Not a valid Route Origin (SOO) extended community")
  }
}

// --- MPLS Label Encoding (RFC 3107 / RFC 8277) ---

pub fn encode_mpls_label(label: Int, bottom_of_stack: Bool) -> BitArray {
  let s_bit = case bottom_of_stack {
    True -> 1
    False -> 0
  }
  // 20 bits label, 3 bits exp (0), 1 bit bottom-of-stack
  <<label:20, 0:3, s_bit:1>>
}

pub fn decode_mpls_label(bytes: BitArray) -> Result(#(Int, Bool), String) {
  case bytes {
    <<label:20, _exp:3, s_bit:1>> -> {
      let is_bottom = s_bit == 1
      Ok(#(label, is_bottom))
    }
    _ -> Error("Invalid 24-bit MPLS label")
  }
}

// --- VPN-IPv4 and VPN-IPv6 NLRI Encoding / Decoding ---
// NLRI wire layout:
// Length: 1 octet (total length in bits: 24 label bits + 64 RD bits + prefix_len)
// MPLS Label Stack (24 bits)
// Route Distinguisher (64 bits / 8 octets)
// Prefix bits (ceiling(prefix_len / 8) octets)

pub fn encode_vpn_nlri(route: MplsVpnRoute) -> BitArray {
  let label_bytes = encode_mpls_label(route.label, True)
  let rd_bytes = encode_rd(route.rd)
  let prefix_len = route.prefix.length
  let total_bits = 24 + 64 + prefix_len

  let pfx_bits = case route.prefix.address {
    Ipv4(a, b, c, d) -> {
      let full = <<a:8, b:8, c:8, d:8>>
      let byte_count = { prefix_len + 7 } / 8
      case bit_array.slice(full, 0, byte_count) {
        Ok(b) -> b
        Error(_) -> <<>>
      }
    }
    Ipv6(a, b, c, d, e, f, g, h) -> {
      let full = <<a:16, b:16, c:16, d:16, e:16, f:16, g:16, h:16>>
      let byte_count = { prefix_len + 7 } / 8
      case bit_array.slice(full, 0, byte_count) {
        Ok(b) -> b
        Error(_) -> <<>>
      }
    }
  }

  <<total_bits:8, label_bytes:bits, rd_bytes:bits, pfx_bits:bits>>
}

pub fn decode_vpn_nlri(
  bytes: BitArray,
  is_ipv6: Bool,
) -> Result(List(MplsVpnRoute), String) {
  decode_vpn_nlri_loop(bytes, is_ipv6, [])
}

fn decode_vpn_nlri_loop(
  bytes: BitArray,
  is_ipv6: Bool,
  acc: List(MplsVpnRoute),
) -> Result(List(MplsVpnRoute), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    <<total_bits:8, rest:bits>> -> {
      // Must be at least 24 (label) + 64 (RD) = 88 bits
      case total_bits < 88 {
        True ->
          Error("VPN NLRI bit length too short: " <> int.to_string(total_bits))
        False -> {
          let prefix_len = total_bits - 88
          let pfx_byte_len = { prefix_len + 7 } / 8

          case rest {
            <<label_raw:bits-size(24), rd_raw:bits-size(64), rem_after_rd:bits>> -> {
              use #(label, _) <- result.try(decode_mpls_label(label_raw))
              use rd <- result.try(decode_rd(rd_raw))

              case bit_array.slice(rem_after_rd, 0, pfx_byte_len) {
                Ok(pfx_bytes) -> {
                  let rem_next = case
                    bit_array.slice(
                      rem_after_rd,
                      pfx_byte_len,
                      bit_array.byte_size(rem_after_rd) - pfx_byte_len,
                    )
                  {
                    Ok(r) -> r
                    Error(_) -> <<>>
                  }

                  use ip_addr <- result.try(case is_ipv6 {
                    False -> {
                      let padded = pad_right(pfx_bytes, 4)
                      case bytes_to_ipv4(padded) {
                        Ok(ip) -> Ok(ip)
                        Error(_) -> Error("Failed to parse VPN-IPv4 prefix")
                      }
                    }
                    True -> {
                      let padded = pad_right(pfx_bytes, 16)
                      case bytes_to_ipv6(padded) {
                        Ok(ip) -> Ok(ip)
                        Error(_) -> Error("Failed to parse VPN-IPv6 prefix")
                      }
                    }
                  })

                  let route =
                    MplsVpnRoute(
                      rd: rd,
                      label: label,
                      prefix: IpPrefix(ip_addr, prefix_len),
                    )
                  decode_vpn_nlri_loop(rem_next, is_ipv6, [route, ..acc])
                }
                Error(_) -> Error("Truncated prefix bytes in VPN NLRI")
              }
            }
            _ -> Error("Truncated label/RD in VPN NLRI")
          }
        }
      }
    }
    _ -> Error("Malformed VPN NLRI data")
  }
}

fn pad_right(bytes: BitArray, target_len: Int) -> BitArray {
  let cur = bit_array.byte_size(bytes)
  case cur >= target_len {
    True -> bytes
    False -> pad_right(<<bytes:bits, 0:8>>, target_len)
  }
}
