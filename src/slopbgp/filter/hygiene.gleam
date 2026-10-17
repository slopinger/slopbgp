//// BGP Route Hygiene & Martian/Bogon Filtering (RFC 7454, RFC 7938, RFC 8212)
////
//// Enforces strict internet and DN42 routing hygiene:
//// - Martian & bogon ASN detection (AS0 RFC 7607, documentation ASNs RFC 5398, reserved RFC 7300)
//// - Martian & bogon prefix filtering (RFC 6890 special-purpose registries)
//// - DN42 address space compliance (172.20.0.0/14 and fd00::/8 within valid prefix length bounds)
//// - AS-Path length bounding and excessive prepending detection
//// - First-AS enforcement on eBGP sessions

import gleam/int
import gleam/list
import gleam/option.{type Option, Some}
import slopbgp/types.{
  type AsPathSegment, type IpPrefix, type Route, AsConfedSequence, AsConfedSet,
  AsSequence, AsSet, Ipv4, Ipv6,
}

pub type RouteHygieneConfig {
  RouteHygieneConfig(
    max_as_path_length: Int,
    max_as_path_prepending: Int,
    drop_martian_asns: Bool,
    drop_martian_prefixes: Bool,
    enforce_first_as: Bool,
    dn42_space_only: Bool,
  )
}

pub fn default_dn42_hygiene() -> RouteHygieneConfig {
  RouteHygieneConfig(
    max_as_path_length: 32,
    max_as_path_prepending: 6,
    drop_martian_asns: True,
    drop_martian_prefixes: True,
    enforce_first_as: True,
    dn42_space_only: True,
  )
}

pub fn default_internet_hygiene() -> RouteHygieneConfig {
  RouteHygieneConfig(
    max_as_path_length: 50,
    max_as_path_prepending: 10,
    drop_martian_asns: True,
    drop_martian_prefixes: True,
    enforce_first_as: True,
    dn42_space_only: False,
  )
}

/// Returns True if the ASN is a martian, reserved, or documentation ASN
pub fn is_martian_asn(asn: Int) -> Bool {
  // AS 0: RFC 7607 Codification of AS 0 Processing
  asn == 0
  // AS 23456: AS_TRANS (RFC 6793) - should not be origin or path on 4-byte sessions
  || asn == 23_456
  // RFC 5398 16-bit Documentation ASNs: 64496 - 64511
  || { asn >= 64_496 && asn <= 64_511 }
  // RFC 7300 Last 16-bit ASN
  || asn == 65_535
  // RFC 5398 32-bit Documentation ASNs: 65536 - 65551
  || { asn >= 65_536 && asn <= 65_551 }
  // IANA Reserved: 65552 - 131071
  || { asn >= 65_552 && asn <= 131_071 }
  // RFC 7300 Last 32-bit ASN
  || asn == 4_294_967_295
}

/// Returns True if the prefix is an RFC 6890 / IANA special-purpose martian or bogon prefix
pub fn is_bogon_prefix(pfx: IpPrefix) -> Bool {
  case pfx.address {
    Ipv4(o1, o2, _, _) -> {
      // 0.0.0.0/8 (Current network)
      o1 == 0
      // 10.0.0.0/8 (RFC 1918 Private)
      || o1 == 10
      // 100.64.0.0/10 (RFC 6598 Shared Address Space / CGNAT)
      || { o1 == 100 && o2 >= 64 && o2 <= 127 }
      // 127.0.0.0/8 (Loopback)
      || o1 == 127
      // 169.254.0.0/16 (Link Local)
      || { o1 == 169 && o2 == 254 }
      // 172.16.0.0/12 (RFC 1918 Private)
      || { o1 == 172 && o2 >= 16 && o2 <= 31 }
      // 192.0.0.0/24 (IETF Protocol Assignments)
      || { o1 == 192 && o2 == 0 }
      // 192.0.2.0/24 (TEST-NET-1)
      || { o1 == 192 && o2 == 0 }
      // 192.168.0.0/16 (RFC 1918 Private)
      || { o1 == 192 && o2 == 168 }
      // 198.18.0.0/15 (Benchmarking)
      || { o1 == 198 && { o2 == 18 || o2 == 19 } }
      // 198.51.100.0/24 (TEST-NET-2)
      || { o1 == 198 && o2 == 51 }
      // 203.0.113.0/24 (TEST-NET-3)
      || { o1 == 203 && o2 == 0 }
      // 224.0.0.0/4 (Multicast)
      || o1 >= 224
      && o1 <= 239
      // 240.0.0.0/4 (Reserved / Future Use)
      || o1 >= 240
    }
    Ipv6(w1, w2, _, _, _, _, _, _) -> {
      // ::/128 (Unspecified) or ::1/128 (Loopback)
      { w1 == 0 && w2 == 0 && pfx.length >= 127 }
      // ::ffff:0:0/96 (IPv4-mapped)
      || { w1 == 0 && w2 == 0 && pfx.length <= 96 }
      // 100::/64 (Discard prefix)
      || { w1 == 0x0100 && w2 == 0 }
      // 2001:2::/48 (Benchmarking)
      || { w1 == 0x2001 && w2 == 0x0002 }
      // 2001:db8::/32 (Documentation)
      || { w1 == 0x2001 && w2 == 0x0db8 }
      // 2002::/16 (6to4)
      || w1 == 0x2002
      // fe80::/10 (Link-Local)
      || { w1 >= 0xfe80 && w1 <= 0xfebf }
      // ff00::/8 (Multicast)
      || w1 >= 0xff00
    }
  }
}

/// Checks if a prefix is in valid DN42 address space:
/// IPv4: 172.20.0.0/14 with prefix length between 21 and 29 inclusive
/// IPv6: fd00::/8 with prefix length between 40 and 64 inclusive
pub fn is_valid_dn42_space(pfx: IpPrefix) -> Bool {
  case pfx.address {
    Ipv4(o1, o2, _, _) -> {
      let in_dn42_v4 = o1 == 172 && o2 >= 20 && o2 <= 23
      in_dn42_v4 && pfx.length >= 21 && pfx.length <= 29
    }
    Ipv6(w1, _, _, _, _, _, _, _) -> {
      let in_dn42_v6 = w1 >= 0xfd00 && w1 <= 0xfdff
      in_dn42_v6 && pfx.length >= 40 && pfx.length <= 64
    }
  }
}

/// Flatten all ASNs in an AS-Path into an ordered list
pub fn extract_asns_from_path(segments: List(AsPathSegment)) -> List(Int) {
  list.flat_map(segments, fn(seg) {
    case seg {
      AsSequence(asns) -> asns
      AsSet(asns) -> asns
      AsConfedSequence(asns) -> asns
      AsConfedSet(asns) -> asns
    }
  })
}

/// Checks AS-Path hygiene:
/// 1. Maximum total path length
/// 2. Excessive prepending (same ASN repeated more than max_prepending times)
/// 3. Martian ASNs present anywhere in the path
/// 4. First-AS enforcement if peer_as is provided
pub fn check_as_path_hygiene(
  route: Route,
  config: RouteHygieneConfig,
  peer_as: Option(Int),
) -> Result(Nil, String) {
  let asns = extract_asns_from_path(route.as_path)
  let path_len = list.length(asns)

  // 1. Max path length
  case path_len > config.max_as_path_length {
    True ->
      Error(
        "AS-Path length "
        <> int.to_string(path_len)
        <> " exceeds limit "
        <> int.to_string(config.max_as_path_length),
      )
    False -> {
      // 2. Martian ASNs
      case config.drop_martian_asns {
        True -> {
          case list.find(asns, is_martian_asn) {
            Ok(bad_as) ->
              Error("AS-Path contains martian ASN " <> int.to_string(bad_as))
            Error(Nil) -> Ok(Nil)
          }
        }
        False -> Ok(Nil)
      }
      |> fn(res) {
        case res {
          Error(e) -> Error(e)
          Ok(Nil) -> {
            // 3. Excessive prepending check
            case check_prepending_limit(asns, config.max_as_path_prepending) {
              Error(asn) ->
                Error(
                  "Excessive AS prepending detected for AS"
                  <> int.to_string(asn)
                  <> " (exceeds "
                  <> int.to_string(config.max_as_path_prepending)
                  <> ")",
                )
              Ok(Nil) -> {
                // 4. First-AS enforcement on eBGP
                case config.enforce_first_as, peer_as, asns {
                  True, Some(expected_as), [first_as, ..] -> {
                    case first_as == expected_as {
                      True -> Ok(Nil)
                      False ->
                        Error(
                          "First-AS mismatch: route has AS"
                          <> int.to_string(first_as)
                          <> " but peer is AS"
                          <> int.to_string(expected_as),
                        )
                    }
                  }
                  _, _, _ -> Ok(Nil)
                }
              }
            }
          }
        }
      }
    }
  }
}

fn check_prepending_limit(
  asns: List(Int),
  max_prepending: Int,
) -> Result(Nil, Int) {
  case asns {
    [] -> Ok(Nil)
    [first, ..rest] -> check_prepending_loop(rest, first, 1, max_prepending)
  }
}

fn check_prepending_loop(
  remaining: List(Int),
  current_as: Int,
  count: Int,
  max_prepending: Int,
) -> Result(Nil, Int) {
  case count > max_prepending {
    True -> Error(current_as)
    False -> {
      case remaining {
        [] -> Ok(Nil)
        [next, ..rest] -> {
          case next == current_as {
            True ->
              check_prepending_loop(rest, current_as, count + 1, max_prepending)
            False -> check_prepending_loop(rest, next, 1, max_prepending)
          }
        }
      }
    }
  }
}

pub fn validate_route_hygiene(
  route: Route,
  config: RouteHygieneConfig,
  peer_as: Option(Int),
) -> Result(Route, String) {
  case config.dn42_space_only {
    True -> {
      case is_valid_dn42_space(route.prefix) {
        False ->
          Error(
            "Prefix does not belong to authorized DN42 space (172.20.0.0/14 or fd00::/8)",
          )
        True -> {
          case check_as_path_hygiene(route, config, peer_as) {
            Ok(Nil) -> Ok(route)
            Error(err) -> Error(err)
          }
        }
      }
    }
    False -> {
      case config.drop_martian_prefixes && is_bogon_prefix(route.prefix) {
        True -> Error("Prefix is an RFC 6890 martian/bogon space")
        False -> {
          case check_as_path_hygiene(route, config, peer_as) {
            Ok(Nil) -> Ok(route)
            Error(err) -> Error(err)
          }
        }
      }
    }
  }
}
