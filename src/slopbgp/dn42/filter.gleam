import gleam/list
import slopbgp/ip.{is_prefix_contained, parse_prefix}
import slopbgp/types.{type IpPrefix, Ipv4, Ipv6}

pub fn is_valid_dn42_network(prefix: IpPrefix) -> Bool {
  case prefix.address {
    Ipv4(172, b, _, _) if b >= 20 && b <= 23 -> {
      // Standard DN42 range: 172.20.0.0/14
      // Anycast ranges 172.20.0.0/24 .. 172.23.0.0/24 can be /28 to /32
      // Standard allocations are /21 to /29
      case prefix.length >= 21 && prefix.length <= 29 {
        True -> True
        False -> prefix.length >= 28 && prefix.length <= 32
      }
    }
    Ipv4(172, 31, _, _) -> prefix.length >= 16 && prefix.length <= 28
    Ipv4(10, 100, _, _) -> prefix.length >= 14 && prefix.length <= 28
    Ipv4(10, 127, _, _) -> prefix.length >= 16 && prefix.length <= 28
    Ipv4(10, _, _, _) -> prefix.length >= 15 && prefix.length <= 24
    Ipv6(first, _, _, _, _, _, _, _) -> {
      // ULA: fd00::/8 with length between 44 and 64
      let is_fd = first / 256 == 0xFD
      is_fd && prefix.length >= 44 && prefix.length <= 64
    }
    _ -> False
  }
}

pub fn is_bogon(prefix: IpPrefix) -> Bool {
  case prefix.address {
    Ipv4(0, 0, 0, 0) if prefix.length == 0 -> True
    Ipv4(127, _, _, _) -> True
    Ipv4(169, 254, _, _) -> True
    Ipv4(a, _, _, _) if a >= 224 -> True
    Ipv6(0, 0, 0, 0, 0, 0, 0, 0) if prefix.length == 0 -> True
    Ipv6(0, 0, 0, 0, 0, 0, 0, 1) if prefix.length == 128 -> True
    Ipv6(a, _, _, _, _, _, _, _) if a >= 0xFE80 && a <= 0xFEBF -> True
    Ipv6(a, _, _, _, _, _, _, _) if a >= 0xFF00 -> True
    _ -> False
  }
}

pub fn is_self_network(prefix: IpPrefix, own_prefixes: List(IpPrefix)) -> Bool {
  list.any(own_prefixes, fn(own) { is_prefix_contained(prefix, own) })
}

pub fn default_dn42_own_prefixes() -> List(IpPrefix) {
  let p4 = case parse_prefix("172.22.64.128/27") {
    Ok(p) -> [p]
    Error(_) -> []
  }
  let p6 = case parse_prefix("fdd4:af47:dcfa::/48") {
    Ok(p) -> [p]
    Error(_) -> []
  }
  list.append(p4, p6)
}
