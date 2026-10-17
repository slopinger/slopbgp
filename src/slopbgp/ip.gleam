import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import slopbgp/types.{
  type Afi, type IpAddress, type IpPrefix, AfiIpv4, IpPrefix, Ipv4, Ipv6,
}

pub fn ipv4_to_string(ip: IpAddress) -> String {
  case ip {
    Ipv4(a, b, c, d) ->
      int.to_string(a)
      <> "."
      <> int.to_string(b)
      <> "."
      <> int.to_string(c)
      <> "."
      <> int.to_string(d)
    Ipv6(_, _, _, _, _, _, _, _) -> ipv6_to_string(ip)
  }
}

pub fn is_ipv6(ip: IpAddress) -> Bool {
  case ip {
    Ipv6(_, _, _, _, _, _, _, _) -> True
    _ -> False
  }
}

pub fn is_ipv6_prefix(prefix: IpPrefix) -> Bool {
  is_ipv6(prefix.address)
}

pub fn ipv6_to_string(ip: IpAddress) -> String {
  case ip {
    Ipv6(a, b, c, d, e, f, g, h) -> {
      let parts = [
        int.to_base16(a),
        int.to_base16(b),
        int.to_base16(c),
        int.to_base16(d),
        int.to_base16(e),
        int.to_base16(f),
        int.to_base16(g),
        int.to_base16(h),
      ]
      string.lowercase(string.join(parts, ":"))
    }
    Ipv4(_, _, _, _) -> ipv4_to_string(ip)
  }
}

pub fn ip_to_string(ip: IpAddress) -> String {
  case ip {
    Ipv4(_, _, _, _) -> ipv4_to_string(ip)
    Ipv6(_, _, _, _, _, _, _, _) -> ipv6_to_string(ip)
  }
}

pub fn parse_ipv4(str: String) -> Result(IpAddress, String) {
  let parts = string.split(string.trim(str), ".")
  case parts {
    [a_str, b_str, c_str, d_str] -> {
      use a <- result.try(
        int.parse(a_str)
        |> result.replace_error("Invalid IPv4 octet: " <> a_str),
      )
      use b <- result.try(
        int.parse(b_str)
        |> result.replace_error("Invalid IPv4 octet: " <> b_str),
      )
      use c <- result.try(
        int.parse(c_str)
        |> result.replace_error("Invalid IPv4 octet: " <> c_str),
      )
      use d <- result.try(
        int.parse(d_str)
        |> result.replace_error("Invalid IPv4 octet: " <> d_str),
      )
      case
        a >= 0
        && a <= 255
        && b >= 0
        && b <= 255
        && c >= 0
        && c <= 255
        && d >= 0
        && d <= 255
      {
        True -> Ok(Ipv4(a, b, c, d))
        False -> Error("IPv4 octet out of 0..255 range: " <> str)
      }
    }
    _ -> Error("Invalid IPv4 address format: " <> str)
  }
}

pub fn parse_ipv6(str: String) -> Result(IpAddress, String) {
  let trimmed = string.trim(str)
  let is_double_colon = string.contains(trimmed, "::")
  case is_double_colon {
    True -> {
      let halves = string.split(trimmed, "::")
      case halves {
        [left, right] -> {
          let left_parts = case left {
            "" -> []
            _ -> string.split(left, ":")
          }
          let right_parts = case right {
            "" -> []
            _ -> string.split(right, ":")
          }
          let missing_count =
            8 - list.length(left_parts) - list.length(right_parts)
          case missing_count >= 0 {
            True -> {
              let zeros = list.repeat("0", missing_count)
              let all_parts = list.flatten([left_parts, zeros, right_parts])
              parse_ipv6_parts(all_parts)
            }
            False -> Error("Too many parts in IPv6 address: " <> str)
          }
        }
        _ -> Error("Multiple '::' not allowed in IPv6: " <> str)
      }
    }
    False -> {
      let parts = string.split(trimmed, ":")
      case list.length(parts) == 8 {
        True -> parse_ipv6_parts(parts)
        False -> Error("IPv6 address must have 8 groups: " <> str)
      }
    }
  }
}

fn parse_ipv6_parts(parts: List(String)) -> Result(IpAddress, String) {
  case parts {
    [p0, p1, p2, p3, p4, p5, p6, p7] -> {
      use a <- result.try(parse_hex_group(p0))
      use b <- result.try(parse_hex_group(p1))
      use c <- result.try(parse_hex_group(p2))
      use d <- result.try(parse_hex_group(p3))
      use e <- result.try(parse_hex_group(p4))
      use f <- result.try(parse_hex_group(p5))
      use g <- result.try(parse_hex_group(p6))
      use h <- result.try(parse_hex_group(p7))
      Ok(Ipv6(a, b, c, d, e, f, g, h))
    }
    _ -> Error("Expected 8 hex groups for IPv6")
  }
}

fn parse_hex_group(group: String) -> Result(Int, String) {
  case int.base_parse(group, 16) {
    Ok(val) if val >= 0 && val <= 65_535 -> Ok(val)
    _ -> Error("Invalid 16-bit hex group: " <> group)
  }
}

pub fn parse_ip(str: String) -> Result(IpAddress, String) {
  case string.contains(str, ":") {
    True -> parse_ipv6(str)
    False -> parse_ipv4(str)
  }
}

pub fn prefix_to_string(prefix: IpPrefix) -> String {
  ip_to_string(prefix.address) <> "/" <> int.to_string(prefix.length)
}

pub fn parse_prefix(str: String) -> Result(IpPrefix, String) {
  case string.split(string.trim(str), "/") {
    [ip_str, len_str] -> {
      use ip <- result.try(parse_ip(ip_str))
      use len <- result.try(
        int.parse(len_str)
        |> result.replace_error("Invalid prefix length: " <> len_str),
      )
      case ip {
        Ipv4(_, _, _, _) if len >= 0 && len <= 32 ->
          Ok(IpPrefix(normalize_ipv4(ip, len), len))
        Ipv6(_, _, _, _, _, _, _, _) if len >= 0 && len <= 128 ->
          Ok(IpPrefix(normalize_ipv6(ip, len), len))
        _ -> Error("Prefix length out of range: " <> str)
      }
    }
    _ -> Error("Invalid CIDR prefix format: " <> str)
  }
}

pub fn ipv4_to_int(ip: IpAddress) -> Int {
  case ip {
    Ipv4(a, b, c, d) -> {
      a * 16_777_216 + b * 65_536 + c * 256 + d
    }
    Ipv6(_, _, _, _, _, _, _, _) -> 0
  }
}

pub fn int_to_ipv4(val: Int) -> IpAddress {
  let a = val / 16_777_216 % 256
  let b = val / 65_536 % 256
  let c = val / 256 % 256
  let d = val % 256
  Ipv4(a, b, c, d)
}

pub fn normalize_ipv4(ip: IpAddress, len: Int) -> IpAddress {
  case ip {
    Ipv4(_, _, _, _) -> {
      let ip_int = ipv4_to_int(ip)
      let mask = case len {
        0 -> 0
        32 -> 4_294_967_295
        _ -> {
          let shift = 32 - len
          let inv_mask = int_pow2(shift) - 1
          4_294_967_295 - inv_mask
        }
      }
      int_to_ipv4(int.bitwise_and(ip_int, mask))
    }
    _ -> ip
  }
}

pub fn normalize_ipv6(ip: IpAddress, len: Int) -> IpAddress {
  case ip {
    Ipv6(a, b, c, d, e, f, g, h) -> {
      let groups = [a, b, c, d, e, f, g, h]
      let norm =
        list.index_map(groups, fn(group, idx) {
          let bit_start = idx * 16
          let bit_end = bit_start + 16
          case len <= bit_start {
            True -> 0
            False ->
              case len >= bit_end {
                True -> group
                False -> {
                  let bits_in_group = len - bit_start
                  let shift = 16 - bits_in_group
                  let inv_mask = int_pow2(shift) - 1
                  let mask = 65_535 - inv_mask
                  int.bitwise_and(group, mask)
                }
              }
          }
        })
      case norm {
        [na, nb, nc, nd, ne, nf, ng, nh] -> Ipv6(na, nb, nc, nd, ne, nf, ng, nh)
        _ -> ip
      }
    }
    _ -> ip
  }
}

fn int_pow2(exponent: Int) -> Int {
  case exponent <= 0 {
    True -> 1
    False -> 2 * int_pow2(exponent - 1)
  }
}

pub fn is_prefix_contained(child: IpPrefix, parent: IpPrefix) -> Bool {
  case child.address, parent.address {
    Ipv4(_, _, _, _), Ipv4(_, _, _, _) -> {
      case child.length >= parent.length {
        False -> False
        True -> {
          let parent_norm = normalize_ipv4(child.address, parent.length)
          parent_norm == parent.address
        }
      }
    }
    Ipv6(_, _, _, _, _, _, _, _), Ipv6(_, _, _, _, _, _, _, _) -> {
      case child.length >= parent.length {
        False -> False
        True -> {
          let parent_norm = normalize_ipv6(child.address, parent.length)
          parent_norm == parent.address
        }
      }
    }
    _, _ -> False
  }
}

pub fn ip_to_bytes(ip: IpAddress) -> BitArray {
  case ip {
    Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
    Ipv6(a, b, c, d, e, f, g, h) -> <<
      a:16,
      b:16,
      c:16,
      d:16,
      e:16,
      f:16,
      g:16,
      h:16,
    >>
  }
}

pub fn bytes_to_ipv4(bytes: BitArray) -> Result(IpAddress, String) {
  case bytes {
    <<a:8, b:8, c:8, d:8>> -> Ok(Ipv4(a, b, c, d))
    _ -> Error("Expected 4 bytes for IPv4")
  }
}

pub fn bytes_to_ipv6(bytes: BitArray) -> Result(IpAddress, String) {
  case bytes {
    <<a:16, b:16, c:16, d:16, e:16, f:16, g:16, h:16>> ->
      Ok(Ipv6(a, b, c, d, e, f, g, h))
    _ -> Error("Expected 16 bytes for IPv6")
  }
}

pub fn encode_prefix(prefix: IpPrefix, path_id: Option(Int)) -> BitArray {
  let path_id_bytes = case path_id {
    Some(id) -> <<id:32>>
    None -> <<>>
  }
  let len = prefix.length
  let octets_needed = case len {
    0 -> 0
    _ -> { len + 7 } / 8
  }
  let full_bytes = ip_to_bytes(prefix.address)
  let prefix_octets = extract_first_bytes(full_bytes, octets_needed)
  <<path_id_bytes:bits, len:8, prefix_octets:bits>>
}

pub fn decode_prefixes_ipv4(
  bytes: BitArray,
  has_path_id: Bool,
) -> Result(List(#(IpPrefix, Option(Int))), String) {
  decode_prefixes_ipv4_loop(bytes, has_path_id, [])
}

fn decode_prefixes_ipv4_loop(
  bytes: BitArray,
  has_path_id: Bool,
  acc: List(#(IpPrefix, Option(Int))),
) -> Result(List(#(IpPrefix, Option(Int))), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(path_id, rest1) <- result.try(case has_path_id {
        True ->
          case bytes {
            <<id:32, rem:bits>> -> Ok(#(Some(id), rem))
            _ -> Error("Truncated Path ID in NLRI")
          }
        False -> Ok(#(None, bytes))
      })

      case rest1 {
        <<len:8, rest2:bits>> if len <= 32 -> {
          let octets_needed = case len {
            0 -> 0
            _ -> { len + 7 } / 8
          }
          use #(prefix_bytes, rem) <- result.try(
            split_bytes(rest2, octets_needed)
            |> result.replace_error("Truncated IPv4 prefix bits in NLRI"),
          )
          let padded_bytes = pad_to_bytes(prefix_bytes, 4)
          use ip <- result.try(bytes_to_ipv4(padded_bytes))
          let normalized = normalize_ipv4(ip, len)
          let prefix = IpPrefix(normalized, len)
          decode_prefixes_ipv4_loop(rem, has_path_id, [
            #(prefix, path_id),
            ..acc
          ])
        }
        _ -> Error("Invalid IPv4 prefix length in NLRI")
      }
    }
  }
}

pub fn decode_prefixes_ipv6(
  bytes: BitArray,
  has_path_id: Bool,
) -> Result(List(#(IpPrefix, Option(Int))), String) {
  decode_prefixes_ipv6_loop(bytes, has_path_id, [])
}

fn decode_prefixes_ipv6_loop(
  bytes: BitArray,
  has_path_id: Bool,
  acc: List(#(IpPrefix, Option(Int))),
) -> Result(List(#(IpPrefix, Option(Int))), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(path_id, rest1) <- result.try(case has_path_id {
        True ->
          case bytes {
            <<id:32, rem:bits>> -> Ok(#(Some(id), rem))
            _ -> Error("Truncated Path ID in IPv6 NLRI")
          }
        False -> Ok(#(None, bytes))
      })

      case rest1 {
        <<len:8, rest2:bits>> if len <= 128 -> {
          let octets_needed = case len {
            0 -> 0
            _ -> { len + 7 } / 8
          }
          use #(prefix_bytes, rem) <- result.try(
            split_bytes(rest2, octets_needed)
            |> result.replace_error("Truncated IPv6 prefix bits in NLRI"),
          )
          let padded_bytes = pad_to_bytes(prefix_bytes, 16)
          use ip <- result.try(bytes_to_ipv6(padded_bytes))
          let normalized = normalize_ipv6(ip, len)
          let prefix = IpPrefix(normalized, len)
          decode_prefixes_ipv6_loop(rem, has_path_id, [
            #(prefix, path_id),
            ..acc
          ])
        }
        _ -> Error("Invalid IPv6 prefix length in NLRI")
      }
    }
  }
}

pub fn decode_single_prefix(
  bytes: BitArray,
  afi: Afi,
) -> Result(#(IpPrefix, BitArray), String) {
  case afi {
    AfiIpv4 -> {
      case bytes {
        <<len:8, rest:bits>> if len <= 32 -> {
          let octets_needed = case len {
            0 -> 0
            _ -> { len + 7 } / 8
          }
          use #(prefix_bytes, rem) <- result.try(
            split_bytes(rest, octets_needed)
            |> result.replace_error("Truncated IPv4 prefix in NLRI"),
          )
          let padded_bytes = pad_to_bytes(prefix_bytes, 4)
          use ip <- result.try(bytes_to_ipv4(padded_bytes))
          let normalized = normalize_ipv4(ip, len)
          Ok(#(IpPrefix(normalized, len), rem))
        }
        _ -> Error("Invalid IPv4 prefix in NLRI")
      }
    }
    _ -> {
      case bytes {
        <<len:8, rest:bits>> if len <= 128 -> {
          let octets_needed = case len {
            0 -> 0
            _ -> { len + 7 } / 8
          }
          use #(prefix_bytes, rem) <- result.try(
            split_bytes(rest, octets_needed)
            |> result.replace_error("Truncated IPv6 prefix in NLRI"),
          )
          let padded_bytes = pad_to_bytes(prefix_bytes, 16)
          use ip <- result.try(bytes_to_ipv6(padded_bytes))
          let normalized = normalize_ipv6(ip, len)
          Ok(#(IpPrefix(normalized, len), rem))
        }
        _ -> Error("Invalid IPv6 prefix in NLRI")
      }
    }
  }
}

fn extract_first_bytes(bytes: BitArray, n: Int) -> BitArray {
  case split_bytes(bytes, n) {
    Ok(#(first, _)) -> first
    Error(_) -> bytes
  }
}

fn split_bytes(bytes: BitArray, n: Int) -> Result(#(BitArray, BitArray), Nil) {
  case n <= 0 {
    True -> Ok(#(<<>>, bytes))
    False -> {
      let bits_needed = n * 8
      case bytes {
        <<chunk:bits-size(bits_needed), rest:bits>> -> Ok(#(chunk, rest))
        _ -> Error(Nil)
      }
    }
  }
}

pub fn pad_to_bytes(bytes: BitArray, target_len: Int) -> BitArray {
  let curr_len = bit_size_in_bytes(bytes)
  case curr_len >= target_len {
    True -> bytes
    False -> {
      let missing = target_len - curr_len
      let pad = make_zero_bytes(missing)
      <<bytes:bits, pad:bits>>
    }
  }
}

fn bit_size_in_bytes(bytes: BitArray) -> Int {
  case bytes {
    <<_:8, rest:bits>> -> 1 + bit_size_in_bytes(rest)
    _ -> 0
  }
}

fn make_zero_bytes(n: Int) -> BitArray {
  case n <= 0 {
    True -> <<>>
    False -> <<0:8, make_zero_bytes(n - 1):bits>>
  }
}
