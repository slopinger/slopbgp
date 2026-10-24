import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import slopbgp/ip.{
  bytes_to_ipv4, bytes_to_ipv6, ip_to_string, is_ip_in_prefix, pad_to_bytes,
  prefix_to_string,
}
import slopbgp/types.{
  type Afi, type IpAddress, type IpPrefix, AfiIpv4, AfiIpv6, IpPrefix, Ipv4,
  Ipv6,
}

// RFC 8277: Using BGP to Distribute MPLS Label Information (BGP-LU / SAFI 4)
// Obsoletes RFC 3107

pub type MplsLabel {
  MplsLabel(value: Int, tc: Int, bottom_of_stack: Bool)
}

pub type LabeledPrefix {
  LabeledPrefix(labels: List(MplsLabel), prefix: IpPrefix)
}

pub type LabeledRoute {
  LabeledRoute(
    prefix: IpPrefix,
    labels: List(MplsLabel),
    next_hop: IpAddress,
    origin_asn: Int,
  )
}

pub type LabeledRib {
  LabeledRib(routes: List(LabeledRoute))
}

// --- Wire Encoding ---

pub fn new_mpls_label(value: Int, bottom_of_stack: Bool) -> MplsLabel {
  MplsLabel(value: value, tc: 0, bottom_of_stack: bottom_of_stack)
}

pub fn encode_mpls_label(label: MplsLabel) -> BitArray {
  let s_bit = case label.bottom_of_stack {
    True -> 1
    False -> 0
  }
  <<label.value:20, label.tc:3, s_bit:1>>
}

pub fn encode_labeled_prefix(lp: LabeledPrefix) -> BitArray {
  let num_labels = list.length(lp.labels)
  let total_len_bits = { num_labels * 24 } + lp.prefix.length

  let labels_bin =
    list.fold(lp.labels, <<>>, fn(acc, l) {
      <<acc:bits, { encode_mpls_label(l) }:bits>>
    })

  let prefix_bytes = case lp.prefix.address {
    Ipv4(a, b, c, d) -> {
      let full = <<a:8, b:8, c:8, d:8>>
      let octets = case lp.prefix.length {
        0 -> 0
        _ -> { lp.prefix.length + 7 } / 8
      }
      case bit_array.slice(full, 0, octets) {
        Ok(b) -> b
        Error(_) -> <<>>
      }
    }
    Ipv6(..) -> {
      let full = ip.ip_to_bytes(lp.prefix.address)
      let octets = case lp.prefix.length {
        0 -> 0
        _ -> { lp.prefix.length + 7 } / 8
      }
      case bit_array.slice(full, 0, octets) {
        Ok(b) -> b
        Error(_) -> <<>>
      }
    }
  }

  <<total_len_bits:8, labels_bin:bits, prefix_bytes:bits>>
}

pub fn encode_labeled_prefixes(prefixes: List(LabeledPrefix)) -> BitArray {
  list.fold(prefixes, <<>>, fn(acc, lp) {
    <<acc:bits, { encode_labeled_prefix(lp) }:bits>>
  })
}

// --- Wire Decoding ---

pub fn decode_labeled_prefix(
  afi: Afi,
  bytes: BitArray,
) -> Result(#(LabeledPrefix, BitArray), String) {
  case bytes {
    <<total_len_bits:8, rest:bits>> -> {
      use #(labels, rem1) <- result.try(decode_label_stack(rest, []))
      let num_labels = list.length(labels)
      let label_bits = num_labels * 24

      case total_len_bits >= label_bits {
        False ->
          Error(
            "Total length bits ("
            <> int.to_string(total_len_bits)
            <> ") smaller than label stack ("
            <> int.to_string(label_bits)
            <> ")",
          )
        True -> {
          let prefix_len = total_len_bits - label_bits
          let octets_needed = case prefix_len {
            0 -> 0
            _ -> { prefix_len + 7 } / 8
          }

          use #(prefix_raw, rem2) <- result.try(
            split_bytes(rem1, octets_needed)
            |> result.replace_error("Truncated prefix octets in labeled NLRI"),
          )

          use ip_addr <- result.try(case afi {
            AfiIpv4 -> {
              let padded = pad_to_bytes(prefix_raw, 4)
              bytes_to_ipv4(padded)
            }
            AfiIpv6 -> {
              let padded = pad_to_bytes(prefix_raw, 16)
              bytes_to_ipv6(padded)
            }
            _ -> {
              case prefix_len <= 32 {
                True -> {
                  let padded = pad_to_bytes(prefix_raw, 4)
                  bytes_to_ipv4(padded)
                }
                False -> {
                  let padded = pad_to_bytes(prefix_raw, 16)
                  bytes_to_ipv6(padded)
                }
              }
            }
          })

          let lp =
            LabeledPrefix(
              labels: labels,
              prefix: IpPrefix(address: ip_addr, length: prefix_len),
            )
          Ok(#(lp, rem2))
        }
      }
    }
    _ -> Error("Truncated labeled prefix header")
  }
}

fn decode_label_stack(
  bytes: BitArray,
  acc: List(MplsLabel),
) -> Result(#(List(MplsLabel), BitArray), String) {
  case bytes {
    <<val:20, tc:3, s_bit:1, rem:bits>> -> {
      let is_bos = s_bit == 1
      let label = MplsLabel(value: val, tc: tc, bottom_of_stack: is_bos)
      let new_acc = [label, ..acc]
      case is_bos {
        True -> Ok(#(list.reverse(new_acc), rem))
        False -> decode_label_stack(rem, new_acc)
      }
    }
    _ -> Error("Truncated or missing Bottom-of-Stack in MPLS label stack")
  }
}

pub fn decode_labeled_stream(
  afi: Afi,
  bytes: BitArray,
) -> Result(List(LabeledPrefix), String) {
  decode_labeled_stream_loop(afi, bytes, [])
}

fn decode_labeled_stream_loop(
  afi: Afi,
  bytes: BitArray,
  acc: List(LabeledPrefix),
) -> Result(List(LabeledPrefix), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(lp, rest) <- result.try(decode_labeled_prefix(afi, bytes))
      decode_labeled_stream_loop(afi, rest, [lp, ..acc])
    }
  }
}

// --- Labeled RIB Operations ---

pub fn new_labeled_rib() -> LabeledRib {
  LabeledRib(routes: [])
}

pub fn insert_labeled_route(
  rib: LabeledRib,
  route: LabeledRoute,
) -> LabeledRib {
  let other_routes =
    list.filter(rib.routes, fn(r) {
      !{ r.prefix == route.prefix && r.origin_asn == route.origin_asn }
    })
  LabeledRib(routes: [route, ..other_routes])
}

pub fn remove_labeled_route(
  rib: LabeledRib,
  prefix: IpPrefix,
  origin_asn: Int,
) -> LabeledRib {
  LabeledRib(
    routes: list.filter(rib.routes, fn(r) {
      !{ r.prefix == prefix && r.origin_asn == origin_asn }
    }),
  )
}

fn split_bytes(bytes: BitArray, n: Int) -> Result(#(BitArray, BitArray), Nil) {
  case n <= bit_array.byte_size(bytes) {
    True -> {
      let rem_len = bit_array.byte_size(bytes) - n
      case bit_array.slice(bytes, 0, n), bit_array.slice(bytes, n, rem_len) {
        Ok(prefix), Ok(rest) -> Ok(#(prefix, rest))
        _, _ -> Error(Nil)
      }
    }
    False -> Error(Nil)
  }
}

pub fn lookup_labeled_route(
  rib: LabeledRib,
  target_ip: IpAddress,
) -> Option(LabeledRoute) {
  let matches =
    list.filter(rib.routes, fn(r) { is_ip_in_prefix(target_ip, r.prefix) })

  // Longest Prefix Match
  let sorted =
    list.sort(matches, fn(a, b) {
      int.compare(b.prefix.length, a.prefix.length)
    })

  list.first(sorted) |> option.from_result
}

pub fn labeled_route_to_string(r: LabeledRoute) -> String {
  let p_str = prefix_to_string(r.prefix)
  let nh_str = ip_to_string(r.next_hop)
  let labels_str =
    list.map(r.labels, fn(l) { int.to_string(l.value) })
    |> list.fold("", fn(acc, s) {
      case acc {
        "" -> s
        _ -> acc <> "/" <> s
      }
    })
  p_str <> " -> NextHop: " <> nh_str <> " [MPLS: " <> labels_str <> "]"
}
