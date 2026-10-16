import gleam/bit_array
import gleam/float
import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/string
import slopbgp/ip.{decode_single_prefix, encode_prefix, prefix_to_string}
import slopbgp/types.{
  type Afi, type ExtendedCommunity, type FlowspecAction, type FlowspecComponent,
  type FlowspecRule, ExtCommunity, FlowActionDrop, FlowActionMarkDscp,
  FlowActionRateLimit, FlowActionRedirect, FlowActionSample, FlowDscp,
  FlowDstPort, FlowDstPrefix, FlowIcmpCode, FlowIcmpType, FlowIpProtocol,
  FlowPacketLength, FlowPort, FlowSrcPort, FlowSrcPrefix, FlowTcpFlags,
}

// RFC 5575 / RFC 8955 Flowspec Component Type Codes
pub const type_dst_prefix = 1

pub const type_src_prefix = 2

pub const type_ip_protocol = 3

pub const type_port = 4

pub const type_dst_port = 5

pub const type_src_port = 6

pub const type_icmp_type = 7

pub const type_icmp_code = 8

pub const type_tcp_flags = 9

pub const type_packet_length = 10

pub const type_dscp = 11

pub const type_fragment = 12

// Flowspec Extended Community Sub-Types (Type 0x80)
pub const ext_sub_traffic_rate = 0x06

pub const ext_sub_traffic_action = 0x07

pub const ext_sub_redirect = 0x08

pub const ext_sub_traffic_marking = 0x09

/// Encode a Flowspec component into wire binary
pub fn encode_component(comp: FlowspecComponent) -> BitArray {
  case comp {
    FlowDstPrefix(pfx) -> {
      let pfx_bin = encode_prefix(pfx, None)
      <<type_dst_prefix:8, pfx_bin:bits>>
    }
    FlowSrcPrefix(pfx) -> {
      let pfx_bin = encode_prefix(pfx, None)
      <<type_src_prefix:8, pfx_bin:bits>>
    }
    FlowIpProtocol(op, val) -> {
      // numeric operator byte: end-of-list (0x80) | op (e.g. 0x01 == EQ) | length (0x00 for 1-byte)
      let op_byte = int.bitwise_or(0x81, op)
      <<type_ip_protocol:8, op_byte:8, val:8>>
    }
    FlowPort(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_port:8, op_byte:8, val:16>>
    }
    FlowDstPort(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_dst_port:8, op_byte:8, val:16>>
    }
    FlowSrcPort(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_src_port:8, op_byte:8, val:16>>
    }
    FlowIcmpType(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_icmp_type:8, op_byte:8, val:8>>
    }
    FlowIcmpCode(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_icmp_code:8, op_byte:8, val:8>>
    }
    FlowTcpFlags(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_tcp_flags:8, op_byte:8, val:8>>
    }
    FlowPacketLength(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_packet_length:8, op_byte:8, val:16>>
    }
    FlowDscp(op, val) -> {
      let op_byte = int.bitwise_or(0x81, op)
      <<type_dscp:8, op_byte:8, val:8>>
    }
  }
}

/// Encode full Flowspec NLRI with length prefix
pub fn encode_flowspec_nlri(components: List(FlowspecComponent)) -> BitArray {
  let payload =
    list.map(components, encode_component)
    |> list.fold(<<>>, bit_array.append)
  let len = bit_array.byte_size(payload)
  case len < 240 {
    True -> <<len:8, payload:bits>>
    False -> {
      // RFC 5575 extended length encoding: 2-octet length with high bit set
      let high_len = int.bitwise_or(0xf000, len)
      <<high_len:16, payload:bits>>
    }
  }
}

/// Decode Flowspec NLRI components from binary
pub fn decode_flowspec_nlri(
  data: BitArray,
  afi: Afi,
) -> Result(List(FlowspecComponent), String) {
  decode_components_loop(data, afi, [])
}

fn decode_components_loop(
  data: BitArray,
  afi: Afi,
  acc: List(FlowspecComponent),
) -> Result(List(FlowspecComponent), String) {
  case data {
    <<>> -> Ok(list.reverse(acc))
    <<type_code:8, rest:bits>> -> {
      case type_code {
        1 -> {
          // Destination Prefix
          case decode_single_prefix(rest, afi) {
            Ok(#(pfx, remaining)) ->
              decode_components_loop(remaining, afi, [FlowDstPrefix(pfx), ..acc])
            Error(err) -> Error("Flowspec decode dst prefix failed: " <> err)
          }
        }
        2 -> {
          // Source Prefix
          case decode_single_prefix(rest, afi) {
            Ok(#(pfx, remaining)) ->
              decode_components_loop(remaining, afi, [FlowSrcPrefix(pfx), ..acc])
            Error(err) -> Error("Flowspec decode src prefix failed: " <> err)
          }
        }
        3 -> {
          // IP Protocol
          case rest {
            <<op:8, proto:8, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowIpProtocol(op, proto),
                ..acc
              ])
            _ -> Error("Truncated Flowspec IP protocol component")
          }
        }
        4 -> {
          // Port
          case rest {
            <<op:8, port:16, remaining:bits>> ->
              decode_components_loop(remaining, afi, [FlowPort(op, port), ..acc])
            _ -> Error("Truncated Flowspec port component")
          }
        }
        5 -> {
          // Destination Port
          case rest {
            <<op:8, port:16, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowDstPort(op, port),
                ..acc
              ])
            _ -> Error("Truncated Flowspec dst port component")
          }
        }
        6 -> {
          // Source Port
          case rest {
            <<op:8, port:16, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowSrcPort(op, port),
                ..acc
              ])
            _ -> Error("Truncated Flowspec src port component")
          }
        }
        7 -> {
          // ICMP Type
          case rest {
            <<op:8, icmp_t:8, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowIcmpType(op, icmp_t),
                ..acc
              ])
            _ -> Error("Truncated Flowspec ICMP type component")
          }
        }
        8 -> {
          // ICMP Code
          case rest {
            <<op:8, icmp_c:8, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowIcmpCode(op, icmp_c),
                ..acc
              ])
            _ -> Error("Truncated Flowspec ICMP code component")
          }
        }
        9 -> {
          // TCP Flags
          case rest {
            <<op:8, flags:8, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowTcpFlags(op, flags),
                ..acc
              ])
            _ -> Error("Truncated Flowspec TCP flags component")
          }
        }
        10 -> {
          // Packet Length
          case rest {
            <<op:8, len:16, remaining:bits>> ->
              decode_components_loop(remaining, afi, [
                FlowPacketLength(op, len),
                ..acc
              ])
            _ -> Error("Truncated Flowspec packet length component")
          }
        }
        11 -> {
          // DSCP
          case rest {
            <<op:8, dscp:8, remaining:bits>> ->
              decode_components_loop(remaining, afi, [FlowDscp(op, dscp), ..acc])
            _ -> Error("Truncated Flowspec DSCP component")
          }
        }
        _ ->
          Error(
            "Unsupported Flowspec component type: " <> int.to_string(type_code),
          )
      }
    }
    _ -> Error("Malformed Flowspec NLRI binary")
  }
}

/// Encode Flowspec Action into BGP Extended Community
pub fn encode_action_community(
  action: FlowspecAction,
  asn: Int,
) -> ExtendedCommunity {
  case action {
    FlowActionDrop -> {
      // Traffic-rate 0 bytes/sec
      ExtCommunity(0x80, ext_sub_traffic_rate, <<asn:16, 0.0:float-32>>)
    }
    FlowActionRateLimit(rate) -> {
      ExtCommunity(0x80, ext_sub_traffic_rate, <<asn:16, rate:float-32>>)
    }
    FlowActionSample -> {
      ExtCommunity(0x80, ext_sub_traffic_action, <<0:32, 0x02:16>>)
    }
    FlowActionMarkDscp(dscp) -> {
      ExtCommunity(0x80, ext_sub_traffic_marking, <<0:40, dscp:8>>)
    }
    FlowActionRedirect(target_as, target) -> {
      ExtCommunity(0x80, ext_sub_redirect, <<target_as:16, target:32>>)
    }
  }
}

/// Decode Flowspec Action from BGP Extended Community
pub fn decode_action_community(
  ext: ExtendedCommunity,
) -> Result(FlowspecAction, Nil) {
  case ext.type_code, ext.sub_type {
    0x80, 0x06 -> {
      // Traffic-rate
      case ext.value {
        <<_asn:16, rate:float-32>> -> {
          case rate == 0.0 {
            True -> Ok(FlowActionDrop)
            False -> Ok(FlowActionRateLimit(rate))
          }
        }
        _ -> Error(Nil)
      }
    }
    0x80, 0x07 -> Ok(FlowActionSample)
    0x80, 0x09 -> {
      case ext.value {
        <<_:40, dscp:8>> -> Ok(FlowActionMarkDscp(dscp))
        _ -> Error(Nil)
      }
    }
    0x80, 0x08 -> {
      case ext.value {
        <<target_as:16, target:32>> -> Ok(FlowActionRedirect(target_as, target))
        _ -> Error(Nil)
      }
    }
    _, _ -> Error(Nil)
  }
}

/// Convert Flowspec Rule into human-readable description
pub fn format_rule(rule: FlowspecRule) -> String {
  let comps_str =
    list.map(rule.components, fn(c) {
      case c {
        FlowDstPrefix(pfx) -> "dst " <> prefix_to_string(pfx)
        FlowSrcPrefix(pfx) -> "src " <> prefix_to_string(pfx)
        FlowIpProtocol(_op, proto) -> {
          let name = case proto {
            6 -> "tcp"
            17 -> "udp"
            1 -> "icmp"
            _ -> int.to_string(proto)
          }
          "proto " <> name
        }
        FlowPort(_op, p) -> "port " <> int.to_string(p)
        FlowDstPort(_op, p) -> "dport " <> int.to_string(p)
        FlowSrcPort(_op, p) -> "sport " <> int.to_string(p)
        FlowIcmpType(_op, t) -> "icmp-type " <> int.to_string(t)
        FlowIcmpCode(_op, c) -> "icmp-code " <> int.to_string(c)
        FlowTcpFlags(_op, f) -> "tcp-flags 0x" <> int.to_base16(f)
        FlowPacketLength(_op, l) -> "length " <> int.to_string(l)
        FlowDscp(_op, d) -> "dscp " <> int.to_string(d)
      }
    })
    |> string.join(" ")

  let actions_str =
    list.map(rule.actions, fn(a) {
      case a {
        FlowActionDrop -> "DROP"
        FlowActionRateLimit(r) -> "RATE_LIMIT " <> float.to_string(r) <> " B/s"
        FlowActionSample -> "SAMPLE"
        FlowActionMarkDscp(d) -> "MARK_DSCP " <> int.to_string(d)
        FlowActionRedirect(asn, tgt) ->
          "REDIRECT AS" <> int.to_string(asn) <> ":" <> int.to_string(tgt)
      }
    })
    |> string.join(", ")

  comps_str <> " -> " <> actions_str
}

/// Generate Linux nftables rule snippet from a Flowspec rule
pub fn to_nftables_rule(rule: FlowspecRule) -> String {
  let parts =
    list.filter_map(rule.components, fn(c) {
      case c {
        FlowDstPrefix(pfx) -> Ok("ip daddr " <> prefix_to_string(pfx))
        FlowSrcPrefix(pfx) -> Ok("ip saddr " <> prefix_to_string(pfx))
        FlowIpProtocol(_op, 6) -> Ok("ip protocol tcp")
        FlowIpProtocol(_op, 17) -> Ok("ip protocol udp")
        FlowIpProtocol(_op, 1) -> Ok("ip protocol icmp")
        FlowIpProtocol(_op, other) -> Ok("ip protocol " <> int.to_string(other))
        FlowDstPort(_op, p) -> Ok("th dport " <> int.to_string(p))
        FlowSrcPort(_op, p) -> Ok("th sport " <> int.to_string(p))
        _ -> Error(Nil)
      }
    })
    |> string.join(" ")

  let action = case rule.actions {
    [FlowActionDrop, ..] -> "drop"
    [FlowActionRateLimit(r), ..] ->
      "limit rate over "
      <> int.to_string(float.truncate(r))
      <> " bytes/second drop"
    _ -> "drop"
  }

  "nft add rule inet filter input " <> parts <> " " <> action
}
