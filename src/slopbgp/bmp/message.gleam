import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import slopbgp/ip.{bytes_to_ipv4, bytes_to_ipv6, ip_to_bytes, is_ipv6}
import slopbgp/types.{
  type BmpMessage, type BmpPeerHeader, type BmpStatCounter, BmpMsgInitiation,
  BmpMsgPeerDown, BmpMsgPeerUp, BmpMsgRouteMonitoring, BmpMsgStatsReport,
  BmpMsgTermination, BmpPeerHeader, BmpStatCounter, Ipv4,
}

// RFC 7854 BGP Monitoring Protocol (BMP) Version 3
pub const bmp_version = 3

pub const type_route_monitoring = 0

pub const type_statistics_report = 1

pub const type_peer_down = 2

pub const type_peer_up = 3

pub const type_initiation = 4

pub const type_termination = 5

// Initiation Information Types
pub const init_info_string = 0

pub const init_sys_descr = 1

pub const init_sys_name = 2

// Termination Information Types
pub const term_info_string = 0

pub const term_info_reason = 1

// Stat Report Counter Types (RFC 7854 Section 4.8)
pub const stat_rejected_prefixes = 0

pub const stat_duplicate_prefixes = 1

pub const stat_duplicate_withdraws = 2

pub const stat_invalid_cluster_list = 3

pub const stat_adj_rib_in_routes = 7

pub const stat_loc_rib_routes = 8

/// Encode a BmpPeerHeader into 42-octet wire binary
pub fn encode_peer_header(peer: BmpPeerHeader) -> BitArray {
  let v_flag = case peer.is_ipv6 {
    True -> 0x80
    False -> 0x00
  }
  let l_flag = case peer.is_post_policy {
    True -> 0x40
    False -> 0x00
  }
  let flags = int.bitwise_or(v_flag, l_flag)

  let peer_dist = case bit_array.byte_size(peer.peer_distinguisher) {
    8 -> peer.peer_distinguisher
    _ -> <<0:64>>
  }

  let addr_bytes = case peer.peer_ip {
    Ipv4(a, b, c, d) -> <<0:80, 0xFFFF:16, a:8, b:8, c:8, d:8>>
    _ -> ip_to_bytes(peer.peer_ip)
  }

  let id_bytes = case peer.peer_bgp_id {
    Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
    _ -> <<0:32>>
  }

  <<
    peer.peer_type:8,
    flags:8,
    peer_dist:bits-size(64),
    addr_bytes:bits-size(128),
    peer.peer_as:32,
    id_bytes:bits-size(32),
    peer.timestamp_sec:32,
    peer.timestamp_usec:32,
  >>
}

/// Decode a 42-octet BmpPeerHeader
pub fn decode_peer_header(
  bytes: BitArray,
) -> Result(#(BmpPeerHeader, BitArray), String) {
  case bytes {
    <<
      peer_type:8,
      flags:8,
      peer_dist:bits-size(64),
      addr_bytes:bits-size(128),
      peer_as:32,
      id_bytes:bits-size(32),
      sec:32,
      usec:32,
      rest:bits,
    >> -> {
      let is_v6 = int.bitwise_and(flags, 0x80) != 0
      let is_post = int.bitwise_and(flags, 0x40) != 0

      use ip_addr <- result.try(case is_v6 {
        True -> bytes_to_ipv6(addr_bytes)
        False -> {
          case addr_bytes {
            <<_:80, _:16, v4:bits-size(32)>> -> bytes_to_ipv4(v4)
            _ -> bytes_to_ipv4(addr_bytes)
          }
        }
      })

      use bgp_id <- result.try(bytes_to_ipv4(id_bytes))

      let header =
        BmpPeerHeader(
          peer_type: peer_type,
          is_ipv6: is_v6,
          is_post_policy: is_post,
          peer_distinguisher: peer_dist,
          peer_ip: ip_addr,
          peer_as: peer_as,
          peer_bgp_id: bgp_id,
          timestamp_sec: sec,
          timestamp_usec: usec,
        )
      Ok(#(header, rest))
    }
    _ -> Error("Truncated BMP Per-Peer Header (requires 42 octets)")
  }
}

/// Encode full RFC 7854 BMP Message with 6-octet common header
pub fn encode_bmp_message(msg: BmpMessage) -> BitArray {
  let #(msg_type, body) = case msg {
    BmpMsgRouteMonitoring(peer, update) -> {
      let peer_bin = encode_peer_header(peer)
      #(type_route_monitoring, <<peer_bin:bits, update:bits>>)
    }

    BmpMsgStatsReport(peer, counters) -> {
      let peer_bin = encode_peer_header(peer)
      let count = list.length(counters)
      let counters_bin =
        list.fold(counters, <<>>, fn(acc, c) {
          <<acc:bits, c.stat_type:16, 4:16, c.value:32>>
        })
      #(type_statistics_report, <<peer_bin:bits, count:32, counters_bin:bits>>)
    }

    BmpMsgPeerDown(peer, reason, notif_opt) -> {
      let peer_bin = encode_peer_header(peer)
      let notif_bin = case notif_opt {
        Some(pdu) -> pdu
        None -> <<>>
      }
      #(type_peer_down, <<peer_bin:bits, reason:8, notif_bin:bits>>)
    }

    BmpMsgPeerUp(peer, local_ip, local_port, remote_port, sent_open, recv_open) -> {
      let peer_bin = encode_peer_header(peer)
      let loc_bytes = case is_ipv6(local_ip) {
        True -> ip_to_bytes(local_ip)
        False ->
          case local_ip {
            Ipv4(a, b, c, d) -> <<0:80, 0xFFFF:16, a:8, b:8, c:8, d:8>>
            _ -> <<0:128>>
          }
      }
      #(type_peer_up, <<
        peer_bin:bits,
        loc_bytes:bits-size(128),
        local_port:16,
        remote_port:16,
        sent_open:bits,
        recv_open:bits,
      >>)
    }

    BmpMsgInitiation(sys_name, sys_descr) -> {
      let name_tlv = encode_tlv(init_sys_name, sys_name)
      let descr_tlv = encode_tlv(init_sys_descr, sys_descr)
      #(type_initiation, <<name_tlv:bits, descr_tlv:bits>>)
    }

    BmpMsgTermination(reason, message) -> {
      let reason_tlv = <<term_info_reason:16, 2:16, reason:16>>
      let msg_tlv = encode_tlv(term_info_string, message)
      #(type_termination, <<reason_tlv:bits, msg_tlv:bits>>)
    }
  }

  let total_len = 6 + bit_array.byte_size(body)
  <<bmp_version:8, total_len:32, msg_type:8, body:bits>>
}

/// Decode an RFC 7854 BMP Message from wire bytes
pub fn decode_bmp_message(bytes: BitArray) -> Result(BmpMessage, String) {
  case bytes {
    <<version:8, length:32, msg_type:8, rest:bits>> -> {
      case version == bmp_version {
        False -> Error("Unsupported BMP version (expected 3)")
        True -> {
          let body_len = length - 6
          let bits_needed = body_len * 8
          case rest {
            <<body:bits-size(bits_needed), _:bits>> -> {
              decode_bmp_body(msg_type, body)
            }
            _ -> Error("Incomplete BMP message body")
          }
        }
      }
    }
    _ -> Error("Truncated BMP header (requires at least 6 octets)")
  }
}

fn decode_bmp_body(
  msg_type: Int,
  body: BitArray,
) -> Result(BmpMessage, String) {
  case msg_type {
    0 -> {
      use #(peer, update) <- result.try(decode_peer_header(body))
      Ok(BmpMsgRouteMonitoring(peer, update))
    }

    1 -> {
      use #(peer, rest) <- result.try(decode_peer_header(body))
      case rest {
        <<count:32, counters_raw:bits>> -> {
          let counters = decode_counters(counters_raw, count, [])
          Ok(BmpMsgStatsReport(peer, counters))
        }
        _ -> Error("Truncated BMP Stats Report header")
      }
    }

    2 -> {
      use #(peer, rest) <- result.try(decode_peer_header(body))
      case rest {
        <<reason:8, notif_raw:bits>> -> {
          let notif = case bit_array.byte_size(notif_raw) > 0 {
            True -> Some(notif_raw)
            False -> None
          }
          Ok(BmpMsgPeerDown(peer, reason, notif))
        }
        _ -> Error("Truncated BMP Peer Down body")
      }
    }

    3 -> {
      use #(peer, rest) <- result.try(decode_peer_header(body))
      case rest {
        <<
          loc_raw:bits-size(128),
          local_port:16,
          remote_port:16,
          sent_open_pdu:bits,
        >> -> {
          use loc_ip <- result.try(case peer.is_ipv6 {
            True -> bytes_to_ipv6(loc_raw)
            False ->
              case loc_raw {
                <<_:80, _:16, v4:bits-size(32)>> -> bytes_to_ipv4(v4)
                _ -> bytes_to_ipv4(loc_raw)
              }
          })
          Ok(
            BmpMsgPeerUp(
              peer,
              loc_ip,
              local_port,
              remote_port,
              sent_open_pdu,
              <<>>,
            ),
          )
        }
        _ -> Error("Truncated BMP Peer Up body")
      }
    }

    4 -> {
      let #(name, descr) = decode_init_tlvs(body, "", "")
      Ok(BmpMsgInitiation(name, descr))
    }

    5 -> {
      let #(reason, msg) = decode_term_tlvs(body, 0, "")
      Ok(BmpMsgTermination(reason, msg))
    }

    _ -> Error("Unsupported BMP message type: " <> int.to_string(msg_type))
  }
}

fn encode_tlv(type_code: Int, value: String) -> BitArray {
  let val_bits = <<value:utf8>>
  let len = bit_array.byte_size(val_bits)
  <<type_code:16, len:16, val_bits:bits>>
}

fn decode_counters(
  raw: BitArray,
  remaining: Int,
  acc: List(BmpStatCounter),
) -> List(BmpStatCounter) {
  case remaining <= 0 {
    True -> list.reverse(acc)
    False -> {
      case raw {
        <<stype:16, len:16, rest:bits>> -> {
          let bits_needed = len * 8
          case rest {
            <<val:bits-size(bits_needed), rem:bits>> -> {
              let num = case len {
                4 ->
                  case val {
                    <<v:32>> -> v
                    _ -> 0
                  }
                8 ->
                  case val {
                    <<v:64>> -> v
                    _ -> 0
                  }
                _ -> 0
              }
              decode_counters(rem, remaining - 1, [
                BmpStatCounter(stype, num),
                ..acc
              ])
            }
            _ -> list.reverse(acc)
          }
        }
        _ -> list.reverse(acc)
      }
    }
  }
}

fn decode_init_tlvs(
  raw: BitArray,
  acc_name: String,
  acc_descr: String,
) -> #(String, String) {
  case raw {
    <<tlv_type:16, len:16, rest:bits>> -> {
      let bits_needed = len * 8
      case rest {
        <<val_raw:bits-size(bits_needed), rem:bits>> -> {
          let text = case bit_array.to_string(val_raw) {
            Ok(s) -> s
            Error(_) -> ""
          }
          case tlv_type {
            2 -> decode_init_tlvs(rem, text, acc_descr)
            1 -> decode_init_tlvs(rem, acc_name, text)
            _ -> decode_init_tlvs(rem, acc_name, acc_descr)
          }
        }
        _ -> #(acc_name, acc_descr)
      }
    }
    _ -> #(acc_name, acc_descr)
  }
}

fn decode_term_tlvs(
  raw: BitArray,
  acc_reason: Int,
  acc_msg: String,
) -> #(Int, String) {
  case raw {
    <<tlv_type:16, len:16, rest:bits>> -> {
      let bits_needed = len * 8
      case rest {
        <<val_raw:bits-size(bits_needed), rem:bits>> -> {
          case tlv_type {
            1 -> {
              let r = case val_raw {
                <<code:16>> -> code
                _ -> 0
              }
              decode_term_tlvs(rem, r, acc_msg)
            }
            0 -> {
              let text = case bit_array.to_string(val_raw) {
                Ok(s) -> s
                Error(_) -> ""
              }
              decode_term_tlvs(rem, acc_reason, text)
            }
            _ -> decode_term_tlvs(rem, acc_reason, acc_msg)
          }
        }
        _ -> #(acc_reason, acc_msg)
      }
    }
    _ -> #(acc_reason, acc_msg)
  }
}
