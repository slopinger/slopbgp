import gleam/bit_array
import gleam/list
import gleam/result
import slopbgp/ip.{bytes_to_ipv6, ip_to_bytes}
import slopbgp/types.{type IpAddress, Ipv4}

pub const rtr_version_0 = 0

pub const rtr_version_1 = 1

pub type RtrPdu {
  RtrSerialNotify(version: Int, session_id: Int, serial: Int)
  RtrSerialQuery(version: Int, session_id: Int, serial: Int)
  RtrResetQuery(version: Int)
  RtrCacheResponse(version: Int, session_id: Int)
  RtrIpv4Prefix(
    version: Int,
    flags: Int,
    prefix_len: Int,
    max_len: Int,
    prefix: IpAddress,
    asn: Int,
  )
  RtrIpv6Prefix(
    version: Int,
    flags: Int,
    prefix_len: Int,
    max_len: Int,
    prefix: IpAddress,
    asn: Int,
  )
  RtrEndOfData(
    version: Int,
    session_id: Int,
    serial: Int,
    refresh_sec: Int,
    retry_sec: Int,
    expire_sec: Int,
  )
  RtrCacheReset(version: Int)
  RtrErrorReport(
    version: Int,
    error_code: Int,
    encapsulated_pdu: BitArray,
    message: String,
  )
}

pub fn encode_rtr_pdu(pdu: RtrPdu) -> BitArray {
  case pdu {
    RtrSerialNotify(v, sid, serial) -> <<v:8, 0:8, sid:16, 12:32, serial:32>>

    RtrSerialQuery(v, sid, serial) -> <<v:8, 1:8, sid:16, 12:32, serial:32>>

    RtrResetQuery(v) -> <<v:8, 2:8, 0:16, 8:32>>

    RtrCacheResponse(v, sid) -> <<v:8, 3:8, sid:16, 8:32>>

    RtrIpv4Prefix(v, flags, plen, mlen, prefix, asn) -> {
      let ip_bytes = case prefix {
        Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
        _ -> <<0:32>>
      }
      <<
        v:8,
        4:8,
        0:16,
        20:32,
        flags:8,
        plen:8,
        mlen:8,
        0:8,
        ip_bytes:bits,
        asn:32,
      >>
    }

    RtrIpv6Prefix(v, flags, plen, mlen, prefix, asn) -> {
      let ip_bytes = ip_to_bytes(prefix)
      <<
        v:8,
        6:8,
        0:16,
        32:32,
        flags:8,
        plen:8,
        mlen:8,
        0:8,
        ip_bytes:bits,
        asn:32,
      >>
    }

    RtrEndOfData(v, sid, serial, refresh, retry, expire) -> <<
      v:8,
      7:8,
      sid:16,
      24:32,
      serial:32,
      refresh:32,
      retry:32,
      expire:32,
    >>

    RtrCacheReset(v) -> <<v:8, 8:8, 0:16, 8:32>>

    RtrErrorReport(v, code, enc, msg) -> {
      let msg_bytes = bit_array.from_string(msg)
      let enc_len = bit_array.byte_size(enc)
      let msg_len = bit_array.byte_size(msg_bytes)
      let tot_len = 8 + 4 + enc_len + 4 + msg_len
      <<
        v:8,
        10:8,
        code:16,
        tot_len:32,
        enc_len:32,
        enc:bits,
        msg_len:32,
        msg_bytes:bits,
      >>
    }
  }
}

pub fn decode_rtr_pdu(bytes: BitArray) -> Result(#(RtrPdu, BitArray), String) {
  let size = bit_array.byte_size(bytes)
  case size < 8 {
    True -> Error("Truncated RTR PDU header")
    False -> {
      case bytes {
        <<v:8, pdu_type:8, sid:16, len:32, rest:bits>> if len >= 8 -> {
          let payload_len = len - 8
          let payload_bits = payload_len * 8
          case rest {
            <<payload:bits-size(payload_bits), rem:bits>> -> {
              use pdu <- result.try(parse_pdu_payload(v, pdu_type, sid, payload))
              Ok(#(pdu, rem))
            }
            _ -> Error("Truncated RTR PDU payload")
          }
        }
        _ -> Error("Invalid RTR framing or length")
      }
    }
  }
}

fn parse_pdu_payload(
  v: Int,
  pdu_type: Int,
  sid: Int,
  payload: BitArray,
) -> Result(RtrPdu, String) {
  case pdu_type {
    0 ->
      case payload {
        <<serial:32>> -> Ok(RtrSerialNotify(v, sid, serial))
        _ -> Error("Malformed Serial Notify")
      }
    1 ->
      case payload {
        <<serial:32>> -> Ok(RtrSerialQuery(v, sid, serial))
        _ -> Error("Malformed Serial Query")
      }
    2 -> Ok(RtrResetQuery(v))
    3 -> Ok(RtrCacheResponse(v, sid))
    4 ->
      case payload {
        <<flags:8, plen:8, mlen:8, _:8, a:8, b:8, c:8, d:8, asn:32>> ->
          Ok(RtrIpv4Prefix(v, flags, plen, mlen, Ipv4(a, b, c, d), asn))
        _ -> Error("Malformed IPv4 Prefix PDU")
      }
    6 ->
      case payload {
        <<flags:8, plen:8, mlen:8, _:8, ip_bytes:bits-size(128), asn:32>> -> {
          use ip <- result.try(bytes_to_ipv6(ip_bytes))
          Ok(RtrIpv6Prefix(v, flags, plen, mlen, ip, asn))
        }
        _ -> Error("Malformed IPv6 Prefix PDU")
      }
    7 ->
      case payload {
        <<serial:32, ref:32, ret:32, exp:32>> ->
          Ok(RtrEndOfData(v, sid, serial, ref, ret, exp))
        _ -> Error("Malformed End of Data PDU")
      }
    8 -> Ok(RtrCacheReset(v))
    10 ->
      case payload {
        <<enc_len:32, enc_raw:bits>> -> {
          let enc_bits = enc_len * 8
          case enc_raw {
            <<enc:bits-size(enc_bits), msg_len:32, msg_raw:bits>> -> {
              let msg_bits = msg_len * 8
              case msg_raw {
                <<msg_bin:bits-size(msg_bits), _:bits>> -> {
                  let msg = case bit_array.to_string(msg_bin) {
                    Ok(s) -> s
                    Error(_) -> ""
                  }
                  Ok(RtrErrorReport(v, sid, enc, msg))
                }
                _ -> Error("Truncated Error Report text")
              }
            }
            _ -> Error("Truncated Error Report encapsulated PDU")
          }
        }
        _ -> Error("Malformed Error Report PDU")
      }
    _ -> Error("Unknown RTR PDU type: " <> int_to_string(pdu_type))
  }
}

pub fn decode_rtr_stream(bytes: BitArray) -> Result(List(RtrPdu), String) {
  decode_rtr_stream_loop(bytes, [])
}

fn decode_rtr_stream_loop(
  bytes: BitArray,
  acc: List(RtrPdu),
) -> Result(List(RtrPdu), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(pdu, rest) <- result.try(decode_rtr_pdu(bytes))
      decode_rtr_stream_loop(rest, [pdu, ..acc])
    }
  }
}

fn int_to_string(i: Int) -> String {
  case i {
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
    10 -> "10"
    _ -> "unknown"
  }
}
