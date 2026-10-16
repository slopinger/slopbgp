import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/result
import slopbgp/bgp/attributes.{decode_attributes, encode_attributes}
import slopbgp/bgp/capabilities.{
  afi_to_int, decode_capabilities, encode_capability, int_to_afi, int_to_safi,
  safi_to_int,
}
import slopbgp/ip.{
  bytes_to_ipv4, decode_prefixes_ipv4, encode_prefix, ip_to_bytes,
}
import slopbgp/types.{
  type Afi, type BgpCapability, type BgpMessage, type IpAddress, type IpPrefix,
  type PathAttribute, type Safi, CapFourOctetAsn, MsgKeepalive, MsgNotification,
  MsgOpen, MsgRouteRefresh, MsgUpdate,
}

pub const bgp_marker: BitArray = <<
  0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8,
  0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8, 0xFF:8,
>>

pub const as_trans: Int = 23_456

pub fn encode_open(
  version: Int,
  my_as: Int,
  hold_time: Int,
  bgp_id: IpAddress,
  capabilities: List(BgpCapability),
) -> BitArray {
  let two_byte_as = case my_as > 65_535 {
    True -> as_trans
    False -> my_as
  }
  let id_bytes = ip_to_bytes(bgp_id)
  let caps_to_send = case my_as > 65_535 {
    True -> {
      let has_4byte =
        list.any(capabilities, fn(c) {
          case c {
            CapFourOctetAsn(_) -> True
            _ -> False
          }
        })
      case has_4byte {
        True -> capabilities
        False -> [CapFourOctetAsn(my_as), ..capabilities]
      }
    }
    False -> capabilities
  }

  let caps_bin =
    list.fold(caps_to_send, <<>>, fn(acc, c) {
      <<acc:bits, { encode_capability(c) }:bits>>
    })
  let caps_len = byte_length(caps_bin)

  let opt_params = case caps_len > 0 {
    True -> <<2:8, caps_len:8, caps_bin:bits>>
    False -> <<>>
  }
  let opt_len = byte_length(opt_params)

  let body = <<
    version:8,
    two_byte_as:16,
    hold_time:16,
    id_bytes:bits,
    opt_len:8,
    opt_params:bits,
  >>
  wrap_header(1, body)
}

pub fn encode_update(
  withdrawn: List(IpPrefix),
  attributes: List(PathAttribute),
  nlri: List(IpPrefix),
) -> BitArray {
  let w_bin =
    list.fold(withdrawn, <<>>, fn(acc, p) {
      <<acc:bits, { encode_prefix(p, None) }:bits>>
    })
  let w_len = byte_length(w_bin)

  let attr_bin = encode_attributes(attributes)
  let attr_len = byte_length(attr_bin)

  let nlri_bin =
    list.fold(nlri, <<>>, fn(acc, p) {
      <<acc:bits, { encode_prefix(p, None) }:bits>>
    })

  let body = <<
    w_len:16,
    w_bin:bits,
    attr_len:16,
    attr_bin:bits,
    nlri_bin:bits,
  >>
  wrap_header(2, body)
}

pub fn encode_notification(
  code: Int,
  subcode: Int,
  data: BitArray,
) -> BitArray {
  let body = <<code:8, subcode:8, data:bits>>
  wrap_header(3, body)
}

pub fn encode_keepalive() -> BitArray {
  wrap_header(4, <<>>)
}

pub fn encode_route_refresh(afi: Afi, subtype: Int, safi: Safi) -> BitArray {
  let a = afi_to_int(afi)
  let s = safi_to_int(safi)
  let body = <<a:16, subtype:8, s:8>>
  wrap_header(5, body)
}

pub fn encode_message(msg: BgpMessage) -> BitArray {
  case msg {
    MsgOpen(ver, my_as, hold, id, caps) ->
      encode_open(ver, my_as, hold, id, caps)
    MsgUpdate(w, attrs, nlri) -> encode_update(w, attrs, nlri)
    MsgNotification(c, s, d) -> encode_notification(c, s, d)
    MsgKeepalive -> encode_keepalive()
    MsgRouteRefresh(a, sub, s) -> encode_route_refresh(a, sub, s)
  }
}

fn wrap_header(msg_type: Int, body: BitArray) -> BitArray {
  let len = 19 + byte_length(body)
  <<bgp_marker:bits, len:16, msg_type:8, body:bits>>
}

pub fn decode_message(
  bytes: BitArray,
  has_add_path: Bool,
) -> Result(#(BgpMessage, BitArray), String) {
  case bytes {
    <<marker:bits-size(128), length:16, msg_type:8, rest:bits>> -> {
      case marker == bgp_marker {
        False -> Error("BGP header synchronization error: invalid marker")
        True -> {
          case length < 19 || length > 65_535 {
            True ->
              Error(
                "BGP header length error: bad length " <> int_to_str(length),
              )
            False -> {
              let body_len = length - 19
              let body_bits = body_len * 8
              case rest {
                <<body:bits-size(body_bits), rem:bits>> -> {
                  use msg <- result.try(decode_message_body(
                    msg_type,
                    body,
                    has_add_path,
                  ))
                  Ok(#(msg, rem))
                }
                _ -> Error("Incomplete BGP message body")
              }
            }
          }
        }
      }
    }
    _ -> Error("Incomplete BGP message header")
  }
}

fn decode_message_body(
  msg_type: Int,
  body: BitArray,
  has_add_path: Bool,
) -> Result(BgpMessage, String) {
  case msg_type {
    1 -> decode_open_body(body)
    2 -> decode_update_body(body, has_add_path)
    3 -> decode_notification_body(body)
    4 -> Ok(MsgKeepalive)
    5 -> decode_route_refresh_body(body)
    _ -> Error("Unsupported BGP message type: " <> int_to_str(msg_type))
  }
}

fn decode_open_body(body: BitArray) -> Result(BgpMessage, String) {
  case body {
    <<
      version:8,
      my_as:16,
      hold_time:16,
      bgp_id_raw:bits-size(32),
      _opt_len:8,
      opt_raw:bits,
    >> -> {
      use bgp_id <- result.try(bytes_to_ipv4(bgp_id_raw))
      let caps = decode_opt_params(opt_raw)
      let resolved_as = case
        list.find(caps, fn(c) {
          case c {
            CapFourOctetAsn(_) -> True
            _ -> False
          }
        })
      {
        Ok(CapFourOctetAsn(asn4)) -> asn4
        _ -> my_as
      }
      Ok(MsgOpen(version, resolved_as, hold_time, bgp_id, caps))
    }
    _ -> Error("Malformed OPEN message")
  }
}

fn decode_opt_params(bytes: BitArray) -> List(BgpCapability) {
  decode_opt_params_loop(bytes, [])
}

fn decode_opt_params_loop(
  bytes: BitArray,
  acc: List(BgpCapability),
) -> List(BgpCapability) {
  case bytes {
    <<>> -> list.reverse(acc)
    <<param_type:8, param_len:8, rest:bits>> -> {
      let bits_needed = param_len * 8
      case rest {
        <<val:bits-size(bits_needed), rem:bits>> -> {
          case param_type {
            2 -> {
              let caps = decode_capabilities(val)
              decode_opt_params_loop(rem, list.append(caps, acc))
            }
            _ -> decode_opt_params_loop(rem, acc)
          }
        }
        _ -> list.reverse(acc)
      }
    }
    _ -> list.reverse(acc)
  }
}

fn decode_update_body(
  body: BitArray,
  has_add_path: Bool,
) -> Result(BgpMessage, String) {
  case body {
    <<w_len:16, rest1:bits>> -> {
      let w_bits = w_len * 8
      case rest1 {
        <<w_raw:bits-size(w_bits), attr_len:16, rest2:bits>> -> {
          let attr_bits = attr_len * 8
          case rest2 {
            <<attr_raw:bits-size(attr_bits), nlri_raw:bits>> -> {
              use w_with_id <- result.try(decode_prefixes_ipv4(
                w_raw,
                has_add_path,
              ))
              let withdrawn = list.map(w_with_id, fn(p) { p.0 })

              use attrs <- result.try(decode_attributes(attr_raw, has_add_path))

              use nlri_with_id <- result.try(decode_prefixes_ipv4(
                nlri_raw,
                has_add_path,
              ))
              let nlri = list.map(nlri_with_id, fn(p) { p.0 })

              Ok(MsgUpdate(withdrawn, attrs, nlri))
            }
            _ -> Error("Truncated attributes or NLRI in UPDATE")
          }
        }
        _ -> Error("Truncated withdrawn routes in UPDATE")
      }
    }
    _ -> Error("Truncated UPDATE header")
  }
}

fn decode_notification_body(body: BitArray) -> Result(BgpMessage, String) {
  case body {
    <<code:8, subcode:8, data:bits>> -> Ok(MsgNotification(code, subcode, data))
    _ -> Error("Malformed NOTIFICATION message")
  }
}

fn decode_route_refresh_body(body: BitArray) -> Result(BgpMessage, String) {
  case body {
    <<afi:16, subtype:8, safi:8>> ->
      Ok(MsgRouteRefresh(int_to_afi(afi), subtype, int_to_safi(safi)))
    _ -> Error("Malformed ROUTE-REFRESH message")
  }
}

fn byte_length(bytes: BitArray) -> Int {
  case bytes {
    <<_:8, rest:bits>> -> 1 + byte_length(rest)
    _ -> 0
  }
}

fn int_to_str(val: Int) -> String {
  int.to_string(val)
}
