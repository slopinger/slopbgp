import gleam/bit_array
import gleam/int
import slopbgp/types.{type BgpMessage, MsgNotification}

// RFC 9003: Extended BGP Administrative Shutdown Communication
// Allows operator reason strings in BGP NOTIFICATION messages (Cease subcode 2/4).

pub const cease_administrative_shutdown: Int = 2

pub const cease_administrative_reset: Int = 4

pub fn encode_shutdown_communication(reason: String) -> BitArray {
  case reason {
    "" -> <<0:8>>
    _ -> {
      let raw_bits = <<reason:utf8>>
      let raw_len = bit_array.byte_size(raw_bits)
      // RFC 9003 Section 3 recommends maximum length of 128 octets
      let capped_len = case raw_len > 128 {
        True -> 128
        False -> raw_len
      }
      let bits_needed = capped_len * 8
      case raw_bits {
        <<payload:bits-size(bits_needed), _:bits>> -> <<
          capped_len:8,
          payload:bits,
        >>
        _ -> <<capped_len:8, raw_bits:bits>>
      }
    }
  }
}

pub fn decode_shutdown_communication(data: BitArray) -> Result(String, Nil) {
  case data {
    <<0:8, _:bits>> -> Error(Nil)
    <<len:8, rest:bits>> -> {
      let bits_needed = len * 8
      case rest {
        <<payload:bits-size(bits_needed), _:bits>> ->
          bit_array.to_string(payload)
        _ -> bit_array.to_string(rest)
      }
    }
    _ -> bit_array.to_string(data)
  }
}

pub fn format_cease_subcode(subcode: Int) -> String {
  case subcode {
    1 -> "Maximum Number of Prefixes Reached"
    2 -> "Administrative Shutdown (RFC 9003)"
    3 -> "Peer De-configured"
    4 -> "Administrative Reset (RFC 9003)"
    5 -> "Connection Rejected"
    6 -> "Other Configuration Change"
    7 -> "Connection Collision Resolution"
    8 -> "Out of Resources"
    9 -> "Hard Reset (RFC 8538)"
    10 -> "BFD Down"
    _ -> "Cease (subcode " <> int.to_string(subcode) <> ")"
  }
}

pub fn make_shutdown_notification(subcode: Int, reason: String) -> BgpMessage {
  let comm_data = encode_shutdown_communication(reason)
  MsgNotification(6, subcode, comm_data)
}
