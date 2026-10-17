import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import slopbgp/ip.{bytes_to_ipv6, ip_to_bytes, ip_to_string}
import slopbgp/types.{type IpAddress}

// RFC 8669: Segment Routing Prefix-SID extensions for BGP (SR-MPLS / SRv6)
// Attribute Type 40: BGP-Prefix-SID (Optional Transitive, 0xC0)

pub type SrgbBlock {
  SrgbBlock(base_label: Int, range_size: Int)
}

pub type PrefixSidTlv {
  LabelIndexTlv(label_index: Int, flags: Int)
  Ipv6SidTlv(sid: IpAddress, flags: Int)
  OriginatorSrgbTlv(flags: Int, blocks: List(SrgbBlock))
  UnknownSidTlv(type_code: Int, data: BitArray)
}

pub type BgpPrefixSid {
  BgpPrefixSid(tlvs: List(PrefixSidTlv))
}

// --- Wire Encoding ---

pub fn encode_tlv(tlv: PrefixSidTlv) -> BitArray {
  case tlv {
    LabelIndexTlv(label_index, flags) -> {
      // Type 1, Length 7, Reserved 1B, Flags 2B, Label-Index 4B
      <<1:8, 7:16, 0:8, flags:16, label_index:32>>
    }
    Ipv6SidTlv(sid, flags) -> {
      // Type 2, Length 19, Reserved 1B, Flags 2B, SID 16B
      let sid_bytes = ip_to_bytes(sid)
      <<2:8, 19:16, 0:8, flags:16, sid_bytes:bits>>
    }
    OriginatorSrgbTlv(flags, blocks) -> {
      let block_bytes =
        list.fold(blocks, <<>>, fn(acc, b) {
          <<acc:bits, b.base_label:24, b.range_size:24>>
        })
      let len = 2 + bit_array.byte_size(block_bytes)
      <<3:8, len:16, flags:16, block_bytes:bits>>
    }
    UnknownSidTlv(t, data) -> {
      let len = bit_array.byte_size(data)
      <<t:8, len:16, data:bits>>
    }
  }
}

pub fn encode_prefix_sid(sid: BgpPrefixSid) -> BitArray {
  let tlv_bytes =
    list.fold(sid.tlvs, <<>>, fn(acc, tlv) {
      let b = encode_tlv(tlv)
      <<acc:bits, b:bits>>
    })
  let len = bit_array.byte_size(tlv_bytes)
  // Attribute Type 40, Flags 0xC0 (Optional Transitive)
  <<0xC0:8, 40:8, len:16, tlv_bytes:bits>>
}

// --- Wire Decoding ---

pub fn decode_prefix_sid(bytes: BitArray) -> Result(BgpPrefixSid, String) {
  decode_tlvs_loop(bytes, [])
}

fn decode_tlvs_loop(
  bytes: BitArray,
  acc: List(PrefixSidTlv),
) -> Result(BgpPrefixSid, String) {
  case bytes {
    <<>> -> Ok(BgpPrefixSid(tlvs: list.reverse(acc)))
    <<type_code:8, len:16, rest:bits>> -> {
      case bit_array.slice(rest, 0, len) {
        Ok(tlv_data) -> {
          let rem_len = bit_array.byte_size(rest) - len
          let rem = case bit_array.slice(rest, len, rem_len) {
            Ok(r) -> r
            Error(_) -> <<>>
          }

          use tlv <- result.try(decode_single_tlv(type_code, tlv_data))
          decode_tlvs_loop(rem, [tlv, ..acc])
        }
        Error(_) -> Error("Truncated TLV in BGP-Prefix-SID")
      }
    }
    _ -> Error("Malformed TLV header in BGP-Prefix-SID")
  }
}

fn decode_single_tlv(
  type_code: Int,
  data: BitArray,
) -> Result(PrefixSidTlv, String) {
  case type_code {
    1 -> {
      case data {
        <<_res:8, flags:16, label_index:32>> ->
          Ok(LabelIndexTlv(label_index, flags))
        _ -> Error("Invalid Label-Index TLV length/format")
      }
    }
    2 -> {
      case data {
        <<_res:8, flags:16, sid_raw:bits-size(128)>> -> {
          case bytes_to_ipv6(sid_raw) {
            Ok(sid) -> Ok(Ipv6SidTlv(sid, flags))
            Error(_) -> Error("Invalid IPv6 SID address in TLV")
          }
        }
        _ -> Error("Invalid IPv6 SRv6 SID TLV length/format")
      }
    }
    3 -> {
      case data {
        <<flags:16, blocks_raw:bits>> -> {
          use blocks <- result.try(decode_srgb_blocks(blocks_raw, []))
          Ok(OriginatorSrgbTlv(flags, blocks))
        }
        _ -> Error("Invalid Originator SRGB TLV length/format")
      }
    }
    _ -> Ok(UnknownSidTlv(type_code, data))
  }
}

fn decode_srgb_blocks(
  bytes: BitArray,
  acc: List(SrgbBlock),
) -> Result(List(SrgbBlock), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    <<base:24, range:24, rest:bits>> ->
      decode_srgb_blocks(rest, [SrgbBlock(base, range), ..acc])
    _ -> Error("Malformed SRGB block entry (expected 6 octets)")
  }
}

// --- JSON Serialization for Web API & Dashboard ---

pub fn prefix_sid_to_json(sid: BgpPrefixSid) -> String {
  let tlv_strs =
    list.map(sid.tlvs, fn(tlv) {
      case tlv {
        LabelIndexTlv(idx, flags) ->
          "{\"type\":\"label_index\",\"label_index\":"
          <> int.to_string(idx)
          <> ",\"flags\":"
          <> int.to_string(flags)
          <> "}"
        Ipv6SidTlv(sid_ip, flags) ->
          "{\"type\":\"srv6_sid\",\"sid\":\""
          <> ip_to_string(sid_ip)
          <> "\",\"flags\":"
          <> int.to_string(flags)
          <> "}"
        OriginatorSrgbTlv(flags, blocks) -> {
          let block_strs =
            list.map(blocks, fn(b) {
              "{\"base_label\":"
              <> int.to_string(b.base_label)
              <> ",\"range_size\":"
              <> int.to_string(b.range_size)
              <> "}"
            })
          "{\"type\":\"originator_srgb\",\"flags\":"
          <> int.to_string(flags)
          <> ",\"blocks\":["
          <> string.join(block_strs, ",")
          <> "]}"
        }
        UnknownSidTlv(t, _) ->
          "{\"type\":\"unknown\",\"type_code\":" <> int.to_string(t) <> "}"
      }
    })

  "{\"tlv_count\":"
  <> int.to_string(list.length(sid.tlvs))
  <> ",\"tlvs\":["
  <> string.join(tlv_strs, ",")
  <> "]}"
}
