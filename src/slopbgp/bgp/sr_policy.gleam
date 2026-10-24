import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order.{Gt, Lt}
import gleam/result
import slopbgp/ip.{bytes_to_ipv6, ip_to_bytes, ip_to_string}
import slopbgp/types.{
  type Afi, type ExtendedCommunity, type IpAddress, type IpPrefix, AfiIpv4,
  AfiIpv6, ExtCommunity, Ipv4, Ipv6,
}

// RFC 9256: Segment Routing Policy Architecture in BGP (SAFI 73)
// RFC 9012: The BGP Tunnel Encapsulation Attribute (Attribute 23, Tunnel Type 15: SR Policy)
// RFC 9012 Section 4.3: Color Extended Community (Type 0x08, Sub-Type 0x0B)

pub type Segment {
  SegmentMpls(label: Int, tc: Int, s: Bool, ttl: Int)
  SegmentSrv6(sid: IpAddress, behavior: Int)
}

pub type SegmentList {
  SegmentList(weight: Int, segments: List(Segment))
}

pub type BindingSid {
  BindingMpls(label: Int)
  BindingSrv6(sid: IpAddress)
}

pub type SrCandidatePath {
  SrCandidatePath(
    preference: Int,
    binding_sid: Option(BindingSid),
    segment_lists: List(SegmentList),
    protocol_origin: Int,
    originator_asn: Int,
    discriminator: Int,
  )
}

pub type SrPolicyNlri {
  SrPolicyNlri(distinguisher: Int, color: Int, endpoint: IpAddress)
}

pub type SrPolicy {
  SrPolicy(
    color: Int,
    endpoint: IpAddress,
    candidate_paths: List(SrCandidatePath),
    active_path: Option(SrCandidatePath),
  )
}

pub type SrPolicyTable {
  SrPolicyTable(policies: List(SrPolicy))
}

pub type SteeredPath {
  SteeredSrPolicy(color: Int, endpoint: IpAddress, active_path: SrCandidatePath)
  SteeredStandardNextHop(next_hop: IpAddress)
}

// --- NLRI Encoding & Decoding (RFC 9256 Section 2.1) ---

pub fn encode_sr_policy_nlri(nlri: SrPolicyNlri) -> BitArray {
  let #(len, endpoint_bytes) = case nlri.endpoint {
    Ipv4(a, b, c, d) -> #(12, <<a:8, b:8, c:8, d:8>>)
    Ipv6(..) -> #(24, ip_to_bytes(nlri.endpoint))
  }
  <<len:8, nlri.distinguisher:32, nlri.color:32, endpoint_bytes:bits>>
}

pub fn decode_sr_policy_nlri(
  afi: Afi,
  bytes: BitArray,
) -> Result(SrPolicyNlri, String) {
  case bytes {
    <<len:8, distinguisher:32, color:32, rest:bits>> -> {
      case afi {
        AfiIpv4 -> {
          case rest {
            <<a:8, b:8, c:8, d:8>> ->
              Ok(SrPolicyNlri(
                distinguisher: distinguisher,
                color: color,
                endpoint: Ipv4(a, b, c, d),
              ))
            _ -> Error("Malformed IPv4 endpoint in SR Policy NLRI")
          }
        }
        AfiIpv6 -> {
          case bit_array.byte_size(rest) == 16 {
            True -> {
              use ipv6 <- result.try(bytes_to_ipv6(rest))
              Ok(SrPolicyNlri(
                distinguisher: distinguisher,
                color: color,
                endpoint: ipv6,
              ))
            }
            False -> Error("Malformed IPv6 endpoint in SR Policy NLRI")
          }
        }
        _ -> {
          case len {
            12 -> {
              case rest {
                <<a:8, b:8, c:8, d:8>> ->
                  Ok(SrPolicyNlri(
                    distinguisher: distinguisher,
                    color: color,
                    endpoint: Ipv4(a, b, c, d),
                  ))
                _ -> Error("Malformed IPv4 endpoint in SR Policy NLRI")
              }
            }
            24 -> {
              case bit_array.byte_size(rest) == 16 {
                True -> {
                  use ipv6 <- result.try(bytes_to_ipv6(rest))
                  Ok(SrPolicyNlri(
                    distinguisher: distinguisher,
                    color: color,
                    endpoint: ipv6,
                  ))
                }
                False -> Error("Malformed IPv6 endpoint in SR Policy NLRI")
              }
            }
            _ ->
              Error("Unsupported SR Policy NLRI length: " <> int.to_string(len))
          }
        }
      }
    }
    _ -> Error("Truncated SR Policy NLRI header")
  }
}

// --- Color Extended Community (RFC 9012 Section 4.3) ---

pub fn encode_color_extended_community(color: Int) -> ExtendedCommunity {
  // Transitive Opaque Extended Community (0x08), Sub-Type 0x0B (Color)
  // Value: 2-octet Flags (0x0000) + 4-octet Color value
  ExtCommunity(type_code: 0x08, sub_type: 0x0B, value: <<0:16, color:32>>)
}

pub fn decode_color_extended_community(
  community: ExtendedCommunity,
) -> Result(Int, Nil) {
  case community.type_code == 0x08 && community.sub_type == 0x0B {
    True -> {
      case community.value {
        <<_:16, color:32>> -> Ok(color)
        _ -> Error(Nil)
      }
    }
    False -> Error(Nil)
  }
}

// --- Tunnel Encapsulation Attribute (RFC 9012 Type 23, Tunnel Type 15: SR Policy) ---

pub fn encode_tunnel_encap_sr_policy(
  preference: Int,
  binding_sid: Option(BindingSid),
  segment_lists: List(SegmentList),
) -> BitArray {
  // Sub-TLV 1: Preference (Length 4)
  let pref_tlv = <<1:8, 4:16, preference:32>>

  // Sub-TLV 2: Binding SID (Optional)
  let bsid_tlv = case binding_sid {
    None -> <<>>
    Some(BindingMpls(label)) -> <<2:8, 6:16, 0:8, 0:8, label:32>>
    Some(BindingSrv6(sid)) -> {
      let s_bytes = ip_to_bytes(sid)
      <<2:8, 18:16, 0:8, 0:8, s_bytes:bits>>
    }
  }

  // Sub-TLV 128: Explicit Segment Lists
  let sl_tlvs =
    list.fold(segment_lists, <<>>, fn(acc, sl) {
      // Weight sub-TLV 129
      let weight_bytes = <<129:8, 4:16, sl.weight:32>>

      // Segments sub-sub-TLVs
      let segs_bytes =
        list.fold(sl.segments, <<>>, fn(s_acc, seg) {
          case seg {
            SegmentMpls(label, tc, s, ttl) -> {
              let s_bit = case s {
                True -> 1
                False -> 0
              }
              // Type 1 (Type A: MPLS SID): Flags 1B, Label 20b, TC 3b, S 1b, TTL 8b -> 6 bytes
              let sub = <<1:8, 6:16, 0:8, label:20, tc:3, s_bit:1, ttl:8>>
              <<s_acc:bits, sub:bits>>
            }
            SegmentSrv6(sid, behavior) -> {
              let sid_bytes = ip_to_bytes(sid)
              // Type 2 (Type B: SRv6 SID): Flags 1B, Reserved/Behavior 1B, SID 16B -> 18 bytes
              let sub = <<2:8, 18:16, 0:8, behavior:8, sid_bytes:bits>>
              <<s_acc:bits, sub:bits>>
            }
          }
        })

      let sl_payload = <<weight_bytes:bits, segs_bytes:bits>>
      let sl_len = bit_array.byte_size(sl_payload)
      let sl_tlv = <<128:8, sl_len:16, sl_payload:bits>>
      <<acc:bits, sl_tlv:bits>>
    })

  let tunnel_payload = <<pref_tlv:bits, bsid_tlv:bits, sl_tlvs:bits>>
  let tunnel_len = bit_array.byte_size(tunnel_payload)

  // Tunnel TLV: Type 15 (SR Policy), Length 2B, Payload
  <<15:16, tunnel_len:16, tunnel_payload:bits>>
}

pub fn decode_tunnel_encap_sr_policy(
  bytes: BitArray,
) -> Result(#(Int, Option(BindingSid), List(SegmentList)), String) {
  case bytes {
    <<15:16, len:16, rest:bits>> -> {
      let bits_len = len * 8
      case rest {
        <<payload:bits-size(bits_len), _rem:bits>> -> {
          decode_sr_sub_tlvs(payload, 100, None, [])
        }
        _ -> Error("Truncated SR Policy Tunnel TLV")
      }
    }
    _ -> Error("Missing Tunnel Type 15 (SR Policy) in Encapsulation Attribute")
  }
}

fn decode_sr_sub_tlvs(
  bytes: BitArray,
  cur_pref: Int,
  cur_bsid: Option(BindingSid),
  acc_sl: List(SegmentList),
) -> Result(#(Int, Option(BindingSid), List(SegmentList)), String) {
  case bytes {
    <<>> -> Ok(#(cur_pref, cur_bsid, list.reverse(acc_sl)))
    <<1:8, 4:16, pref:32, rem:bits>> -> {
      decode_sr_sub_tlvs(rem, pref, cur_bsid, acc_sl)
    }
    <<2:8, 6:16, _flags:8, _res:8, label:32, rem:bits>> -> {
      decode_sr_sub_tlvs(rem, cur_pref, Some(BindingMpls(label)), acc_sl)
    }
    <<2:8, 18:16, _flags:8, _res:8, sid_raw:bits-size(128), rem:bits>> -> {
      use sid <- result.try(bytes_to_ipv6(sid_raw))
      decode_sr_sub_tlvs(rem, cur_pref, Some(BindingSrv6(sid)), acc_sl)
    }
    <<128:8, sl_len:16, rest:bits>> -> {
      let sl_bits = sl_len * 8
      case rest {
        <<sl_payload:bits-size(sl_bits), rem:bits>> -> {
          use sl <- result.try(decode_segment_list(sl_payload))
          decode_sr_sub_tlvs(rem, cur_pref, cur_bsid, [sl, ..acc_sl])
        }
        _ -> Error("Truncated Segment List Sub-TLV 128")
      }
    }
    <<_code:8, l:16, rest:bits>> -> {
      let skip_bits = l * 8
      case rest {
        <<_skip:bits-size(skip_bits), rem:bits>> ->
          decode_sr_sub_tlvs(rem, cur_pref, cur_bsid, acc_sl)
        _ -> Error("Truncated unknown sub-TLV in SR Policy")
      }
    }
    _ -> Error("Malformed sub-TLV header in SR Policy")
  }
}

fn decode_segment_list(bytes: BitArray) -> Result(SegmentList, String) {
  decode_segment_list_loop(bytes, 1, [])
}

fn decode_segment_list_loop(
  bytes: BitArray,
  cur_weight: Int,
  acc_segs: List(Segment),
) -> Result(SegmentList, String) {
  case bytes {
    <<>> ->
      Ok(SegmentList(weight: cur_weight, segments: list.reverse(acc_segs)))
    <<129:8, 4:16, w:32, rem:bits>> -> {
      decode_segment_list_loop(rem, w, acc_segs)
    }
    <<1:8, 6:16, _flags:8, label:20, tc:3, s_bit:1, ttl:8, rem:bits>> -> {
      let s = s_bit == 1
      let seg = SegmentMpls(label: label, tc: tc, s: s, ttl: ttl)
      decode_segment_list_loop(rem, cur_weight, [seg, ..acc_segs])
    }
    <<2:8, 18:16, _flags:8, behavior:8, sid_raw:bits-size(128), rem:bits>> -> {
      use sid <- result.try(bytes_to_ipv6(sid_raw))
      let seg = SegmentSrv6(sid: sid, behavior: behavior)
      decode_segment_list_loop(rem, cur_weight, [seg, ..acc_segs])
    }
    <<_c:8, l:16, rest:bits>> -> {
      let skip_bits = l * 8
      case rest {
        <<_skip:bits-size(skip_bits), rem:bits>> ->
          decode_segment_list_loop(rem, cur_weight, acc_segs)
        _ -> Error("Truncated segment sub-sub-TLV")
      }
    }
    _ -> Error("Malformed segment list payload")
  }
}

// --- RFC 9256 Section 2.7: Candidate Path Selection ---

pub fn select_active_candidate_path(
  paths: List(SrCandidatePath),
) -> Option(SrCandidatePath) {
  case paths {
    [] -> None
    _ -> {
      let sorted =
        list.sort(paths, fn(a, b) {
          // 1. Highest Preference
          case a.preference != b.preference {
            True -> {
              case a.preference > b.preference {
                True -> Lt
                False -> Gt
              }
            }
            False -> {
              // 2. Highest Protocol Origin
              case a.protocol_origin != b.protocol_origin {
                True -> {
                  case a.protocol_origin > b.protocol_origin {
                    True -> Lt
                    False -> Gt
                  }
                }
                False -> {
                  // 3. Lowest Discriminator
                  case a.discriminator < b.discriminator {
                    True -> Lt
                    False -> Gt
                  }
                }
              }
            }
          }
        })
      list.first(sorted) |> option.from_result
    }
  }
}

// --- SR Policy Table Operations ---

pub fn new_sr_policy_table() -> SrPolicyTable {
  SrPolicyTable(policies: [])
}

pub fn update_sr_policy(
  table: SrPolicyTable,
  color: Int,
  endpoint: IpAddress,
  candidate_path: SrCandidatePath,
) -> SrPolicyTable {
  let existing_opt =
    list.find(table.policies, fn(p) {
      p.color == color && p.endpoint == endpoint
    })

  let updated_policies = case existing_opt {
    Ok(existing) -> {
      let other_paths =
        list.filter(existing.candidate_paths, fn(cp) {
          cp.discriminator != candidate_path.discriminator
        })
      let new_paths = [candidate_path, ..other_paths]
      let active = select_active_candidate_path(new_paths)
      let new_policy =
        SrPolicy(
          color: color,
          endpoint: endpoint,
          candidate_paths: new_paths,
          active_path: active,
        )
      list.map(table.policies, fn(p) {
        case p.color == color && p.endpoint == endpoint {
          True -> new_policy
          False -> p
        }
      })
    }
    Error(Nil) -> {
      let new_paths = [candidate_path]
      let active = select_active_candidate_path(new_paths)
      let new_policy =
        SrPolicy(
          color: color,
          endpoint: endpoint,
          candidate_paths: new_paths,
          active_path: active,
        )
      [new_policy, ..table.policies]
    }
  }

  SrPolicyTable(policies: updated_policies)
}

pub fn remove_sr_policy(
  table: SrPolicyTable,
  color: Int,
  endpoint: IpAddress,
) -> SrPolicyTable {
  SrPolicyTable(
    policies: list.filter(table.policies, fn(p) {
      !{ p.color == color && p.endpoint == endpoint }
    }),
  )
}

// --- Color Steering Engine ---

pub fn steer_route(
  _prefix: IpPrefix,
  next_hop: IpAddress,
  ext_communities: List(ExtendedCommunity),
  table: SrPolicyTable,
) -> SteeredPath {
  // Extract Color Extended Community
  let color_opt =
    list.find_map(ext_communities, fn(comm) {
      decode_color_extended_community(comm)
    })

  case color_opt {
    Ok(color) -> {
      let match_policy =
        list.find(table.policies, fn(p) {
          p.color == color && p.endpoint == next_hop
        })

      case match_policy {
        Ok(policy) -> {
          case policy.active_path {
            Some(active) -> {
              case list.is_empty(active.segment_lists) {
                False ->
                  SteeredSrPolicy(
                    color: color,
                    endpoint: next_hop,
                    active_path: active,
                  )
                True -> SteeredStandardNextHop(next_hop)
              }
            }
            None -> SteeredStandardNextHop(next_hop)
          }
        }
        Error(Nil) -> SteeredStandardNextHop(next_hop)
      }
    }
    Error(Nil) -> SteeredStandardNextHop(next_hop)
  }
}

pub fn sr_policy_to_string(policy: SrPolicy) -> String {
  let ep_str = ip_to_string(policy.endpoint)
  let status_str = case policy.active_path {
    Some(ap) -> {
      "Active (Pref: "
      <> int.to_string(ap.preference)
      <> ", SegLists: "
      <> int.to_string(list.length(ap.segment_lists))
      <> ")"
    }
    None -> "Inactive"
  }
  "Color "
  <> int.to_string(policy.color)
  <> " -> "
  <> ep_str
  <> " ["
  <> status_str
  <> "]"
}
