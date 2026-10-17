//// RFC 7752: Distribution of BGP Link-State (BGP-LS)
////
//// Implements BGP-LS NLRI (AFI 16388 / SAFI 71) and BGP-LS Attribute (Type 29)
//// wire encoding, decoding, and topology graph extraction.

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import slopbgp/ip.{bytes_to_ipv6, ip_to_bytes}
import slopbgp/types.{type IpAddress, Ipv4}

pub const afi_bgp_ls = 16_388

pub const safi_bgp_ls = 71

pub const attr_bgp_ls = 29

// NLRI Types
pub const nlri_node = 1

pub const nlri_link = 2

pub const nlri_ipv4_prefix = 3

pub const nlri_ipv6_prefix = 4

// Protocol IDs
pub const proto_isis_l1 = 1

pub const proto_isis_l2 = 2

pub const proto_ospfv2 = 3

pub const proto_direct = 4

pub const proto_static = 5

pub const proto_ospfv3 = 6

pub const proto_bgp = 7

// Node Descriptor Sub-TLVs
pub const tlv_node_as = 512

pub const tlv_node_ls_id = 513

pub const tlv_node_ospf_area = 514

pub const tlv_node_igp_router_id = 515

// Link Descriptor Sub-TLVs
pub const tlv_link_local_remote_id = 258

pub const tlv_link_ipv4_iface = 259

pub const tlv_link_ipv4_nbr = 260

pub const tlv_link_ipv6_iface = 261

pub const tlv_link_ipv6_nbr = 262

// BGP-LS Attribute TLVs
pub const tlv_attr_node_name = 1026

pub const tlv_attr_admin_group = 1088

pub const tlv_attr_max_link_bw = 1089

pub const tlv_attr_max_res_bw = 1090

pub const tlv_attr_te_metric = 1092

pub const tlv_attr_igp_metric = 1095

pub const tlv_attr_link_protection = 1093

pub type BgpLsNodeDescriptor {
  BgpLsNodeDescriptor(asn: Int, ls_id: Int, igp_router_id: String)
}

pub type BgpLsLinkDescriptor {
  BgpLsLinkDescriptor(
    local_id: Int,
    remote_id: Int,
    local_ip: Option(IpAddress),
    remote_ip: Option(IpAddress),
  )
}

pub type BgpLsNlri {
  LsNodeNlri(protocol_id: Int, identifier: Int, node: BgpLsNodeDescriptor)
  LsLinkNlri(
    protocol_id: Int,
    identifier: Int,
    local_node: BgpLsNodeDescriptor,
    remote_node: BgpLsNodeDescriptor,
    link: BgpLsLinkDescriptor,
  )
}

pub type BgpLsAttributes {
  BgpLsAttributes(
    node_name: Option(String),
    igp_metric: Option(Int),
    te_metric: Option(Int),
    max_bandwidth_bytes: Option(Float),
    admin_group: Option(Int),
  )
}

pub fn default_ls_attributes() -> BgpLsAttributes {
  BgpLsAttributes(
    node_name: None,
    igp_metric: None,
    te_metric: None,
    max_bandwidth_bytes: None,
    admin_group: None,
  )
}

/// Encode a Node Descriptor TLV list
pub fn encode_node_descriptor(desc: BgpLsNodeDescriptor) -> BitArray {
  let as_bin = <<tlv_node_as:16, 4:16, desc.asn:32>>
  let ls_bin = <<tlv_node_ls_id:16, 4:16, desc.ls_id:32>>
  let r_id_bytes = bit_array.from_string(desc.igp_router_id)
  let r_id_len = bit_array.byte_size(r_id_bytes)
  let r_id_bin = <<tlv_node_igp_router_id:16, r_id_len:16, r_id_bytes:bits>>
  <<as_bin:bits, ls_bin:bits, r_id_bin:bits>>
}

/// Encode a Link Descriptor TLV list
pub fn encode_link_descriptor(desc: BgpLsLinkDescriptor) -> BitArray {
  let id_bin = <<
    tlv_link_local_remote_id:16,
    8:16,
    desc.local_id:32,
    desc.remote_id:32,
  >>
  let local_ip_bin = case desc.local_ip {
    Some(Ipv4(a, b, c, d)) -> <<
      tlv_link_ipv4_iface:16,
      4:16,
      a:8,
      b:8,
      c:8,
      d:8,
    >>
    Some(ip) -> {
      let b = ip_to_bytes(ip)
      <<tlv_link_ipv6_iface:16, 16:16, b:bits>>
    }
    None -> <<>>
  }
  let remote_ip_bin = case desc.remote_ip {
    Some(Ipv4(a, b, c, d)) -> <<tlv_link_ipv4_nbr:16, 4:16, a:8, b:8, c:8, d:8>>
    Some(ip) -> {
      let b = ip_to_bytes(ip)
      <<tlv_link_ipv6_nbr:16, 16:16, b:bits>>
    }
    None -> <<>>
  }
  <<id_bin:bits, local_ip_bin:bits, remote_ip_bin:bits>>
}

/// Encode a BGP-LS NLRI
pub fn encode_bgp_ls_nlri(nlri: BgpLsNlri) -> BitArray {
  case nlri {
    LsNodeNlri(proto, id, node) -> {
      let node_desc = encode_node_descriptor(node)
      let desc_len = bit_array.byte_size(node_desc)
      let payload = <<proto:8, id:64, 256:16, desc_len:16, node_desc:bits>>
      let total_len = bit_array.byte_size(payload)
      <<nlri_node:16, total_len:16, payload:bits>>
    }
    LsLinkNlri(proto, id, local_node, remote_node, link) -> {
      let l_desc = encode_node_descriptor(local_node)
      let l_len = bit_array.byte_size(l_desc)
      let r_desc = encode_node_descriptor(remote_node)
      let r_len = bit_array.byte_size(r_desc)
      let link_desc = encode_link_descriptor(link)

      let payload = <<
        proto:8,
        id:64,
        256:16,
        l_len:16,
        l_desc:bits,
        257:16,
        r_len:16,
        r_desc:bits,
        link_desc:bits,
      >>
      let total_len = bit_array.byte_size(payload)
      <<nlri_link:16, total_len:16, payload:bits>>
    }
  }
}

/// Encode BGP-LS Attribute (Type 29) TLVs
pub fn encode_bgp_ls_attributes(attrs: BgpLsAttributes) -> BitArray {
  let name_bin = case attrs.node_name {
    Some(name) -> {
      let b = bit_array.from_string(name)
      let len = bit_array.byte_size(b)
      <<tlv_attr_node_name:16, len:16, b:bits>>
    }
    None -> <<>>
  }
  let igp_bin = case attrs.igp_metric {
    Some(m) -> <<tlv_attr_igp_metric:16, 4:16, m:32>>
    None -> <<>>
  }
  let te_bin = case attrs.te_metric {
    Some(m) -> <<tlv_attr_te_metric:16, 4:16, m:32>>
    None -> <<>>
  }
  let bw_bin = case attrs.max_bandwidth_bytes {
    Some(bw) -> <<tlv_attr_max_link_bw:16, 4:16, bw:float-32>>
    None -> <<>>
  }
  let admin_bin = case attrs.admin_group {
    Some(ag) -> <<tlv_attr_admin_group:16, 4:16, ag:32>>
    None -> <<>>
  }
  <<name_bin:bits, igp_bin:bits, te_bin:bits, bw_bin:bits, admin_bin:bits>>
}

/// Decode a Node Descriptor from wire TLVs
pub fn decode_node_descriptor(
  bytes: BitArray,
) -> Result(BgpLsNodeDescriptor, String) {
  decode_node_desc_loop(bytes, 0, 0, "")
}

fn decode_node_desc_loop(
  bytes: BitArray,
  asn: Int,
  ls_id: Int,
  r_id: String,
) -> Result(BgpLsNodeDescriptor, String) {
  case bytes {
    <<>> -> Ok(BgpLsNodeDescriptor(asn: asn, ls_id: ls_id, igp_router_id: r_id))
    <<tag:16, len:16, rest:bits>> -> {
      case tag {
        512 -> {
          case rest {
            <<as_val:32, rem:bits>> ->
              decode_node_desc_loop(rem, as_val, ls_id, r_id)
            _ -> Error("Truncated ASN in BGP-LS node descriptor")
          }
        }
        513 -> {
          case rest {
            <<id_val:32, rem:bits>> ->
              decode_node_desc_loop(rem, asn, id_val, r_id)
            _ -> Error("Truncated LS-ID in BGP-LS node descriptor")
          }
        }
        515 -> {
          case rest {
            <<id_bytes:bytes-size(len), rem:bits>> -> {
              let str = case bit_array.to_string(id_bytes) {
                Ok(s) -> s
                Error(_) -> "unknown"
              }
              decode_node_desc_loop(rem, asn, ls_id, str)
            }
            _ -> Error("Truncated IGP Router ID in BGP-LS descriptor")
          }
        }
        _ -> {
          case rest {
            <<_:bytes-size(len), rem:bits>> ->
              decode_node_desc_loop(rem, asn, ls_id, r_id)
            _ -> Error("Truncated sub-TLV in BGP-LS node descriptor")
          }
        }
      }
    }
    _ -> Error("Malformed BGP-LS node descriptor")
  }
}

/// Decode BGP-LS NLRI
pub fn decode_bgp_ls_nlri(bytes: BitArray) -> Result(BgpLsNlri, String) {
  case bytes {
    <<1:16, _len:16, proto:8, id:64, 256:16, d_len:16, rest:bits>> -> {
      case rest {
        <<node_data:bytes-size(d_len), _rem:bits>> -> {
          case decode_node_descriptor(node_data) {
            Ok(node) -> Ok(LsNodeNlri(proto, id, node))
            Error(err) -> Error(err)
          }
        }
        _ -> Error("Truncated BGP-LS node NLRI")
      }
    }
    <<2:16, _len:16, proto:8, id:64, 256:16, l_len:16, rest:bits>> -> {
      case rest {
        <<
          l_data:bytes-size(l_len),
          257:16,
          r_len:16,
          r_data:bytes-size(r_len),
          link_data:bits,
        >> -> {
          case decode_node_descriptor(l_data), decode_node_descriptor(r_data) {
            Ok(l_node), Ok(r_node) -> {
              let link_desc = decode_link_descriptor(link_data)
              Ok(LsLinkNlri(proto, id, l_node, r_node, link_desc))
            }
            _, _ ->
              Error("Malformed local/remote node descriptors in BGP-LS link")
          }
        }
        _ -> Error("Truncated BGP-LS link NLRI")
      }
    }
    _ -> Error("Unknown or unsupported BGP-LS NLRI type")
  }
}

pub fn decode_link_descriptor(bytes: BitArray) -> BgpLsLinkDescriptor {
  decode_link_desc_loop(bytes, 0, 0, None, None)
}

fn decode_link_desc_loop(
  bytes: BitArray,
  local_id: Int,
  remote_id: Int,
  l_ip: Option(IpAddress),
  r_ip: Option(IpAddress),
) -> BgpLsLinkDescriptor {
  case bytes {
    <<>> ->
      BgpLsLinkDescriptor(
        local_id: local_id,
        remote_id: remote_id,
        local_ip: l_ip,
        remote_ip: r_ip,
      )
    <<tag:16, len:16, rest:bits>> -> {
      case tag {
        258 -> {
          case rest {
            <<lid:32, rid:32, rem:bits>> ->
              decode_link_desc_loop(rem, lid, rid, l_ip, r_ip)
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
        259 -> {
          case rest {
            <<a:8, b:8, c:8, d:8, rem:bits>> ->
              decode_link_desc_loop(
                rem,
                local_id,
                remote_id,
                Some(Ipv4(a, b, c, d)),
                r_ip,
              )
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
        260 -> {
          case rest {
            <<a:8, b:8, c:8, d:8, rem:bits>> ->
              decode_link_desc_loop(
                rem,
                local_id,
                remote_id,
                l_ip,
                Some(Ipv4(a, b, c, d)),
              )
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
        261 -> {
          case rest {
            <<ip6_bytes:bytes-size(16), rem:bits>> -> {
              case bytes_to_ipv6(ip6_bytes) {
                Ok(ip6) ->
                  decode_link_desc_loop(
                    rem,
                    local_id,
                    remote_id,
                    Some(ip6),
                    r_ip,
                  )
                Error(_) ->
                  decode_link_desc_loop(rem, local_id, remote_id, l_ip, r_ip)
              }
            }
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
        262 -> {
          case rest {
            <<ip6_bytes:bytes-size(16), rem:bits>> -> {
              case bytes_to_ipv6(ip6_bytes) {
                Ok(ip6) ->
                  decode_link_desc_loop(
                    rem,
                    local_id,
                    remote_id,
                    l_ip,
                    Some(ip6),
                  )
                Error(_) ->
                  decode_link_desc_loop(rem, local_id, remote_id, l_ip, r_ip)
              }
            }
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
        _ -> {
          case rest {
            <<_:bytes-size(len), rem:bits>> ->
              decode_link_desc_loop(rem, local_id, remote_id, l_ip, r_ip)
            _ -> BgpLsLinkDescriptor(local_id, remote_id, l_ip, r_ip)
          }
        }
      }
    }
    _ ->
      BgpLsLinkDescriptor(
        local_id: local_id,
        remote_id: remote_id,
        local_ip: l_ip,
        remote_ip: r_ip,
      )
  }
}

/// Decode BGP-LS Attribute TLVs
pub fn decode_bgp_ls_attributes(bytes: BitArray) -> BgpLsAttributes {
  decode_ls_attrs_loop(bytes, default_ls_attributes())
}

fn decode_ls_attrs_loop(
  bytes: BitArray,
  acc: BgpLsAttributes,
) -> BgpLsAttributes {
  case bytes {
    <<>> -> acc
    <<tag:16, len:16, rest:bits>> -> {
      case tag {
        1026 -> {
          case rest {
            <<name_bytes:bytes-size(len), rem:bits>> -> {
              let name = case bit_array.to_string(name_bytes) {
                Ok(s) -> Some(s)
                Error(_) -> None
              }
              decode_ls_attrs_loop(rem, BgpLsAttributes(..acc, node_name: name))
            }
            _ -> acc
          }
        }
        1095 -> {
          case rest {
            <<m:32, rem:bits>> ->
              decode_ls_attrs_loop(
                rem,
                BgpLsAttributes(..acc, igp_metric: Some(m)),
              )
            _ -> acc
          }
        }
        1092 -> {
          case rest {
            <<m:32, rem:bits>> ->
              decode_ls_attrs_loop(
                rem,
                BgpLsAttributes(..acc, te_metric: Some(m)),
              )
            _ -> acc
          }
        }
        1089 -> {
          case rest {
            <<bw:float-32, rem:bits>> ->
              decode_ls_attrs_loop(
                rem,
                BgpLsAttributes(..acc, max_bandwidth_bytes: Some(bw)),
              )
            _ -> acc
          }
        }
        1088 -> {
          case rest {
            <<ag:32, rem:bits>> ->
              decode_ls_attrs_loop(
                rem,
                BgpLsAttributes(..acc, admin_group: Some(ag)),
              )
            _ -> acc
          }
        }
        _ -> {
          case rest {
            <<_:bytes-size(len), rem:bits>> -> decode_ls_attrs_loop(rem, acc)
            _ -> acc
          }
        }
      }
    }
    _ -> acc
  }
}
