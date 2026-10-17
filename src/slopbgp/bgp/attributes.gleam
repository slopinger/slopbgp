import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/result
import slopbgp/bgp/capabilities.{
  afi_to_int, int_to_afi, int_to_safi, safi_to_int,
}
import slopbgp/ip.{
  bytes_to_ipv4, decode_prefixes_ipv4, decode_prefixes_ipv6, encode_prefix,
  ip_to_bytes,
}
import slopbgp/types.{
  type Afi, type AsPathSegment, type Community, type ExtendedCommunity,
  type IpAddress, type IpPrefix, type LargeCommunity, type Origin,
  type PathAttribute, type Safi, AfiIpv4, AfiIpv6, AsConfedSequence, AsConfedSet,
  AsSequence, AsSet, AttrAggregator, AttrAsPath, AttrAtomicAggregate,
  AttrClusterList, AttrCommunities, AttrExtendedCommunities,
  AttrLargeCommunities, AttrLocalPref, AttrMed, AttrMpReachNlri,
  AttrMpUnreachNlri, AttrNextHop, AttrOnlyToCustomer, AttrOrigin,
  AttrOriginatorId, AttrUnknown, Community, ExtCommunity, Ipv4, Ipv6,
  LargeCommunity, OriginEgp, OriginIgp, OriginIncomplete,
}

pub fn encode_origin(origin: Origin) -> BitArray {
  let code = case origin {
    OriginIgp -> 0
    OriginEgp -> 1
    OriginIncomplete -> 2
  }
  encode_attribute(0x40, 1, <<code:8>>)
}

pub fn encode_as_path(segments: List(AsPathSegment)) -> BitArray {
  let seg_bytes =
    list.map(segments, fn(seg) {
      case seg {
        AsSequence(asns) -> {
          let count = list.length(asns)
          let asn_bin =
            list.fold(asns, <<>>, fn(acc, asn) { <<acc:bits, asn:32>> })
          <<2:8, count:8, asn_bin:bits>>
        }
        AsSet(asns) -> {
          let count = list.length(asns)
          let asn_bin =
            list.fold(asns, <<>>, fn(acc, asn) { <<acc:bits, asn:32>> })
          <<1:8, count:8, asn_bin:bits>>
        }
        AsConfedSequence(asns) -> {
          let count = list.length(asns)
          let asn_bin =
            list.fold(asns, <<>>, fn(acc, asn) { <<acc:bits, asn:32>> })
          <<3:8, count:8, asn_bin:bits>>
        }
        AsConfedSet(asns) -> {
          let count = list.length(asns)
          let asn_bin =
            list.fold(asns, <<>>, fn(acc, asn) { <<acc:bits, asn:32>> })
          <<4:8, count:8, asn_bin:bits>>
        }
      }
    })
  let val = list.fold(seg_bytes, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
  encode_attribute(0x40, 2, val)
}

pub fn encode_next_hop(ip: IpAddress) -> BitArray {
  case ip {
    Ipv4(a, b, c, d) -> encode_attribute(0x40, 3, <<a:8, b:8, c:8, d:8>>)
    _ -> <<>>
  }
}

pub fn encode_med(med: Int) -> BitArray {
  encode_attribute(0x80, 4, <<med:32>>)
}

pub fn encode_local_pref(pref: Int) -> BitArray {
  encode_attribute(0x40, 5, <<pref:32>>)
}

pub fn encode_atomic_aggregate() -> BitArray {
  encode_attribute(0x40, 6, <<>>)
}

pub fn encode_aggregator(asn: Int, router_id: IpAddress) -> BitArray {
  let r_id = case router_id {
    Ipv4(a, b, c, d) -> <<a:8, b:8, c:8, d:8>>
    _ -> <<0:32>>
  }
  encode_attribute(0xC0, 7, <<asn:32, r_id:bits>>)
}

pub fn encode_communities(communities: List(Community)) -> BitArray {
  case communities {
    [] -> <<>>
    _ -> {
      let comm_bins = list.map(communities, fn(c) { <<c.asn:16, c.value:16>> })
      let val = list.fold(comm_bins, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
      encode_attribute(0xC0, 8, val)
    }
  }
}

pub fn encode_originator_id(ip: IpAddress) -> BitArray {
  case ip {
    Ipv4(a, b, c, d) -> encode_attribute(0x80, 9, <<a:8, b:8, c:8, d:8>>)
    _ -> <<>>
  }
}

pub fn encode_cluster_list(clusters: List(IpAddress)) -> BitArray {
  case clusters {
    [] -> <<>>
    _ -> {
      let cluster_bytes =
        list.fold(clusters, <<>>, fn(acc, c) {
          <<acc:bits, { ip_to_bytes(c) }:bits>>
        })
      encode_attribute(0x80, 10, cluster_bytes)
    }
  }
}

pub fn encode_mp_reach(
  afi: Afi,
  safi: Safi,
  next_hops: List(IpAddress),
  nlri: List(IpPrefix),
) -> BitArray {
  let afi_int = afi_to_int(afi)
  let safi_int = safi_to_int(safi)
  let nh_bytes =
    list.fold(next_hops, <<>>, fn(acc, nh) {
      <<acc:bits, { ip_to_bytes(nh) }:bits>>
    })
  let nh_len = byte_length(nh_bytes)
  let nlri_bytes =
    list.fold(nlri, <<>>, fn(acc, prefix) {
      <<acc:bits, { encode_prefix(prefix, None) }:bits>>
    })
  let val = <<
    afi_int:16,
    safi_int:8,
    nh_len:8,
    nh_bytes:bits,
    0:8,
    nlri_bytes:bits,
  >>
  encode_attribute(0x80, 14, val)
}

pub fn encode_mp_unreach(
  afi: Afi,
  safi: Safi,
  withdrawn: List(IpPrefix),
) -> BitArray {
  let afi_int = afi_to_int(afi)
  let safi_int = safi_to_int(safi)
  let w_bytes =
    list.fold(withdrawn, <<>>, fn(acc, prefix) {
      <<acc:bits, { encode_prefix(prefix, None) }:bits>>
    })
  let val = <<afi_int:16, safi_int:8, w_bytes:bits>>
  encode_attribute(0x80, 15, val)
}

pub fn encode_extended_communities(
  communities: List(ExtendedCommunity),
) -> BitArray {
  case communities {
    [] -> <<>>
    _ -> {
      let bins =
        list.map(communities, fn(c) {
          <<c.type_code:8, c.sub_type:8, c.value:bits>>
        })
      let val = list.fold(bins, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
      encode_attribute(0xC0, 16, val)
    }
  }
}

pub fn encode_large_communities(communities: List(LargeCommunity)) -> BitArray {
  case communities {
    [] -> <<>>
    _ -> {
      let bins =
        list.map(communities, fn(c) {
          <<c.global_admin:32, c.local_data1:32, c.local_data2:32>>
        })
      let val = list.fold(bins, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
      encode_attribute(0xC0, 32, val)
    }
  }
}

pub fn encode_only_to_customer(asn: Int) -> BitArray {
  encode_attribute(0xC0, 35, <<asn:32>>)
}

pub fn encode_path_attribute(attr: PathAttribute) -> BitArray {
  case attr {
    AttrOrigin(o) -> encode_origin(o)
    AttrAsPath(segs) -> encode_as_path(segs)
    AttrNextHop(ip) -> encode_next_hop(ip)
    AttrMed(m) -> encode_med(m)
    AttrLocalPref(p) -> encode_local_pref(p)
    AttrAtomicAggregate -> encode_atomic_aggregate()
    AttrAggregator(asn, r_id) -> encode_aggregator(asn, r_id)
    AttrCommunities(comms) -> encode_communities(comms)
    AttrOriginatorId(id) -> encode_originator_id(id)
    AttrClusterList(cls) -> encode_cluster_list(cls)
    AttrMpReachNlri(afi, safi, nhs, nlri) ->
      encode_mp_reach(afi, safi, nhs, nlri)
    AttrMpUnreachNlri(afi, safi, w) -> encode_mp_unreach(afi, safi, w)
    AttrExtendedCommunities(comms) -> encode_extended_communities(comms)
    AttrLargeCommunities(comms) -> encode_large_communities(comms)
    AttrOnlyToCustomer(asn) -> encode_only_to_customer(asn)
    AttrUnknown(flags, type_code, data) ->
      encode_attribute(flags, type_code, data)
  }
}

pub fn encode_attributes(attrs: List(PathAttribute)) -> BitArray {
  list.fold(attrs, <<>>, fn(acc, attr) {
    <<acc:bits, { encode_path_attribute(attr) }:bits>>
  })
}

fn encode_attribute(flags: Int, type_code: Int, data: BitArray) -> BitArray {
  let len = byte_length(data)
  case len > 255 {
    True -> {
      let ext_flags = int_bitwise_or(flags, 0x10)
      <<ext_flags:8, type_code:8, len:16, data:bits>>
    }
    False -> <<flags:8, type_code:8, len:8, data:bits>>
  }
}

pub fn decode_attributes(
  bytes: BitArray,
  has_add_path: Bool,
) -> Result(List(PathAttribute), String) {
  decode_attributes_loop(bytes, has_add_path, [])
}

fn decode_attributes_loop(
  bytes: BitArray,
  has_add_path: Bool,
  acc: List(PathAttribute),
) -> Result(List(PathAttribute), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    <<flags:8, type_code:8, rest:bits>> -> {
      let is_extended = int_bitwise_and(flags, 0x10) != 0
      use #(len, data_rest) <- result.try(case is_extended {
        True ->
          case rest {
            <<l:16, r:bits>> -> Ok(#(l, r))
            _ -> Error("Truncated extended attribute length")
          }
        False ->
          case rest {
            <<l:8, r:bits>> -> Ok(#(l, r))
            _ -> Error("Truncated standard attribute length")
          }
      })

      let bits_needed = len * 8
      case data_rest {
        <<data:bits-size(bits_needed), rem:bits>> -> {
          let attr =
            decode_single_attribute(flags, type_code, data, has_add_path)
          decode_attributes_loop(rem, has_add_path, [attr, ..acc])
        }
        _ -> Error("Attribute length exceeds remaining data")
      }
    }
    _ -> Error("Malformed path attribute header")
  }
}

fn decode_single_attribute(
  flags: Int,
  type_code: Int,
  data: BitArray,
  has_add_path: Bool,
) -> PathAttribute {
  case type_code {
    1 ->
      case data {
        <<0:8>> -> AttrOrigin(OriginIgp)
        <<1:8>> -> AttrOrigin(OriginEgp)
        <<2:8>> -> AttrOrigin(OriginIncomplete)
        _ -> AttrOrigin(OriginIncomplete)
      }
    2 -> {
      let segments = decode_as_path_segments(data, [])
      AttrAsPath(segments)
    }
    3 ->
      case bytes_to_ipv4(data) {
        Ok(ip) -> AttrNextHop(ip)
        Error(_) -> AttrUnknown(flags, type_code, data)
      }
    4 ->
      case data {
        <<med:32>> -> AttrMed(med)
        _ -> AttrUnknown(flags, type_code, data)
      }
    5 ->
      case data {
        <<pref:32>> -> AttrLocalPref(pref)
        _ -> AttrUnknown(flags, type_code, data)
      }
    6 -> AttrAtomicAggregate
    7 ->
      case data {
        <<asn:32, a:8, b:8, c:8, d:8>> -> AttrAggregator(asn, Ipv4(a, b, c, d))
        <<asn:16, a:8, b:8, c:8, d:8>> -> AttrAggregator(asn, Ipv4(a, b, c, d))
        _ -> AttrUnknown(flags, type_code, data)
      }
    8 -> {
      let comms = decode_communities_data(data, [])
      AttrCommunities(comms)
    }
    9 ->
      case bytes_to_ipv4(data) {
        Ok(ip) -> AttrOriginatorId(ip)
        Error(_) -> AttrUnknown(flags, type_code, data)
      }
    10 -> {
      let clusters = decode_cluster_list_data(data, [])
      AttrClusterList(clusters)
    }
    14 ->
      case decode_mp_reach_data(data, has_add_path) {
        Ok(attr) -> attr
        Error(_) -> AttrUnknown(flags, type_code, data)
      }
    15 ->
      case decode_mp_unreach_data(data, has_add_path) {
        Ok(attr) -> attr
        Error(_) -> AttrUnknown(flags, type_code, data)
      }
    16 -> {
      let comms = decode_ext_communities_data(data, [])
      AttrExtendedCommunities(comms)
    }
    32 -> {
      let comms = decode_large_communities_data(data, [])
      AttrLargeCommunities(comms)
    }
    35 ->
      case data {
        <<asn:32>> -> AttrOnlyToCustomer(asn)
        _ -> AttrUnknown(flags, type_code, data)
      }
    _ -> AttrUnknown(flags, type_code, data)
  }
}

fn decode_as_path_segments(
  bytes: BitArray,
  acc: List(AsPathSegment),
) -> List(AsPathSegment) {
  case bytes {
    <<>> -> list.reverse(acc)
    <<seg_type:8, count:8, rest:bits>> -> {
      let #(asns, rem) = decode_asns(rest, count, [])
      let seg = case seg_type {
        1 -> AsSet(asns)
        2 -> AsSequence(asns)
        3 -> AsConfedSequence(asns)
        4 -> AsConfedSet(asns)
        _ -> AsSequence(asns)
      }
      decode_as_path_segments(rem, [seg, ..acc])
    }
    _ -> list.reverse(acc)
  }
}

fn decode_cluster_list_data(
  data: BitArray,
  acc: List(IpAddress),
) -> List(IpAddress) {
  case data {
    <<a:8, b:8, c:8, d:8, rest:bits>> ->
      decode_cluster_list_data(rest, [Ipv4(a, b, c, d), ..acc])
    _ -> list.reverse(acc)
  }
}

fn decode_asns(
  bytes: BitArray,
  count: Int,
  acc: List(Int),
) -> #(List(Int), BitArray) {
  case count <= 0 {
    True -> #(list.reverse(acc), bytes)
    False ->
      case bytes {
        <<asn:32, rest:bits>> -> decode_asns(rest, count - 1, [asn, ..acc])
        _ -> #(list.reverse(acc), bytes)
      }
  }
}

fn decode_communities_data(
  bytes: BitArray,
  acc: List(Community),
) -> List(Community) {
  case bytes {
    <<asn:16, val:16, rest:bits>> ->
      decode_communities_data(rest, [Community(asn, val), ..acc])
    _ -> list.reverse(acc)
  }
}

fn decode_ext_communities_data(
  bytes: BitArray,
  acc: List(ExtendedCommunity),
) -> List(ExtendedCommunity) {
  case bytes {
    <<t:8, s:8, v:bits-size(48), rest:bits>> ->
      decode_ext_communities_data(rest, [ExtCommunity(t, s, v), ..acc])
    _ -> list.reverse(acc)
  }
}

fn decode_large_communities_data(
  bytes: BitArray,
  acc: List(LargeCommunity),
) -> List(LargeCommunity) {
  case bytes {
    <<g:32, d1:32, d2:32, rest:bits>> ->
      decode_large_communities_data(rest, [LargeCommunity(g, d1, d2), ..acc])
    _ -> list.reverse(acc)
  }
}

fn decode_mp_reach_data(
  bytes: BitArray,
  has_add_path: Bool,
) -> Result(PathAttribute, String) {
  case bytes {
    <<afi_int:16, safi_int:8, nh_len:8, rest1:bits>> -> {
      let afi = int_to_afi(afi_int)
      let safi = int_to_safi(safi_int)
      let nh_bits = nh_len * 8
      case rest1 {
        <<nh_raw:bits-size(nh_bits), _:8, nlri_raw:bits>> -> {
          let next_hops = decode_next_hop_addrs(afi, nh_raw)
          use prefixes_with_id <- result.try(case afi {
            AfiIpv6 -> decode_prefixes_ipv6(nlri_raw, has_add_path)
            AfiIpv4 -> decode_prefixes_ipv4(nlri_raw, has_add_path)
            _ -> Ok([])
          })
          let prefixes = list.map(prefixes_with_id, fn(p) { p.0 })
          Ok(AttrMpReachNlri(afi, safi, next_hops, prefixes))
        }
        _ -> Error("Invalid MP_REACH_NLRI layout")
      }
    }
    _ -> Error("Truncated MP_REACH_NLRI header")
  }
}

fn decode_mp_unreach_data(
  bytes: BitArray,
  has_add_path: Bool,
) -> Result(PathAttribute, String) {
  case bytes {
    <<afi_int:16, safi_int:8, nlri_raw:bits>> -> {
      let afi = int_to_afi(afi_int)
      let safi = int_to_safi(safi_int)
      use prefixes_with_id <- result.try(case afi {
        AfiIpv6 -> decode_prefixes_ipv6(nlri_raw, has_add_path)
        AfiIpv4 -> decode_prefixes_ipv4(nlri_raw, has_add_path)
        _ -> Ok([])
      })
      let prefixes = list.map(prefixes_with_id, fn(p) { p.0 })
      Ok(AttrMpUnreachNlri(afi, safi, prefixes))
    }
    _ -> Error("Truncated MP_UNREACH_NLRI header")
  }
}

fn decode_next_hop_addrs(afi: Afi, bytes: BitArray) -> List(IpAddress) {
  case afi {
    AfiIpv4 ->
      case bytes {
        <<a:8, b:8, c:8, d:8>> -> [Ipv4(a, b, c, d)]
        _ -> []
      }
    AfiIpv6 ->
      case bytes {
        <<
          ga:16,
          gb:16,
          gc:16,
          gd:16,
          ge:16,
          gf:16,
          gg:16,
          gh:16,
          la:16,
          lb:16,
          lc:16,
          ld:16,
          le:16,
          lf:16,
          lg:16,
          lh:16,
        >> -> [
          Ipv6(ga, gb, gc, gd, ge, gf, gg, gh),
          Ipv6(la, lb, lc, ld, le, lf, lg, lh),
        ]
        <<ga:16, gb:16, gc:16, gd:16, ge:16, gf:16, gg:16, gh:16>> -> [
          Ipv6(ga, gb, gc, gd, ge, gf, gg, gh),
        ]
        _ -> []
      }
    _ -> []
  }
}

fn byte_length(bytes: BitArray) -> Int {
  case bytes {
    <<_:8, rest:bits>> -> 1 + byte_length(rest)
    _ -> 0
  }
}

fn int_bitwise_and(a: Int, b: Int) -> Int {
  int.bitwise_and(a, b)
}

fn int_bitwise_or(a: Int, b: Int) -> Int {
  int.bitwise_or(a, b)
}
