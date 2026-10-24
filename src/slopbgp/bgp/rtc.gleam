import gleam/dict.{type Dict}
import gleam/int
import gleam/json
import gleam/list
import slopbgp/bgp/l3vpn.{
  type RouteTarget, decode_route_target, encode_route_target,
  route_target_to_string,
}
import slopbgp/types.{type Route, ExtCommunity}

// RFC 4684: Constrained Route Distribution for BGP/MPLS IP VPNs (Route Target Constraint - RTC)

pub type RtcPrefix {
  RtcDefault
  RtcOriginAs(origin_as: Int)
  RtcFull(origin_as: Int, route_target: RouteTarget)
}

pub type RtcNlri {
  RtcNlri(prefix: RtcPrefix)
}

pub type RtcPeerSubscription {
  RtcPeerSubscription(
    peer_id: String,
    remote_as: Int,
    subscriptions: List(RtcPrefix),
  )
}

pub type RtcTable {
  RtcTable(peers: Dict(String, RtcPeerSubscription))
}

pub fn new_rtc_table() -> RtcTable {
  RtcTable(peers: dict.new())
}

// --- Encoding RTC NLRI (AFI 1, SAFI 132) ---

pub fn encode_rtc_nlri(nlri: RtcNlri) -> BitArray {
  case nlri.prefix {
    RtcDefault -> <<0:8>>
    RtcOriginAs(origin_as) -> <<32:8, origin_as:32>>
    RtcFull(origin_as, target) -> {
      let ext = encode_route_target(target)
      let rt_bytes = <<ext.type_code:8, ext.sub_type:8, ext.value:bits>>
      <<96:8, origin_as:32, rt_bytes:bits>>
    }
  }
}

pub fn encode_rtc_nlri_list(nlris: List(RtcNlri)) -> BitArray {
  list.fold(nlris, <<>>, fn(acc, n) {
    <<acc:bits, { encode_rtc_nlri(n) }:bits>>
  })
}

// --- Decoding RTC NLRI ---

pub fn decode_rtc_nlri(bytes: BitArray) -> Result(List(RtcNlri), String) {
  decode_rtc_nlri_loop(bytes, [])
}

fn decode_rtc_nlri_loop(
  bytes: BitArray,
  acc: List(RtcNlri),
) -> Result(List(RtcNlri), String) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    <<0:8, rest:bits>> -> {
      decode_rtc_nlri_loop(rest, [RtcNlri(RtcDefault), ..acc])
    }
    <<32:8, origin_as:32, rest:bits>> -> {
      decode_rtc_nlri_loop(rest, [RtcNlri(RtcOriginAs(origin_as)), ..acc])
    }
    <<96:8, origin_as:32, t_code:8, s_code:8, val:bits-size(48), rest:bits>> -> {
      let ext = ExtCommunity(t_code, s_code, val)
      case decode_route_target(ext) {
        Ok(target) ->
          decode_rtc_nlri_loop(rest, [
            RtcNlri(RtcFull(origin_as, target)),
            ..acc
          ])
        Error(err) -> Error("Invalid Route Target in RTC NLRI: " <> err)
      }
    }
    _ -> Error("Malformed RFC 4684 RTC NLRI framing")
  }
}

// --- RTC Table Management ---

pub fn add_peer_subscription(
  table: RtcTable,
  peer_id: String,
  remote_as: Int,
  prefix: RtcPrefix,
) -> RtcTable {
  let existing = case dict.get(table.peers, peer_id) {
    Ok(sub) -> sub
    Error(_) -> RtcPeerSubscription(peer_id, remote_as, [])
  }
  let updated_subs = case list.contains(existing.subscriptions, prefix) {
    True -> existing.subscriptions
    False -> [prefix, ..existing.subscriptions]
  }
  let new_sub = RtcPeerSubscription(peer_id, remote_as, updated_subs)
  RtcTable(dict.insert(table.peers, peer_id, new_sub))
}

pub fn remove_peer_subscription(
  table: RtcTable,
  peer_id: String,
  prefix: RtcPrefix,
) -> RtcTable {
  case dict.get(table.peers, peer_id) {
    Ok(sub) -> {
      let filtered = list.filter(sub.subscriptions, fn(s) { s != prefix })
      let new_sub = RtcPeerSubscription(sub.peer_id, sub.remote_as, filtered)
      RtcTable(dict.insert(table.peers, peer_id, new_sub))
    }
    Error(_) -> table
  }
}

pub fn remove_peer(table: RtcTable, peer_id: String) -> RtcTable {
  RtcTable(dict.delete(table.peers, peer_id))
}

// --- Outbound Route Filtering ---

pub fn matches_rtc_prefix(route_rt: RouteTarget, rtc: RtcPrefix) -> Bool {
  case rtc {
    RtcDefault -> True
    RtcOriginAs(_) -> True
    RtcFull(_, target) -> target == route_rt
  }
}

pub fn should_advertise_to_peer(
  route_rts: List(RouteTarget),
  peer_subs: List(RtcPrefix),
) -> Bool {
  case peer_subs {
    [] -> False
    _ ->
      list.any(peer_subs, fn(rtc) {
        case rtc {
          RtcDefault -> True
          RtcOriginAs(_) -> True
          RtcFull(_, target) -> list.contains(route_rts, target)
        }
      })
  }
}

pub fn filter_outbound_vpn_routes(
  routes: List(Route),
  peer_id: String,
  table: RtcTable,
) -> #(List(Route), Int) {
  case dict.get(table.peers, peer_id) {
    Error(_) -> {
      // Peer has not enabled RTC; send all routes
      #(routes, 0)
    }
    Ok(sub) -> {
      case sub.subscriptions {
        [] -> #([], list.length(routes))
        subs -> {
          let #(allowed, suppressed) =
            list.partition(routes, fn(r) {
              // Extract route targets from route's extended communities
              let rts = list.filter_map(r.ext_communities, decode_route_target)
              case rts {
                [] -> True
                // Routes with no RT pass standard policy
                _ -> should_advertise_to_peer(rts, subs)
              }
            })
          #(allowed, list.length(suppressed))
        }
      }
    }
  }
}

// --- Representation and Formatting ---

pub fn rtc_prefix_to_string(prefix: RtcPrefix) -> String {
  case prefix {
    RtcDefault -> "default (wildcard)"
    RtcOriginAs(asn) -> "origin-as:AS" <> int.to_string(asn)
    RtcFull(asn, target) ->
      "AS" <> int.to_string(asn) <> ":" <> route_target_to_string(target)
  }
}

pub fn rtc_table_to_json(table: RtcTable) -> String {
  let peer_objects =
    dict.values(table.peers)
    |> list.map(fn(sub) {
      let subs_json =
        list.map(sub.subscriptions, fn(s) {
          json.object([
            #("prefix", json.string(rtc_prefix_to_string(s))),
            #("type", case s {
              RtcDefault -> json.string("default")
              RtcOriginAs(_) -> json.string("origin_as")
              RtcFull(_, _) -> json.string("full_rt")
            }),
          ])
        })
      json.object([
        #("peer_id", json.string(sub.peer_id)),
        #("remote_as", json.int(sub.remote_as)),
        #("subscriptions", json.preprocessed_array(subs_json)),
        #("subscription_count", json.int(list.length(sub.subscriptions))),
      ])
    })

  json.object([
    #("peer_count", json.int(dict.size(table.peers))),
    #("peers", json.preprocessed_array(peer_objects)),
  ])
  |> json.to_string
}
