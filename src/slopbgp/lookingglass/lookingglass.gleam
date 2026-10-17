import gleam/int
import gleam/json
import gleam/list
import gleam/string
import slopbgp/bgp/blackhole.{has_blackhole_community}
import slopbgp/ip.{
  ip_to_string, is_ip_in_prefix, is_prefix_contained, parse_ip, parse_prefix,
  prefix_to_string,
}
import slopbgp/types.{
  type AsPathSegment, type PeerStats, type Route, AsConfedSequence, AsConfedSet,
  AsSequence, AsSet, OriginEgp, OriginIgp, OriginIncomplete, RoaInvalid,
  RoaNotFound, RoaValid, StateEstablished,
}

pub type LgRouteDetail {
  LgRouteDetail(
    prefix: String,
    best: Bool,
    next_hop: String,
    as_path: String,
    origin: String,
    local_pref: Int,
    med: Int,
    roa_status: String,
    communities: List(String),
    large_communities: List(String),
    peer_id: String,
    age_seconds: Int,
    is_blackhole: Bool,
  )
}

pub type LgQueryResult {
  LgQueryResult(
    query: String,
    query_type: String,
    routes_found: Int,
    routes: List(LgRouteDetail),
  )
}

pub type LgSummary {
  LgSummary(
    asn: Int,
    router_id: String,
    uptime_seconds: Int,
    peers_total: Int,
    peers_established: Int,
    routes_total: Int,
    roa_total: Int,
    rtr_status: String,
    bfd_sessions_up: Int,
    blackholes_active: Int,
  )
}

pub fn route_to_detail(route: Route, best: Bool, now_ts: Int) -> LgRouteDetail {
  let p_str = prefix_to_string(route.prefix)
  let nh_str = ip_to_string(route.next_hop)
  let as_path_str = format_as_path(route.as_path)
  let roa_str = case route.roa_status {
    RoaValid -> "VALID"
    RoaInvalid -> "INVALID"
    RoaNotFound -> "NOT_FOUND"
  }
  let origin_str = case route.origin {
    OriginIgp -> "IGP"
    OriginEgp -> "EGP"
    OriginIncomplete -> "INCOMPLETE"
  }
  let comms =
    list.map(route.communities, fn(c) {
      int.to_string(c.asn) <> ":" <> int.to_string(c.value)
    })
  let lcomms =
    list.map(route.large_communities, fn(lc) {
      int.to_string(lc.global_admin)
      <> ":"
      <> int.to_string(lc.local_data1)
      <> ":"
      <> int.to_string(lc.local_data2)
    })
  let age = case now_ts >= route.timestamp {
    True -> now_ts - route.timestamp
    False -> 0
  }
  let blackhole = has_blackhole_community(route.communities)

  LgRouteDetail(
    prefix: p_str,
    best: best,
    next_hop: nh_str,
    as_path: as_path_str,
    origin: origin_str,
    local_pref: route.local_pref,
    med: route.med,
    roa_status: roa_str,
    communities: comms,
    large_communities: lcomms,
    peer_id: route.peer_id,
    age_seconds: age,
    is_blackhole: blackhole,
  )
}

pub fn query_route(
  routes: List(Route),
  now_ts: Int,
  query_str: String,
) -> LgQueryResult {
  let trimmed = string.trim(query_str)
  let matching_routes = case parse_prefix(trimmed) {
    Ok(target_prefix) -> {
      // Find exact match or covering prefixes
      list.filter(routes, fn(r) {
        prefix_to_string(r.prefix) == trimmed
        || is_prefix_contained(target_prefix, r.prefix)
        || is_prefix_contained(r.prefix, target_prefix)
      })
    }
    Error(_) -> {
      // Try parsing single IP address for longest prefix match
      case parse_ip(trimmed) {
        Ok(ip) -> list.filter(routes, fn(r) { is_ip_in_prefix(ip, r.prefix) })
        Error(_) -> []
      }
    }
  }

  // Sort: longest prefix length first (LPM)
  let sorted =
    list.sort(matching_routes, fn(a, b) {
      int.compare(b.prefix.length, a.prefix.length)
    })

  let details =
    list.index_map(sorted, fn(r, idx) {
      let is_best = idx == 0
      route_to_detail(r, is_best, now_ts)
    })

  LgQueryResult(
    query: trimmed,
    query_type: "route",
    routes_found: list.length(details),
    routes: details,
  )
}

pub fn query_aspath(
  routes: List(Route),
  now_ts: Int,
  asn_str: String,
) -> LgQueryResult {
  let trimmed = string.trim(asn_str)
  let matching = case int.parse(trimmed) {
    Ok(target_asn) -> {
      list.filter(routes, fn(r) { as_path_contains_asn(r.as_path, target_asn) })
    }
    Error(_) -> []
  }

  let details =
    list.index_map(matching, fn(r, idx) { route_to_detail(r, idx == 0, now_ts) })

  LgQueryResult(
    query: trimmed,
    query_type: "aspath",
    routes_found: list.length(details),
    routes: details,
  )
}

pub fn query_community(
  routes: List(Route),
  now_ts: Int,
  comm_str: String,
) -> LgQueryResult {
  let trimmed = string.trim(comm_str)
  let matching =
    list.filter(routes, fn(r) {
      let comms =
        list.map(r.communities, fn(c) {
          int.to_string(c.asn) <> ":" <> int.to_string(c.value)
        })
      let lcomms =
        list.map(r.large_communities, fn(lc) {
          int.to_string(lc.global_admin)
          <> ":"
          <> int.to_string(lc.local_data1)
          <> ":"
          <> int.to_string(lc.local_data2)
        })
      list.contains(comms, trimmed) || list.contains(lcomms, trimmed)
    })

  let details =
    list.index_map(matching, fn(r, idx) { route_to_detail(r, idx == 0, now_ts) })

  LgQueryResult(
    query: trimmed,
    query_type: "community",
    routes_found: list.length(details),
    routes: details,
  )
}

pub fn query_summary(
  asn: Int,
  router_id: String,
  uptime_sec: Int,
  peers: List(PeerStats),
  routes: List(Route),
  roa_count: Int,
  rtr_status: String,
  bfd_up_count: Int,
) -> LgSummary {
  let established = list.count(peers, fn(p) { p.state == StateEstablished })
  let blackholes =
    list.count(routes, fn(r) { has_blackhole_community(r.communities) })

  LgSummary(
    asn: asn,
    router_id: router_id,
    uptime_seconds: uptime_sec,
    peers_total: list.length(peers),
    peers_established: established,
    routes_total: list.length(routes),
    roa_total: roa_count,
    rtr_status: rtr_status,
    bfd_sessions_up: bfd_up_count,
    blackholes_active: blackholes,
  )
}

pub fn render_json_lg_result(res: LgQueryResult) -> String {
  let route_objects =
    list.map(res.routes, fn(r) {
      json.object([
        #("prefix", json.string(r.prefix)),
        #("best", json.bool(r.best)),
        #("next_hop", json.string(r.next_hop)),
        #("as_path", json.string(r.as_path)),
        #("origin", json.string(r.origin)),
        #("local_pref", json.int(r.local_pref)),
        #("med", json.int(r.med)),
        #("roa_status", json.string(r.roa_status)),
        #("communities", json.array(r.communities, fn(c) { json.string(c) })),
        #(
          "large_communities",
          json.array(r.large_communities, fn(c) { json.string(c) }),
        ),
        #("peer_id", json.string(r.peer_id)),
        #("age_seconds", json.int(r.age_seconds)),
        #("is_blackhole", json.bool(r.is_blackhole)),
      ])
    })

  json.object([
    #("query", json.string(res.query)),
    #("query_type", json.string(res.query_type)),
    #("routes_found", json.int(res.routes_found)),
    #("routes", json.preprocessed_array(route_objects)),
  ])
  |> json.to_string
}

pub fn render_json_lg_summary(sum: LgSummary) -> String {
  json.object([
    #("asn", json.int(sum.asn)),
    #("router_id", json.string(sum.router_id)),
    #("uptime_seconds", json.int(sum.uptime_seconds)),
    #("peers_total", json.int(sum.peers_total)),
    #("peers_established", json.int(sum.peers_established)),
    #("routes_total", json.int(sum.routes_total)),
    #("roa_total", json.int(sum.roa_total)),
    #("rtr_status", json.string(sum.rtr_status)),
    #("bfd_sessions_up", json.int(sum.bfd_sessions_up)),
    #("blackholes_active", json.int(sum.blackholes_active)),
  ])
  |> json.to_string
}

fn as_path_contains_asn(segs: List(AsPathSegment), target_asn: Int) -> Bool {
  list.any(segs, fn(seg) {
    case seg {
      AsSequence(asns)
      | AsSet(asns)
      | AsConfedSequence(asns)
      | AsConfedSet(asns) -> list.contains(asns, target_asn)
    }
  })
}

fn format_as_path(segs: List(AsPathSegment)) -> String {
  let seg_strs =
    list.map(segs, fn(seg) {
      case seg {
        AsSequence(asns) ->
          list.map(asns, fn(asn) { int.to_string(asn) })
          |> string.join(" ")
        AsSet(asns) ->
          "{"
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> "}"
        AsConfedSequence(asns) ->
          "("
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> ")"
        AsConfedSet(asns) ->
          "[("
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> ")]"
      }
    })
  string.join(seg_strs, " ")
}
