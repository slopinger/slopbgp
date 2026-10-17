import gleam/int
import gleam/list
import gleam/option.{None, Some}
import slopbgp/ip.{prefix_to_string}
import slopbgp/types.{
  type Community, type IpAddress, type IpPrefix, type Route, Community, Ipv4,
  Ipv6, OriginIgp, RoaNotFound, Route,
}

pub const blackhole_asn = 65_535

pub const blackhole_value = 666

pub const no_export_value = 65_281

pub fn blackhole_community() -> Community {
  Community(asn: blackhole_asn, value: blackhole_value)
}

pub fn no_export_community() -> Community {
  Community(asn: blackhole_asn, value: no_export_value)
}

pub fn is_blackhole_community(c: Community) -> Bool {
  c.asn == blackhole_asn && c.value == blackhole_value
}

pub fn has_blackhole_community(communities: List(Community)) -> Bool {
  list.any(communities, is_blackhole_community)
}

pub fn tag_blackhole(route: Route) -> Route {
  case has_blackhole_community(route.communities) {
    True -> route
    False ->
      Route(..route, communities: [blackhole_community(), ..route.communities])
  }
}

pub fn untag_blackhole(route: Route) -> Route {
  let filtered =
    list.filter(route.communities, fn(c) { !is_blackhole_community(c) })
  Route(..route, communities: filtered)
}

pub fn is_host_prefix(prefix: IpPrefix) -> Bool {
  case prefix.address {
    Ipv4(..) -> prefix.length == 32
    Ipv6(..) -> prefix.length == 128
  }
}

pub fn process_inbound_rtbh(
  route: Route,
  allow_rtbh: Bool,
) -> Result(Route, String) {
  case has_blackhole_community(route.communities) {
    False -> Ok(route)
    True -> {
      case allow_rtbh {
        False ->
          Error(
            "RTBH rejected: peer not authorized for Remote Triggered Blackholing",
          )
        True -> {
          case is_host_prefix(route.prefix) {
            False ->
              Error(
                "RTBH rejected: blackhole announcement must be a host route (/32 or /128)",
              )
            True -> {
              // Rewrite next-hop to loopback sinkhole address
              let sinkhole_nh = case route.prefix.address {
                Ipv4(..) -> Ipv4(127, 0, 0, 1)
                Ipv6(..) -> Ipv6(0, 0, 0, 0, 0, 0, 0, 1)
              }
              Ok(Route(..route, next_hop: sinkhole_nh))
            }
          }
        }
      }
    }
  }
}

pub fn create_outbound_rtbh(
  prefix: IpPrefix,
  _local_as: Int,
  router_id: IpAddress,
  timestamp: Int,
) -> Route {
  let sinkhole_nh = case prefix.address {
    Ipv4(..) -> Ipv4(127, 0, 0, 1)
    Ipv6(..) -> Ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  }
  Route(
    prefix: prefix,
    origin: OriginIgp,
    as_path: [],
    next_hop: sinkhole_nh,
    med: 0,
    local_pref: 200,
    atomic_aggregate: False,
    communities: [blackhole_community(), no_export_community()],
    large_communities: [],
    ext_communities: [],
    otc: None,
    roa_status: RoaNotFound,
    peer_id: "local_blackhole",
    timestamp: timestamp,
    path_id: None,
    originator_id: Some(router_id),
    cluster_list: [],
  )
}

pub fn to_fib_blackhole_command(prefix: IpPrefix, table_id: Int) -> String {
  let p_str = prefix_to_string(prefix)
  case prefix.address {
    Ipv4(..) ->
      "ip route replace blackhole "
      <> p_str
      <> " table "
      <> int.to_string(table_id)
    Ipv6(..) ->
      "ip -6 route replace blackhole "
      <> p_str
      <> " table "
      <> int.to_string(table_id)
  }
}
