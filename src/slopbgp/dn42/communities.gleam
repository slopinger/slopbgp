import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import slopbgp/types.{type Community, type LargeCommunity, Community}

pub const dn42_asn: Int = 64_511

pub const comm_wireguard: Community = Community(dn42_asn, 34)

pub const comm_region_europe: Community = Community(dn42_asn, 41)

pub const comm_no_export: Community = Community(65_535, 65_281)

pub const comm_no_advertise: Community = Community(65_535, 65_282)

pub fn latency_to_community(ms: Int) -> Community {
  let code = case ms {
    _ if ms <= 1 -> 1
    _ if ms <= 2 -> 2
    _ if ms <= 3 -> 3
    _ if ms <= 5 -> 4
    _ if ms <= 8 -> 5
    _ if ms <= 13 -> 6
    _ if ms <= 21 -> 7
    _ if ms <= 34 -> 8
    _ if ms <= 55 -> 9
    _ -> 9
  }
  Community(dn42_asn, code)
}

pub fn extract_dn42_latency(communities: List(Community)) -> Option(Int) {
  let latencies =
    list.filter_map(communities, fn(c) {
      case c.asn == dn42_asn && c.value >= 1 && c.value <= 9 {
        True -> Ok(c.value)
        False -> Error(Nil)
      }
    })
  case latencies {
    [] -> None
    [first, ..rest] ->
      Some(
        list.fold(rest, first, fn(min_val, val) {
          case val < min_val {
            True -> val
            False -> min_val
          }
        }),
      )
  }
}

pub fn has_no_export(communities: List(Community)) -> Bool {
  list.any(communities, fn(c) { c.asn == 65_535 && c.value == 65_281 })
}

pub fn has_no_advertise(communities: List(Community)) -> Bool {
  list.any(communities, fn(c) { c.asn == 65_535 && c.value == 65_282 })
}

pub fn community_to_string(c: Community) -> String {
  int.to_string(c.asn) <> ":" <> int.to_string(c.value)
}

pub fn large_community_to_string(lc: LargeCommunity) -> String {
  int.to_string(lc.global_admin)
  <> ":"
  <> int.to_string(lc.local_data1)
  <> ":"
  <> int.to_string(lc.local_data2)
}
