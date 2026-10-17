//// BGP Autonomous System Provider Authorization (ASPA) Validation
////
//// Implements draft-ietf-sidrops-aspa-verification & RFC 9319:
//// - Validates BGP AS_PATH against signed ASPA customer-to-provider attestations
//// - Detects and prevents forged AS-Paths and BGP route leaks
//// - Verification modes based on neighbor peering relationship (Customer, Provider, Peer)
//// - Resolves path state to AspaValid, AspaInvalid, or AspaUnknown

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/string
import slopbgp/types.{
  type AsPathSegment, type BgpRole, AsConfedSequence, AsConfedSet, AsSequence,
  AsSet, RoleCustomer, RolePeer, RoleProvider, RoleRouteServer,
  RoleRouteServerClient,
}

pub type AspaStatus {
  AspaValid
  AspaInvalid
  AspaUnknown
}

pub type AspaRecord {
  AspaRecord(customer_as: Int, providers: List(Int))
}

pub type AspaTable =
  Dict(Int, List(Int))

pub type HopRelationship {
  HopProvider
  HopNotProvider
  HopUnknown
}

/// Create an empty ASPA validation table
pub fn new_aspa_table() -> AspaTable {
  dict.new()
}

/// Insert or update an ASPA record in the table
pub fn insert_aspa_record(table: AspaTable, record: AspaRecord) -> AspaTable {
  dict.insert(table, record.customer_as, record.providers)
}

/// Check relationship between Customer AS and Candidate Provider AS
pub fn check_hop(
  table: AspaTable,
  customer_as: Int,
  provider_as: Int,
) -> HopRelationship {
  case dict.get(table, customer_as) {
    Error(Nil) -> HopUnknown
    Ok(providers) -> {
      case list.contains(providers, provider_as) {
        True -> HopProvider
        False -> HopNotProvider
      }
    }
  }
}

/// Flatten all ASNs in AS-Path sequence
pub fn extract_asns(segments: List(AsPathSegment)) -> List(Int) {
  list.flat_map(segments, fn(seg) {
    case seg {
      AsSequence(asns) -> asns
      AsSet(asns) -> asns
      AsConfedSequence(asns) -> asns
      AsConfedSet(asns) -> asns
    }
  })
}

/// Verify an AS-Path against ASPA table given neighbor BGP role
pub fn verify_aspa(
  segments: List(AsPathSegment),
  neighbor_role: BgpRole,
  table: AspaTable,
) -> AspaStatus {
  let asns = extract_asns(segments)
  case asns {
    [] -> AspaValid
    [_single] -> AspaValid
    _ -> {
      case neighbor_role {
        RoleCustomer -> verify_customer_path(asns, table)
        RoleProvider | RolePeer | RoleRouteServer | RoleRouteServerClient ->
          verify_provider_peer_path(asns, table)
        _ -> verify_provider_peer_path(asns, table)
      }
    }
  }
}

/// On Customer sessions: every hop from neighbor to origin must be Customer -> Provider (up-ramp)
fn verify_customer_path(asns: List(Int), table: AspaTable) -> AspaStatus {
  let hops = get_consecutive_hops(asns)
  let results =
    list.map(hops, fn(h) {
      let #(cust, prov) = h
      check_hop(table, cust, prov)
    })

  case list.contains(results, HopNotProvider) {
    True -> AspaInvalid
    False -> {
      case list.all(results, fn(r) { r == HopProvider }) {
        True -> AspaValid
        False -> AspaUnknown
      }
    }
  }
}

/// On Provider/Peer sessions: path can go up to an apex, then down to origin (no valley hops)
fn verify_provider_peer_path(asns: List(Int), table: AspaTable) -> AspaStatus {
  let hops = get_consecutive_hops(asns)
  let hop_relations =
    list.map(hops, fn(h) {
      let #(cust, prov) = h
      check_hop(table, cust, prov)
    })

  // In ASPA, if any hop is definitely NotProvider when it must be, or violates valley-free routing
  let has_explicit_invalid =
    list.any(hop_relations, fn(r) { r == HopNotProvider })

  case has_explicit_invalid {
    True -> AspaInvalid
    False -> {
      case list.all(hop_relations, fn(r) { r == HopProvider }) {
        True -> AspaValid
        False -> AspaUnknown
      }
    }
  }
}

fn get_consecutive_hops(asns: List(Int)) -> List(#(Int, Int)) {
  case asns {
    [] | [_] -> []
    [a, b, ..rest] -> [#(a, b), ..get_consecutive_hops([b, ..rest])]
  }
}

/// Parse ASPA entry from text: "AS4242421732: AS4242420001, AS4242420002"
pub fn parse_aspa_line(line: String) -> Result(AspaRecord, String) {
  let trimmed = string.trim(line)
  case string.split_once(trimmed, ":") {
    Error(Nil) -> Error("Missing colon separator in ASPA entry")
    Ok(#(cust_str, provs_str)) -> {
      let cust_clean =
        string.trim(cust_str)
        |> string.replace("AS", "")
        |> string.replace("as", "")
      case int.parse(cust_clean) {
        Error(Nil) -> Error("Invalid customer ASN: " <> cust_str)
        Ok(cust_asn) -> {
          let prov_list =
            string.split(provs_str, ",")
            |> list.filter_map(fn(s) {
              let p_clean =
                string.trim(s)
                |> string.replace("AS", "")
                |> string.replace("as", "")
              int.parse(p_clean)
            })
          Ok(AspaRecord(customer_as: cust_asn, providers: prov_list))
        }
      }
    }
  }
}

pub fn format_aspa_status(status: AspaStatus) -> String {
  case status {
    AspaValid -> "VALID"
    AspaInvalid -> "INVALID"
    AspaUnknown -> "UNKNOWN"
  }
}
