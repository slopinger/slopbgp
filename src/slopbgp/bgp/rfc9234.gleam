//// RFC 9234: BGP Route Leak Detection and Prevention using Roles and Only to Customer (OTC)
////
//// Implements RFC 9234 BGP Role capability negotiation, strict role validation,
//// and automatic route leak detection via the Only to Customer (OTC, Type 35)
//// transitive path attribute.

import gleam/int
import gleam/option.{type Option, None, Some}
import slopbgp/types.{
  type BgpRole, type Route, RoleCustomer, RolePeer, RoleProvider,
  RoleRouteServer, RoleRouteServerClient, RoleUnknown, Route,
}

/// RFC 9234 Notification Subcode for OPEN Message Error (Code 2)
pub const notif_subcode_role_mismatch = 11

/// Validate whether two negotiated BGP roles are compatible per RFC 9234 Section 4.2.
///
/// Permissible pairs:
/// - Provider <-> Customer
/// - Customer <-> Provider
/// - Route Server <-> Route Server Client
/// - Route Server Client <-> Route Server
/// - Peer <-> Peer
pub fn validate_role_pair(
  local_role: BgpRole,
  remote_role: BgpRole,
) -> Result(Nil, String) {
  case local_role, remote_role {
    RoleProvider, RoleCustomer -> Ok(Nil)
    RoleCustomer, RoleProvider -> Ok(Nil)
    RoleRouteServer, RoleRouteServerClient -> Ok(Nil)
    RoleRouteServerClient, RoleRouteServer -> Ok(Nil)
    RolePeer, RolePeer -> Ok(Nil)
    _, _ ->
      Error(
        "RFC 9234: Role mismatch! Local role ("
        <> format_role(local_role)
        <> ") is incompatible with remote role ("
        <> format_role(remote_role)
        <> ")",
      )
  }
}

/// Convert a BgpRole to human-readable string representation
pub fn format_role(role: BgpRole) -> String {
  case role {
    RoleProvider -> "Provider"
    RoleRouteServer -> "Route Server"
    RoleRouteServerClient -> "RS-Client"
    RoleCustomer -> "Customer"
    RolePeer -> "Peer"
    RoleUnknown(code) -> "Unknown(" <> int.to_string(code) <> ")"
  }
}

/// Extract OTC attribute ASN from a route, if present
pub fn get_otc(route: Route) -> Option(Int) {
  route.otc
}

/// Evaluate inbound route per RFC 9234 Section 5.1.
///
/// - If received from Customer, Peer, or RS-Client:
///   If OTC is present and OTC != remote_as, this is a ROUTE LEAK -> Return Error.
/// - If received from Provider or Route Server:
///   If OTC is absent, attach OTC with value = remote_as.
pub fn evaluate_inbound_otc(
  route: Route,
  remote_as: Int,
  peer_role: BgpRole,
) -> Result(Route, String) {
  let existing_otc = route.otc

  case peer_role {
    // Routes received from lateral Peer, Customer, or RS-Client:
    // Any existing OTC with a different ASN indicates an upstream route leak!
    RolePeer | RoleCustomer | RoleRouteServerClient -> {
      case existing_otc {
        Some(otc_as) -> {
          case otc_as == remote_as {
            True -> Ok(route)
            False ->
              Error(
                "RFC 9234: Inbound route leak detected! Prefix has OTC AS"
                <> int.to_string(otc_as)
                <> " but arrived from "
                <> format_role(peer_role)
                <> " AS"
                <> int.to_string(remote_as),
              )
          }
        }
        None -> Ok(route)
      }
    }

    // Routes received from Provider or Route Server:
    // If OTC is not already set, attach OTC set to remote_as
    RoleProvider | RoleRouteServer -> {
      case existing_otc {
        Some(_) -> Ok(route)
        None -> Ok(Route(..route, otc: Some(remote_as)))
      }
    }

    RoleUnknown(_) -> Ok(route)
  }
}

/// Evaluate outbound route advertisement per RFC 9234 Section 5.2.
///
/// When sending to Customer, Peer, or RS-Client:
/// - If OTC is absent, attach OTC set to local_as.
/// - If OTC is present, preserve it unmodified.
pub fn evaluate_outbound_otc(
  route: Route,
  local_as: Int,
  peer_role: BgpRole,
) -> Route {
  case peer_role {
    RoleCustomer | RolePeer | RoleRouteServerClient -> {
      case route.otc {
        Some(_) -> route
        None -> Route(..route, otc: Some(local_as))
      }
    }
    _ -> route
  }
}
