//// RFC 8212: Default External BGP (eBGP) Route Propagation Behavior without Policies
////
//// Enforces the default-deny baseline for eBGP sessions to prevent accidental route leaks
//// or unintended transit in the absence of explicit routing policy chains.

import slopbgp/types.{type Route}

/// Check if a BGP peering session is an external BGP (eBGP) session.
pub fn is_ebgp(local_as: Int, remote_as: Int) -> Bool {
  local_as != remote_as
}

/// Evaluate inbound route propagation per RFC 8212.
///
/// If enforce is True and session is eBGP, routes without an explicit
/// import policy rule matching them are rejected (default deny).
pub fn evaluate_rfc8212_inbound(
  route: Route,
  is_ebgp_session: Bool,
  has_explicit_import_policy: Bool,
  enforce: Bool,
) -> Result(Route, String) {
  case enforce && is_ebgp_session && !has_explicit_import_policy {
    True ->
      Error(
        "RFC 8212: Rejected inbound eBGP route without explicit import policy",
      )
    False -> Ok(route)
  }
}

/// Evaluate outbound route propagation per RFC 8212.
///
/// If enforce is True and session is eBGP, routes cannot be advertised
/// without an explicit export policy permitting them (default deny).
pub fn evaluate_rfc8212_outbound(
  _route: Route,
  is_ebgp_session: Bool,
  has_explicit_export_policy: Bool,
  enforce: Bool,
) -> Bool {
  case enforce && is_ebgp_session && !has_explicit_export_policy {
    True -> False
    False -> True
  }
}
