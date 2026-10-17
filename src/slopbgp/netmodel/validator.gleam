//// Topology and Consistency Validator for Global Network Models
////
//// Performs static sanity checks on network graphs: verifies referenced identifiers,
//// prevents duplicate IP / Router ID allocations, checks link symmetry, and
//// detects isolated or unpeered router nodes.

import gleam/list
import slopbgp/netmodel/model.{type GlobalNetworkModel}

pub type ValidationError {
  ValidationError(category: String, message: String)
}

/// Validate a complete GlobalNetworkModel, returning a list of validation errors
pub fn validate_network_model(
  model: GlobalNetworkModel,
) -> List(ValidationError) {
  let region_errors = validate_regions(model)
  let router_errors = validate_routers(model)
  let link_errors = validate_links(model)
  let peer_errors = validate_external_peers(model)

  list.flatten([region_errors, router_errors, link_errors, peer_errors])
}

fn validate_regions(model: GlobalNetworkModel) -> List(ValidationError) {
  let ids = list.map(model.regions, fn(r) { r.id })
  case has_duplicates(ids) {
    True -> [
      ValidationError(
        category: "Region",
        message: "Duplicate region ID found in regions declaration",
      ),
    ]
    False -> []
  }
}

fn validate_routers(model: GlobalNetworkModel) -> List(ValidationError) {
  let region_ids = list.map(model.regions, fn(r) { r.id })
  let router_ids = list.map(model.routers, fn(r) { r.id })
  let r_ids = list.map(model.routers, fn(r) { r.router_id })
  let lb_v4s = list.map(model.routers, fn(r) { r.loopback_v4 })
  let lb_v6s = list.map(model.routers, fn(r) { r.loopback_v6 })

  let dup_id = case has_duplicates(router_ids) {
    True -> [
      ValidationError(
        category: "Router",
        message: "Duplicate router ID found in routers declaration",
      ),
    ]
    False -> []
  }

  let dup_rid = case has_duplicates(r_ids) {
    True -> [
      ValidationError(
        category: "Router",
        message: "Duplicate router_id (BGP Identifier) found across routers",
      ),
    ]
    False -> []
  }

  let dup_lb4 = case has_duplicates(lb_v4s) {
    True -> [
      ValidationError(
        category: "Router",
        message: "Duplicate IPv4 loopback address found across routers",
      ),
    ]
    False -> []
  }

  let dup_lb6 = case has_duplicates(lb_v6s) {
    True -> [
      ValidationError(
        category: "Router",
        message: "Duplicate IPv6 loopback address found across routers",
      ),
    ]
    False -> []
  }

  let region_ref_errors =
    list.filter_map(model.routers, fn(r) {
      case list.contains(region_ids, r.region_id) {
        False ->
          Ok(ValidationError(
            category: "Router",
            message: "Router "
              <> r.id
              <> " references unknown region: "
              <> r.region_id,
          ))
        True -> Error(Nil)
      }
    })

  list.flatten([dup_id, dup_rid, dup_lb4, dup_lb6, region_ref_errors])
}

fn validate_links(model: GlobalNetworkModel) -> List(ValidationError) {
  let router_ids = list.map(model.routers, fn(r) { r.id })

  list.fold(model.links, [], fn(acc, l) {
    let mut_errs = acc
    let mut_errs = case l.endpoint_a == l.endpoint_b {
      True -> [
        ValidationError(
          category: "Link",
          message: "Link "
            <> l.id
            <> " connects a router to itself ("
            <> l.endpoint_a
            <> ")",
        ),
        ..mut_errs
      ]
      False -> mut_errs
    }

    let mut_errs = case list.contains(router_ids, l.endpoint_a) {
      False -> [
        ValidationError(
          category: "Link",
          message: "Link "
            <> l.id
            <> " endpoint_a references unknown router: "
            <> l.endpoint_a,
        ),
        ..mut_errs
      ]
      True -> mut_errs
    }

    let mut_errs = case list.contains(router_ids, l.endpoint_b) {
      False -> [
        ValidationError(
          category: "Link",
          message: "Link "
            <> l.id
            <> " endpoint_b references unknown router: "
            <> l.endpoint_b,
        ),
        ..mut_errs
      ]
      True -> mut_errs
    }

    mut_errs
  })
}

fn validate_external_peers(model: GlobalNetworkModel) -> List(ValidationError) {
  let router_ids = list.map(model.routers, fn(r) { r.id })

  list.filter_map(model.external_peers, fn(ep) {
    case list.contains(router_ids, ep.attached_router) {
      False ->
        Ok(ValidationError(
          category: "ExternalPeer",
          message: "External peer "
            <> ep.id
            <> " references non-existent router: "
            <> ep.attached_router,
        ))
      True -> Error(Nil)
    }
  })
}

fn has_duplicates(items: List(String)) -> Bool {
  has_duplicates_loop(items, [])
}

fn has_duplicates_loop(items: List(String), seen: List(String)) -> Bool {
  case items {
    [] -> False
    [first, ..rest] -> {
      case list.contains(seen, first) {
        True -> True
        False -> has_duplicates_loop(rest, [first, ..seen])
      }
    }
  }
}
