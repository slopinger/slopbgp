import gleam/int
import gleam/list
import gleam/string
import slopbgp/bgp/evpn.{type RouteDistinguisher, RdAsn2, RdAsn4, RdIpv4}
import slopbgp/bgp/l3vpn.{
  type MplsVpnRoute, type RouteTarget, MplsVpnRoute, decode_route_target,
  encode_route_target, route_target_to_string,
}
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/types.{type ExtendedCommunity, type Route, Route}

// VRF (Virtual Routing and Forwarding) - Multi-Tenant Route Isolation

pub type VrfConfig {
  VrfConfig(
    name: String,
    rd: RouteDistinguisher,
    import_targets: List(RouteTarget),
    export_targets: List(RouteTarget),
    table_id: Int,
    export_label: Int,
  )
}

pub type VrfTable {
  VrfTable(config: VrfConfig, routes: List(Route), last_updated: Int)
}

pub type VrfManager {
  VrfManager(vrfs: List(VrfTable))
}

pub fn new_manager() -> VrfManager {
  VrfManager(vrfs: [])
}

pub fn add_vrf(mgr: VrfManager, config: VrfConfig) -> VrfManager {
  let existing_removed =
    list.filter(mgr.vrfs, fn(v) { v.config.name != config.name })
  let new_table = VrfTable(config: config, routes: [], last_updated: 0)
  VrfManager(vrfs: [new_table, ..existing_removed])
}

pub fn remove_vrf(mgr: VrfManager, name: String) -> VrfManager {
  VrfManager(vrfs: list.filter(mgr.vrfs, fn(v) { v.config.name != name }))
}

pub fn get_vrf(mgr: VrfManager, name: String) -> Result(VrfTable, String) {
  case list.find(mgr.vrfs, fn(v) { v.config.name == name }) {
    Ok(v) -> Ok(v)
    Error(_) -> Error("VRF not found: " <> name)
  }
}

pub fn list_vrfs(mgr: VrfManager) -> List(VrfTable) {
  mgr.vrfs
}

pub fn add_local_route(
  mgr: VrfManager,
  vrf_name: String,
  route: Route,
) -> Result(VrfManager, String) {
  case get_vrf(mgr, vrf_name) {
    Error(e) -> Error(e)
    Ok(v) -> {
      let updated_routes = [
        route,
        ..list.filter(v.routes, fn(r) { r.prefix != route.prefix })
      ]
      let updated_vrf =
        VrfTable(
          config: v.config,
          routes: updated_routes,
          last_updated: route.timestamp,
        )
      let other_vrfs =
        list.filter(mgr.vrfs, fn(item) { item.config.name != vrf_name })
      Ok(VrfManager(vrfs: [updated_vrf, ..other_vrfs]))
    }
  }
}

// Import a received VPNv4/VPNv6 route into any VRF whose import_targets match
pub fn import_vpn_route(
  mgr: VrfManager,
  vpn_route: MplsVpnRoute,
  base_route: Route,
) -> VrfManager {
  // Extract all Route Targets from base_route's extended communities
  let received_rts =
    list.filter_map(base_route.ext_communities, fn(ext) {
      decode_route_target(ext)
    })

  let updated_vrfs =
    list.map(mgr.vrfs, fn(vrf) {
      // Check if any received RT is in vrf.config.import_targets
      let matches =
        list.any(received_rts, fn(r_rt) {
          list.contains(vrf.config.import_targets, r_rt)
        })

      case matches {
        False -> vrf
        True -> {
          // Strip RD and attach prefix into VRF's local table
          let vrf_route =
            Route(
              prefix: vpn_route.prefix,
              origin: base_route.origin,
              as_path: base_route.as_path,
              next_hop: base_route.next_hop,
              med: base_route.med,
              local_pref: base_route.local_pref,
              atomic_aggregate: base_route.atomic_aggregate,
              communities: base_route.communities,
              large_communities: base_route.large_communities,
              ext_communities: base_route.ext_communities,
              otc: base_route.otc,
              roa_status: base_route.roa_status,
              peer_id: base_route.peer_id,
              timestamp: base_route.timestamp,
              path_id: base_route.path_id,
              originator_id: base_route.originator_id,
              cluster_list: base_route.cluster_list,
            )

          let filtered_routes =
            list.filter(vrf.routes, fn(r) { r.prefix != vpn_route.prefix })
          VrfTable(
            config: vrf.config,
            routes: [vrf_route, ..filtered_routes],
            last_updated: base_route.timestamp,
          )
        }
      }
    })

  VrfManager(vrfs: updated_vrfs)
}

// Export a route from a VRF to MP-BGP with VRF's RD and Export Route Targets
pub fn export_vrf_route(
  vrf: VrfTable,
  route: Route,
) -> #(MplsVpnRoute, List(ExtendedCommunity)) {
  let vpn_route =
    MplsVpnRoute(
      rd: vrf.config.rd,
      label: vrf.config.export_label,
      prefix: route.prefix,
    )
  let rt_exts = list.map(vrf.config.export_targets, encode_route_target)
  #(vpn_route, rt_exts)
}

// Generate Linux FIB route commands for this VRF table
pub fn generate_vrf_fib_commands(vrf: VrfTable) -> List(String) {
  let table_str = int.to_string(vrf.config.table_id)
  list.map(vrf.routes, fn(r) {
    let pfx_str = prefix_to_string(r.prefix)
    let gw_str = ip_to_string(r.next_hop)
    "ip route replace "
    <> pfx_str
    <> " via "
    <> gw_str
    <> " table "
    <> table_str
  })
}

// JSON Serialization for Web API & Dashboard
pub fn rd_to_string(rd: RouteDistinguisher) -> String {
  case rd {
    RdAsn2(asn, assigned) ->
      int.to_string(asn) <> ":" <> int.to_string(assigned)
    RdIpv4(ip, assigned) -> ip_to_string(ip) <> ":" <> int.to_string(assigned)
    RdAsn4(asn, assigned) ->
      int.to_string(asn) <> ":" <> int.to_string(assigned)
  }
}

pub fn vrf_manager_to_json(mgr: VrfManager) -> String {
  let vrf_entries =
    list.map(mgr.vrfs, fn(v) {
      let import_rt_strs =
        list.map(v.config.import_targets, fn(rt) {
          "\"" <> route_target_to_string(rt) <> "\""
        })
      let export_rt_strs =
        list.map(v.config.export_targets, fn(rt) {
          "\"" <> route_target_to_string(rt) <> "\""
        })

      let route_entries =
        list.map(v.routes, fn(r) {
          "{\"prefix\":\""
          <> prefix_to_string(r.prefix)
          <> "\",\"next_hop\":\""
          <> ip_to_string(r.next_hop)
          <> "\",\"local_pref\":"
          <> int.to_string(r.local_pref)
          <> "}"
        })

      "{\"name\":\""
      <> v.config.name
      <> "\",\"rd\":\""
      <> rd_to_string(v.config.rd)
      <> "\",\"table_id\":"
      <> int.to_string(v.config.table_id)
      <> ",\"export_label\":"
      <> int.to_string(v.config.export_label)
      <> ",\"import_targets\":["
      <> string.join(import_rt_strs, ",")
      <> "],\"export_targets\":["
      <> string.join(export_rt_strs, ",")
      <> "],\"routes_count\":"
      <> int.to_string(list.length(v.routes))
      <> ",\"routes\":["
      <> string.join(route_entries, ",")
      <> "]}"
    })

  "{\"vrf_count\":"
  <> int.to_string(list.length(mgr.vrfs))
  <> ",\"vrfs\":["
  <> string.join(vrf_entries, ",")
  <> "]}"
}
