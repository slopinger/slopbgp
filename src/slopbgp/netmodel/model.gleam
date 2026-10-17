//// Global Network Model Definition and JSON Serialization
////
//// Defines the unified schema for declaring a complex multi-region, multi-router
//// autonomous system network topology, including PoPs, routers, inter-router links,
//// external peering relationships, and policy intent.

import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None}
import gleam/string
import slopbgp/bgp/rfc9234.{format_role}
import slopbgp/types.{
  type BgpRole, RoleCustomer, RolePeer, RoleProvider, RoleRouteServer,
  RoleRouteServerClient,
}

pub type Region {
  Region(
    id: String,
    name: String,
    country: String,
    dn42_region: Int,
    lat: Float,
    lon: Float,
  )
}

pub type NodeRole {
  RoleEdge
  RoleCore
  RoleRouteReflector
  RoleRouteServerNode
}

pub type RouterNode {
  RouterNode(
    id: String,
    hostname: String,
    region_id: String,
    role: NodeRole,
    asn: Option(Int),
    router_id: String,
    loopback_v4: String,
    loopback_v6: String,
    bgp_port: Int,
    api_port: Int,
    extra_tags: List(String),
  )
}

pub type LinkType {
  LinkWireGuard
  LinkUnnumberedV6
  LinkVlan
  LinkEthernet
}

pub type InterRouterLink {
  InterRouterLink(
    id: String,
    endpoint_a: String,
    endpoint_b: String,
    link_type: LinkType,
    cost: Int,
    latency_ms: Int,
    bandwidth_mbps: Int,
    bfd: Bool,
    ip_a: String,
    ip_b: String,
  )
}

pub type ExternalPeerDef {
  ExternalPeerDef(
    id: String,
    name: String,
    attached_router: String,
    remote_as: Int,
    remote_ip: String,
    local_ip: Option(String),
    port: Int,
    bgp_role: BgpRole,
    import_policies: List(String),
    export_policies: List(String),
    bfd: Bool,
    dn42_latency: Option(Int),
    dn42_bandwidth: Option(Int),
    dn42_crypto: Option(Int),
  )
}

pub type GlobalNetworkModel {
  GlobalNetworkModel(
    name: String,
    asn: Int,
    regions: List(Region),
    routers: List(RouterNode),
    links: List(InterRouterLink),
    external_peers: List(ExternalPeerDef),
  )
}

pub fn node_role_to_string(role: NodeRole) -> String {
  case role {
    RoleEdge -> "edge"
    RoleCore -> "core"
    RoleRouteReflector -> "route_reflector"
    RoleRouteServerNode -> "route_server"
  }
}

pub fn string_to_node_role(s: String) -> NodeRole {
  case string.lowercase(s) {
    "edge" -> RoleEdge
    "core" -> RoleCore
    "route_reflector" | "rr" -> RoleRouteReflector
    "route_server" | "rs" -> RoleRouteServerNode
    _ -> RoleEdge
  }
}

pub fn link_type_to_string(lt: LinkType) -> String {
  case lt {
    LinkWireGuard -> "wireguard"
    LinkUnnumberedV6 -> "unnumbered_v6"
    LinkVlan -> "vlan"
    LinkEthernet -> "ethernet"
  }
}

pub fn string_to_link_type(s: String) -> LinkType {
  case string.lowercase(s) {
    "wireguard" | "wg" -> LinkWireGuard
    "unnumbered_v6" | "unnumbered" -> LinkUnnumberedV6
    "vlan" -> LinkVlan
    _ -> LinkEthernet
  }
}

pub fn string_to_bgp_role(s: String) -> BgpRole {
  case string.lowercase(s) {
    "provider" -> RoleProvider
    "customer" -> RoleCustomer
    "routeserver" | "route_server" | "rs" -> RoleRouteServer
    "rsclient" | "rs_client" | "client" -> RoleRouteServerClient
    "peer" -> RolePeer
    _ -> RolePeer
  }
}

pub fn decode_network_model(
  json_str: String,
) -> Result(GlobalNetworkModel, String) {
  let region_decoder = {
    use id <- decode.field("id", decode.string)
    use name <- decode.field("name", decode.string)
    use country <- decode.optional_field("country", "ZZ", decode.string)
    use dn42_region <- decode.optional_field("dn42_region", 41, decode.int)
    use lat <- decode.optional_field("lat", 0.0, decode.float)
    use lon <- decode.optional_field("lon", 0.0, decode.float)
    decode.success(Region(
      id: id,
      name: name,
      country: country,
      dn42_region: dn42_region,
      lat: lat,
      lon: lon,
    ))
  }

  let router_decoder = {
    use id <- decode.field("id", decode.string)
    use hostname <- decode.field("hostname", decode.string)
    use region_id <- decode.field("region_id", decode.string)
    use role_str <- decode.optional_field("role", "edge", decode.string)
    use asn <- decode.optional_field("asn", None, decode.optional(decode.int))
    use router_id <- decode.field("router_id", decode.string)
    use loopback_v4 <- decode.field("loopback_v4", decode.string)
    use loopback_v6 <- decode.field("loopback_v6", decode.string)
    use bgp_port <- decode.optional_field("bgp_port", 179, decode.int)
    use api_port <- decode.optional_field("api_port", 9179, decode.int)
    use tags <- decode.optional_field(
      "extra_tags",
      [],
      decode.list(decode.string),
    )
    decode.success(RouterNode(
      id: id,
      hostname: hostname,
      region_id: region_id,
      role: string_to_node_role(role_str),
      asn: asn,
      router_id: router_id,
      loopback_v4: loopback_v4,
      loopback_v6: loopback_v6,
      bgp_port: bgp_port,
      api_port: api_port,
      extra_tags: tags,
    ))
  }

  let link_decoder = {
    use id <- decode.field("id", decode.string)
    use endpoint_a <- decode.field("endpoint_a", decode.string)
    use endpoint_b <- decode.field("endpoint_b", decode.string)
    use type_str <- decode.optional_field(
      "link_type",
      "wireguard",
      decode.string,
    )
    use cost <- decode.optional_field("cost", 10, decode.int)
    use latency_ms <- decode.optional_field("latency_ms", 15, decode.int)
    use bandwidth_mbps <- decode.optional_field(
      "bandwidth_mbps",
      1000,
      decode.int,
    )
    use bfd <- decode.optional_field("bfd", True, decode.bool)
    use ip_a <- decode.field("ip_a", decode.string)
    use ip_b <- decode.field("ip_b", decode.string)
    decode.success(InterRouterLink(
      id: id,
      endpoint_a: endpoint_a,
      endpoint_b: endpoint_b,
      link_type: string_to_link_type(type_str),
      cost: cost,
      latency_ms: latency_ms,
      bandwidth_mbps: bandwidth_mbps,
      bfd: bfd,
      ip_a: ip_a,
      ip_b: ip_b,
    ))
  }

  let peer_decoder = {
    use id <- decode.field("id", decode.string)
    use name <- decode.field("name", decode.string)
    use attached_router <- decode.field("attached_router", decode.string)
    use remote_as <- decode.field("remote_as", decode.int)
    use remote_ip <- decode.field("remote_ip", decode.string)
    use local_ip <- decode.optional_field(
      "local_ip",
      None,
      decode.optional(decode.string),
    )
    use port <- decode.optional_field("port", 179, decode.int)
    use role_str <- decode.optional_field("bgp_role", "peer", decode.string)
    use import_policies <- decode.optional_field(
      "import_policies",
      [],
      decode.list(decode.string),
    )
    use export_policies <- decode.optional_field(
      "export_policies",
      [],
      decode.list(decode.string),
    )
    use bfd <- decode.optional_field("bfd", True, decode.bool)
    use latency <- decode.optional_field(
      "dn42_latency",
      None,
      decode.optional(decode.int),
    )
    use bandwidth <- decode.optional_field(
      "dn42_bandwidth",
      None,
      decode.optional(decode.int),
    )
    use crypto <- decode.optional_field(
      "dn42_crypto",
      None,
      decode.optional(decode.int),
    )
    decode.success(ExternalPeerDef(
      id: id,
      name: name,
      attached_router: attached_router,
      remote_as: remote_as,
      remote_ip: remote_ip,
      local_ip: local_ip,
      port: port,
      bgp_role: string_to_bgp_role(role_str),
      import_policies: import_policies,
      export_policies: export_policies,
      bfd: bfd,
      dn42_latency: latency,
      dn42_bandwidth: bandwidth,
      dn42_crypto: crypto,
    ))
  }

  let model_decoder = {
    use name <- decode.field("name", decode.string)
    use asn <- decode.field("asn", decode.int)
    use regions <- decode.field("regions", decode.list(region_decoder))
    use routers <- decode.field("routers", decode.list(router_decoder))
    use links <- decode.field("links", decode.list(link_decoder))
    use external_peers <- decode.optional_field(
      "external_peers",
      [],
      decode.list(peer_decoder),
    )
    decode.success(GlobalNetworkModel(
      name: name,
      asn: asn,
      regions: regions,
      routers: routers,
      links: links,
      external_peers: external_peers,
    ))
  }

  case json.parse(json_str, model_decoder) {
    Ok(model) -> Ok(model)
    Error(err) -> Error("JSON parse error: " <> string.inspect(err))
  }
}

pub fn encode_network_model(model: GlobalNetworkModel) -> String {
  json.object([
    #("name", json.string(model.name)),
    #("asn", json.int(model.asn)),
    #(
      "regions",
      json.array(model.regions, fn(r) {
        json.object([
          #("id", json.string(r.id)),
          #("name", json.string(r.name)),
          #("country", json.string(r.country)),
          #("dn42_region", json.int(r.dn42_region)),
          #("lat", json.float(r.lat)),
          #("lon", json.float(r.lon)),
        ])
      }),
    ),
    #(
      "routers",
      json.array(model.routers, fn(rt) {
        json.object([
          #("id", json.string(rt.id)),
          #("hostname", json.string(rt.hostname)),
          #("region_id", json.string(rt.region_id)),
          #("role", json.string(node_role_to_string(rt.role))),
          #("router_id", json.string(rt.router_id)),
          #("loopback_v4", json.string(rt.loopback_v4)),
          #("loopback_v6", json.string(rt.loopback_v6)),
          #("bgp_port", json.int(rt.bgp_port)),
          #("api_port", json.int(rt.api_port)),
        ])
      }),
    ),
    #(
      "links",
      json.array(model.links, fn(l) {
        json.object([
          #("id", json.string(l.id)),
          #("endpoint_a", json.string(l.endpoint_a)),
          #("endpoint_b", json.string(l.endpoint_b)),
          #("link_type", json.string(link_type_to_string(l.link_type))),
          #("cost", json.int(l.cost)),
          #("latency_ms", json.int(l.latency_ms)),
          #("bandwidth_mbps", json.int(l.bandwidth_mbps)),
          #("bfd", json.bool(l.bfd)),
          #("ip_a", json.string(l.ip_a)),
          #("ip_b", json.string(l.ip_b)),
        ])
      }),
    ),
    #(
      "external_peers",
      json.array(model.external_peers, fn(ep) {
        json.object([
          #("id", json.string(ep.id)),
          #("name", json.string(ep.name)),
          #("attached_router", json.string(ep.attached_router)),
          #("remote_as", json.int(ep.remote_as)),
          #("remote_ip", json.string(ep.remote_ip)),
          #("bgp_role", json.string(format_role(ep.bgp_role))),
          #("bfd", json.bool(ep.bfd)),
        ])
      }),
    ),
  ])
  |> json.to_string
}
