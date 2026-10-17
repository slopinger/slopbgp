//// Global Network Model Compiler and Local Config Derivation Engine
////
//// Transforms a high-level network topology graph into node-specific
//// daemon configurations (DaemonConfig), automatically synthesizing iBGP meshes,
//// Route Reflector client hierarchies, link-local parameters, and policy bindings.

import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import slopbgp/config.{type DaemonConfig, DaemonConfig}
import slopbgp/ip.{parse_ip}
import slopbgp/netmodel/model.{
  type GlobalNetworkModel, type RouterNode, LinkWireGuard, RoleEdge,
  RoleRouteReflector,
}
import slopbgp/types.{
  type IpAddress, type PeerConfig, Ipv4, PeerConfig, RolePeer,
}

/// Derive the node-specific DaemonConfig for a target router from the GlobalNetworkModel
pub fn compile_router_config(
  model: GlobalNetworkModel,
  target_id: String,
) -> Result(DaemonConfig, String) {
  case list.find(model.routers, fn(r) { r.id == target_id }) {
    Error(_) ->
      Error("Target router ID not found in network model: " <> target_id)
    Ok(node) -> {
      let node_asn = option.unwrap(node.asn, model.asn)
      let r_id = case parse_ip(node.router_id) {
        Ok(ip) -> ip
        Error(_) -> Ipv4(127, 0, 0, 1)
      }
      let lb_v4 = case parse_ip(node.loopback_v4) {
        Ok(ip) -> ip
        Error(_) -> Ipv4(172, 22, 64, 1)
      }
      let lb_v6 = case parse_ip(node.loopback_v6) {
        Ok(ip) -> ip
        Error(_) -> Ipv4(172, 22, 64, 1)
      }

      let node_region =
        list.find(model.regions, fn(reg) { reg.id == node.region_id })
      let dn42_reg_code = case node_region {
        Ok(reg) -> Some(reg.dn42_region)
        Error(_) -> None
      }

      // Compile internal links into iBGP sessions
      let internal_peers =
        compile_internal_links(model, node, node_asn, lb_v4, dn42_reg_code)

      // Compile external peers attached to this router
      let external_peers =
        compile_external_peers(model, node, node_asn, lb_v4, dn42_reg_code)

      let all_peers = list.append(internal_peers, external_peers)

      let cluster_id = case node.role {
        RoleRouteReflector -> Some(r_id)
        _ -> None
      }

      Ok(
        DaemonConfig(
          asn: node_asn,
          router_id: r_id,
          local_ipv4: lb_v4,
          local_ipv6: lb_v6,
          bgp_port: node.bgp_port,
          api_port: node.api_port,
          roa_v4_path: "/etc/bird/roa_dn42.conf",
          roa_v6_path: "/etc/bird/roa_dn42_v6.conf",
          fib_table: 42,
          peers: all_peers,
          cluster_id: cluster_id,
          confederation_id: None,
          confederation_peers: [],
        ),
      )
    }
  }
}

fn compile_internal_links(
  model: GlobalNetworkModel,
  node: RouterNode,
  node_asn: Int,
  default_local_ip: IpAddress,
  region_code: Option(Int),
) -> List(PeerConfig) {
  let incident_links =
    list.filter(model.links, fn(l) {
      l.endpoint_a == node.id || l.endpoint_b == node.id
    })

  list.filter_map(incident_links, fn(link) {
    let #(remote_id, local_ip_str, remote_ip_str) = case
      link.endpoint_a == node.id
    {
      True -> #(link.endpoint_b, link.ip_a, link.ip_b)
      False -> #(link.endpoint_a, link.ip_b, link.ip_a)
    }

    case list.find(model.routers, fn(r) { r.id == remote_id }) {
      Error(_) -> Error(Nil)
      Ok(remote_node) -> {
        let remote_asn = option.unwrap(remote_node.asn, model.asn)
        let remote_ip = case parse_ip(remote_ip_str) {
          Ok(ip) -> ip
          Error(_) ->
            case parse_ip(remote_node.loopback_v4) {
              Ok(ip) -> ip
              Error(_) -> Ipv4(127, 0, 0, 1)
            }
        }
        let local_ip = case parse_ip(local_ip_str) {
          Ok(ip) -> ip
          Error(_) -> default_local_ip
        }

        let is_rr_client = case node.role, remote_node.role {
          RoleRouteReflector, RoleEdge -> True
          RoleRouteReflector, _ -> False
          _, _ -> False
        }

        let crypto_tag = case link.link_type {
          LinkWireGuard -> Some(41)
          _ -> None
        }

        Ok(PeerConfig(
          id: "ibgp_" <> remote_node.id,
          name: "iBGP " <> remote_node.hostname <> " (" <> remote_node.id <> ")",
          remote_as: remote_asn,
          remote_ip: remote_ip,
          local_as: node_asn,
          local_ip: local_ip,
          port: remote_node.bgp_port,
          hold_time: 90,
          keepalive_time: 30,
          passive: False,
          enable_ipv4: True,
          enable_ipv6: True,
          extended_next_hop: True,
          add_path_rx: True,
          add_path_tx: True,
          dn42_latency: Some(link.latency_ms),
          dn42_bandwidth: Some(link.bandwidth_mbps),
          dn42_crypto: crypto_tag,
          dn42_region: region_code,
          import_filters: ["internal_ibgp_in"],
          export_filters: ["internal_ibgp_out"],
          route_server_client: False,
          route_reflector_client: is_rr_client,
          confederation_member: False,
          bgp_role: Some(RolePeer),
        ))
      }
    }
  })
}

fn compile_external_peers(
  model: GlobalNetworkModel,
  node: RouterNode,
  node_asn: Int,
  default_local_ip: IpAddress,
  region_code: Option(Int),
) -> List(PeerConfig) {
  let attached =
    list.filter(model.external_peers, fn(ep) { ep.attached_router == node.id })

  list.map(attached, fn(ep) {
    let r_ip = case parse_ip(ep.remote_ip) {
      Ok(ip) -> ip
      Error(_) -> Ipv4(127, 0, 0, 1)
    }
    let l_ip = case ep.local_ip {
      Some(str) ->
        case parse_ip(str) {
          Ok(ip) -> ip
          Error(_) -> default_local_ip
        }
      None -> default_local_ip
    }

    Ok(PeerConfig(
      id: ep.id,
      name: ep.name,
      remote_as: ep.remote_as,
      remote_ip: r_ip,
      local_as: node_asn,
      local_ip: l_ip,
      port: ep.port,
      hold_time: 90,
      keepalive_time: 30,
      passive: False,
      enable_ipv4: True,
      enable_ipv6: True,
      extended_next_hop: True,
      add_path_rx: True,
      add_path_tx: True,
      dn42_latency: ep.dn42_latency,
      dn42_bandwidth: ep.dn42_bandwidth,
      dn42_crypto: ep.dn42_crypto,
      dn42_region: region_code,
      import_filters: ep.import_policies,
      export_filters: ep.export_policies,
      route_server_client: False,
      route_reflector_client: False,
      confederation_member: False,
      bgp_role: Some(ep.bgp_role),
    ))
  })
  |> list.filter_map(fn(x) { x })
}

/// Compile configurations for all routers defined in the network model
pub fn compile_all_configs(
  model: GlobalNetworkModel,
) -> List(#(String, Result(DaemonConfig, String))) {
  list.map(model.routers, fn(r) { #(r.id, compile_router_config(model, r.id)) })
}

/// Serialize a DaemonConfig into a native slopbgp.json configuration file
pub fn daemon_config_to_json(cfg: DaemonConfig) -> String {
  json.object([
    #("asn", json.int(cfg.asn)),
    #("router_id", json.string(ip.ip_to_string(cfg.router_id))),
    #("local_ipv4", json.string(ip.ip_to_string(cfg.local_ipv4))),
    #("local_ipv6", json.string(ip.ip_to_string(cfg.local_ipv6))),
    #("bgp_port", json.int(cfg.bgp_port)),
    #("api_port", json.int(cfg.api_port)),
    #("fib_table", json.int(cfg.fib_table)),
    #(
      "peers",
      json.array(cfg.peers, fn(p) {
        json.object([
          #("id", json.string(p.id)),
          #("name", json.string(p.name)),
          #("remote_as", json.int(p.remote_as)),
          #("remote_ip", json.string(ip.ip_to_string(p.remote_ip))),
          #("port", json.int(p.port)),
          #("hold_time", json.int(p.hold_time)),
          #("keepalive_time", json.int(p.keepalive_time)),
          #(
            "latency",
            json.int(case p.dn42_latency {
              Some(l) -> l
              None -> 0
            }),
          ),
          #(
            "bandwidth",
            json.int(case p.dn42_bandwidth {
              Some(b) -> b
              None -> 0
            }),
          ),
        ])
      }),
    ),
  ])
  |> json.to_string
}

/// Generate Graphviz DOT visualization of the network topology
pub fn to_graphviz_dot(model: GlobalNetworkModel) -> String {
  let header =
    "graph \""
    <> model.name
    <> "\" {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fillcolor=\"#1e293b\", fontcolor=\"#f8fafc\", fontname=\"monospace\"];\n  edge [color=\"#06b6d4\", fontcolor=\"#94a3b8\", fontname=\"monospace\", fontsize=10];\n"

  let region_subgraphs =
    list.map(model.regions, fn(reg) {
      let reg_nodes =
        list.filter(model.routers, fn(r) { r.region_id == reg.id })
      let node_lines =
        list.map(reg_nodes, fn(rn) {
          "    \""
          <> rn.id
          <> "\" [label=\""
          <> rn.hostname
          <> "\\n"
          <> rn.router_id
          <> "\\n["
          <> model.node_role_to_string(rn.role)
          <> "]\"];\n"
        })
        |> string.concat

      "  subgraph \"cluster_"
      <> reg.id
      <> "\" {\n    label=\""
      <> reg.name
      <> " ("
      <> reg.country
      <> ")\";\n    style=\"rounded,dashed\";\n    color=\"#334155\";\n"
      <> node_lines
      <> "  }\n"
    })
    |> string.concat

  let link_lines =
    list.map(model.links, fn(l) {
      "  \""
      <> l.endpoint_a
      <> "\" -- \""
      <> l.endpoint_b
      <> "\" [label=\""
      <> int.to_string(l.latency_ms)
      <> "ms / "
      <> int.to_string(l.bandwidth_mbps)
      <> "M\"];\n"
    })
    |> string.concat

  header <> region_subgraphs <> link_lines <> "}\n"
}

/// Generate Mermaid flowchart diagram of the network topology
pub fn to_mermaid_graph(model: GlobalNetworkModel) -> String {
  let header = "flowchart LR\n"

  let region_blocks =
    list.map(model.regions, fn(reg) {
      let reg_nodes =
        list.filter(model.routers, fn(r) { r.region_id == reg.id })
      let node_lines =
        list.map(reg_nodes, fn(rn) {
          "    "
          <> rn.id
          <> "[\""
          <> rn.hostname
          <> "<br/>"
          <> rn.router_id
          <> "<br/><i>"
          <> model.node_role_to_string(rn.role)
          <> "</i>\"]\n"
        })
        |> string.concat

      "  subgraph "
      <> reg.id
      <> " [\""
      <> reg.name
      <> " ("
      <> reg.country
      <> ")\"]\n"
      <> node_lines
      <> "  end\n"
    })
    |> string.concat

  let link_lines =
    list.map(model.links, fn(l) {
      "  "
      <> l.endpoint_a
      <> " <-->|"
      <> int.to_string(l.latency_ms)
      <> "ms| "
      <> l.endpoint_b
      <> "\n"
    })
    |> string.concat

  header <> region_blocks <> link_lines
}
