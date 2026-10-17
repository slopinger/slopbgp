import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import simplifile
import slopbgp/ip.{parse_ip}
import slopbgp/types.{type IpAddress, type PeerConfig, Ipv4, Ipv6, PeerConfig}

pub type RawPeer {
  RawPeer(
    id: String,
    name: String,
    remote_as: Int,
    remote_ip: String,
    port: Int,
    hold_time: Int,
    keepalive_time: Int,
    latency: Int,
    bandwidth: Int,
  )
}

pub type RawConfig {
  RawConfig(
    asn: Int,
    router_id: String,
    local_ipv4: String,
    local_ipv6: String,
    bgp_port: Int,
    api_port: Int,
    fib_table: Int,
    peers: List(RawPeer),
  )
}

pub type DaemonConfig {
  DaemonConfig(
    asn: Int,
    router_id: IpAddress,
    local_ipv4: IpAddress,
    local_ipv6: IpAddress,
    bgp_port: Int,
    api_port: Int,
    roa_v4_path: String,
    roa_v6_path: String,
    fib_table: Int,
    peers: List(PeerConfig),
    cluster_id: Option(IpAddress),
    confederation_id: Option(Int),
    confederation_peers: List(Int),
  )
}

pub fn default_config() -> DaemonConfig {
  DaemonConfig(
    asn: 4_242_420_125,
    router_id: Ipv4(172, 22, 64, 129),
    local_ipv4: Ipv4(172, 22, 64, 129),
    local_ipv6: Ipv6(0xFDD4, 0xAF47, 0xDCFA, 0, 0, 0, 0, 1),
    bgp_port: 179,
    api_port: 9179,
    roa_v4_path: "/etc/bird/roa_dn42.conf",
    roa_v6_path: "/etc/bird/roa_dn42_v6.conf",
    fib_table: 42,
    peers: [],
    cluster_id: Some(Ipv4(172, 22, 64, 129)),
    confederation_id: None,
    confederation_peers: [],
  )
}

pub fn load_config_file(path: String) -> Result(DaemonConfig, String) {
  case simplifile.read(path) {
    Ok(content) -> parse_config_json(content)
    Error(err) ->
      Error("Could not read config file: " <> string_from_file_error(err))
  }
}

pub fn parse_config_json(json_str: String) -> Result(DaemonConfig, String) {
  let peer_decoder = {
    use id <- decode.field("id", decode.string)
    use name <- decode.field("name", decode.string)
    use remote_as <- decode.field("remote_as", decode.int)
    use remote_ip <- decode.field("remote_ip", decode.string)
    use port <- decode.optional_field("port", 179, decode.int)
    use hold_time <- decode.optional_field("hold_time", 90, decode.int)
    use keepalive_time <- decode.optional_field(
      "keepalive_time",
      30,
      decode.int,
    )
    use latency <- decode.optional_field("latency", 0, decode.int)
    use bandwidth <- decode.optional_field("bandwidth", 0, decode.int)
    decode.success(RawPeer(
      id: id,
      name: name,
      remote_as: remote_as,
      remote_ip: remote_ip,
      port: port,
      hold_time: hold_time,
      keepalive_time: keepalive_time,
      latency: latency,
      bandwidth: bandwidth,
    ))
  }

  let config_decoder = {
    use asn <- decode.field("asn", decode.int)
    use router_id <- decode.field("router_id", decode.string)
    use local_ipv4 <- decode.field("local_ipv4", decode.string)
    use local_ipv6 <- decode.field("local_ipv6", decode.string)
    use bgp_port <- decode.optional_field("bgp_port", 179, decode.int)
    use api_port <- decode.optional_field("api_port", 9179, decode.int)
    use fib_table <- decode.optional_field("fib_table", 42, decode.int)
    use peers <- decode.optional_field("peers", [], decode.list(peer_decoder))
    decode.success(RawConfig(
      asn: asn,
      router_id: router_id,
      local_ipv4: local_ipv4,
      local_ipv6: local_ipv6,
      bgp_port: bgp_port,
      api_port: api_port,
      fib_table: fib_table,
      peers: peers,
    ))
  }

  case json.parse(json_str, config_decoder) {
    Ok(raw) -> {
      use r_id <- result.try(parse_ip(raw.router_id))
      use v4 <- result.try(parse_ip(raw.local_ipv4))
      use v6 <- result.try(parse_ip(raw.local_ipv6))

      let peers_res =
        result.all(
          list.map(raw.peers, fn(rp: RawPeer) {
            use rip <- result.try(parse_ip(rp.remote_ip))
            let lat_opt = case rp.latency > 0 {
              True -> Some(rp.latency)
              False -> None
            }
            let bw_opt = case rp.bandwidth > 0 {
              True -> Some(rp.bandwidth)
              False -> None
            }
            Ok(PeerConfig(
              id: rp.id,
              name: rp.name,
              remote_as: rp.remote_as,
              remote_ip: rip,
              local_as: raw.asn,
              local_ip: v4,
              port: rp.port,
              hold_time: rp.hold_time,
              keepalive_time: rp.keepalive_time,
              passive: False,
              enable_ipv4: True,
              enable_ipv6: True,
              extended_next_hop: True,
              add_path_rx: True,
              add_path_tx: False,
              dn42_latency: lat_opt,
              dn42_bandwidth: bw_opt,
              dn42_crypto: Some(34),
              dn42_region: Some(41),
              import_filters: [],
              export_filters: [],
              route_server_client: False,
              route_reflector_client: False,
              confederation_member: False,
            ))
          }),
        )

      use peers <- result.try(peers_res)

      Ok(
        DaemonConfig(
          asn: raw.asn,
          router_id: r_id,
          local_ipv4: v4,
          local_ipv6: v6,
          bgp_port: raw.bgp_port,
          api_port: raw.api_port,
          roa_v4_path: "/etc/bird/roa_dn42.conf",
          roa_v6_path: "/etc/bird/roa_dn42_v6.conf",
          fib_table: raw.fib_table,
          peers: peers,
          cluster_id: Some(r_id),
          confederation_id: None,
          confederation_peers: [],
        ),
      )
    }
    Error(_) -> Error("JSON parse or validation error in config")
  }
}

fn string_from_file_error(err: simplifile.FileError) -> String {
  case err {
    simplifile.Enoent -> "File not found"
    simplifile.Eacces -> "Permission denied"
    _ -> "I/O error"
  }
}
