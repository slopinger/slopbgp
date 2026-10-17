import gleam/int
import gleam/list
import gleam/string
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/types.{type IpAddress, type IpPrefix, Ipv4, Ipv6}

// RFC 5549 / RFC 8950 BGP Unnumbered (IPv6 Link-Local Peering with Extended Next Hop)

pub type UnnumberedPeer {
  UnnumberedPeer(
    interface: String,
    remote_link_local: IpAddress,
    local_link_local: IpAddress,
    peer_asn: Int,
    extended_next_hop: Bool,
    status: String,
  )
}

// Check if an IPv6 address is within the Link-Local Unicast range fe80::/10 (fe80..febf)
pub fn is_link_local(ip: IpAddress) -> Bool {
  case ip {
    Ipv6(a, _, _, _, _, _, _, _) -> {
      // fe80::/10 means first 10 bits are 1111 1110 10 -> high byte 0xFE, next 2 bits 10 (0x80 to 0xBF)
      a >= 0xFE80 && a <= 0xFEBF
    }
    Ipv4(_, _, _, _) -> False
  }
}

pub fn format_scoped_link_local(ip: IpAddress, interface: String) -> String {
  ip_to_string(ip) <> "%" <> interface
}

// Linux kernel 4.11+ syntax for RFC 5549 IPv4 route via IPv6 link-local gateway:
// "ip route replace <v4_prefix> via inet6 <v6_link_local> dev <iface>"
// For IPv6 prefix:
// "ip -6 route replace <v6_prefix> via <v6_link_local> dev <iface>"
pub fn format_kernel_unnumbered_route(
  prefix: IpPrefix,
  gw: IpAddress,
  interface: String,
) -> String {
  let pfx_str = prefix_to_string(prefix)
  let gw_str = ip_to_string(gw)
  case prefix.address {
    Ipv4(_, _, _, _) ->
      "ip route replace "
      <> pfx_str
      <> " via inet6 "
      <> gw_str
      <> " dev "
      <> interface
    Ipv6(_, _, _, _, _, _, _, _) ->
      "ip -6 route replace "
      <> pfx_str
      <> " via "
      <> gw_str
      <> " dev "
      <> interface
  }
}

// JSON Serialization for Web API & Dashboard
pub fn unnumbered_peers_to_json(peers: List(UnnumberedPeer)) -> String {
  let entries =
    list.map(peers, fn(p) {
      "{\"interface\":\""
      <> p.interface
      <> "\",\"remote_link_local\":\""
      <> format_scoped_link_local(p.remote_link_local, p.interface)
      <> "\",\"local_link_local\":\""
      <> format_scoped_link_local(p.local_link_local, p.interface)
      <> "\",\"peer_asn\":"
      <> int.to_string(p.peer_asn)
      <> ",\"extended_next_hop\":"
      <> case p.extended_next_hop {
        True -> "true"
        False -> "false"
      }
      <> ",\"status\":\""
      <> p.status
      <> "\"}"
    })

  "{\"unnumbered_peer_count\":"
  <> int.to_string(list.length(peers))
  <> ",\"peers\":["
  <> string.join(entries, ",")
  <> "]}"
}
