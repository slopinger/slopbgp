import gleam/option.{type Option}

pub type IpAddress {
  Ipv4(Int, Int, Int, Int)
  Ipv6(Int, Int, Int, Int, Int, Int, Int, Int)
}

pub type IpPrefix {
  IpPrefix(address: IpAddress, length: Int)
}

pub type Afi {
  AfiIpv4
  AfiIpv6
  AfiUnknown(Int)
}

pub type Safi {
  SafiUnicast
  SafiMulticast
  SafiMplsVpn
  SafiUnknown(Int)
}

pub type BgpRole {
  RoleProvider
  RoleRouteServer
  RoleRouteServerClient
  RolePeer
  RoleCustomer
  RoleUnknown(Int)
}

pub type BgpCapability {
  CapMultiProtocol(afi: Afi, safi: Safi)
  CapRouteRefresh
  CapExtendedNextHop(nlri_afi: Afi, nlri_safi: Safi, next_hop_afi: Afi)
  CapBgpRole(role: BgpRole)
  CapGracefulRestart(flags: Int, time: Int, afi_safi: List(#(Afi, Safi, Int)))
  CapFourOctetAsn(asn: Int)
  CapAddPath(afi: Afi, safi: Safi, send: Bool, receive: Bool)
  CapEnhancedRouteRefresh
  CapExtendedMessage
  CapUnknown(code: Int, value: BitArray)
}

pub type Origin {
  OriginIgp
  OriginEgp
  OriginIncomplete
}

pub type AsPathSegment {
  AsSequence(List(Int))
  AsSet(List(Int))
}

pub type Community {
  Community(asn: Int, value: Int)
}

pub type LargeCommunity {
  LargeCommunity(global_admin: Int, local_data1: Int, local_data2: Int)
}

pub type ExtendedCommunity {
  ExtCommunity(type_code: Int, sub_type: Int, value: BitArray)
}

pub type PathAttribute {
  AttrOrigin(Origin)
  AttrAsPath(List(AsPathSegment))
  AttrNextHop(IpAddress)
  AttrMed(Int)
  AttrLocalPref(Int)
  AttrAtomicAggregate
  AttrAggregator(asn: Int, router_id: IpAddress)
  AttrCommunities(List(Community))
  AttrMpReachNlri(
    afi: Afi,
    safi: Safi,
    next_hop: List(IpAddress),
    nlri: List(IpPrefix),
  )
  AttrMpUnreachNlri(afi: Afi, safi: Safi, withdrawn: List(IpPrefix))
  AttrExtendedCommunities(List(ExtendedCommunity))
  AttrLargeCommunities(List(LargeCommunity))
  AttrOnlyToCustomer(asn: Int)
  AttrUnknown(flags: Int, type_code: Int, data: BitArray)
}

pub type BgpMessage {
  MsgOpen(
    version: Int,
    my_as: Int,
    hold_time: Int,
    bgp_id: IpAddress,
    capabilities: List(BgpCapability),
  )
  MsgUpdate(
    withdrawn: List(IpPrefix),
    attributes: List(PathAttribute),
    nlri: List(IpPrefix),
  )
  MsgNotification(code: Int, subcode: Int, data: BitArray)
  MsgKeepalive
  MsgRouteRefresh(afi: Afi, subtype: Int, safi: Safi)
}

pub type FsmState {
  StateIdle
  StateConnect
  StateActive
  StateOpenSent
  StateOpenConfirm
  StateEstablished
}

pub type RoaStatus {
  RoaValid
  RoaInvalid
  RoaNotFound
}

pub type RoaEntry {
  RoaEntry(prefix: IpPrefix, max_length: Int, asn: Int)
}

pub type Route {
  Route(
    prefix: IpPrefix,
    origin: Origin,
    as_path: List(AsPathSegment),
    next_hop: IpAddress,
    med: Int,
    local_pref: Int,
    atomic_aggregate: Bool,
    communities: List(Community),
    large_communities: List(LargeCommunity),
    ext_communities: List(ExtendedCommunity),
    otc: Option(Int),
    roa_status: RoaStatus,
    peer_id: String,
    timestamp: Int,
    path_id: Option(Int),
  )
}

pub type PeerConfig {
  PeerConfig(
    id: String,
    name: String,
    remote_as: Int,
    remote_ip: IpAddress,
    local_as: Int,
    local_ip: IpAddress,
    port: Int,
    hold_time: Int,
    keepalive_time: Int,
    passive: Bool,
    enable_ipv4: Bool,
    enable_ipv6: Bool,
    extended_next_hop: Bool,
    add_path_rx: Bool,
    add_path_tx: Bool,
    dn42_latency: Option(Int),
    dn42_bandwidth: Option(Int),
    dn42_crypto: Option(Int),
    dn42_region: Option(Int),
    import_filters: List(String),
    export_filters: List(String),
  )
}

pub type PeerStats {
  PeerStats(
    id: String,
    name: String,
    remote_as: Int,
    state: FsmState,
    uptime_seconds: Int,
    prefixes_received: Int,
    prefixes_advertised: Int,
    updates_received: Int,
    updates_sent: Int,
    keepalives_received: Int,
    keepalives_sent: Int,
    last_error: Option(String),
  )
}
