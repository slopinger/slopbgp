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
  AfiL2Vpn
  AfiUnknown(Int)
}

pub type Safi {
  SafiUnicast
  SafiMulticast
  SafiEvpn
  SafiMplsVpn
  SafiFlowspec
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
  AsConfedSequence(List(Int))
  AsConfedSet(List(Int))
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
  AttrOriginatorId(IpAddress)
  AttrClusterList(List(IpAddress))
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
    originator_id: Option(IpAddress),
    cluster_list: List(IpAddress),
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
    route_server_client: Bool,
    route_reflector_client: Bool,
    confederation_member: Bool,
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
    last_shutdown_communication: Option(String),
    drained: Bool,
  )
}

// RFC 5575 / RFC 8955 BGP Flowspec (DDoS Mitigation Rules)
pub type FlowspecComponent {
  FlowDstPrefix(IpPrefix)
  FlowSrcPrefix(IpPrefix)
  FlowIpProtocol(op: Int, value: Int)
  FlowPort(op: Int, value: Int)
  FlowDstPort(op: Int, value: Int)
  FlowSrcPort(op: Int, value: Int)
  FlowIcmpType(op: Int, value: Int)
  FlowIcmpCode(op: Int, value: Int)
  FlowTcpFlags(op: Int, value: Int)
  FlowPacketLength(op: Int, value: Int)
  FlowDscp(op: Int, value: Int)
  FlowNextHeader(op: Int, value: Int)
  FlowLabel(op: Int, value: Int)
}

pub type FlowspecAction {
  FlowActionDrop
  FlowActionRateLimit(rate_bytes_sec: Float)
  FlowActionSample
  FlowActionMarkDscp(Int)
  FlowActionRedirect(asn: Int, target: Int)
}

pub type FlowspecRule {
  FlowspecRule(
    id: String,
    afi: Afi,
    components: List(FlowspecComponent),
    actions: List(FlowspecAction),
    origin_peer: String,
    timestamp: Int,
  )
}

// RFC 2439 Route Flap Damping
pub type FlapHistory {
  FlapHistory(
    penalty: Float,
    flaps_count: Int,
    last_flap: Int,
    suppressed: Bool,
    suppressed_until: Int,
  )
}

pub type DampingConfig {
  DampingConfig(
    half_life_seconds: Int,
    reuse_threshold: Float,
    suppress_threshold: Float,
    max_suppress_seconds: Int,
    penalty_per_flap: Float,
  )
}

pub type DampedRoute {
  DampedRoute(
    prefix: IpPrefix,
    peer_id: String,
    penalty: Float,
    flaps_count: Int,
    suppressed: Bool,
    seconds_remaining: Int,
  )
}

// Routing Policy DSL
pub type PolicyMatch {
  MatchAny
  MatchPrefix(prefix: IpPrefix, min_len: Int, max_len: Int)
  MatchAsPathContains(asn: Int)
  MatchAsPathOrigin(asn: Int)
  MatchAsLength(max_length: Int)
  MatchCommunity(Community)
  MatchLargeCommunity(LargeCommunity)
  MatchRoa(RoaStatus)
}

pub type PolicyAction {
  ActionAccept
  ActionReject
  ActionSetLocalPref(Int)
  ActionSetMed(Int)
  ActionPrependAs(asn: Int, times: Int)
  ActionAddCommunity(Community)
  ActionAddLargeCommunity(LargeCommunity)
  ActionRemoveCommunity(Community)
  ActionSetNextHop(IpAddress)
}

pub type PolicyRule {
  PolicyRule(
    name: String,
    matches: List(PolicyMatch),
    actions: List(PolicyAction),
  )
}

pub type PolicyChain {
  PolicyChain(
    name: String,
    default_action: PolicyAction,
    rules: List(PolicyRule),
  )
}

// RFC 7854 BGP Monitoring Protocol (BMP)
pub type BmpPeerHeader {
  BmpPeerHeader(
    peer_type: Int,
    is_ipv6: Bool,
    is_post_policy: Bool,
    peer_distinguisher: BitArray,
    peer_ip: IpAddress,
    peer_as: Int,
    peer_bgp_id: IpAddress,
    timestamp_sec: Int,
    timestamp_usec: Int,
  )
}

pub type BmpStatCounter {
  BmpStatCounter(stat_type: Int, value: Int)
}

pub type BmpMessage {
  BmpMsgRouteMonitoring(peer: BmpPeerHeader, bgp_update: BitArray)
  BmpMsgStatsReport(peer: BmpPeerHeader, counters: List(BmpStatCounter))
  BmpMsgPeerDown(peer: BmpPeerHeader, reason_code: Int, notif: Option(BitArray))
  BmpMsgPeerUp(
    peer: BmpPeerHeader,
    local_ip: IpAddress,
    local_port: Int,
    remote_port: Int,
    sent_open: BitArray,
    recv_open: BitArray,
  )
  BmpMsgInitiation(sys_name: String, sys_descr: String)
  BmpMsgTermination(reason: Int, message: String)
}
