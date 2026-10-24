import gleam/int
import gleam/list
import slopbgp/types.{
  type Afi, type BgpCapability, type BgpRole, type LlgrAfiSafi, type Safi,
  AfiIpv4, AfiIpv6, AfiL2Vpn, AfiUnknown, CapAddPath, CapBgpRole,
  CapEnhancedRouteRefresh, CapExtendedMessage, CapExtendedNextHop,
  CapFourOctetAsn, CapGracefulRestart, CapLongLivedGracefulRestart,
  CapMultiProtocol, CapRouteRefresh, CapUnknown, LlgrAfiSafi, RoleCustomer,
  RolePeer, RoleProvider, RoleRouteServer, RoleRouteServerClient, RoleUnknown,
  SafiEvpn, SafiFlowspec, SafiMplsVpn, SafiMulticast, SafiRtc, SafiUnicast,
  SafiUnknown,
}

pub fn afi_to_int(afi: Afi) -> Int {
  case afi {
    AfiIpv4 -> 1
    AfiIpv6 -> 2
    AfiL2Vpn -> 25
    AfiUnknown(code) -> code
  }
}

pub fn int_to_afi(code: Int) -> Afi {
  case code {
    1 -> AfiIpv4
    2 -> AfiIpv6
    25 -> AfiL2Vpn
    _ -> AfiUnknown(code)
  }
}

pub fn safi_to_int(safi: Safi) -> Int {
  case safi {
    SafiUnicast -> 1
    SafiMulticast -> 2
    SafiEvpn -> 70
    SafiMplsVpn -> 128
    SafiRtc -> 132
    SafiFlowspec -> 133
    SafiUnknown(code) -> code
  }
}

pub fn int_to_safi(code: Int) -> Safi {
  case code {
    1 -> SafiUnicast
    2 -> SafiMulticast
    70 -> SafiEvpn
    128 -> SafiMplsVpn
    132 -> SafiRtc
    133 -> SafiFlowspec
    _ -> SafiUnknown(code)
  }
}

pub fn role_to_int(role: BgpRole) -> Int {
  case role {
    RoleProvider -> 0
    RoleRouteServer -> 1
    RoleRouteServerClient -> 2
    RoleCustomer -> 3
    RolePeer -> 4
    RoleUnknown(code) -> code
  }
}

pub fn int_to_role(code: Int) -> BgpRole {
  case code {
    0 -> RoleProvider
    1 -> RoleRouteServer
    2 -> RoleRouteServerClient
    3 -> RoleCustomer
    4 -> RolePeer
    _ -> RoleUnknown(code)
  }
}

pub fn encode_capability(cap: BgpCapability) -> BitArray {
  case cap {
    CapMultiProtocol(afi, safi) -> {
      let afi_int = afi_to_int(afi)
      let safi_int = safi_to_int(safi)
      <<1:8, 4:8, afi_int:16, 0:8, safi_int:8>>
    }
    CapRouteRefresh -> <<2:8, 0:8>>
    CapExtendedNextHop(nlri_afi, nlri_safi, nh_afi) -> {
      let n_afi = afi_to_int(nlri_afi)
      let n_safi = safi_to_int(nlri_safi)
      let nh = afi_to_int(nh_afi)
      <<5:8, 6:8, n_afi:16, n_safi:16, nh:16>>
    }
    CapBgpRole(role) -> {
      let r = role_to_int(role)
      <<9:8, 1:8, r:8>>
    }
    CapGracefulRestart(flags, time, afi_safis) -> {
      let entries =
        list.map(afi_safis, fn(entry) {
          let #(a, s, f) = entry
          <<{ afi_to_int(a) }:16, { safi_to_int(s) }:8, f:8>>
        })
      let entries_bin =
        list.fold(entries, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
      let header = <<flags:4, time:12>>
      let val = <<header:bits, entries_bin:bits>>
      let len = byte_size(val)
      <<64:8, len:8, val:bits>>
    }
    CapLongLivedGracefulRestart(families) -> {
      let entries =
        list.map(families, fn(fam) {
          let flags = case fam.forwarding_preserved {
            True -> 0x80
            False -> 0x00
          }
          let stale_time = fam.stale_time_seconds
          let b1 =
            int.bitwise_and(int.bitwise_shift_right(stale_time, 16), 0xFF)
          let b2 = int.bitwise_and(int.bitwise_shift_right(stale_time, 8), 0xFF)
          let b3 = int.bitwise_and(stale_time, 0xFF)
          <<
            { afi_to_int(fam.afi) }:16,
            { safi_to_int(fam.safi) }:8,
            flags:8,
            b1:8,
            b2:8,
            b3:8,
          >>
        })
      let val = list.fold(entries, <<>>, fn(acc, b) { <<acc:bits, b:bits>> })
      let len = byte_size(val)
      <<71:8, len:8, val:bits>>
    }
    CapFourOctetAsn(asn) -> <<65:8, 4:8, asn:32>>
    CapAddPath(afi, safi, send, receive) -> {
      let flag = case send, receive {
        True, True -> 3
        True, False -> 2
        False, True -> 1
        False, False -> 0
      }
      <<69:8, 4:8, { afi_to_int(afi) }:16, { safi_to_int(safi) }:8, flag:8>>
    }
    CapEnhancedRouteRefresh -> <<70:8, 0:8>>
    CapExtendedMessage -> <<74:8, 0:8>>
    CapUnknown(code, val) -> {
      let len = byte_size(val)
      <<code:8, len:8, val:bits>>
    }
  }
}

pub fn decode_capabilities(bytes: BitArray) -> List(BgpCapability) {
  decode_capabilities_loop(bytes, [])
}

fn decode_capabilities_loop(
  bytes: BitArray,
  acc: List(BgpCapability),
) -> List(BgpCapability) {
  case bytes {
    <<>> -> list.reverse(acc)
    <<code:8, len:8, rest:bits>> -> {
      let bits_needed = len * 8
      case rest {
        <<val:bits-size(bits_needed), rem:bits>> -> {
          let cap = decode_single_capability(code, val)
          decode_capabilities_loop(rem, [cap, ..acc])
        }
        _ -> list.reverse(acc)
      }
    }
    _ -> list.reverse(acc)
  }
}

fn decode_single_capability(code: Int, val: BitArray) -> BgpCapability {
  case code, val {
    1, <<afi_int:16, _:8, safi_int:8>> ->
      CapMultiProtocol(int_to_afi(afi_int), int_to_safi(safi_int))
    2, <<>> -> CapRouteRefresh
    5, <<n_afi:16, n_safi:16, nh:16>> ->
      CapExtendedNextHop(int_to_afi(n_afi), int_to_safi(n_safi), int_to_afi(nh))
    9, <<role_int:8>> -> CapBgpRole(int_to_role(role_int))
    64, <<flags:4, time:12, entries_bin:bits>> -> {
      let entries = decode_gr_entries(entries_bin, [])
      CapGracefulRestart(flags, time, entries)
    }
    65, <<asn:32>> -> CapFourOctetAsn(asn)
    69, <<afi:16, safi:8, flag:8>> -> {
      let send = flag == 2 || flag == 3
      let receive = flag == 1 || flag == 3
      CapAddPath(int_to_afi(afi), int_to_safi(safi), send, receive)
    }
    70, <<>> -> CapEnhancedRouteRefresh
    71, entries_bin -> {
      let entries = decode_llgr_entries(entries_bin, [])
      CapLongLivedGracefulRestart(entries)
    }
    74, <<>> -> CapExtendedMessage
    _, _ -> CapUnknown(code, val)
  }
}

fn decode_llgr_entries(
  bytes: BitArray,
  acc: List(LlgrAfiSafi),
) -> List(LlgrAfiSafi) {
  case bytes {
    <<afi:16, safi:8, flags:8, b1:8, b2:8, b3:8, rest:bits>> -> {
      let f_preserved = int.bitwise_and(flags, 0x80) != 0
      let stale_time =
        int.bitwise_or(
          int.bitwise_shift_left(b1, 16),
          int.bitwise_or(int.bitwise_shift_left(b2, 8), b3),
        )
      let fam =
        LlgrAfiSafi(
          afi: int_to_afi(afi),
          safi: int_to_safi(safi),
          forwarding_preserved: f_preserved,
          stale_time_seconds: stale_time,
        )
      decode_llgr_entries(rest, [fam, ..acc])
    }
    _ -> list.reverse(acc)
  }
}

fn decode_gr_entries(
  bytes: BitArray,
  acc: List(#(Afi, Safi, Int)),
) -> List(#(Afi, Safi, Int)) {
  case bytes {
    <<afi:16, safi:8, flags:8, rest:bits>> ->
      decode_gr_entries(rest, [
        #(int_to_afi(afi), int_to_safi(safi), flags),
        ..acc
      ])
    _ -> list.reverse(acc)
  }
}

fn byte_size(bytes: BitArray) -> Int {
  case bytes {
    <<_:8, rest:bits>> -> 1 + byte_size(rest)
    _ -> 0
  }
}
