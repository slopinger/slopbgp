import gleam/bit_array

pub type BfdState {
  BfdAdminDown
  BfdDown
  BfdInit
  BfdUp
}

pub type BfdPacket {
  BfdPacket(
    version: Int,
    diag: Int,
    state: BfdState,
    poll: Bool,
    final: Bool,
    control_plane_independent: Bool,
    auth_present: Bool,
    demand: Bool,
    multipoint: Bool,
    detect_mult: Int,
    my_discriminator: Int,
    your_discriminator: Int,
    desired_min_tx_us: Int,
    required_min_rx_us: Int,
    required_min_echo_us: Int,
  )
}

pub fn state_to_int(state: BfdState) -> Int {
  case state {
    BfdAdminDown -> 0
    BfdDown -> 1
    BfdInit -> 2
    BfdUp -> 3
  }
}

pub fn int_to_state(code: Int) -> BfdState {
  case code {
    0 -> BfdAdminDown
    1 -> BfdDown
    2 -> BfdInit
    3 -> BfdUp
    _ -> BfdDown
  }
}

pub fn state_to_string(state: BfdState) -> String {
  case state {
    BfdAdminDown -> "AdminDown"
    BfdDown -> "Down"
    BfdInit -> "Init"
    BfdUp -> "Up"
  }
}

pub fn encode_bfd_packet(pkt: BfdPacket) -> BitArray {
  let v = pkt.version
  let diag = pkt.diag
  let sta = state_to_int(pkt.state)
  let p = case pkt.poll {
    True -> 1
    False -> 0
  }
  let f = case pkt.final {
    True -> 1
    False -> 0
  }
  let c = case pkt.control_plane_independent {
    True -> 1
    False -> 0
  }
  let a = case pkt.auth_present {
    True -> 1
    False -> 0
  }
  let d = case pkt.demand {
    True -> 1
    False -> 0
  }
  let m = case pkt.multipoint {
    True -> 1
    False -> 0
  }
  let len = 24

  <<
    v:3, diag:5, sta:2, p:1, f:1, c:1, a:1, d:1, m:1, pkt.detect_mult:8, len:8,
    pkt.my_discriminator:32, pkt.your_discriminator:32, pkt.desired_min_tx_us:32,
    pkt.required_min_rx_us:32, pkt.required_min_echo_us:32,
  >>
}

pub fn decode_bfd_packet(bytes: BitArray) -> Result(BfdPacket, String) {
  let size = bit_array.byte_size(bytes)
  case size < 24 {
    True -> Error("Truncated BFD packet (expected at least 24 bytes)")
    False -> {
      case bytes {
        <<
          v:3,
          diag:5,
          sta:2,
          p:1,
          f:1,
          c:1,
          a:1,
          d:1,
          m:1,
          detect_mult:8,
          _len:8,
          my_discr:32,
          your_discr:32,
          tx_us:32,
          rx_us:32,
          echo_us:32,
          _:bits,
        >> -> {
          case v {
            1 -> {
              Ok(BfdPacket(
                version: v,
                diag: diag,
                state: int_to_state(sta),
                poll: p == 1,
                final: f == 1,
                control_plane_independent: c == 1,
                auth_present: a == 1,
                demand: d == 1,
                multipoint: m == 1,
                detect_mult: detect_mult,
                my_discriminator: my_discr,
                your_discriminator: your_discr,
                desired_min_tx_us: tx_us,
                required_min_rx_us: rx_us,
                required_min_echo_us: echo_us,
              ))
            }
            _ -> Error("Unsupported BFD version: " <> int_to_string(v))
          }
        }
        _ -> Error("Malformed BFD packet framing")
      }
    }
  }
}

fn int_to_string(i: Int) -> String {
  case i {
    1 -> "1"
    2 -> "2"
    3 -> "3"
    _ -> "other"
  }
}
