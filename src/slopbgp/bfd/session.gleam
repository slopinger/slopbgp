import gleam/option.{type Option, None, Some}
import slopbgp/bfd/message.{
  type BfdPacket, type BfdState, BfdAdminDown, BfdDown, BfdInit, BfdPacket,
  BfdUp,
}

pub type BfdSession {
  BfdSession(
    peer_id: String,
    local_discr: Int,
    remote_discr: Int,
    local_state: BfdState,
    remote_state: BfdState,
    desired_tx_us: Int,
    required_rx_us: Int,
    negotiated_tx_us: Int,
    negotiated_rx_us: Int,
    detect_mult: Int,
    last_rx_us: Int,
    last_tx_us: Int,
    packets_sent: Int,
    packets_received: Int,
    diag: Int,
    down_reason: Option(String),
  )
}

pub type BfdAction {
  BfdActionSendPacket(BfdPacket)
  BfdActionSignalBgpDown(peer_id: String, reason: String)
}

pub fn new_bfd_session(
  peer_id: String,
  local_discr: Int,
  desired_tx_us: Int,
  required_rx_us: Int,
  detect_mult: Int,
) -> BfdSession {
  BfdSession(
    peer_id: peer_id,
    local_discr: local_discr,
    remote_discr: 0,
    local_state: BfdDown,
    remote_state: BfdDown,
    desired_tx_us: desired_tx_us,
    required_rx_us: required_rx_us,
    negotiated_tx_us: desired_tx_us,
    negotiated_rx_us: required_rx_us,
    detect_mult: detect_mult,
    last_rx_us: 0,
    last_tx_us: 0,
    packets_sent: 0,
    packets_received: 0,
    diag: 0,
    down_reason: None,
  )
}

pub fn create_control_packet(
  session: BfdSession,
  poll: Bool,
  final: Bool,
) -> BfdPacket {
  BfdPacket(
    version: 1,
    diag: session.diag,
    state: session.local_state,
    poll: poll,
    final: final,
    control_plane_independent: False,
    auth_present: False,
    demand: False,
    multipoint: False,
    detect_mult: session.detect_mult,
    my_discriminator: session.local_discr,
    your_discriminator: session.remote_discr,
    desired_min_tx_us: session.desired_tx_us,
    required_min_rx_us: session.required_rx_us,
    required_min_echo_us: 0,
  )
}

pub fn handle_packet(
  session: BfdSession,
  pkt: BfdPacket,
  now_us: Int,
) -> #(BfdSession, List(BfdAction)) {
  let updated_rx = session.packets_received + 1
  let neg_tx = case pkt.required_min_rx_us > session.desired_tx_us {
    True -> pkt.required_min_rx_us
    False -> session.desired_tx_us
  }
  let neg_rx = case pkt.desired_min_tx_us > session.required_rx_us {
    True -> pkt.desired_min_tx_us
    False -> session.required_rx_us
  }

  let session1 =
    BfdSession(
      ..session,
      remote_discr: pkt.my_discriminator,
      remote_state: pkt.state,
      last_rx_us: now_us,
      packets_received: updated_rx,
      negotiated_tx_us: neg_tx,
      negotiated_rx_us: neg_rx,
    )

  case session1.local_state {
    BfdAdminDown -> #(session1, [])

    BfdDown -> {
      case pkt.state {
        BfdDown -> {
          // Received Down, transition to Init
          let session2 = BfdSession(..session1, local_state: BfdInit)
          let reply_pkt = create_control_packet(session2, False, pkt.poll)
          #(session2, [BfdActionSendPacket(reply_pkt)])
        }
        BfdInit -> {
          // Received Init, transition to Up
          let session2 = BfdSession(..session1, local_state: BfdUp)
          let reply_pkt = create_control_packet(session2, False, pkt.poll)
          #(session2, [BfdActionSendPacket(reply_pkt)])
        }
        BfdUp -> {
          let session2 = BfdSession(..session1, local_state: BfdUp)
          let reply_pkt = create_control_packet(session2, False, pkt.poll)
          #(session2, [BfdActionSendPacket(reply_pkt)])
        }
        BfdAdminDown -> {
          #(session1, [])
        }
      }
    }

    BfdInit -> {
      case pkt.state {
        BfdInit | BfdUp -> {
          let session2 = BfdSession(..session1, local_state: BfdUp)
          let reply_pkt = create_control_packet(session2, False, pkt.poll)
          #(session2, [BfdActionSendPacket(reply_pkt)])
        }
        BfdDown -> {
          let reply_pkt = create_control_packet(session1, False, pkt.poll)
          #(session1, [BfdActionSendPacket(reply_pkt)])
        }
        BfdAdminDown -> {
          let session2 =
            BfdSession(
              ..session1,
              local_state: BfdDown,
              diag: 3,
              down_reason: Some("Neighbor signaled session down (AdminDown)"),
            )
          #(session2, [
            BfdActionSignalBgpDown(session.peer_id, "Remote neighbor AdminDown"),
          ])
        }
      }
    }

    BfdUp -> {
      case pkt.state {
        BfdAdminDown -> {
          let session2 =
            BfdSession(
              ..session1,
              local_state: BfdDown,
              diag: 7,
              down_reason: Some("Neighbor administratively down"),
            )
          #(session2, [
            BfdActionSignalBgpDown(
              session.peer_id,
              "Neighbor signaled AdminDown",
            ),
          ])
        }
        BfdDown -> {
          let session2 =
            BfdSession(
              ..session1,
              local_state: BfdDown,
              diag: 3,
              down_reason: Some("Neighbor signaled session down"),
            )
          #(session2, [
            BfdActionSignalBgpDown(
              session.peer_id,
              "Neighbor signaled session down",
            ),
          ])
        }
        _ -> {
          case pkt.poll {
            True -> {
              let reply_pkt = create_control_packet(session1, False, True)
              #(session1, [BfdActionSendPacket(reply_pkt)])
            }
            False -> #(session1, [])
          }
        }
      }
    }
  }
}

pub fn check_timer(
  session: BfdSession,
  now_us: Int,
) -> #(BfdSession, List(BfdAction)) {
  case session.local_state {
    BfdUp | BfdInit -> {
      let detect_time_us = session.detect_mult * session.negotiated_rx_us
      let elapsed_us = now_us - session.last_rx_us
      case session.last_rx_us > 0 && elapsed_us > detect_time_us {
        True -> {
          // Detection timer expired! Sub-second link drop!
          let session2 =
            BfdSession(
              ..session,
              local_state: BfdDown,
              diag: 1,
              down_reason: Some(
                "Control Detection Time Expired (Sub-second BFD failover)",
              ),
            )
          let pkt = create_control_packet(session2, False, False)
          #(session2, [
            BfdActionSendPacket(pkt),
            BfdActionSignalBgpDown(
              session.peer_id,
              "BFD Detection Time Expired ("
                <> int_to_string(elapsed_us / 1000)
                <> "ms > "
                <> int_to_string(detect_time_us / 1000)
                <> "ms)",
            ),
          ])
        }
        False -> {
          // Check if it's time to transmit periodic keepalive control packet
          let elapsed_tx = now_us - session.last_tx_us
          case
            session.last_tx_us == 0 || elapsed_tx >= session.negotiated_tx_us
          {
            True -> {
              let pkt = create_control_packet(session, False, False)
              let session2 =
                BfdSession(
                  ..session,
                  last_tx_us: now_us,
                  packets_sent: session.packets_sent + 1,
                )
              #(session2, [BfdActionSendPacket(pkt)])
            }
            False -> #(session, [])
          }
        }
      }
    }
    _ -> #(session, [])
  }
}

fn int_to_string(i: Int) -> String {
  case i {
    0 -> "0"
    _ -> {
      // Basic formatter for timeout logging
      let sign = case i < 0 {
        True -> "-"
        False -> ""
      }
      let abs = case i < 0 {
        True -> 0 - i
        False -> i
      }
      sign <> format_uint(abs, "")
    }
  }
}

fn format_uint(n: Int, acc: String) -> String {
  let digit = case n % 10 {
    0 -> "0"
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    6 -> "6"
    7 -> "7"
    8 -> "8"
    _ -> "9"
  }
  let rem = n / 10
  case rem {
    0 -> digit <> acc
    _ -> format_uint(rem, digit <> acc)
  }
}
