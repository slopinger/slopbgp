import gleam/list
import gleam/option.{type Option, None, Some}
import slopbgp/types.{
  type BgpCapability, type BgpMessage, type FsmState, type IpAddress,
  CapFourOctetAsn, MsgOpen, StateActive, StateConnect, StateEstablished,
  StateIdle, StateOpenConfirm, StateOpenSent,
}

pub type FsmEvent {
  EventManualStart
  EventAutomaticStart
  EventConnectRetryExpires
  EventHoldTimerExpires
  EventKeepaliveTimerExpires
  EventTcpConnected
  EventTcpFailed
  EventReceivedOpen(BgpMessage)
  EventReceivedKeepalive
  EventReceivedUpdate(BgpMessage)
  EventReceivedNotification(BgpMessage)
  EventReceivedRouteRefresh(BgpMessage)
  EventError(String)
}

pub type FsmAction {
  ActionNone
  ActionConnect
  ActionSendOpen
  ActionSendKeepalive
  ActionSendNotification(code: Int, subcode: Int, data: BitArray)
  ActionStartHoldTimer(seconds: Int)
  ActionStartKeepaliveTimer(seconds: Int)
  ActionResetHoldTimer
  ActionCloseTcp
  ActionSessionEstablished
  ActionProcessUpdate(BgpMessage)
  ActionProcessRouteRefresh(BgpMessage)
}

pub type FsmSession {
  FsmSession(
    state: FsmState,
    peer_id: String,
    local_as: Int,
    local_id: IpAddress,
    remote_as: Int,
    configured_hold_time: Int,
    negotiated_hold_time: Int,
    peer_capabilities: List(BgpCapability),
    peer_bgp_id: Option(IpAddress),
    four_byte_as: Bool,
    add_path_rx: Bool,
    add_path_tx: Bool,
    extended_next_hop: Bool,
  )
}

pub fn new_session(
  peer_id: String,
  local_as: Int,
  local_id: IpAddress,
  remote_as: Int,
  hold_time: Int,
) -> FsmSession {
  FsmSession(
    state: StateIdle,
    peer_id: peer_id,
    local_as: local_as,
    local_id: local_id,
    remote_as: remote_as,
    configured_hold_time: hold_time,
    negotiated_hold_time: hold_time,
    peer_capabilities: [],
    peer_bgp_id: None,
    four_byte_as: True,
    add_path_rx: False,
    add_path_tx: False,
    extended_next_hop: False,
  )
}

pub fn handle_event(
  session: FsmSession,
  event: FsmEvent,
) -> #(FsmSession, List(FsmAction)) {
  case session.state, event {
    StateIdle, EventManualStart | StateIdle, EventAutomaticStart -> {
      #(FsmSession(..session, state: StateConnect), [ActionConnect])
    }

    StateConnect, EventTcpConnected -> {
      #(FsmSession(..session, state: StateOpenSent), [ActionSendOpen])
    }

    StateConnect, EventTcpFailed | StateConnect, EventConnectRetryExpires -> {
      #(FsmSession(..session, state: StateActive), [ActionConnect])
    }

    StateActive, EventTcpConnected -> {
      #(FsmSession(..session, state: StateOpenSent), [ActionSendOpen])
    }

    StateActive, EventTcpFailed | StateActive, EventConnectRetryExpires -> {
      #(FsmSession(..session, state: StateConnect), [ActionConnect])
    }

    StateOpenSent, EventReceivedOpen(MsgOpen(ver, peer_as, hold, id, caps)) -> {
      case ver == 4 {
        False -> {
          #(FsmSession(..session, state: StateIdle), [
            ActionSendNotification(2, 1, <<>>),
            ActionCloseTcp,
          ])
        }
        True -> {
          let expected_as = session.remote_as
          let valid_as = peer_as == expected_as || peer_as == 23_456
          case valid_as {
            False -> {
              #(FsmSession(..session, state: StateIdle), [
                ActionSendNotification(2, 2, <<>>),
                ActionCloseTcp,
              ])
            }
            True -> {
              let neg_hold = case hold < session.configured_hold_time {
                True -> hold
                False -> session.configured_hold_time
              }
              let keepalive_time = case neg_hold > 0 {
                True -> neg_hold / 3
                False -> 0
              }
              let has_4byte =
                list.any(caps, fn(c) {
                  case c {
                    CapFourOctetAsn(_) -> True
                    _ -> False
                  }
                })
              let has_enh =
                list.any(caps, fn(c) {
                  case c {
                    types.CapExtendedNextHop(_, _, _) -> True
                    _ -> False
                  }
                })

              let updated =
                FsmSession(
                  ..session,
                  state: StateOpenConfirm,
                  negotiated_hold_time: neg_hold,
                  peer_capabilities: caps,
                  peer_bgp_id: Some(id),
                  four_byte_as: has_4byte,
                  extended_next_hop: has_enh,
                )

              let actions = case neg_hold > 0 {
                True -> [
                  ActionSendKeepalive,
                  ActionStartHoldTimer(neg_hold),
                  ActionStartKeepaliveTimer(keepalive_time),
                ]
                False -> [ActionSendKeepalive]
              }
              #(updated, actions)
            }
          }
        }
      }
    }

    StateOpenSent, EventHoldTimerExpires -> {
      #(FsmSession(..session, state: StateIdle), [
        ActionSendNotification(4, 0, <<>>),
        ActionCloseTcp,
      ])
    }

    StateOpenConfirm, EventReceivedKeepalive -> {
      let actions = case session.negotiated_hold_time > 0 {
        True -> [ActionResetHoldTimer, ActionSessionEstablished]
        False -> [ActionSessionEstablished]
      }
      #(FsmSession(..session, state: StateEstablished), actions)
    }

    StateOpenConfirm, EventHoldTimerExpires -> {
      #(FsmSession(..session, state: StateIdle), [
        ActionSendNotification(4, 0, <<>>),
        ActionCloseTcp,
      ])
    }

    StateOpenConfirm, EventKeepaliveTimerExpires -> {
      #(session, [ActionSendKeepalive])
    }

    StateEstablished, EventReceivedKeepalive -> {
      let actions = case session.negotiated_hold_time > 0 {
        True -> [ActionResetHoldTimer]
        False -> []
      }
      #(session, actions)
    }

    StateEstablished, EventKeepaliveTimerExpires -> {
      #(session, [ActionSendKeepalive])
    }

    StateEstablished, EventHoldTimerExpires -> {
      #(FsmSession(..session, state: StateIdle), [
        ActionSendNotification(4, 0, <<>>),
        ActionCloseTcp,
      ])
    }

    StateEstablished, EventReceivedUpdate(update_msg) -> {
      let actions = case session.negotiated_hold_time > 0 {
        True -> [ActionResetHoldTimer, ActionProcessUpdate(update_msg)]
        False -> [ActionProcessUpdate(update_msg)]
      }
      #(session, actions)
    }

    StateEstablished, EventReceivedRouteRefresh(refresh_msg) -> {
      #(session, [ActionProcessRouteRefresh(refresh_msg)])
    }

    _, EventReceivedNotification(_) -> {
      #(FsmSession(..session, state: StateIdle), [ActionCloseTcp])
    }

    _, EventTcpFailed -> {
      #(FsmSession(..session, state: StateActive), [
        ActionCloseTcp,
        ActionConnect,
      ])
    }

    _, EventError(_) -> {
      #(FsmSession(..session, state: StateIdle), [ActionCloseTcp])
    }

    _, _ -> #(session, [ActionNone])
  }
}
