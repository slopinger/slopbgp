import gleam/list
import gleam/option.{type Option, None, Some}
import slopbgp/rtr/message.{
  type RtrPdu, RtrCacheReset, RtrCacheResponse, RtrEndOfData, RtrErrorReport,
  RtrIpv4Prefix, RtrIpv6Prefix, RtrResetQuery, RtrSerialNotify, RtrSerialQuery,
  encode_rtr_pdu, rtr_version_1,
}
import slopbgp/types.{type RoaEntry, IpPrefix, RoaEntry}

pub type RtrClientStatus {
  RtrStatusDisconnected
  RtrStatusConnecting
  RtrStatusSynchronizing
  RtrStatusSynchronized
  RtrStatusError(String)
}

pub type RtrClient {
  RtrClient(
    host: String,
    port: Int,
    version: Int,
    status: RtrClientStatus,
    session_id: Option(Int),
    serial: Option(Int),
    roa_table: List(RoaEntry),
    refresh_interval: Int,
    retry_interval: Int,
    expire_interval: Int,
    last_refresh: Int,
    announcements_count: Int,
    withdrawals_count: Int,
  )
}

pub fn new_rtr_client(host: String, port: Int) -> RtrClient {
  RtrClient(
    host: host,
    port: port,
    version: rtr_version_1,
    status: RtrStatusDisconnected,
    session_id: None,
    serial: None,
    roa_table: [],
    refresh_interval: 3600,
    retry_interval: 600,
    expire_interval: 7200,
    last_refresh: 0,
    announcements_count: 0,
    withdrawals_count: 0,
  )
}

pub fn create_initial_query(client: RtrClient) -> BitArray {
  case client.session_id, client.serial {
    Some(sid), Some(s) ->
      encode_rtr_pdu(RtrSerialQuery(
        version: client.version,
        session_id: sid,
        serial: s,
      ))
    _, _ -> encode_rtr_pdu(RtrResetQuery(version: client.version))
  }
}

pub fn process_pdu(
  client: RtrClient,
  pdu: RtrPdu,
  now_ts: Int,
) -> #(RtrClient, Option(BitArray)) {
  case pdu {
    RtrCacheResponse(version: _, session_id: sid) -> {
      let updated =
        RtrClient(
          ..client,
          session_id: Some(sid),
          status: RtrStatusSynchronizing,
        )
      #(updated, None)
    }

    RtrIpv4Prefix(
      version: _,
      flags: flags,
      prefix_len: plen,
      max_len: mlen,
      prefix: p,
      asn: asn,
    ) -> {
      let entry =
        RoaEntry(prefix: IpPrefix(p, plen), max_length: mlen, asn: asn)
      case flags {
        1 -> {
          // Announce / Add
          let filtered =
            list.filter(client.roa_table, fn(e) { !same_roa(e, entry) })
          let updated =
            RtrClient(
              ..client,
              roa_table: [entry, ..filtered],
              announcements_count: client.announcements_count + 1,
            )
          #(updated, None)
        }
        _ -> {
          // Withdraw / Remove
          let filtered =
            list.filter(client.roa_table, fn(e) { !same_roa(e, entry) })
          let updated =
            RtrClient(
              ..client,
              roa_table: filtered,
              withdrawals_count: client.withdrawals_count + 1,
            )
          #(updated, None)
        }
      }
    }

    RtrIpv6Prefix(
      version: _,
      flags: flags,
      prefix_len: plen,
      max_len: mlen,
      prefix: p,
      asn: asn,
    ) -> {
      let entry =
        RoaEntry(prefix: IpPrefix(p, plen), max_length: mlen, asn: asn)
      case flags {
        1 -> {
          // Announce / Add
          let filtered =
            list.filter(client.roa_table, fn(e) { !same_roa(e, entry) })
          let updated =
            RtrClient(
              ..client,
              roa_table: [entry, ..filtered],
              announcements_count: client.announcements_count + 1,
            )
          #(updated, None)
        }
        _ -> {
          // Withdraw / Remove
          let filtered =
            list.filter(client.roa_table, fn(e) { !same_roa(e, entry) })
          let updated =
            RtrClient(
              ..client,
              roa_table: filtered,
              withdrawals_count: client.withdrawals_count + 1,
            )
          #(updated, None)
        }
      }
    }

    RtrEndOfData(
      version: _,
      session_id: sid,
      serial: s,
      refresh_sec: ref,
      retry_sec: ret,
      expire_sec: exp,
    ) -> {
      let updated =
        RtrClient(
          ..client,
          session_id: Some(sid),
          serial: Some(s),
          refresh_interval: ref,
          retry_interval: ret,
          expire_interval: exp,
          last_refresh: now_ts,
          status: RtrStatusSynchronized,
        )
      #(updated, None)
    }

    RtrCacheReset(version: v) -> {
      let reset_client =
        RtrClient(
          ..client,
          session_id: None,
          serial: None,
          roa_table: [],
          status: RtrStatusConnecting,
        )
      let query = encode_rtr_pdu(RtrResetQuery(v))
      #(reset_client, Some(query))
    }

    RtrSerialNotify(version: v, session_id: sid, serial: _new_serial) -> {
      case client.session_id {
        Some(curr_sid) if curr_sid == sid -> {
          case client.serial {
            Some(curr_s) -> {
              let query =
                encode_rtr_pdu(RtrSerialQuery(
                  version: v,
                  session_id: sid,
                  serial: curr_s,
                ))
              #(client, Some(query))
            }
            None -> {
              let query = encode_rtr_pdu(RtrResetQuery(version: v))
              #(client, Some(query))
            }
          }
        }
        _ -> {
          let query = encode_rtr_pdu(RtrResetQuery(version: v))
          #(client, Some(query))
        }
      }
    }

    RtrErrorReport(
      version: _,
      error_code: code,
      encapsulated_pdu: _,
      message: msg,
    ) -> {
      let err_str = "RTR Error " <> int_to_string(code) <> ": " <> msg
      let updated = RtrClient(..client, status: RtrStatusError(err_str))
      #(updated, None)
    }

    _ -> #(client, None)
  }
}

fn same_roa(a: RoaEntry, b: RoaEntry) -> Bool {
  a.prefix.length == b.prefix.length
  && a.max_length == b.max_length
  && a.asn == b.asn
  && a.prefix.address == b.prefix.address
}

fn int_to_string(i: Int) -> String {
  case i {
    0 -> "0"
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    6 -> "6"
    7 -> "7"
    _ -> "err"
  }
}
