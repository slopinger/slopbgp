import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/string
import slopbgp/bgp/blackhole.{has_blackhole_community}
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/types.{type Route}

pub type FibEntry {
  FibEntry(
    prefix_str: String,
    next_hop_str: String,
    metric: Int,
    peer_id: String,
    is_blackhole: Bool,
  )
}

pub type FibState {
  FibState(
    table_id: Int,
    installed: Dict(String, FibEntry),
    routes_added: Int,
    routes_updated: Int,
    routes_deleted: Int,
  )
}

pub fn new_fib(table_id: Int) -> FibState {
  FibState(
    table_id: table_id,
    installed: dict.new(),
    routes_added: 0,
    routes_updated: 0,
    routes_deleted: 0,
  )
}

pub fn sync_fib(fib: FibState, desired_routes: List(Route)) -> FibState {
  let desired_dict =
    list.fold(desired_routes, dict.new(), fn(acc, route) {
      let p_str = prefix_to_string(route.prefix)
      let nh_str = ip_to_string(route.next_hop)
      let bh = has_blackhole_community(route.communities)
      let entry =
        FibEntry(
          prefix_str: p_str,
          next_hop_str: nh_str,
          metric: route.med,
          peer_id: route.peer_id,
          is_blackhole: bh,
        )
      dict.insert(acc, p_str, entry)
    })

  // Find added or updated routes
  let #(updated_installed, added_cnt, updated_cnt) =
    dict.fold(
      desired_dict,
      #(fib.installed, 0, 0),
      fn(acc, p_str, desired_entry) {
        let #(curr_inst, a_cnt, u_cnt) = acc
        case dict.get(curr_inst, p_str) {
          Ok(existing) ->
            case existing.next_hop_str == desired_entry.next_hop_str {
              True -> acc
              False -> {
                #(
                  dict.insert(curr_inst, p_str, desired_entry),
                  a_cnt,
                  u_cnt + 1,
                )
              }
            }
          Error(_) -> {
            #(dict.insert(curr_inst, p_str, desired_entry), a_cnt + 1, u_cnt)
          }
        }
      },
    )

  // Find deleted routes (in installed but not in desired)
  let #(final_installed, deleted_cnt) =
    dict.fold(
      updated_installed,
      #(updated_installed, 0),
      fn(acc, p_str, _entry) {
        let #(curr_inst, d_cnt) = acc
        case dict.has_key(desired_dict, p_str) {
          True -> acc
          False -> #(dict.delete(curr_inst, p_str), d_cnt + 1)
        }
      },
    )

  FibState(
    table_id: fib.table_id,
    installed: final_installed,
    routes_added: fib.routes_added + added_cnt,
    routes_updated: fib.routes_updated + updated_cnt,
    routes_deleted: fib.routes_deleted + deleted_cnt,
  )
}

pub fn count_installed(fib: FibState) -> Int {
  dict.size(fib.installed)
}

pub fn get_installed_entries(fib: FibState) -> List(FibEntry) {
  dict.values(fib.installed)
}

pub fn fib_entry_to_string(entry: FibEntry) -> String {
  case entry.is_blackhole {
    True ->
      entry.prefix_str <> " [BLACKHOLE/DISCARD] (peer " <> entry.peer_id <> ")"
    False ->
      entry.prefix_str
      <> " via "
      <> entry.next_hop_str
      <> " (metric "
      <> int.to_string(entry.metric)
      <> ", peer "
      <> entry.peer_id
      <> ")"
  }
}

pub fn fib_entry_to_command(entry: FibEntry, table_id: Int) -> String {
  let is_v6 = string.contains(entry.prefix_str, ":")
  let cmd_prefix = case is_v6 {
    True -> "ip -6 route replace "
    False -> "ip route replace "
  }
  case entry.is_blackhole {
    True ->
      cmd_prefix
      <> "blackhole "
      <> entry.prefix_str
      <> " table "
      <> int.to_string(table_id)
    False ->
      cmd_prefix
      <> entry.prefix_str
      <> " via "
      <> entry.next_hop_str
      <> " metric "
      <> int.to_string(entry.metric)
      <> " table "
      <> int.to_string(table_id)
  }
}
