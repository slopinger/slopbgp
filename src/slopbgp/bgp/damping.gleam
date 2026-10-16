import gleam/dict.{type Dict}
import gleam/float
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import slopbgp/ip.{parse_prefix, prefix_to_string}
import slopbgp/types.{
  type DampedRoute, type DampingConfig, type FlapHistory, type IpPrefix,
  DampedRoute, DampingConfig, FlapHistory,
}

@external(erlang, "slopbgp_ffi", "math_pow")
pub fn math_pow(base: Float, exp: Float) -> Float

@external(erlang, "slopbgp_ffi", "math_log")
pub fn math_log(val: Float) -> Float

pub type DampingTable =
  Dict(#(String, String), FlapHistory)

pub fn default_damping_config() -> DampingConfig {
  DampingConfig(
    half_life_seconds: 900,
    reuse_threshold: 750.0,
    suppress_threshold: 2000.0,
    max_suppress_seconds: 2700,
    penalty_per_flap: 1000.0,
  )
}

pub fn new_table() -> DampingTable {
  dict.new()
}

/// Compute decayed penalty after delta_t seconds using half-life decay
pub fn decay_penalty(penalty: Float, delta_t: Int, half_life: Int) -> Float {
  case delta_t <= 0 {
    True -> penalty
    False -> {
      let half_life_f = int.to_float(half_life)
      let delta_f = int.to_float(delta_t)
      let exponent = 0.0 -. delta_f /. half_life_f
      penalty *. math_pow(2.0, exponent)
    }
  }
}

/// Evaluate current flap state at time `now`, updating penalty and lifting suppression if decayed below reuse threshold
pub fn evaluate_flap(
  history: FlapHistory,
  now: Int,
  config: DampingConfig,
) -> FlapHistory {
  let delta_t = now - history.last_flap
  let current_penalty =
    decay_penalty(history.penalty, delta_t, config.half_life_seconds)

  let is_suppressed = case history.suppressed {
    False -> False
    True -> {
      // Unsuppress if decayed below reuse threshold or if suppression duration expired
      case
        current_penalty <. config.reuse_threshold
        || now >= history.suppressed_until
      {
        True -> False
        False -> True
      }
    }
  }

  FlapHistory(
    penalty: current_penalty,
    flaps_count: history.flaps_count,
    last_flap: now,
    suppressed: is_suppressed,
    suppressed_until: history.suppressed_until,
  )
}

/// Record a route flap (withdrawal, attribute change, or re-announcement)
pub fn record_flap(
  history_opt: Option(FlapHistory),
  now: Int,
  config: DampingConfig,
) -> FlapHistory {
  let prev = case history_opt {
    Some(h) -> evaluate_flap(h, now, config)
    None ->
      FlapHistory(
        penalty: 0.0,
        flaps_count: 0,
        last_flap: now,
        suppressed: False,
        suppressed_until: 0,
      )
  }

  let new_penalty = prev.penalty +. config.penalty_per_flap
  let new_flaps = prev.flaps_count + 1

  case new_penalty >. config.suppress_threshold {
    True -> {
      // Calculate suppress duration: delta_t = half_life * log2(penalty / reuse_threshold)
      let ln2 = 0.69314718056
      let ratio = new_penalty /. config.reuse_threshold
      let log2_val = case ratio >. 1.0 {
        True -> math_log(ratio) /. ln2
        False -> 0.0
      }
      let duration_float = int.to_float(config.half_life_seconds) *. log2_val
      let duration_int = float.truncate(duration_float)
      let bounded_duration = case duration_int > config.max_suppress_seconds {
        True -> config.max_suppress_seconds
        False -> duration_int
      }
      FlapHistory(
        penalty: new_penalty,
        flaps_count: new_flaps,
        last_flap: now,
        suppressed: True,
        suppressed_until: now + bounded_duration,
      )
    }
    False ->
      FlapHistory(
        penalty: new_penalty,
        flaps_count: new_flaps,
        last_flap: now,
        suppressed: prev.suppressed,
        suppressed_until: prev.suppressed_until,
      )
  }
}

/// Check if a route is currently suppressed under RFC 2439 Route Flap Damping
pub fn is_route_suppressed(
  table: DampingTable,
  peer_id: String,
  prefix: IpPrefix,
  now: Int,
  config: DampingConfig,
) -> Bool {
  let key = #(peer_id, prefix_to_string(prefix))
  case dict.get(table, key) {
    Ok(history) -> {
      let evaluated = evaluate_flap(history, now, config)
      evaluated.suppressed
    }
    Error(_) -> False
  }
}

/// Register a flap event into the damping table
pub fn register_flap(
  table: DampingTable,
  peer_id: String,
  prefix: IpPrefix,
  now: Int,
  config: DampingConfig,
) -> #(DampingTable, Bool) {
  let key = #(peer_id, prefix_to_string(prefix))
  let current = case dict.get(table, key) {
    Ok(h) -> Some(h)
    Error(_) -> None
  }
  let updated = record_flap(current, now, config)
  let new_table = dict.insert(table, key, updated)
  #(new_table, updated.suppressed)
}

/// Return all actively damped and suppressed routes in the system
pub fn get_damped_routes(
  table: DampingTable,
  now: Int,
  config: DampingConfig,
) -> List(DampedRoute) {
  dict.to_list(table)
  |> list.filter_map(fn(item) {
    let #(#(peer_id, prefix_str), hist) = item
    let evaluated = evaluate_flap(hist, now, config)
    case evaluated.penalty >. 100.0 {
      True -> {
        let secs_remaining = case evaluated.suppressed {
          True -> {
            let rem = evaluated.suppressed_until - now
            case rem > 0 {
              True -> rem
              False -> 0
            }
          }
          False -> 0
        }
        case parse_prefix(prefix_str) {
          Ok(pfx) ->
            Ok(DampedRoute(
              prefix: pfx,
              peer_id: peer_id,
              penalty: evaluated.penalty,
              flaps_count: evaluated.flaps_count,
              suppressed: evaluated.suppressed,
              seconds_remaining: secs_remaining,
            ))
          Error(_) -> Error(Nil)
        }
      }
      False -> Error(Nil)
    }
  })
}
