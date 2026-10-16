import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import slopbgp/fib/kernel.{type FibEntry}
import slopbgp/ip.{ip_to_string, prefix_to_string}
import slopbgp/types.{
  type PeerStats, type Route, AsSequence, AsSet, OriginEgp, OriginIgp,
  OriginIncomplete, RoaInvalid, RoaNotFound, RoaValid, StateActive, StateConnect,
  StateEstablished, StateIdle, StateOpenConfirm, StateOpenSent,
}

pub fn render_json_status(
  asn: Int,
  router_id: String,
  peer_count: Int,
  route_count: Int,
  fib_count: Int,
  roa_count: Int,
  uptime_seconds: Int,
) -> String {
  json.object([
    #("daemon", json.string("slopbgp")),
    #("version", json.string("0.1.0")),
    #("asn", json.int(asn)),
    #("router_id", json.string(router_id)),
    #("peers", json.int(peer_count)),
    #("routes", json.int(route_count)),
    #("fib_entries", json.int(fib_count)),
    #("roa_entries", json.int(roa_count)),
    #("uptime_seconds", json.int(uptime_seconds)),
  ])
  |> json.to_string
}

pub fn render_json_peers(peers: List(PeerStats)) -> String {
  let peer_objects =
    list.map(peers, fn(p) {
      json.object([
        #("id", json.string(p.id)),
        #("name", json.string(p.name)),
        #("remote_as", json.int(p.remote_as)),
        #("state", json.string(fsm_state_to_string(p.state))),
        #("uptime_seconds", json.int(p.uptime_seconds)),
        #("prefixes_received", json.int(p.prefixes_received)),
        #("prefixes_advertised", json.int(p.prefixes_advertised)),
        #("updates_received", json.int(p.updates_received)),
        #("updates_sent", json.int(p.updates_sent)),
        #("keepalives_received", json.int(p.keepalives_received)),
        #("keepalives_sent", json.int(p.keepalives_sent)),
        #("last_error", case p.last_error {
          Some(e) -> json.string(e)
          None -> json.null()
        }),
      ])
    })
  json.preprocessed_array(peer_objects)
  |> json.to_string
}

pub fn render_json_routes(routes: List(Route)) -> String {
  let route_objects =
    list.map(routes, fn(r) {
      let as_path_str = format_as_path(r.as_path)
      let roa_str = case r.roa_status {
        RoaValid -> "VALID"
        RoaInvalid -> "INVALID"
        RoaNotFound -> "NOT_FOUND"
      }
      let comm_strings =
        list.map(r.communities, fn(c) {
          int.to_string(c.asn) <> ":" <> int.to_string(c.value)
        })
      json.object([
        #("prefix", json.string(prefix_to_string(r.prefix))),
        #("origin", json.string(origin_to_string(r.origin))),
        #("as_path", json.string(as_path_str)),
        #("next_hop", json.string(ip_to_string(r.next_hop))),
        #("med", json.int(r.med)),
        #("local_pref", json.int(r.local_pref)),
        #("roa_status", json.string(roa_str)),
        #("peer_id", json.string(r.peer_id)),
        #("timestamp", json.int(r.timestamp)),
        #("communities", json.array(comm_strings, fn(c) { json.string(c) })),
      ])
    })
  json.preprocessed_array(route_objects)
  |> json.to_string
}

pub fn render_json_fib(fib_entries: List(FibEntry)) -> String {
  let objects =
    list.map(fib_entries, fn(e) {
      json.object([
        #("prefix", json.string(e.prefix_str)),
        #("next_hop", json.string(e.next_hop_str)),
        #("metric", json.int(e.metric)),
        #("peer_id", json.string(e.peer_id)),
      ])
    })
  json.preprocessed_array(objects)
  |> json.to_string
}

pub fn render_dashboard_html(
  asn: Int,
  router_id: String,
  peers: List(PeerStats),
  routes: List(Route),
  fib_entries: List(FibEntry),
  roa_count: Int,
) -> String {
  let peer_rows =
    list.map(peers, fn(p) {
      let state_str = fsm_state_to_string(p.state)
      let badge_class = case p.state {
        StateEstablished -> "badge-success"
        StateOpenConfirm | StateOpenSent -> "badge-warning"
        _ -> "badge-danger"
      }
      "<tr>"
      <> "<td><strong>"
      <> p.id
      <> "</strong><br><small style='color:#8b949e'>"
      <> p.name
      <> "</small></td>"
      <> "<td>AS"
      <> int.to_string(p.remote_as)
      <> "</td>"
      <> "<td><span class='badge "
      <> badge_class
      <> "'>"
      <> state_str
      <> "</span></td>"
      <> "<td>"
      <> int.to_string(p.prefixes_received)
      <> "</td>"
      <> "<td>"
      <> int.to_string(p.prefixes_advertised)
      <> "</td>"
      <> "<td>"
      <> int.to_string(p.updates_received)
      <> " / "
      <> int.to_string(p.updates_sent)
      <> "</td>"
      <> "</tr>"
    })
    |> string.join("\n")

  let route_rows =
    list.map(routes, fn(r) {
      let roa_badge = case r.roa_status {
        RoaValid -> "<span class='badge badge-success'>VALID</span>"
        RoaInvalid -> "<span class='badge badge-danger'>INVALID</span>"
        RoaNotFound -> "<span class='badge badge-neutral'>NOT FOUND</span>"
      }
      "<tr>"
      <> "<td><code>"
      <> prefix_to_string(r.prefix)
      <> "</code></td>"
      <> "<td><code>"
      <> ip_to_string(r.next_hop)
      <> "</code></td>"
      <> "<td>"
      <> format_as_path(r.as_path)
      <> "</td>"
      <> "<td>"
      <> int.to_string(r.local_pref)
      <> "</td>"
      <> "<td>"
      <> int.to_string(r.med)
      <> "</td>"
      <> "<td>"
      <> roa_badge
      <> "</td>"
      <> "<td>"
      <> r.peer_id
      <> "</td>"
      <> "</tr>"
    })
    |> string.join("\n")

  "<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>slopbgp // DN42 BGP Daemon Dashboard</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #58a6ff;
      --accent: #bc8cff;
      --green: #3fb950;
      --yellow: #d29922;
      --red: #f85149;
    }
    body {
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      color: var(--heading);
      font-size: 1.6rem;
      letter-spacing: -0.5px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
    }
    .stat-label {
      color: #8b949e;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stat-val {
      font-size: 1.5rem;
      font-weight: bold;
      color: #f0f6fc;
      margin-top: 4px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 24px;
    }
    h2 {
      margin-top: 0;
      color: var(--accent);
      font-size: 1.1rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: #8b949e;
      font-weight: 600;
    }
    tr:hover {
      background: rgba(255, 255, 255, 0.02);
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--green); border: 1px solid rgba(63, 185, 80, 0.4); }
    .badge-warning { background: rgba(210, 153, 34, 0.15); color: var(--yellow); border: 1px solid rgba(210, 153, 34, 0.4); }
    .badge-danger { background: rgba(248, 81, 73, 0.15); color: var(--red); border: 1px solid rgba(248, 81, 73, 0.4); }
    .badge-neutral { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.4); }
    code {
      background: #0d1117;
      padding: 2px 6px;
      border-radius: 4px;
      color: #79c0ff;
    }
    footer {
      color: #8b949e;
      font-size: 0.8rem;
      text-align: center;
      margin-top: 32px;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>slopbgp // dn42</h1>
      <div style=\"color:#8b949e; font-size:0.85rem; margin-top:4px;\">
        revolutionary gleam bgp-4 & mp-bgp daemon for autonomous system AS" <> int.to_string(
    asn,
  ) <> "
      </div>
    </div>
    <div style=\"text-align:right;\">
      <code>router-id: " <> router_id <> "</code>
    </div>
  </header>

  <div class=\"stats-grid\">
    <div class=\"stat-card\">
      <div class=\"stat-label\">Autonomous System</div>
      <div class=\"stat-val\">AS" <> int.to_string(asn) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Peers Configured</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(peers)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Loc-RIB Routes</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(routes)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">Kernel FIB Entries</div>
      <div class=\"stat-val\">" <> int.to_string(list.length(fib_entries)) <> "</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"stat-label\">ROA Validations</div>
      <div class=\"stat-val\">" <> int.to_string(roa_count) <> "</div>
    </div>
  </div>

  <div class=\"card\">
    <h2>BGP Peers</h2>
    <table>
      <thead>
        <tr>
          <th>Peer / Description</th>
          <th>ASN</th>
          <th>State</th>
          <th>Prefixes In</th>
          <th>Prefixes Out</th>
          <th>Updates (In/Out)</th>
        </tr>
      </thead>
      <tbody>
        " <> peer_rows <> "
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>Routing Information Base (Loc-RIB Best Paths)</h2>
    <table>
      <thead>
        <tr>
          <th>Prefix</th>
          <th>Next Hop</th>
          <th>AS Path</th>
          <th>LocalPref</th>
          <th>MED</th>
          <th>ROA Status</th>
          <th>Peer</th>
        </tr>
      </thead>
      <tbody>
        " <> route_rows <> "
      </tbody>
    </table>
  </div>

  <footer>
    slopbgp &bull; engineered with Gleam &amp; Erlang/OTP &bull; AS" <> int.to_string(
    asn,
  ) <> " &bull; https://git.freifick.net/slop/slopbgp
  </footer>
</body>
</html>"
}

fn format_as_path(segs: List(types.AsPathSegment)) -> String {
  let seg_strs =
    list.map(segs, fn(seg) {
      case seg {
        AsSequence(asns) ->
          list.map(asns, fn(asn) { int.to_string(asn) })
          |> string.join(" ")
        AsSet(asns) ->
          "{"
          <> {
            list.map(asns, fn(asn) { int.to_string(asn) })
            |> string.join(" ")
          }
          <> "}"
      }
    })
  string.join(seg_strs, " ")
}

fn fsm_state_to_string(state: types.FsmState) -> String {
  case state {
    StateIdle -> "Idle"
    StateConnect -> "Connect"
    StateActive -> "Active"
    StateOpenSent -> "OpenSent"
    StateOpenConfirm -> "OpenConfirm"
    StateEstablished -> "Established"
  }
}

fn origin_to_string(origin: types.Origin) -> String {
  case origin {
    OriginIgp -> "IGP"
    OriginEgp -> "EGP"
    OriginIncomplete -> "INCOMPLETE"
  }
}
