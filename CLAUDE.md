# slopbgp development notes

Gleam BGP-4/MP-BGP daemon for DN42 on Erlang/OTP, public MIT:
https://github.com/slopinger/slopbgp. `AGENTS.md` points here. README.md is the full
feature/RFC reference and CLI guide; keep it, this file and the Nix packaging current.

- Architecture: one OTP actor per peer session (crashes never take down the Loc-RIB or
  other peers), binary pattern matching for BGP framing, Loc-RIB decision engine, FIB sync
  into an isolated Linux routing table (42 by default).
- Checks: `gleam format --check src test`, `gleam test` (56 suites). Nix: `nix build`
  (offline sandbox build from the committed `manifest.toml`; produces `bin/slopbgp` and
  `bin/slopbgpctl`), `nix flake check`, `nix develop`; commit `flake.lock`.
  `nixosModules.default` exports `services.slopbgp`.
- Dashboard/REST/metrics listen on `http://127.0.0.1:9179` when the daemon runs. It is not
  deployed on the host: live DN42 routing is BIRD (see `~/src/dn42`). Never replace BIRD or
  touch the live sessions without an explicit migration task.
- Network-model examples: `examples/slopnet_global.json`; operator CLI: `slopbgpctl` (README).
- Use small signed commits, push to the GitHub `origin` only. Never add Co-Authored-By
  trailers or session links to public GitHub content.
