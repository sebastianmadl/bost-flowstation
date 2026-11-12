# Fleet Control (station side)

Fleet Control lets the Brew server (brew-server, the SwMI) manage this station
over the control channel (`[command]`). The full protocol and the server side
are in brew-server's `docs/Fleet-Control.md`; this page covers what the station
does. Phase 1 (foundation): the switch, the hello, the general answer and a
round-trip check. Later phases add update, restart, reading and changing the
config.

## Switch

- Infrastructure page, Brew line (above the Server features list, always
  visible) → **Fleet Control** ("Station
  management by SwMI (BrewServer)"). Shown only while the server offers
  `fleet-control` (in `X-Brew-Extensions` of the Brew connection or of the
  control channel). Default **off**.
- Stored as `[command] fleet_control = true` (absent = off). It works at once:
  the config file is written and the running station takes the new value, no
  restart.
- Sidebar, under Health: field **Fleet Control**, green "on" / red "off", only
  while the server offers it. The tooltip says when the control channel is not
  connected. A click opens the Infrastructure page.
- The existing control commands (kick, DGNA, SDS, live SDS, emergency clear,
  ambience listening, service restart / shutdown) do not depend on the switch.

```toml
[command]
host = "brew.example.org"
port = 443
use_tls = true
username = "1000001"     # kept identical to the Brew login
password = "…"
fleet_control = true
```

## Control channel missing

Turning the switch on without a usable `[command]` (missing, no host, or
`enabled = false`) opens a dialog:

| Field | Default |
| --- | --- |
| Server (IP address or DNS name) | empty, never pre-filled |
| Port | 443 |
| TLS (wss://) | on |
| Username | the Brew login |
| Password | empty = take the Brew password (done on the station; the password never goes to the browser) |

Saving writes `[command]` (switched on) with `fleet_control = true`, checks the
whole config like every dashboard save, and restarts the service: the control
channel is started at boot.

## What the station sends

Only on a control connection whose HTTP 101 names `fleet-control`:

- `StationHello {protocol: 1, version, brew_login, mcc, mnc, fleet_control,
  capabilities}` right after connecting and whenever the switch changes (also
  to off, so the server can drop the station from its list and log it).
  `capabilities` is `["fleet-v1"]` while the switch is on, empty while off.
- `CommandResult {handle, ok, code, message}` for every Fleet Control command.

Commands understood (`fleet-v1`):

- `FleetPing {handle}`: answered by the control worker with `CommandResult`
  `ok` / `fleet_control_off`.

A server that does not offer `fleet-control` (older brew-server, TetraPack)
never sees any of this.

## HTTP API (dashboard)

| Route | Body | Answer |
| --- | --- | --- |
| `GET /api/fleet-control` | – | `{offered, enabled, connected, command: "on"/"off"/"missing", brew_login}` |
| `POST /api/fleet-control` | `{"enabled": bool, "command": {host, port, use_tls, username, password}?}` | `{ok: true, enabled, restart}`, or `{ok: false, need_command: true}` when the dialog is needed |

`fleet_control` with the same fields is also part of `GET /api/roaming`.

## Code

- `crates/tetra-entities/src/net_control/fleet.rs`: names, hello, answers.
- `crates/tetra-entities/src/net_control/worker.rs`: offer check on connect,
  hello on connect and on switch changes, `FleetPing`.
- `crates/tetra-entities/src/net_dashboard/fleet.rs`: switch, dialog, status.
- `crates/tetra-config/src/bluestation/sec_control.rs` (`fleet_control`),
  `state.rs` (`FleetControlState`: enabled, offered, connected).
