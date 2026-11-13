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
- Switching off asks twice (the Fleet Control switch and the remote command /
  control switch at the bottom of the page alike): first what stops working,
  **I understand** left and a red **Cancel** right; then "are you sure, the
  system admin and the fleet managers are notified", **Cancel** left and a red
  **Yes, switch off** right. Buttons and colours swap between the two dialogs so
  a double tap cannot get through. Saving the command channel switched off
  while Fleet Control is on first switches Fleet Control off (live), so the
  server logs "switched off Fleet Control" before the channel goes away.

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
  `capabilities` is e.g. `["fleet-v1", "maintenance-v1", "restart-v1", "metrics-v1", "config-v1", "update-v1", "update-live-v1"]` while the switch is on
  (`update-v1` only while the dashboard runs, because the OTA lives there),
  empty while off. A hello is sent again when `update-v1` appears later.
- `CommandResult {handle, ok, code, message}` for every Fleet Control command.

Commands understood (`fleet-v1`):

- `FleetPing {handle}`: answered by the control worker with `CommandResult`
  `ok` / `fleet_control_off`.

Commands understood (`update-v1`, phase 2, remote update): see the next section.

A server that does not offer `fleet-control` (older brew-server, TetraPack)
never sees any of this.

## Remote update (phase 2, `update-v1`)

The server can check for and start the same OTA as the dashboard's Update
button. The station always updates from **its own OTA source**
(`[dashboard] ota_channel`, by default `installed` = the repository and branch
it was installed from); the server never chooses a repository or branch.

| Command (server → station) | Answer |
| --- | --- |
| `CheckUpdate {handle}` | `UpdateInfo {handle, ok, current, latest, update_available, channel, repo, branch, message}` when the check is done (fresh, no cache; it asks GitHub, so it can take some seconds) |
| `StartUpdate {handle, during_call, source?}` | `CommandResult` at once: `ok`, `busy` (an update is already running), `call_active` (a call is in progress and `during_call` is false), `unavailable` (no dashboard, so no OTA), `invalid_source` (live update only), `fleet_control_off`. With `source`: live update, see below |

`during_call` defaults to false. `repo` never carries credentials. `latest` has the form of the running version: the source's version number plus the commit of its tip (`v0.5.9-d081d936`), or `branch@commit` when the version number cannot be read.

While an OTA runs (whoever started it: server or dashboard), the station sends

```json
{"UpdateProgress": {"stage": "build", "percent": 42, "message": "   Compiling tetra-entities v0.1.0", "version": "v0.5.9-8d7a363", "elapsed_secs": 312}}
```

when the stage or the percentage changes and at least every 10 s, and once
more at the end:

| `stage` | Meaning | `percent` |
| --- | --- | --- |
| `download` | checking the source, `git fetch` | 5 |
| `build` | `cargo build`; **the radio is off the air from here on** (the OTA frees the SDR for the build, `rf_status::request_ota_rf_off`) | 10–90, estimated: compiled units against the last successful build (`target/.ota-build-units`, else the packages in `Cargo.lock`) |
| `install` | the new program is put in place | 92 |
| `restart` | built and installed, the service restarts in 5 s | 100 |
| `up_to_date` | nothing to do, the running build is the newest of the source | 100 |
| `failed` | stopped with an error (`message` = last log line); the old version stays or is restarted | 0 |

`version` is the software running now (the old one until the restart). After
the restart the station connects again and its `StationHello` carries the new
version: that is how the server knows the update finished.

A station that is already up to date answers `StartUpdate` with `ok` and then reports `up_to_date`; the server skips it.

The OTA state is one per process (`net_dashboard::ota_remote`): a run started
by the server shows on the dashboard and the other way round, and only one
run can be active.

### Live update (`update-live-v1`)

`StartUpdate` with a `source` asks for a **live update**:

```json
{"StartUpdate": {"handle": 12, "during_call": false, "source": {"repo": "https://github.com/sebastianmadl/bost-flowstation", "branch": "fleet-control"}}}
```

The station runs its installer, the same as
`sudo BOST_REPO=<repo> BOST_BRANCH=<branch> bash contrib/install/install-bost.sh`
in a terminal (`server.rs` `run_live_update`), and **keeps the radio on during
the build**. Only the service restart at the end (5 s after the install) takes
it off the air. Details:

- `repo` must be a plain `https://` URL without credentials and `branch` a plain
  branch name (letters, digits, `-._/`); anything else is refused with
  `invalid_source`. Both go to the installer as environment variables, never
  through a shell line. stdin is closed, so the installer never waits for input.
- The service runs with real-time scheduling (`CPUSchedulingPolicy=fifo` in the
  unit) and children inherit it. The installer is started as a normal task
  (`SCHED_OTHER`, nice 10), like a terminal session, so the build does not take
  CPU time from the radio.
- The installer sets `[dashboard] ota_channel = "installed"` and the git origin
  to `repo`, so the station's normal OTA follows this source afterwards.
- No check is needed first, and coming back with the same version counts as
  done (reinstalled).
- Progress: the same `UpdateProgress` stages, taken from the installer's log
  (`==> Building bluestation-bs` → `build`, `==> Installed` → `install`).
  A failed run leaves the old version running and the radio on.
- The station lists `update-live-v1` together with `update-v1`. A server must
  send `source` only to stations that list it: an older station ignores the
  field and would run a normal OTA (radio off) instead.

## Maintenance banner (`maintenance-v1`)

`SetMaintenance {handle, on, minutes, by, reason}` → `CommandResult` (`ok`,
`fleet_control_off`). While the flag is on, **every page** of the dashboard
shows a solid red banner under the top bar: "Maintenance: work on this base
station in progress", with who set it, the minutes left and the note
(`reason`). `minutes` (default 10, at most 240) is how long the flag stays on
without being sent again, so a closed browser on the server never leaves it on;
the server sends it again after the station reconnects (e.g. after a restart)
while its own copy has time left. The flag lives in memory only
(`net_control::fleet::maintenance`); it is shown only while Fleet Control is on.

A **live update** shows its own red banner on every page, without a flag:
"Live system update: RF on!" with the build percentage, until the service
restarts.

The dashboard reads both from `GET /api/fleet-control` (`maintenance`:
`{by, reason, left_secs}` or null; `live_update`: `{stage, percent}` or null),
every 5 s.

The banner also shows **without a login**: on the login page and on the public
overview. For that, `GET /api/fleet-banner` is open without a session (not on
the private HTTP listener, which stays fully gated) and returns only
`{maintenance, live_update}` as above: no server address, no login, no switch
state. The public overview falls back to it when `/api/fleet-control` answers
401; the login page polls it every 5 s.

## Restart (`restart-v1`)

`RestartStation {handle, host, during_call}` → `CommandResult`: `ok` (the
service restarts, `host` false, or the host reboots, `host` true, 5 s later),
`busy` (an update is running), `call_active` (a call is in progress and
`during_call` is false), `fleet_control_off`. The service runs as root
(`User=root` in the unit the installer writes), so the reboot
(`service_control::schedule_host_reboot`, `systemctl reboot`) needs no sudo or
polkit rule and works right after a fresh install. The server knows the
station is back from its next `StationHello`.

## Station config (`config-v1`)

Phases 4/5: the server reads the config and changes it with a rollback. The
capability is announced once `fleet_config::boot` knows the config path (at
start, in `main`).

- **Hash.** `config_hash` in the hello: md5 (16 hex) of the parsed TOML
  re-serialized, without `[command] fleet_control`, so comments, layout and
  the switch do not count. `config_pending`: seconds left of a change waiting
  for confirmation. The worker sends a new hello when either changes (checked
  every 5 s), so a local edit reaches the server.
- **`GetConfig`** → `ConfigInfo {hash, config, text, pending}`: `config` is
  the Infrastructure view (the same JSON as `GET /api/roaming`, without the
  server's cell directory) plus the Brew link, cell SDR devices and the OTA
  source, `home_mode_display` (the `[cell_info.home_mode_display]` table or
  null) and `access` (`issi_whitelist`, `whitelist_mode`); passwords only as
  `password_set`. `text` is the file with passwords
  and keys as `***`.
- **`SetConfig {base_hash, changes, confirm_secs, during_call, by}`**: refused
  with `conflict` (the file is not `base_hash`), `invalid` (unknown key or
  the result does not validate like the dashboard's own save), `call_active`,
  `busy` (update running or a change already waits). Accepted keys:
  `reselect`, `rxlev_access_min_dbm`, `migration`, `presence_check_secs`,
  `multi_network_enabled`, `networks`, `telemetry`, `command`, `cells`,
  `cells_add`, `cells_remove`, `brew`, `ota`, `net_info`, `raw`. `raw`:
  `[{path, value?, remove?}]`, single values of the file (the server's config
  editor, Home Mode Display and ISSI whitelist cards), applied last; paths
  through a password or key name and `***` values are refused. An empty password
  keeps the old one; a new carrier moves the cell's SoapySDR frequencies. On
  `ok` the station saves `<config>.fleet-backup`, writes
  `<config>.fleet-pending.json` (old/new hash, window, who, when), writes the
  new config and restarts 3 s later.
- **Window.** `confirm_secs` (default 180, 60–900) from the restart, at least
  20 s after the boot. A watchdog thread armed at boot (and at `SetConfig`)
  copies the backup back and restarts when it runs out.
- **`ConfirmConfig`**: removes backup and note (`ok`, `not_pending`). The run
  that wrote the change answers `not_restarted`: its re-announced hello
  already says "pending", but it still runs the old config.
- **`RollbackConfig`**: backup back, restart (`ok`, `not_pending`).
- Keys (`[security]`) are never part of `config` or `changes`.

## Metrics (`metrics-v1`, phase 7)

While the server offers `fleet-control` and the switch is on, the control
worker sends a report 5 s after the connect (or after the switch went on) and
then every 60 s:

```json
{"FleetMetrics": {"interval_secs": 60, "cpu_pct": 17.4, "cpu_temp_c": 52.1,
  "cells": [{"cell": 0, "rf": "online", "sdr_temp_c": 44.3},
            {"cell": 1, "rf": "error", "sdr_temp_c": null, "detail": "SoapySDR: no device found"}],
  "radios": 3, "calls": 1, "health": "ok"}}
```

- `cpu_pct`: busy share of all cores between two reports, from `/proc/stat`
  (idle includes iowait), one decimal; `null` on the very first sample.
- `cpu_temp_c`: the first thermal zone whose type names the CPU (`cpu-thermal`
  on a Raspberry Pi, `x86_pkg_temp`), else a hwmon CPU driver (`coretemp`,
  `k10temp`, `cpu_thermal`, `zenpower`), else the first thermal zone; `null`
  without a sensor.
- `cells`: one entry per cell (`rf_status`): `rf` is `online`, `off` (no SDR
  configured), `error` (the SDR could not be opened, `detail` says why) or
  `starting`; `sdr_temp_c` is the last `SdrHealth` temperature of that cell
  (the telemetry fan-out feeds it, read every 10 s by the PHY), `null` when the
  SDR has no sensor or did not report for 2 min.
- `radios`: registered radios (health registry), `calls`: calls in progress
  (dashboard), `health`: overall stack health (`ok`, `degraded`, `critical`).

No answer is expected. The server uses it for its graphs and alarms
(brew-server `docs/Fleet-Control.md` section 12); it also pings the station
with `FleetPing` for its ping graph.

## Key management (`keys-v1`, phase 8a)

With `[security] key_source = "server"` the Brew server is the authentication
centre (EN 300 392-7 clause 4.1.1): it holds K, the station holds none (no
`[[security.subscribers]]`). The station lists `keys-v1` while the switch is on
and reports `key_source` (`local` / `server`) and `local_keys` (number of K in
its config, never the keys) in its hello. Designed with Patrick, OE1LHP.

Messages (only acted on with `key_source = "server"` and the switch on; a
station with local keys ignores them):

```json
{"AuthSubscribers": {"issis": [2320972], "drop": []}}          // server: radios with K; answer AuthStock
{"AuthVectors": {"issi": 2320972, "vectors": [{"rs": "<20 hex>", "ks": "<32 hex>", "ks_p": "<32 hex>"}]}}
{"AuthStock": {"counts": [{"issi": 2320972, "count": 10}]}}       // station
{"AuthVectorRequest": {"issi": 2320972}}                          // station, at most every 5 s per radio
{"AuthReport": {"issi": 2320972, "rs": "<20 hex>", "ok": true, "mutual": false, "left": 9}}
```

MM takes one set per authentication (`net_control/auc.rs`): RS goes to the
radio with a fresh RAND1, RES1 / DCK1 come from TA12(KS, RAND1); a RAND2 from
the radio is answered with RES2 / DCK2 = TA22(KS', RAND2) under the same RS
(clause 4.1.3 / 4.1.4). Each set is used once and reported. The stock is kept
in `<config>.auth-sets` (mode 600), so the station authenticates after a
restart while the server is away. No set for a radio the server has K for: the
station asks for sets and holds the registration up to 2 s; without an answer
the radio is treated as one without a key (`required`: rejected, `optional`:
registered unauthenticated). With `key_source = "local"` an old stock file is
deleted at start. With server keys the SCK also comes from the server (below).

The switch is a config change (`config-v1`): `{"keys": {"source": "server",
"drop_local_keys": true}}` removes `[[security.subscribers]]` (refused without
`drop_local_keys` while the list is not empty), `{"keys": {"source":
"local"}}` sets it back. `GetConfig` shows `keys: {source, local_keys}`.

**Export for the server**: Security page → *Export keys* (password at least 10
characters) downloads `bost-keys-v1`: JSON `{format, kdf:
"pbkdf2-hmac-sha256", iterations: 600000, salt, nonce, data}`, the lines
`ISSI;K` sealed with AES-256-GCM under PBKDF2-HMAC-SHA256(password, salt).
Import it on the server's Keys page. `POST /api/security/export
{"password"}`.

### Static cipher keys from the server (`sck-v1`, phase 8b)

With server keys the station also takes the security class 2 SCK from the server
(EN 300 392-7 clause 4.2.4.0). Per network the server holds the current key and,
before a change, the next one. The station gets both in clear over the TLS control
channel, because it encrypts the air interface with them; a radio gets them sealed
under its own K by the server (clause 4.5.2.2: KSO = TA41(K, RSO),
SSCK = TA51(SCK, SCK-VN, KSO, SCKN)), so the station never sees K. Messages (only
acted on with `key_source = "server"`):

```json
{"SckKeys": {"keys": [{"sckn": 1, "vn": 3, "key": "<20 hex>"}, {"sckn": 2, "vn": 4, "key": "<20 hex>", "next": true}]}}
{"SckSealed": {"issi": 2320972, "rso": "<20 hex>", "keys": [{"sckn": 1, "vn": 3, "ssck": "<30 hex>"}]}}
{"SckActivate": {"sckn": 2, "vn": 4, "at_ms": 1763049600000}}
{"SckState": {"active": {"sckn": 1, "vn": 3, "check": "<16 hex>"}, "from_config": false, "keys": [...], "switch_at_ms": null}}   // station
{"SckDemand": {"issi": 2320972, "sckns": [2]}}                                                      // station
{"SckResult": {"issi": 2320972, "sckn": 2, "vn": 4, "ok": true}}                                    // station
```

- `SckKeys`: the keys are kept in `<config>.auth-sets` (mode 600). At start the
  station runs on the server key that was in use when it stopped, else on the key of its
  own `[security.aie]` (`from_config`). It answers with `SckState` (keys named by
  check value SHA-256(SCK)[:8], never the value).
- `SckSealed`: MM sends a D-OTAR SCK PROVIDE to the radio if it is registered
  here; otherwise, after 5 s, it reports `SckResult` with `ok: false` and
  `detail: "radio not registered"`. Empty `keys` (the server has nothing for the
  radio) becomes a D-OTAR SCK REJECT "key not available" per number asked for.
  The radio's U-OTAR SCK RESULT goes back as `SckResult`. A radio's own
  U-OTAR SCK DEMAND, and the dashboard's OTAR SCK button, go to the server as
  `SckDemand`.
- `SckActivate`: the network wide change (clause 4.5.5.4). The station turns the
  server time `at_ms` into the first slot of the first frame of the multiframe
  that starts at or after it (an absolute IV, clause 4.5.5.6), sends every radio
  registered with encryption a D-CK CHANGE DEMAND (A.4.1, key change type SCK,
  SCK use TMO, time type absolute IV) and switches on that slot: downlink,
  SYSINFO SCKN / SCK-VN and the MAC-RESOURCE VN parity at once, the uplink two
  slots later so bursts still under way are deciphered with the old key. 72 slots
  later it keeps only the new key and reports `SckState`. A time in the past
  switches at the next multiframe. A station that missed a change while offline is
  switched by the server when it comes back; a station still on its own config key
  only switches when the server activates the current key for it.

### Common cipher keys from the server (`cck-v1`, phase 8c)

On a class 3 cell with server keys the CCK comes from the server too (EN 300 392-7
clause 4.2.3): per location area (or one for every LA, `la` null) the current key and,
before a change, the next one. The station gets them in clear over TLS; a CCK is sealed
for a radio with that radio's DCK (TA31, clause 4.5.1.1), which only the station holds,
so the station does the OTAR itself:

```json
{"CckKeys": {"keys": [{"la": 2, "cck_id": 42, "key": "<20 hex>"}, {"la": 2, "cck_id": 43, "key": "<20 hex>", "next": true}]}}
{"CckActivate": {"la": 2, "cck_id": 43, "at_ms": 1763049600000, "overlap_s": 1800}}
{"CckState": {"la": 2, "active": {"cck_id": 42, "check": "<16 hex>"}, "from_config": true, "keys": [...]}}   // station
{"CckResult": {"issi": 2320972, "cck_id": 43, "ok": true}}                                             // station
```

- `CckKeys`: kept in `<config>.auth-sets`; only the keys of the cell's LA (or `la`
  null) are used. Answered with `CckState` (the server learns the station's LA from
  it). At start the station runs on the server CCK that was in use when it stopped,
  else on `[security.aie] cck` / `cck_id`.
- The next CCK goes to every radio with an active class 3 session as a D-OTAR CCK
  PROVIDE with key type "future" (Table A.42, "the SwMI can deliver to all registered
  MSs a CCK for future use", clause 4.5.1), at most every 10 min per radio; the
  U-OTAR CCK RESULT goes back as `CckResult`. Rejecting a future key does not touch the
  radio's session.
- `CckActivate`: like the SCK, the time becomes the start of the next multiframe; the
  station sends D-CK CHANGE DEMAND (key change type CCK, absolute IV) to its class 3
  radios and switches on that slot (SYSINFO CCK-id, MAC-RESOURCE CCK-id bit and ESIs;
  clause 4.5.5.2). A change for another LA is ignored.
- **Overlap**: the uplink has no key identifier (clause 6.5.2). After the change the
  station decrypts an uplink ESI with the new CCK; if that names no radio with a class 3
  session but the old CCK does, it takes the old one, for `overlap_s` seconds (at least
  the two slots of clause 4.5.5.2). A radio still on the old CCK can so still ask for the
  new one (U-OTAR CCK DEMAND). A radio that accepted a server CCK here before but not the
  one in use now is sent the current one.

**Back to local keys** on a class 3 cell writes the server's CCK in use (`cck`,
`cck_id`) into `[security.aie]`.

**Back to local keys** on a class 2 cell writes the server's active SCK (key, `sckn`, `sck_vn`) into
`[security.aie]`, so class 2 keeps running with the key the radios hold.

## HTTP API (dashboard)

| Route | Body | Answer |
| --- | --- | --- |
| `GET /api/fleet-control` | – | `{offered, enabled, connected, command: "on"/"off"/"missing", brew_login, maintenance, live_update}` |
| `POST /api/fleet-control` | `{"enabled": bool, "command": {host, port, use_tls, username, password}?}` | `{ok: true, enabled, restart}`, or `{ok: false, need_command: true}` when the dialog is needed |

`fleet_control` with the same fields is also part of `GET /api/roaming`.

## Code

- `crates/tetra-entities/src/net_control/fleet.rs`: names, hello, answers.
- `crates/tetra-entities/src/net_control/worker.rs`: offer check on connect,
  hello on connect and on switch changes, `FleetPing`.
- `crates/tetra-entities/src/net_dashboard/fleet.rs`: switch, dialog, status.
- `crates/tetra-entities/src/net_dashboard/ota_remote.rs`: remote update (check,
  start, progress) on the dashboard's OTA (`server.rs` `run_update`,
  `update_check_json`, `UpdateState.stage`).
- `crates/tetra-entities/src/net_control/metrics.rs`: `FleetMetrics` (CPU load,
  temperatures, RF state), sent by `worker.rs` `report_metrics`; SDR
  temperatures are fed from the telemetry fan-out in `bins/bluestation-bs`.
- `crates/tetra-entities/src/net_control/fleet_config.rs`: config read, change,
  backup, watchdog, confirm / rollback (`config-v1`).
- `crates/tetra-entities/src/net_control/auc.rs`: stock of authentication data
  sets (`keys-v1`); `mm/mm_bs.rs` `authentication_gate`, `auth_vector`,
  `process_auth_waiting`; `tetra-security` `auth.rs` `AuthVector`.
- `crates/tetra-config/src/bluestation/sec_control.rs` (`fleet_control`),
  `state.rs` (`FleetControlState`: enabled, offered, connected).
