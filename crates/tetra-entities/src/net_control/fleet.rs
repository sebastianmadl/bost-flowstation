//! Fleet Control: station management by the Brew server (the SwMI) over the control channel.
//!
//! The station opts in with the local switch `[command] fleet_control` (default off, changed on
//! the dashboard's Infrastructure page at run time). The server offers the feature by sending
//! `X-Brew-Extensions: fleet-control` in the 101 answer of the control channel; a station that
//! sees no such header sends nothing new, so older servers never see these messages.
//!
//! Phase 1 (this file): [`ControlResponse::StationHello`] after every connect and on every
//! change of the switch, [`ControlResponse::CommandResult`] as the general answer, and the
//! round-trip command [`ControlCommand::FleetPing`]. The existing commands (kick, DGNA, SDS,
//! restart, ...) do not depend on the switch. Protocol: `Docs/fleet-control.md`.
//!
//! Phase 2 (`update-v1`): [`ControlCommand::CheckUpdate`] / [`ControlCommand::StartUpdate`] run
//! the dashboard's OTA from the station's own source (`net_dashboard::ota_remote`), answered with
//! [`ControlResponse::UpdateInfo`] / [`ControlResponse::CommandResult`]; every OTA run reports
//! [`ControlResponse::UpdateProgress`].

use tetra_config::bluestation::SharedConfig;

use super::commands::{ControlCommand, ControlResponse};

/// Name in `X-Brew-Extensions` with which a server offers Fleet Control.
pub const EXT_FLEET_CONTROL: &str = "fleet-control";

/// Version of the Fleet Control messages ([`ControlResponse::StationHello`] `protocol`).
pub const FLEET_PROTOCOL: u32 = 1;

/// Capability of phase 1: `FleetPing`, `CommandResult`.
pub const CAP_FLEET: &str = "fleet-v1";
/// Capability of phase 2: `CheckUpdate`, `StartUpdate`, `UpdateInfo`, `UpdateProgress`. Listed only
/// while the station can run an OTA (its dashboard is running).
pub const CAP_UPDATE: &str = "update-v1";

/// Capability names the station lists in its hello while the switch is on.
pub fn capabilities(ota_available: bool) -> Vec<String> {
    let mut caps = vec![CAP_FLEET.to_string()];
    if ota_available {
        caps.push(CAP_UPDATE.to_string());
    }
    caps
}

/// `code` values of [`ControlResponse::CommandResult`].
pub mod code {
    /// Done.
    pub const OK: &str = "ok";
    /// Refused: Fleet Control is switched off on this station.
    pub const FLEET_CONTROL_OFF: &str = "fleet_control_off";
    /// Refused: an update is already running.
    pub const BUSY: &str = "busy";
    /// Refused: a call is in progress (and `during_call` was not set).
    pub const CALL_ACTIVE: &str = "call_active";
    /// Refused: this station cannot do it (no dashboard, so no OTA).
    pub const UNAVAILABLE: &str = "unavailable";
}

/// Does this server offer Fleet Control (its `X-Brew-Extensions`)?
pub fn offered(server_extensions: &[String]) -> bool {
    server_extensions.iter().any(|e| e == EXT_FLEET_CONTROL)
}

/// The hello for the current config and switch.
pub fn station_hello(shared: &SharedConfig) -> ControlResponse {
    let cfg = shared.config();
    let enabled = shared.state_read().fleet_control.enabled;
    ControlResponse::StationHello {
        protocol: FLEET_PROTOCOL,
        version: tetra_core::STACK_VERSION.to_string(),
        brew_login: cfg.brew.as_ref().and_then(|b| b.username.clone()),
        mcc: cfg.net.mcc,
        mnc: cfg.net.mnc,
        fleet_control: enabled,
        capabilities: if enabled { capabilities(crate::net_dashboard::ota_remote::available()) } else { Vec::new() },
    }
}

/// The answer to a Fleet Control command the worker handles itself, or `None` for every other
/// command (those go to the stack as before). `enabled`: the local switch.
pub fn answer(command: &ControlCommand, enabled: bool) -> Option<ControlResponse> {
    match command {
        ControlCommand::FleetPing { handle } => Some(if enabled {
            result(*handle, true, code::OK, "Fleet Control is on")
        } else {
            off(*handle)
        }),
        _ => None,
    }
}

/// What the worker does with a Fleet Control update command.
#[derive(Debug)]
pub enum UpdateAction {
    /// Answer at once with this.
    Reply(ControlResponse),
    /// Run the update check off the loop and answer `handle` with an `UpdateInfo` when done.
    Check { handle: u32 },
}

/// Handle `CheckUpdate` / `StartUpdate` (`None` for every other command). `enabled`: the switch;
/// `ota_available`: the station can run an OTA; `start` starts it (the real one is
/// [`crate::net_dashboard::ota_remote::start`]).
pub fn update_command(
    command: &ControlCommand,
    enabled: bool,
    ota_available: bool,
    start: impl FnOnce(bool) -> Result<(), crate::net_dashboard::ota_remote::StartRefused>,
) -> Option<UpdateAction> {
    use crate::net_dashboard::ota_remote::StartRefused;
    let handle = match command {
        ControlCommand::CheckUpdate { handle } | ControlCommand::StartUpdate { handle, .. } => *handle,
        _ => return None,
    };
    if !enabled {
        return Some(UpdateAction::Reply(off(handle)));
    }
    if !ota_available {
        return Some(UpdateAction::Reply(result(handle, false, code::UNAVAILABLE, "No OTA on this station (dashboard not running)")));
    }
    Some(match command {
        ControlCommand::CheckUpdate { .. } => UpdateAction::Check { handle },
        ControlCommand::StartUpdate { during_call, .. } => UpdateAction::Reply(match start(*during_call) {
            Ok(()) => result(handle, true, code::OK, "Update started"),
            Err(StartRefused::Busy) => result(handle, false, code::BUSY, "An update is already running"),
            Err(StartRefused::CallActive) => result(handle, false, code::CALL_ACTIVE, "A call is in progress"),
            Err(StartRefused::Unavailable) => result(handle, false, code::UNAVAILABLE, "No OTA on this station"),
        }),
        _ => unreachable!("matched above"),
    })
}

/// `UpdateInfo` for a finished check.
pub fn update_info(handle: u32, c: crate::net_dashboard::ota_remote::CheckOutcome) -> ControlResponse {
    ControlResponse::UpdateInfo {
        handle,
        ok: c.ok,
        current: c.current,
        latest: c.latest,
        update_available: c.update_available,
        channel: c.channel,
        repo: c.repo,
        branch: c.branch,
        message: c.message,
    }
}

/// `UpdateProgress` for the current OTA state.
pub fn update_progress(p: &crate::net_dashboard::ota_remote::Progress) -> ControlResponse {
    ControlResponse::UpdateProgress {
        stage: p.stage.as_str().to_string(),
        percent: p.percent,
        message: p.message.clone(),
        version: tetra_core::STACK_VERSION.to_string(),
        elapsed_secs: p.elapsed_secs,
    }
}

/// Should the worker send this progress now? `last`: stage and percent last sent, with the time.
pub fn progress_due(p: &crate::net_dashboard::ota_remote::Progress, last: Option<&(String, u8, std::time::Instant)>, now: std::time::Instant) -> bool {
    match last {
        None => p.running || matches!(p.stage, crate::net_dashboard::ota_remote::OtaStage::Restart),
        Some((stage, percent, at)) => {
            stage != p.stage.as_str() || *percent != p.percent || (p.running && now.duration_since(*at) >= std::time::Duration::from_secs(10))
        }
    }
}

fn off(handle: u32) -> ControlResponse {
    result(handle, false, code::FLEET_CONTROL_OFF, "Fleet Control is switched off on this station")
}

fn result(handle: u32, ok: bool, code: &str, message: &str) -> ControlResponse {
    ControlResponse::CommandResult { handle, ok, code: code.to_string(), message: message.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_control::codec::ControlCodecJson;

    #[test]
    fn ping_is_answered_only_while_the_switch_is_on() {
        let on = answer(&ControlCommand::FleetPing { handle: 7 }, true).unwrap();
        assert!(matches!(on, ControlResponse::CommandResult { handle: 7, ok: true, ref code, .. } if code == code::OK));
        let off = answer(&ControlCommand::FleetPing { handle: 8 }, false).unwrap();
        assert!(matches!(off, ControlResponse::CommandResult { handle: 8, ok: false, ref code, .. } if code == code::FLEET_CONTROL_OFF));
    }

    #[test]
    fn other_commands_are_not_fleet_commands() {
        // The existing commands keep working without the switch: the worker routes them as before.
        assert!(answer(&ControlCommand::KickMs { issi: 1 }, false).is_none());
        assert!(answer(&ControlCommand::RestartService, false).is_none());
    }

    use crate::net_dashboard::ota_remote::{CheckOutcome, OtaStage, Progress, StartRefused};

    fn code_of(a: Option<UpdateAction>) -> (bool, String) {
        match a {
            Some(UpdateAction::Reply(ControlResponse::CommandResult { ok, code, .. })) => (ok, code),
            other => panic!("expected a CommandResult, got {other:?}"),
        }
    }

    #[test]
    fn update_commands_need_the_switch_and_an_ota() {
        let never = |_| -> Result<(), StartRefused> { panic!("must not start") };
        assert_eq!(code_of(update_command(&ControlCommand::StartUpdate { handle: 1, during_call: false }, false, true, never)), (false, "fleet_control_off".into()));
        assert_eq!(code_of(update_command(&ControlCommand::CheckUpdate { handle: 2 }, false, true, never)), (false, "fleet_control_off".into()));
        assert_eq!(code_of(update_command(&ControlCommand::StartUpdate { handle: 3, during_call: false }, true, false, never)), (false, "unavailable".into()));
        assert!(matches!(update_command(&ControlCommand::CheckUpdate { handle: 4 }, true, true, never), Some(UpdateAction::Check { handle: 4 })));
        assert!(update_command(&ControlCommand::FleetPing { handle: 5 }, true, true, never).is_none());
    }

    #[test]
    fn start_update_outcomes() {
        let mut seen = None;
        let ok = update_command(&ControlCommand::StartUpdate { handle: 1, during_call: true }, true, true, |d| {
            seen = Some(d);
            Ok(())
        });
        assert_eq!(code_of(ok), (true, "ok".into()));
        assert_eq!(seen, Some(true), "during_call is passed on");
        let busy = update_command(&ControlCommand::StartUpdate { handle: 2, during_call: false }, true, true, |_| Err(StartRefused::Busy));
        assert_eq!(code_of(busy), (false, "busy".into()));
        let call = update_command(&ControlCommand::StartUpdate { handle: 3, during_call: false }, true, true, |_| Err(StartRefused::CallActive));
        assert_eq!(code_of(call), (false, "call_active".into()));
    }

    #[test]
    fn capabilities_list_update_only_with_an_ota() {
        assert_eq!(capabilities(false), vec!["fleet-v1"]);
        assert_eq!(capabilities(true), vec!["fleet-v1", "update-v1"]);
    }

    fn prog(running: bool, stage: OtaStage, percent: u8) -> Progress {
        Progress { running, stage, percent, message: String::new(), elapsed_secs: 0 }
    }

    #[test]
    fn progress_sent_on_change_and_every_ten_seconds() {
        let t0 = std::time::Instant::now();
        assert!(!progress_due(&prog(false, OtaStage::UpToDate, 100), None, t0), "an old finished run is not reported after a restart");
        assert!(progress_due(&prog(true, OtaStage::Download, 5), None, t0));
        let last = ("build".to_string(), 30u8, t0);
        assert!(!progress_due(&prog(true, OtaStage::Build, 30), Some(&last), t0 + std::time::Duration::from_secs(3)));
        assert!(progress_due(&prog(true, OtaStage::Build, 31), Some(&last), t0));
        assert!(progress_due(&prog(true, OtaStage::Build, 30), Some(&last), t0 + std::time::Duration::from_secs(10)));
        assert!(progress_due(&prog(false, OtaStage::Restart, 100), Some(&last), t0), "the end is always sent");
        let done = ("restart".to_string(), 100u8, t0);
        assert!(!progress_due(&prog(false, OtaStage::Restart, 100), Some(&done), t0 + std::time::Duration::from_secs(60)));
    }

    #[test]
    fn update_wire_shapes() {
        let codec = ControlCodecJson;
        let c = codec.decode_command(br#"{"CheckUpdate":{"handle":9}}"#).unwrap();
        assert!(matches!(c, ControlCommand::CheckUpdate { handle: 9 }));
        let s = codec.decode_command(br#"{"StartUpdate":{"handle":10}}"#).unwrap();
        assert!(matches!(s, ControlCommand::StartUpdate { handle: 10, during_call: false }), "during_call defaults to false");
        let s = codec.decode_command(br#"{"StartUpdate":{"handle":11,"during_call":true}}"#).unwrap();
        assert!(matches!(s, ControlCommand::StartUpdate { handle: 11, during_call: true }));
        let info = update_info(
            9,
            CheckOutcome {
                ok: true,
                current: "v0.5.9-aaa".into(),
                latest: Some("v0.5.9-bbb".into()),
                update_available: true,
                channel: "installed".into(),
                repo: "https://github.com/sebastianmadl/bost-flowstation".into(),
                branch: "fleet-control".into(),
                message: "newer version available".into(),
            },
        );
        let json: serde_json::Value = serde_json::from_slice(&codec.encode_response(&info)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"UpdateInfo": {"handle": 9, "ok": true, "current": "v0.5.9-aaa", "latest": "v0.5.9-bbb", "update_available": true, "channel": "installed", "repo": "https://github.com/sebastianmadl/bost-flowstation", "branch": "fleet-control", "message": "newer version available"}})
        );
        let p = update_progress(&Progress { running: true, stage: OtaStage::Build, percent: 42, message: "Compiling x".into(), elapsed_secs: 120 });
        let json: serde_json::Value = serde_json::from_slice(&codec.encode_response(&p)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"UpdateProgress": {"stage": "build", "percent": 42, "message": "Compiling x", "version": tetra_core::STACK_VERSION, "elapsed_secs": 120}})
        );
    }

    #[test]
    fn offered_only_with_the_extension() {
        assert!(!offered(&[]));
        assert!(!offered(&["bts-info".to_string()]));
        assert!(offered(&["bts-info".to_string(), EXT_FLEET_CONTROL.to_string()]));
    }

    #[test]
    fn json_wire_shape() {
        // Externally tagged, as brew-server's `control.rs` parses it (docs: Docs/fleet-control.md).
        let codec = ControlCodecJson;
        let hello = ControlResponse::StationHello {
            protocol: 1,
            version: "v0.5.9-abc".into(),
            brew_login: Some("1000001".into()),
            mcc: 232,
            mnc: 20,
            fleet_control: true,
            capabilities: vec!["fleet-v1".into()],
        };
        let json: serde_json::Value = serde_json::from_slice(&codec.encode_response(&hello)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"StationHello": {"protocol": 1, "version": "v0.5.9-abc", "brew_login": "1000001", "mcc": 232, "mnc": 20, "fleet_control": true, "capabilities": ["fleet-v1"]}})
        );
        let res = result(3, false, code::FLEET_CONTROL_OFF, "off");
        let json: serde_json::Value = serde_json::from_slice(&codec.encode_response(&res)).unwrap();
        assert_eq!(json, serde_json::json!({"CommandResult": {"handle": 3, "ok": false, "code": "fleet_control_off", "message": "off"}}));
        let ping = codec.decode_command(br#"{"FleetPing":{"handle":5}}"#).unwrap();
        assert!(matches!(ping, ControlCommand::FleetPing { handle: 5 }));
    }
}
