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

use tetra_config::bluestation::SharedConfig;

use super::commands::{ControlCommand, ControlResponse};

/// Name in `X-Brew-Extensions` with which a server offers Fleet Control.
pub const EXT_FLEET_CONTROL: &str = "fleet-control";

/// Version of the Fleet Control messages ([`ControlResponse::StationHello`] `protocol`).
pub const FLEET_PROTOCOL: u32 = 1;

/// Capability names the station lists in its hello while the switch is on.
pub const CAPABILITIES: &[&str] = &["fleet-v1"];

/// `code` values of [`ControlResponse::CommandResult`].
pub mod code {
    /// Done.
    pub const OK: &str = "ok";
    /// Refused: Fleet Control is switched off on this station.
    pub const FLEET_CONTROL_OFF: &str = "fleet_control_off";
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
        capabilities: if enabled { CAPABILITIES.iter().map(|c| c.to_string()).collect() } else { Vec::new() },
    }
}

/// The answer to a Fleet Control command the worker handles itself, or `None` for every other
/// command (those go to the stack as before). `enabled`: the local switch.
pub fn answer(command: &ControlCommand, enabled: bool) -> Option<ControlResponse> {
    match command {
        ControlCommand::FleetPing { handle } => Some(if enabled {
            result(*handle, true, code::OK, "Fleet Control is on")
        } else {
            result(*handle, false, code::FLEET_CONTROL_OFF, "Fleet Control is switched off on this station")
        }),
        _ => None,
    }
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
