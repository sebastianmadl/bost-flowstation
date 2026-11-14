//! Security class each radio is registered with (`ms-security` Brew extension, brew-server
//! Radios page). MM writes it when the ciphering of a registration takes effect (after the
//! required LLC acknowledgement of the D-LOCATION UPDATE ACCEPT, EN 300 392-7 clause 6.5.1); the
//! Brew entity reports changes to a server that offered the extension.
//!
//! One map per process: in a multi-cell station every cell's MM writes here and the Brew entity
//! of the primary cell (which sees all radios of the station) reports them. ISSIs are unique
//! within a station.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Security class of one registration: 1 = clear, 2 = SCK, 3 = DCK / CCK (EN 300 392-7
/// clause 6.2), and the KSG number of the ciphering parameters for classes 2 and 3 (Table A.3:
/// 0 = TEA1 … 6 = TEA7, 8 to 11 proprietary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsSecurity {
    pub class: u8,
    pub ksg: Option<u8>,
}

fn map() -> &'static Mutex<HashMap<u32, MsSecurity>> {
    static MAP: OnceLock<Mutex<HashMap<u32, MsSecurity>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The ciphering of `issi`'s registration took effect (`None` ciphering: class 1).
pub fn set(issi: u32, sec: MsSecurity) {
    map().lock().unwrap_or_else(|e| e.into_inner()).insert(issi, sec);
}

/// A new registration of `issi` starts: its class is not known until the ciphering takes effect.
pub fn clear(issi: u32) {
    map().lock().unwrap_or_else(|e| e.into_inner()).remove(&issi);
}

pub fn get(issi: u32) -> Option<MsSecurity> {
    map().lock().unwrap_or_else(|e| e.into_inner()).get(&issi).copied()
}

/// The class a radio runs now: a class 3 registration on a cell that changed to class 2 on the
/// fallback SCK (EN 300 392-7 clause 4.5.6.2, key fallback or the operator's fallback) is
/// class 2 until the cell is back to class 3 (clause 4.5.6.3); the radios stay registered
/// (clause 4.5.6.0), so no new registration tells it.
pub fn effective(sec: MsSecurity, fallback: Option<&tetra_config::bluestation::KeyFallbackRun>) -> MsSecurity {
    let class2 = fallback.is_some_and(|r| r.sck.is_some() && r.back_at.is_none());
    if sec.class == 3 && class2 { MsSecurity { class: 2, ..sec } } else { sec }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_registration_forgets_the_old_class() {
        set(9_990_001, MsSecurity { class: 3, ksg: Some(1) });
        assert_eq!(get(9_990_001), Some(MsSecurity { class: 3, ksg: Some(1) }));
        clear(9_990_001);
        assert_eq!(get(9_990_001), None);
    }

    #[test]
    fn a_class3_radio_counts_as_class2_while_the_cell_runs_the_fallback_sck() {
        use tetra_config::bluestation::{CipherKey, KeyFallbackRun, SckKey};
        let sc3 = MsSecurity { class: 3, ksg: Some(1) };
        let key = SckKey { sckn: 31, vn: 1, key: CipherKey([0; 10]) };
        let t = tetra_core::TdmaTime::default();
        let on = KeyFallbackRun { sck: Some((t, key.clone())), back_at: None, manual: true };
        assert_eq!(effective(sc3, Some(&on)), MsSecurity { class: 2, ksg: Some(1) });
        let back = KeyFallbackRun { back_at: Some(t), ..on.clone() };
        assert_eq!(effective(sc3, Some(&back)), sc3, "back to class 3 planned");
        let no_key = KeyFallbackRun { sck: None, back_at: None, manual: false };
        assert_eq!(effective(sc3, Some(&no_key)), sc3, "fallback without fallback SCK keeps class 3");
        assert_eq!(effective(sc3, None), sc3);
        let sc1 = MsSecurity { class: 1, ksg: None };
        assert_eq!(effective(sc1, Some(&on)), sc1);
    }

    #[test]
    fn the_wire_names_class_and_ksg() {
        use super::super::protocol::*;
        let m = build_service_ms_security(2320001, 3, Some(1));
        assert_eq!((m[0], m[1], *m.last().unwrap()), (BREW_CLASS_SERVICE, 0x25, 0));
        let v: serde_json::Value = serde_json::from_slice(&m[2..m.len() - 1]).unwrap();
        assert_eq!(v, serde_json::json!({"issi": 2320001, "class": 3, "ksg": 1}));
        let clear = build_service_ms_security(7, 1, None);
        let v: serde_json::Value = serde_json::from_slice(&clear[2..clear.len() - 1]).unwrap();
        assert_eq!(v, serde_json::json!({"issi": 7, "class": 1}), "no KSG in the clear");
    }
}
