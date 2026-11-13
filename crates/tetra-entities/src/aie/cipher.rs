//! Per-cell air interface encryption state for security class 2: the SCK modified per carrier
//! (TB5), the ESI mapping (TA61) and the key stream segment of each timeslot. The key stream
//! generators (TEA1/2/3) all live in the `tetra-security` crate; this module only drives them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tetra_config::bluestation::{CfgAie, SckKey};
use tetra_core::{BitBuffer, SsiType, TdmaTime, TetraAddress};
use tetra_security::keys::CipherKey as SecCipherKey;
use tetra_security::ksg::{Iv, KsgId, new_ksg};

use super::{iv, ta61::Ta61, tb5};

/// Bits of key stream per timeslot on a phase modulation channel (TS 100 392-7 clause 6.3): enough
/// for a TCH/7,2 unprotected traffic channel. The second half slot starts at bit 216.
pub const KSS_BITS: usize = 432;
pub const SECOND_HALF_SLOT_KSS_OFFSET: usize = 216;

/// One timeslot's key stream segment. KSS(0) is the most significant bit of the first TEA1 key
/// byte.
pub struct Kss([u8; KSS_BITS / 8]);

impl Kss {
    pub fn bit(&self, i: usize) -> u8 {
        (self.0[i / 8] >> (7 - i % 8)) & 1
    }

    /// XORs `len` bits of `buf`, starting at bit position `start`, with KSS(`kss_offset`) onwards.
    /// The buffer position is restored afterwards.
    pub fn apply(&self, buf: &mut BitBuffer, start: usize, len: usize, kss_offset: usize) {
        assert!(
            kss_offset + len <= KSS_BITS,
            "key stream segment too short: {} + {}",
            kss_offset,
            len
        );
        let saved = buf.get_pos();
        buf.seek(start);
        for i in 0..len {
            buf.xor_bit(self.bit(kss_offset + i));
        }
        buf.seek(saved);
    }
}

/// TCH/S type-1 speech is two consecutive 137-bit codec frames. Apply AIE
/// BEFORE the sensitivity-class reordering of channel coding (EN 300 395-2
/// 5.2, EN 300 392-7 6.1/6.4). Permuting KSS here corrupts interoperable voice.
pub fn tch_s_kss_codec_order(kss: &Kss) -> [u8; 274] {
    std::array::from_fn(|i| kss.bit(i))
}

/// The key material of one SCK (or the class 3 CCK) on this cell: ESI mapping and ECK per
/// carrier.
struct KeyMat {
    sckn: u8,
    vn: u16,
    ta61: Ta61,
    /// ECK per carrier number.
    eck: HashMap<u16, [u8; 10]>,
}

impl KeyMat {
    fn new(sckn: u8, vn: u16, ck: &[u8; 10], carriers: &[u16], location_area: u16, colour_code: u8) -> Self {
        KeyMat {
            sckn,
            vn,
            ta61: Ta61::new(ck),
            eck: carriers.iter().map(|&cn| (cn, tb5(ck, cn, location_area, colour_code))).collect(),
        }
    }
}

/// Class 2 encryption context of one cell.
///
/// The SCK is the one of `[security.aie]` unless the Brew server supplies it
/// (`StackState::sck_run`, Fleet Control key management). A planned change applies from its
/// timeslot on the downlink and two slots later on the uplink (EN 300 392-7 clause 4.5.5.4).
pub struct CellCipher {
    /// 1 = TEA1 (this crate's generator), 2 / 3 = TEA2 / TEA3 from `tetra-security`.
    ksg: u8,
    class3: bool,
    config: Option<tetra_config::bluestation::SharedConfig>,
    location_area: u16,
    colour_code: u8,
    carriers: Vec<u16>,
    /// The key of `[security.aie]` (class 3: the CCK).
    base: Arc<KeyMat>,
    /// Key material of server keys already used, newest last.
    cache: Mutex<Vec<(SckKey, Arc<KeyMat>)>>,
    /// Main carrier, used when a carrier is not known (never expected).
    main_carrier: u16,
}

/// Uplink slots still encrypted with the old SCK after a change (EN 300 392-7 clause 4.5.5.4).
pub const UPLINK_OLD_KEY_SLOTS: i32 = 2;

impl CellCipher {
    /// `carriers` lists every carrier of the cell, main carrier first.
    pub fn new(aie: &CfgAie, carriers: &[u16], location_area: u16, colour_code: u8) -> Self {
        let (sckn, vn, ck) = match &aie.class3 {
            Some(c) => (0, c.cck_id, c.cck.0),
            None => (aie.sckn, aie.sck_vn, aie.sck.0),
        };
        CellCipher {
            ksg: aie.ksg,
            class3: aie.class3.is_some(),
            config: None,
            location_area,
            colour_code,
            carriers: carriers.to_vec(),
            base: Arc::new(KeyMat::new(sckn, vn, &ck, carriers, location_area, colour_code)),
            cache: Mutex::new(Vec::new()),
            main_carrier: carriers[0],
        }
    }

    pub fn with_config(mut self, config: tetra_config::bluestation::SharedConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn is_class3(&self) -> bool {
        self.class3
    }

    fn mat_for(&self, key: &SckKey) -> Arc<KeyMat> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, m)) = cache.iter().find(|(k, _)| k == key) {
            return m.clone();
        }
        let m = Arc::new(KeyMat::new(key.sckn, key.vn, &key.key.0, &self.carriers, self.location_area, self.colour_code));
        cache.push((key.clone(), m.clone()));
        if cache.len() > 3 {
            cache.remove(0);
        }
        m
    }

    /// The SCK in use at `t` (class 3: the CCK).
    fn mat(&self, t: TdmaTime, uplink: bool) -> Arc<KeyMat> {
        let run = self.config.as_ref().and_then(|c| {
            let st = c.state_read();
            if self.class3 { st.cck_run.clone() } else { st.sck_run.clone() }
        });
        let Some(run) = run else {
            return self.base.clone();
        };
        if let Some((at, key)) = &run.switch {
            let lag = if uplink { UPLINK_OLD_KEY_SLOTS } else { 0 };
            if t.diff(*at) >= lag {
                return self.mat_for(key);
            }
        }
        match &run.active {
            Some(key) => self.mat_for(key),
            None => self.base.clone(),
        }
    }

    /// The downlink MAC-RESOURCE encryption mode of an encrypted PDU sent at `t`
    /// (TS 100 392-7 Table 6.6): 10 with an even SCK-VN, 11 with an odd one.
    pub fn encryption_mode_at(&self, t: TdmaTime) -> u8 {
        0b10 | (self.mat(t, false).vn & 1) as u8
    }

    /// SCK-VN (class 3: CCK-id) on the downlink at `t`.
    pub fn sck_vn_at(&self, t: TdmaTime) -> u16 {
        self.mat(t, false).vn
    }

    /// SCKN (1..=32) on the downlink at `t`; 0 on a class 3 cell.
    pub fn sckn_at(&self, t: TdmaTime) -> u8 {
        self.mat(t, false).sckn
    }

    /// UL and individual DL use the terminal DCK; group DL uses the CCK.
    /// Missing individual key is a hard failure, never a fallback to CCK.
    pub fn kss_for(&self, carrier: u16, t: TdmaTime, uplink: bool, addr: TetraAddress) -> Option<Kss> {
        if !self.class3 || (!uplink && addr.ssi_type == SsiType::Gssi) {
            return Some(self.kss(carrier, t, uplink));
        }
        let dck = self.dck_for_address(addr)?;
        Some(self.kss_for_dck(carrier, t, uplink, &dck))
    }

    pub(crate) fn dck_for_address(&self, addr: TetraAddress) -> Option<tetra_config::bluestation::CipherKey> {
        if !matches!(addr.ssi_type, SsiType::Issi | SsiType::Ssi) { return None; }
        self.config.as_ref()?.state_read().sc3_dcks.get(&addr.ssi).cloned()
    }

    pub(crate) fn kss_for_dck(&self, carrier: u16, t: TdmaTime, uplink: bool, dck: &tetra_config::bluestation::CipherKey) -> Kss {
        let eck = SecCipherKey(tb5(&dck.0, carrier, self.location_area, self.colour_code));
        self.generate(&eck, t, uplink)
    }

    /// SSI → ESI for a downlink PDU sent at `t` (TS 100 392-7 clause 4.2.6).
    pub fn esi_at(&self, t: TdmaTime, ssi: u32) -> u32 {
        self.mat(t, false).ta61.encrypt(ssi)
    }

    /// ESI → SSI, for an address received in an encrypted uplink MAC PDU sent at `t`.
    pub fn ssi_at(&self, t: TdmaTime, esi: u32) -> u32 {
        self.mat(t, true).ta61.decrypt(esi)
    }

    /// Class 3, during the overlap after a CCK change: the SSI of `esi` under the old CCK.
    pub fn ssi_old_cck_at(&self, t: TdmaTime, esi: u32) -> Option<u32> {
        if !self.class3 {
            return None;
        }
        let (key, until) = self.config.as_ref()?.state_read().cck_overlap.clone()?;
        if t.diff(until) >= 0 {
            return None;
        }
        Some(self.mat_for(&key).ta61.decrypt(esi))
    }

    /// The key stream segment of timeslot `t` on `carrier`.
    pub fn kss(&self, carrier: u16, t: TdmaTime, uplink: bool) -> Kss {
        let mat = self.mat(t, uplink);
        let eck = mat
            .eck
            .get(&carrier)
            .or_else(|| mat.eck.get(&self.main_carrier))
            .expect("main carrier has an ECK");
        self.generate(&SecCipherKey(*eck), t, uplink)
    }

    fn generate(&self, eck: &SecCipherKey, t: TdmaTime, uplink: bool) -> Kss {
        let mut out = [0u8; KSS_BITS / 8];
        let id = KsgId::from_number(self.ksg - 1).expect("ksg checked by ksg_available");
        let mut g =
            new_ksg(id, eck, Iv::from_raw(iv(t.t, t.f, t.m, t.h, uplink))).expect("ksg_available guarantees a generator for this KSG");
        g.fill(&mut out);
        Kss(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_config::bluestation::CipherKey;

    fn cipher() -> CellCipher {
        let aie = CfgAie {
            class3: None,
            enabled: true,
            ksg: 1,
            sckn: 1,
            sck: CipherKey([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23]),
            sck_vn: 3,
            clear_groups: vec![],
        };
        CellCipher::new(&aie, &[3681, 3684], 2, 1)
    }

    #[test]
    fn kss_is_tea1_of_the_carrier_eck() {
        let c = cipher();
        let t = TdmaTime { t: 2, f: 5, m: 17, h: 300 };
        let kss = c.kss(3681, t, false);
        let mut expected = [0u8; 54];
        let eck = tb5(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23], 3681, 2, 1);
        new_ksg(KsgId::Tea1, &SecCipherKey(eck), Iv::from_raw(iv(2, 5, 17, 300, false)))
            .unwrap()
            .fill(&mut expected);
        assert_eq!(kss.0, expected);
        assert_ne!(kss.0, c.kss(3684, t, false).0, "each carrier has its own ECK");
        assert_ne!(kss.0, c.kss(3681, t, true).0, "uplink and downlink differ");
    }

    #[test]
    fn apply_twice_restores_the_bits() {
        let c = cipher();
        let kss = c.kss(3681, TdmaTime { t: 1, f: 1, m: 1, h: 0 }, false);
        let mut buf = BitBuffer::from_bytes(&[0xA5; 30]);
        let original = buf.dump_bin();
        kss.apply(&mut buf, 13, 150, 0);
        assert_ne!(buf.dump_bin(), original);
        kss.apply(&mut buf, 13, 150, 0);
        assert_eq!(buf.dump_bin(), original);
    }

    /// Radio-side reference: encrypt source frames, then channel-code them.
    /// Decode through the real LMAC path; a permuted KSS fails this test even
    /// though a local encrypt/decrypt round trip would hide that bug.
    #[test]
    fn r4_speech_cipher_matches_type1_before_channel_coding() {
        use crate::lmac::components::errorcontrol::{encode_tp, decode_tp};
        use tetra_saps::tmv::TmvUnitdataReq;
        use tetra_saps::tmv::enums::logical_chans::LogicalChannel;
        let c = cipher();
        let speech: [u8; 274] = std::array::from_fn(|i| ((i * 17 + i / 7) % 3 == 0) as u8);
        for uplink in [false, true] {
            let kss = c.kss(3681, TdmaTime { t: 2, f: 4, m: 9, h: 1 }, uplink);
            let radio: [u8; 274] = std::array::from_fn(|i| speech[i] ^ kss.bit(i));
            let encoded = encode_tp(TmvUnitdataReq { logical_channel: LogicalChannel::TchS,
                mac_block: BitBuffer::from_bitarr(&radio), scrambling_code: 0x1234567 }, 1);
            let (decoded, crc) = decode_tp(LogicalChannel::TchS, encoded, 0x1234567);
            assert!(crc);
            let mut decoded = decoded.unwrap(); decoded.seek(0);
            let mut bits = [0; 274]; decoded.to_bitarr(&mut bits);
            let stack_kss = tch_s_kss_codec_order(&kss);
            for i in 0..274 { bits[i] ^= stack_kss[i]; }
            assert_eq!(bits, speech, "UL/DL must use source bit order, not sensitivity order");
        }
    }

    #[test]
    fn encryption_mode_follows_sck_vn_parity() {
        assert_eq!(cipher().encryption_mode_at(tetra_core::TdmaTime::default()), 0b11);
    }

    /// Each KSG number selects a distinct generator: TEA1, TEA2 and TEA3 produce different key
    /// streams from the same ECK, so the dispatch in `kss()` is wired to the right one.
    #[test]
    fn each_ksg_produces_a_distinct_stream() {
        let t = TdmaTime { t: 2, f: 5, m: 17, h: 300 };
        let sck = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23];
        let streams: Vec<[u8; KSS_BITS / 8]> = [1u8, 2, 3]
            .iter()
            .map(|&ksg| {
                let aie = CfgAie {
                    class3: None,
                    enabled: true,
                    ksg,
                    sckn: 1,
                    sck: CipherKey(sck),
                    sck_vn: 3,
                    clear_groups: vec![],
                };
                CellCipher::new(&aie, &[3681], 2, 1).kss(3681, t, false).0
            })
            .collect();
        assert_ne!(streams[0], streams[1], "TEA1 and TEA2 differ");
        assert_ne!(streams[0], streams[2], "TEA1 and TEA3 differ");
        assert_ne!(streams[1], streams[2], "TEA2 and TEA3 differ");
    }
    #[test]
    fn a_server_sck_change_switches_downlink_on_its_slot_and_uplink_two_slots_later() {
        use tetra_config::bluestation::{SckRun, SharedConfig};
        let cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
        let shared = SharedConfig::from_parts(cfg, None);
        let c = cipher().with_config(shared.clone());
        let t0 = TdmaTime { t: 1, f: 1, m: 9, h: 4 };
        let base_dl = c.kss(3681, t0, false).0;
        let base_esi = c.esi_at(t0, 100);
        assert_eq!((c.sckn_at(t0), c.sck_vn_at(t0)), (1, 3), "no server key: [security.aie]");

        let old = SckKey { sckn: 1, vn: 8, key: CipherKey([0x44; 10]) };
        let new = SckKey { sckn: 2, vn: 9, key: CipherKey([0x55; 10]) };
        shared.state_write().sck_run = Some(SckRun { active: Some(old.clone()), switch: None });
        assert_eq!((c.sckn_at(t0), c.sck_vn_at(t0), c.encryption_mode_at(t0)), (1, 8, 0b10), "the server's active key replaces the config key");
        assert_ne!(c.kss(3681, t0, false).0, base_dl);
        assert_ne!(c.esi_at(t0, 100), base_esi);
        let old_dl = c.kss(3681, t0, false).0;
        let old_esi = c.esi_at(t0, 100);

        let at = t0.add_timeslots(8);
        shared.state_write().sck_run = Some(SckRun { active: Some(old), switch: Some((at, new.clone())) });
        let before = at.add_timeslots(-1);
        assert_eq!(c.kss(3681, before, false).0, cipher_with(&shared, before, false, &[0x44; 10]));
        assert_eq!((c.sckn_at(before), c.sck_vn_at(before)), (1, 8));
        assert_eq!((c.sckn_at(at), c.sck_vn_at(at), c.encryption_mode_at(at)), (2, 9, 0b11), "downlink from the change slot on");
        assert_eq!(c.kss(3681, at, false).0, cipher_with(&shared, at, false, &[0x55; 10]));
        assert_ne!(c.esi_at(at, 100), old_esi);
        // Uplink: still the old key for two slots (clause 4.5.5.4).
        for k in 0..UPLINK_OLD_KEY_SLOTS {
            let ut = at.add_timeslots(k);
            assert_eq!(c.kss(3681, ut, true).0, cipher_with(&shared, ut, true, &[0x44; 10]), "uplink slot {k} after the change");
            assert_eq!(c.ssi_at(ut, old_esi), 100);
        }
        let ut = at.add_timeslots(UPLINK_OLD_KEY_SLOTS);
        assert_eq!(c.kss(3681, ut, true).0, cipher_with(&shared, ut, true, &[0x55; 10]));
        assert_ne!(old_dl, c.kss(3681, at, false).0);
    }

    /// Key stream of a plain cell whose config key is `ck`.
    fn cipher_with(_: &tetra_config::bluestation::SharedConfig, t: TdmaTime, uplink: bool, ck: &[u8; 10]) -> [u8; KSS_BITS / 8] {
        let aie = CfgAie { class3: None, enabled: true, ksg: 1, sckn: 1, sck: CipherKey(*ck), sck_vn: 0, clear_groups: vec![] };
        CellCipher::new(&aie, &[3681, 3684], 2, 1).kss(3681, t, uplink).0
    }
}

#[cfg(test)]
mod sc3_tests {
    use super::*;
    use tetra_config::bluestation::sec_security::CfgClass3;
    use tetra_config::bluestation::{CipherKey, SharedConfig};
    #[test]
    fn a_server_cck_change_moves_esi_and_group_keys_and_the_old_cck_resolves_during_the_overlap() {
        use tetra_config::bluestation::SckRun;
        let aie = CfgAie {
            enabled: true,
            ksg: 2,
            sck: CipherKey([0; 10]),
            sckn: 1,
            sck_vn: 0,
            class3: Some(CfgClass3 { cck: CipherKey([0x33; 10]), cck_id: 42 }),
            clear_groups: vec![],
        };
        let cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
        let shared = SharedConfig::from_parts(cfg, None);
        let c = CellCipher::new(&aie, &[1521], 7, 3).with_config(shared.clone());
        let t0 = TdmaTime { t: 1, f: 2, m: 3, h: 4 };
        let old_esi = c.esi_at(t0, 100);
        assert_eq!(c.sck_vn_at(t0), 42, "config CCK-id");
        let old = SckKey { sckn: 0, vn: 42, key: CipherKey([0x33; 10]) };
        let new = SckKey { sckn: 0, vn: 43, key: CipherKey([0x44; 10]) };
        let at = t0.add_timeslots(4);
        shared.state_write().cck_run = Some(SckRun { active: Some(old.clone()), switch: Some((at, new.clone())) });
        assert_eq!(c.sck_vn_at(at), 43, "SYSINFO CCK-id follows the change (clause 4.5.5.2)");
        assert_eq!(c.encryption_mode_at(at), 0b11, "odd CCK-id in the MAC-RESOURCE (clause 6.5.1)");
        let new_esi = c.esi_at(at, 100);
        assert_ne!(new_esi, old_esi);
        assert_eq!(c.ssi_at(at.add_timeslots(1), old_esi), 100, "two uplink slots with the old CCK");
        assert_eq!(c.ssi_at(at.add_timeslots(2), new_esi), 100);
        let g = TetraAddress::new(900, SsiType::Gssi);
        assert_ne!(c.kss_for(1521, t0, false, g).unwrap().0, c.kss_for(1521, at, false, g).unwrap().0, "group downlink uses the new CCK");
        // Overlap: the old CCK still resolves an ESI until its end, then no longer.
        let until = at.add_timeslots(100);
        shared.state_write().cck_overlap = Some((old, until));
        assert_ne!(c.ssi_at(at.add_timeslots(10), old_esi), 100);
        assert_eq!(c.ssi_old_cck_at(at.add_timeslots(10), old_esi), Some(100));
        assert_eq!(c.ssi_old_cck_at(until, old_esi), None);
    }

    #[test]
    fn sc3_dck_selection_and_group_cck_are_distinct_and_cell_bound() {
        let aie = CfgAie {
            enabled: true,
            ksg: 2,
            sck: CipherKey([0; 10]),
            sckn: 1,
            sck_vn: 0,
            class3: Some(CfgClass3 {
                cck: CipherKey([0x33; 10]),
                cck_id: 43,
            }),
            clear_groups: vec![],
        };
        let cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
        let shared = SharedConfig::from_parts(cfg, None);
        shared.state_write().sc3_dcks.insert(100, CipherKey([0x11; 10]));
        shared.state_write().sc3_dcks.insert(101, CipherKey([0x22; 10]));
        let c = CellCipher::new(&aie, &[1521, 1522], 7, 3).with_config(shared.clone());
        let t = TdmaTime { t: 2, f: 3, m: 4, h: 5 };
        assert!(c.kss_for(1521, t, true, TetraAddress::issi(102)).is_none());
        assert!(c.kss_for(1521, t, true, TetraAddress::new(900, SsiType::Gssi)).is_none());
        let d1 = c.kss_for(1521, t, true, TetraAddress::issi(100)).unwrap();
        let d2 = c.kss_for(1521, t, true, TetraAddress::issi(101)).unwrap();
        assert_ne!(d1.0, d2.0);
        let expected = c.generate(&SecCipherKey(tb5(&[0x11; 10], 1521, 7, 3)), t, true);
        assert_eq!(d1.0, expected.0);
        assert_ne!(d1.0, c.kss_for(1522, t, true, TetraAddress::issi(100)).unwrap().0);
        assert_ne!(d1.0, c.kss_for(1521, t, false, TetraAddress::issi(100)).unwrap().0);
        assert_eq!(
            c.kss_for(1521, t, false, TetraAddress::new(900, SsiType::Gssi)).unwrap().0,
            c.kss(1521, t, false).0
        );
        assert_eq!(c.esi_at(tetra_core::TdmaTime::default(), 100), Ta61::new(&[0x33; 10]).encrypt(100));
        assert_eq!(c.encryption_mode_at(tetra_core::TdmaTime::default()), 0b11);
        shared.state_write().sc3_dcks.remove(&100);
        assert!(c.kss_for(1521, t, true, TetraAddress::issi(100)).is_none());
        let (_, ext) = super::super::sysinfo_security(Some(&aie));
        assert!(ext.class3_supported && ext.auth_required && !ext.class2_supported && !ext.class1_supported);
        assert!(!ext.gck_supported);
        use super::super::{CipherDecision, registration_decision};
        use tetra_pdus::mm::fields::ciphering_parameters::CipheringParameters;
        assert!(matches!(registration_decision(Some(&aie), false, None), CipherDecision::Reject(_)));
        assert!(matches!(
            registration_decision(Some(&aie), true, Some(CipheringParameters::class2(2, 1).to_bits())),
            CipherDecision::Reject(_)
        ));
        assert!(matches!(
            registration_decision(Some(&aie), true, Some(CipheringParameters::class3(2).to_bits())),
            CipherDecision::Encrypted(_)
        ));
        // The MS can advertise capabilities in these five bits; the BS must
        // clear them in its downlink ciphering parameters (EN 300 392-7 A.8.12).
        assert_eq!(
            registration_decision(Some(&aie), true, Some(CipheringParameters::class3(2).to_bits() | 0b11111)),
            CipherDecision::Encrypted(CipheringParameters::class3(2))
        );
    }

}
