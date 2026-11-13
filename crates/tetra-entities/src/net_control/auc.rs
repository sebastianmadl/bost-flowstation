//! Fleet Control key management (`keys-v1`): authentication data from the Brew server, the
//! authentication centre (EN 300 392-7 clause 4.1.1).
//!
//! With `[security] key_source = "server"` the station holds no K. The server sends the list of
//! radios it has a K for and, per radio, authentication data sets (RS, KS, KS'). MM takes one set
//! per authentication: RS goes to the radio, XRES1 / DCK1 come from KS and a fresh RAND1 (TA12),
//! RES2 / DCK2 from KS' and the radio's RAND2 (TA22). Every set is used once and reported back, so
//! the server tops the stock up. The stock is kept in a file (mode 600) next to the config, so the
//! station can authenticate after a restart while the server is unreachable.
//!
//! One store per process (all cells share it); tests use their own [`Handle`].

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tetra_security::auth::AuthVector;

use tetra_config::bluestation::{CipherKey, SckKey, StackConfig};

use super::commands::{AuthVectorWire, CckRef, CckWire, ControlResponse, IssiCount, SckRef, SckWire, SealedSckWire};

/// Station capability: understands `AuthSubscribers` / `AuthVectors`.
pub const CAP_KEYS: &str = "keys-v1";

/// Station capability: understands `SckKeys` / `SckSealed` / `SckActivate` (security class 2 keys
/// from the server).
pub const CAP_SCK: &str = "sck-v1";

/// Station capability: understands `CckKeys` / `CckActivate` (security class 3 CCKs from the
/// server).
pub const CAP_CCK: &str = "cck-v1";

/// A radio without sets is asked for at most this often.
const REQUEST_EVERY: Duration = Duration::from_secs(5);

pub type Handle = Arc<Mutex<AucStore>>;

static GLOBAL: OnceLock<Handle> = OnceLock::new();

/// The process-wide store.
pub fn global() -> Handle {
    GLOBAL.get_or_init(|| Arc::new(Mutex::new(AucStore::default()))).clone()
}

/// Called once at boot. `server`: `key_source = "server"`, load the stock file next to the config
/// (`<config>.auth-sets`); else a stock left from earlier is deleted (the station no longer uses
/// the server's data and must not keep it).
pub fn boot(config_path: &str, server: bool) {
    let path = PathBuf::from(format!("{config_path}.auth-sets"));
    if !server {
        if std::fs::remove_file(&path).is_ok() {
            tracing::info!("Key management: key source is local, stock of authentication data sets removed");
        }
        return;
    }
    let handle = global();
    let mut s = handle.lock().unwrap_or_else(|e| e.into_inner());
    s.load(path);
}

#[derive(Default)]
pub struct AucStore {
    path: Option<PathBuf>,
    /// Radios the server has a K for (its last `AuthSubscribers`).
    known: BTreeSet<u32>,
    sets: BTreeMap<u32, VecDeque<AuthVector>>,
    /// Messages for the server, sent by the control worker.
    outbox: Vec<ControlResponse>,
    requested: HashMap<u32, Instant>,
    /// Radios that got sets since MM last looked (to go on with a held registration).
    arrived: BTreeSet<u32>,
    /// Class 2 SCKs from the server.
    sck: SckFile,
    /// Sealed SCK deliveries for MM to send.
    sealed: VecDeque<(u32, String, Vec<SealedSckWire>, Instant)>,
    /// Class 3 CCKs from the server.
    cck: CckFile,
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    known: Vec<u32>,
    sets: BTreeMap<u32, Vec<AuthVectorWire>>,
    #[serde(default)]
    sck: SckFile,
    #[serde(default)]
    cck: CckFile,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
struct CckFile {
    /// The server's keys (every LA it sent; current and next).
    keys: Vec<CckWire>,
    /// The key of this cell's LA in use once the server's key took over (`None`: the config key).
    active: Option<CckWire>,
    /// Planned change: key, server time (Unix ms) and overlap (s).
    switch: Option<(CckWire, u64, u32)>,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
struct SckFile {
    /// The server's keys (current and next).
    keys: Vec<SckWire>,
    /// The key in use once the server's key took over (`None`: the config key).
    active: Option<SckWire>,
    /// Planned change: the key and the server time (Unix ms).
    switch: Option<(SckWire, u64)>,
}

/// SHA-256(key), first 8 bytes, upper case hex: the check value the server shows.
pub fn check_value(key: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, key);
    hex(&d.as_ref()[..8]).to_uppercase()
}

fn sck_key(w: &SckWire) -> Option<SckKey> {
    if !(1..=32).contains(&w.sckn) {
        return None;
    }
    Some(SckKey { sckn: w.sckn, vn: w.vn, key: CipherKey(unhex::<10>(&w.key.to_ascii_lowercase())?) })
}

/// A CCK as the cipher holds it: `sckn` 0, the CCK-id as `vn`.
fn cck_key(w: &CckWire) -> Option<SckKey> {
    Some(SckKey { sckn: 0, vn: w.cck_id, key: CipherKey(unhex::<10>(&w.key.to_ascii_lowercase())?) })
}

fn cck_ref(k: &SckKey) -> CckRef {
    CckRef { cck_id: k.vn, check: check_value(&k.key.0) }
}

fn cck_wire(k: &SckKey, la: Option<u16>) -> CckWire {
    CckWire { la, cck_id: k.vn, key: hex(&k.key.0), next: false }
}

/// A server CCK applies to location area `la`.
fn for_la(w: &CckWire, la: u16) -> bool {
    w.la.is_none_or(|l| l == la)
}

/// The CCK in use when the station runs with its own config key.
pub fn config_cck(cfg: &StackConfig) -> Option<SckKey> {
    let c = cfg.security.aie.as_ref()?.class3.as_ref()?;
    Some(SckKey { sckn: 0, vn: c.cck_id, key: c.cck.clone() })
}

/// Before the stack is built: with `key_source = "server"` a class 3 cell runs with the server's
/// CCK that was in use when the station stopped, instead of the one in `[security.aie]`.
pub fn apply_server_cck(config_path: &str, cfg: &mut StackConfig) -> Option<String> {
    if cfg.security.key_source != tetra_config::bluestation::KeySource::Server {
        return None;
    }
    let la = cfg.cell.location_area;
    let c = cfg.security.aie.as_mut()?.class3.as_mut()?;
    let f = std::fs::read(format!("{config_path}.auth-sets")).ok().and_then(|b| serde_json::from_slice::<File>(&b).ok())?;
    let key = f.cck.active.as_ref().filter(|w| for_la(w, la)).and_then(cck_key)?;
    c.cck_id = key.vn;
    c.cck = key.key;
    Some(format!("Key management: class 3 runs with the server's CCK {}", c.cck_id))
}

fn sck_ref(k: &SckKey) -> SckRef {
    SckRef { sckn: k.sckn, vn: k.vn, check: check_value(&k.key.0) }
}

/// The SCK in use when the station runs with its own config key.
pub fn config_sck(cfg: &StackConfig) -> Option<SckKey> {
    let aie = cfg.security.aie.as_ref().filter(|a| a.class3.is_none())?;
    Some(SckKey { sckn: aie.sckn, vn: aie.sck_vn, key: aie.sck.clone() })
}

/// Before the stack is built: with `key_source = "server"` a class 2 cell runs with the server's
/// SCK that was in use when the station stopped (kept in `<config>.auth-sets`), instead of the
/// one in `[security.aie]`. Returns a line for the log (written once logging is up).
pub fn apply_server_sck(config_path: &str, cfg: &mut StackConfig) -> Option<String> {
    if cfg.security.key_source != tetra_config::bluestation::KeySource::Server {
        return None;
    }
    let aie = cfg.security.aie.as_mut().filter(|a| a.class3.is_none())?;
    let f = std::fs::read(format!("{config_path}.auth-sets")).ok().and_then(|b| serde_json::from_slice::<File>(&b).ok())?;
    let key = f.sck.active.as_ref().and_then(sck_key)?;
    aie.sckn = key.sckn;
    aie.sck_vn = key.vn;
    aie.sck = key.key;
    Some(format!("Key management: class 2 runs with the server's SCK {} version {}", aie.sckn, aie.sck_vn))
}

impl AucStore {
    fn load(&mut self, path: PathBuf) {
        if let Some(f) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<File>(&b).ok()) {
            self.known = f.known.into_iter().collect();
            self.sets = f
                .sets
                .into_iter()
                .map(|(issi, v)| (issi, v.iter().filter_map(AuthVectorWire::to_vector).collect()))
                .collect();
            tracing::info!("Key management: {} authentication data sets for {} radios loaded", self.total(), self.sets.len());
            self.sck = f.sck;
            self.cck = f.cck;
        }
        self.path = Some(path);
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let f = File {
            known: self.known.iter().copied().collect(),
            sets: self.sets.iter().map(|(i, v)| (*i, v.iter().map(AuthVectorWire::from_vector).collect())).collect(),
            sck: self.sck.clone(),
            cck: self.cck.clone(),
        };
        let Ok(bytes) = serde_json::to_vec(&f) else { return };
        if let Err(e) = write_private(path, &bytes) {
            tracing::warn!("Key management: cannot write {}: {}", path.display(), e);
        }
    }

    /// The server's list of radios with K; sets of radios not listed or in `drop` (K changed) go.
    /// Returns the stock for the server.
    pub fn subscribers(&mut self, issis: &[u32], drop: &[u32]) -> ControlResponse {
        self.known = issis.iter().copied().collect();
        let known = &self.known;
        self.sets.retain(|i, _| known.contains(i) && !drop.contains(i));
        self.save();
        self.stock()
    }

    /// Sets for `issi` from the server (none: it has no K for it).
    pub fn add(&mut self, issi: u32, vectors: &[AuthVectorWire]) {
        self.requested.remove(&issi);
        if vectors.is_empty() {
            if self.known.remove(&issi) {
                self.sets.remove(&issi);
                self.save();
            }
            self.arrived.insert(issi);
            return;
        }
        self.known.insert(issi);
        let q = self.sets.entry(issi).or_default();
        q.extend(vectors.iter().filter_map(AuthVectorWire::to_vector));
        self.arrived.insert(issi);
        self.save();
    }

    /// The server has a K for this radio.
    pub fn is_known(&self, issi: u32) -> bool {
        self.known.contains(&issi)
    }

    pub fn count(&self, issi: u32) -> u32 {
        self.sets.get(&issi).map_or(0, |q| q.len() as u32)
    }

    pub fn total(&self) -> u32 {
        self.sets.values().map(|q| q.len() as u32).sum()
    }

    pub fn known_count(&self) -> u32 {
        self.known.len() as u32
    }

    /// One set for an authentication of `issi` (removed from the stock).
    pub fn take(&mut self, issi: u32) -> Option<AuthVector> {
        let v = self.sets.get_mut(&issi)?.pop_front()?;
        if self.sets.get(&issi).is_some_and(|q| q.is_empty()) {
            self.sets.remove(&issi);
        }
        self.save();
        Some(v)
    }

    /// Ask the server for sets of `issi` (at most every 5 s). Returns true when a request went out.
    pub fn request(&mut self, issi: u32, now: Instant) -> bool {
        if self.requested.get(&issi).is_some_and(|t| now.duration_since(*t) < REQUEST_EVERY) {
            return false;
        }
        self.requested.insert(issi, now);
        self.outbox.push(ControlResponse::AuthVectorRequest { issi });
        true
    }

    /// Tell the server that one set of `issi` was used.
    pub fn report(&mut self, issi: u32, rs: &[u8; 10], ok: bool, mutual: bool) {
        let left = Some(self.count(issi));
        self.outbox.push(ControlResponse::AuthReport { issi, rs: hex(rs), ok, mutual, left });
    }

    /// The stock per radio, for the server.
    pub fn stock(&self) -> ControlResponse {
        ControlResponse::AuthStock { counts: self.sets.iter().map(|(i, q)| IssiCount { issi: *i, count: q.len() as u32 }).collect() }
    }

    pub fn drain_outbox(&mut self) -> Vec<ControlResponse> {
        std::mem::take(&mut self.outbox)
    }

    /// Radios that got an answer from the server since the last call.
    pub fn take_arrived(&mut self) -> BTreeSet<u32> {
        std::mem::take(&mut self.arrived)
    }

    /// The whole stock goes (key source back to local, or for tests).
    pub fn clear(&mut self) {
        self.known.clear();
        self.sets.clear();
        self.sck = SckFile::default();
        self.cck = CckFile::default();
        self.save();
    }

    // ───────────── class 3 CCKs (`cck-v1`) ─────────────

    /// The server's CCKs. Invalid entries are dropped. A planned change to a key the server no
    /// longer lists is cancelled.
    pub fn set_cck_keys(&mut self, keys: &[CckWire]) {
        self.cck.keys = keys.iter().filter(|w| cck_key(w).is_some()).cloned().collect();
        if let Some((w, _, _)) = &self.cck.switch
            && !self.cck.keys.iter().any(|k| k.cck_id == w.cck_id && k.key == w.key && k.la == w.la)
        {
            tracing::warn!("Key management: planned CCK change cancelled, the server no longer has that key");
            self.cck.switch = None;
        }
        self.save();
    }

    /// Plan the change of this cell's LA (`cell_la`) to the server CCK `cck_id` at `at_ms`.
    /// A change for another LA is ignored (`Ok(false)`).
    pub fn cck_activate(&mut self, cell_la: u16, la: Option<u16>, cck_id: u16, at_ms: u64, overlap_s: u32) -> Result<bool, &'static str> {
        if la.is_some_and(|l| l != cell_la) {
            return Ok(false);
        }
        let Some(w) = self.cck.keys.iter().find(|k| k.cck_id == cck_id && for_la(k, cell_la)).cloned() else {
            return Err("unknown key");
        };
        if self.cck.active.as_ref().is_some_and(|a| a.cck_id == cck_id && a.key == w.key) {
            self.cck.switch = None;
        } else {
            self.cck.switch = Some((w, at_ms, overlap_s.min(86_400)));
        }
        self.save();
        Ok(true)
    }

    /// The server CCK in use (`None`: the config key).
    pub fn cck_active(&self) -> Option<SckKey> {
        self.cck.active.as_ref().and_then(cck_key)
    }

    /// The server's next CCK for location area `la`, if it sent one.
    pub fn cck_next(&self, la: u16) -> Option<SckKey> {
        self.cck.keys.iter().filter(|k| k.next && for_la(k, la)).find_map(cck_key)
    }

    /// The server's current CCK for location area `la`, if it sent one.
    pub fn cck_current(&self, la: u16) -> Option<SckKey> {
        self.cck.keys.iter().filter(|k| !k.next && for_la(k, la)).find_map(cck_key)
    }

    /// The planned change: key, server time (Unix ms) and overlap (s).
    pub fn cck_switch(&self) -> Option<(SckKey, u64, u32)> {
        let (w, at, overlap) = self.cck.switch.as_ref()?;
        Some((cck_key(w)?, *at, *overlap))
    }

    /// The change to `key` took place on the cell of location area `la`.
    pub fn commit_cck(&mut self, la: u16, key: &SckKey, config: Option<&SckKey>) {
        if self.cck_active().as_ref() == Some(key) && self.cck.switch.is_none() {
            return;
        }
        let scope = self.cck.switch.as_ref().map(|(w, _, _)| w.la).unwrap_or(Some(la));
        self.cck.active = Some(cck_wire(key, scope));
        self.cck.switch = None;
        // The server sends its new set once it hears of the change; until then only this key.
        self.cck.keys.retain(|k| !for_la(k, la) || k.cck_id == key.vn);
        for k in self.cck.keys.iter_mut().filter(|k| for_la(k, la)) {
            k.next = false;
        }
        self.save();
        tracing::info!("Key management: CCK {} is in use now", key.vn);
        let state = self.cck_state(la, config);
        self.outbox.push(state);
    }

    /// What the cell of location area `la` runs with, for the server.
    pub fn cck_state(&self, la: u16, config: Option<&SckKey>) -> ControlResponse {
        let active = self.cck_active();
        ControlResponse::CckState {
            la,
            from_config: active.is_none() && config.is_some(),
            active: active.as_ref().or(config).map(cck_ref),
            keys: self.cck.keys.iter().filter(|k| for_la(k, la)).filter_map(cck_key).map(|k| cck_ref(&k)).collect(),
            switch_at_ms: self.cck.switch.as_ref().map(|(_, at, _)| *at),
        }
    }

    pub fn cck_result(&mut self, issi: u32, cck_id: u16, ok: bool, detail: Option<String>) {
        self.outbox.push(ControlResponse::CckResult { issi, cck_id, ok, detail });
    }

    // ───────────── class 2 SCKs (`sck-v1`) ─────────────

    /// The server's SCKs (current, next). Invalid entries are dropped. A planned change to a key
    /// the server no longer lists is cancelled.
    pub fn set_sck_keys(&mut self, keys: &[SckWire]) {
        self.sck.keys = keys.iter().filter(|w| sck_key(w).is_some()).cloned().collect();
        if let Some((w, _)) = &self.sck.switch
            && !self.sck.keys.iter().any(|k| k.sckn == w.sckn && k.vn == w.vn && k.key == w.key)
        {
            tracing::warn!("Key management: planned SCK change cancelled, the server no longer has that key");
            self.sck.switch = None;
        }
        self.save();
    }

    /// Plan the change to the server key (`sckn`, `vn`) at `at_ms`.
    pub fn sck_activate(&mut self, sckn: u8, vn: u16, at_ms: u64) -> Result<(), &'static str> {
        let Some(w) = self.sck.keys.iter().find(|k| k.sckn == sckn && k.vn == vn).cloned() else {
            return Err("unknown key");
        };
        if self.sck.active.as_ref().is_some_and(|a| a.sckn == sckn && a.vn == vn && a.key == w.key) {
            self.sck.switch = None;
        } else {
            self.sck.switch = Some((w, at_ms));
        }
        self.save();
        Ok(())
    }

    /// The server key in use (`None`: the config key).
    pub fn sck_active(&self) -> Option<SckKey> {
        self.sck.active.as_ref().and_then(sck_key)
    }

    /// The planned change: key and server time (Unix ms).
    pub fn sck_switch(&self) -> Option<(SckKey, u64)> {
        let (w, at) = self.sck.switch.as_ref()?;
        Some((sck_key(w)?, *at))
    }

    /// The change to `key` took place: it is the key in use and the current one of the set.
    pub fn commit_sck(&mut self, key: &SckKey, config: Option<&SckKey>) {
        if self.sck_active().as_ref() == Some(key) && self.sck.switch.is_none() {
            return;
        }
        let w = SckWire { sckn: key.sckn, vn: key.vn, key: hex(&key.key.0), next: false };
        self.sck.active = Some(w);
        self.sck.switch = None;
        // The server sends its new set once it hears of the change; until then only this key.
        self.sck.keys.retain(|k| k.sckn == key.sckn && k.vn == key.vn);
        for k in &mut self.sck.keys {
            k.next = false;
        }
        self.save();
        tracing::info!("Key management: SCK {} version {} is in use now", key.sckn, key.vn);
        let state = self.sck_state(config);
        self.outbox.push(state);
    }

    /// What the station runs with, for the server. `config`: the key of `[security.aie]`.
    pub fn sck_state(&self, config: Option<&SckKey>) -> ControlResponse {
        let active = self.sck_active();
        ControlResponse::SckState {
            from_config: active.is_none() && config.is_some(),
            active: active.as_ref().or(config).map(sck_ref),
            keys: self.sck.keys.iter().filter_map(sck_key).map(|k| sck_ref(&k)).collect(),
            switch_at_ms: self.sck.switch.as_ref().map(|(_, at)| *at),
        }
    }

    /// The server key with this number and version, if the station holds it.
    pub fn sck_by_number(&self, sckn: u8) -> Vec<SckKey> {
        self.sck.keys.iter().filter_map(sck_key).filter(|k| k.sckn == sckn).collect()
    }

    pub fn push_sealed(&mut self, issi: u32, rso: String, keys: Vec<SealedSckWire>) {
        self.sealed.push_back((issi, rso, keys, Instant::now()));
        while self.sealed.len() > 200 {
            self.sealed.pop_front();
        }
    }

    /// Sealed deliveries for radios `mine` says are here; the others stay for another cell.
    pub fn take_sealed(&mut self, mine: impl Fn(u32) -> bool) -> Vec<(u32, String, Vec<SealedSckWire>)> {
        let (take, keep): (Vec<_>, Vec<_>) = self.sealed.drain(..).partition(|(i, _, _, _)| mine(*i));
        self.sealed = keep.into();
        take.into_iter().map(|(i, r, k, _)| (i, r, k)).collect()
    }

    /// Deliveries no cell took within `age` (the radio is not registered here): reported to the
    /// server as not delivered.
    pub fn drop_stale_sealed(&mut self, age: Duration) {
        let (stale, keep): (Vec<_>, Vec<_>) = self.sealed.drain(..).partition(|(_, _, _, t)| t.elapsed() >= age);
        self.sealed = keep.into();
        for (issi, _, keys, _) in stale {
            for k in keys {
                self.sck_result(issi, k.sckn, k.vn, false, Some("radio not registered".into()));
            }
        }
    }

    pub fn sck_demand(&mut self, issi: u32, sckns: Vec<u8>) {
        self.outbox.push(ControlResponse::SckDemand { issi, sckns });
    }

    pub fn sck_result(&mut self, issi: u32, sckn: u8, vn: u16, ok: bool, detail: Option<String>) {
        self.outbox.push(ControlResponse::SckResult { issi, sckn, vn, ok, detail });
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl AuthVectorWire {
    pub fn to_vector(&self) -> Option<AuthVector> {
        Some(AuthVector { rs: unhex::<10>(&self.rs)?, ks: unhex::<16>(&self.ks)?, ks_p: unhex::<16>(&self.ks_p)? })
    }

    pub fn from_vector(v: &AuthVector) -> Self {
        AuthVectorWire { rs: hex(&v.rs), ks: hex(&v.ks), ks_p: hex(&v.ks_p) }
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("auth-sets.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_security::AuthKey;

    fn wire(k: &AuthKey, n: u8) -> AuthVectorWire {
        AuthVectorWire::from_vector(&AuthVector::from_k(k, [n; 10]))
    }

    #[test]
    fn sets_are_used_once_and_reported() {
        let k: AuthKey = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let mut s = AucStore::default();
        let stock = s.subscribers(&[100, 200], &[]);
        assert!(matches!(stock, ControlResponse::AuthStock { counts } if counts.is_empty()));
        s.add(100, &[wire(&k, 1), wire(&k, 2)]);
        assert_eq!(s.count(100), 2);
        assert_eq!(s.take_arrived().into_iter().collect::<Vec<_>>(), vec![100]);
        let v = s.take(100).unwrap();
        assert_eq!(v.rs, [1; 10]);
        s.report(100, &v.rs, true, true);
        assert_eq!(s.take(100).unwrap().rs, [2; 10]);
        assert!(s.take(100).is_none(), "each set only once");
        let out = s.drain_outbox();
        assert!(matches!(&out[0], ControlResponse::AuthReport { issi: 100, ok: true, mutual: true, left: Some(1), .. }));
    }

    #[test]
    fn unlisted_and_changed_radios_lose_their_sets() {
        let k: AuthKey = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let mut s = AucStore::default();
        s.subscribers(&[1, 2, 3], &[]);
        for i in [1, 2, 3] {
            s.add(i, &[wire(&k, i as u8)]);
        }
        let stock = s.subscribers(&[1, 2], &[2]);
        let ControlResponse::AuthStock { counts } = stock else { panic!() };
        assert_eq!(counts, vec![IssiCount { issi: 1, count: 1 }]);
        assert!(!s.is_known(3) && s.is_known(2));
        // No K at the server: an empty answer.
        s.add(2, &[]);
        assert!(!s.is_known(2));
    }

    #[test]
    fn requests_are_throttled() {
        let mut s = AucStore::default();
        let t = Instant::now();
        assert!(s.request(5, t));
        assert!(!s.request(5, t + Duration::from_secs(1)));
        assert!(s.request(5, t + Duration::from_secs(6)));
        assert_eq!(s.drain_outbox().len(), 2);
    }

    #[test]
    fn the_stock_survives_a_restart_in_a_private_file() {
        let k: AuthKey = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let dir = std::env::temp_dir().join(format!("auc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml.auth-sets");
        let mut s = AucStore::default();
        s.load(path.clone());
        s.subscribers(&[7], &[]);
        s.add(7, &[wire(&k, 9)]);
        let mut again = AucStore::default();
        again.load(path.clone());
        assert!(again.is_known(7));
        assert_eq!(again.take(7).unwrap(), AuthVector::from_k(&k, [9; 10]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
