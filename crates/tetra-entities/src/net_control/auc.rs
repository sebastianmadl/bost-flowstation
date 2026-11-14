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

use super::commands::{AuthVectorWire, CckRef, CckWire, ControlResponse, DckWire, FallbackEpisode, IssiCount, SckRef, SckWire, SealedSckWire};

/// Station capability: understands `AuthSubscribers` / `AuthVectors`.
pub const CAP_KEYS: &str = "keys-v1";

/// Station capability: understands `SckKeys` / `SckSealed` / `SckActivate` (security class 2 keys
/// from the server).
pub const CAP_SCK: &str = "sck-v1";

/// Station capability: understands `CckKeys` / `CckActivate` (security class 3 CCKs from the
/// server).
pub const CAP_CCK: &str = "cck-v1";

/// Station capability: the station sends the DCKs of its class 3 radios and takes those of other stations
/// (`DckKeys` / `DckReport`).
pub const CAP_DCK: &str = "dck-v1";

/// Station capability: understands `FallbackKeys` and reports `FallbackState` (phase 8d: fallback
/// while the key server is unreachable, throttled re-authentication when it is back).
pub const CAP_FALLBACK: &str = "fallback-v1";

/// Fallback periods kept for the server.
const EPISODES_KEPT: usize = 10;

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
///
/// The station's own K list kept from a switch to server keys (`<config>.local-keys`, see
/// `fleet_config::park_local_keys`) goes with local keys (the config holds the list again); with
/// server keys it stays until the first authentication with the server's data succeeds.
pub fn boot(config_path: &str, server: bool) {
    let path = PathBuf::from(format!("{config_path}.auth-sets"));
    let parked = PathBuf::from(super::fleet_config::parked_keys_path(config_path));
    if !server {
        if std::fs::remove_file(&path).is_ok() {
            tracing::info!("Key management: key source is local, stock of authentication data sets removed");
        }
        let _ = std::fs::remove_file(&parked);
        return;
    }
    let handle = global();
    let mut s = handle.lock().unwrap_or_else(|e| e.into_inner());
    s.load(path);
    if let Some(list) = super::fleet_config::read_parked_keys(config_path) {
        tracing::warn!(
            "Key management: the station's own {} keys are kept until the first authentication with the server's data",
            list.as_array().map_or(0, |a| a.len())
        );
        s.parked = Some(parked);
    }
}

#[derive(Default)]
pub struct AucStore {
    path: Option<PathBuf>,
    /// Radios the server has a K for (its last `AuthSubscribers`).
    known: BTreeSet<u32>,
    sets: BTreeMap<u32, VecDeque<StoredSet>>,
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
    /// Fallback settings and periods (`fallback-v1`).
    fallback: FallbackFile,
    /// The control channel to the key server is up (set by the control worker).
    link_up: bool,
    /// The server sent its radio list on this connection (`AuthSubscribers`): its data flows again.
    synced: bool,
    /// The station's own K list kept from a switch to server keys, removed after the first
    /// successful authentication with the server's data.
    parked: Option<PathBuf>,
    /// When expired sets were last looked for ([`AucStore::expire`]).
    expiry_checked: Option<Instant>,
    /// Current fallback phase, as MM last set it (`normal` / `fallback` / `returning`).
    phase: String,
}

/// One set in stock with its end of validity and the K revision it was made from.
#[derive(Clone, Debug)]
struct StoredSet {
    v: AuthVector,
    exp_ms: u64,
    rev: u32,
}

impl StoredSet {
    fn from_wire(w: &AuthVectorWire) -> Option<Self> {
        Some(StoredSet { v: w.to_vector()?, exp_ms: w.exp_ms, rev: w.rev })
    }

    fn wire(&self) -> AuthVectorWire {
        AuthVectorWire { exp_ms: self.exp_ms, rev: self.rev, ..AuthVectorWire::from_vector(&self.v) }
    }

    fn valid(&self, now_ms: u64) -> bool {
        self.exp_ms == 0 || self.exp_ms > now_ms
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    known: Vec<u32>,
    sets: BTreeMap<u32, Vec<AuthVectorWire>>,
    #[serde(default)]
    sck: SckFile,
    #[serde(default)]
    cck: CckFile,
    #[serde(default)]
    fallback: FallbackFile,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct FallbackFile {
    /// The network's fallback SCK (SCKN 31 or 32).
    key: Option<SckWire>,
    after_s: u32,
    reauth_per_s: u8,
    /// Fallback periods not yet confirmed by the server, newest last.
    episodes: Vec<FallbackEpisode>,
    /// The operator switched the network to the fallback SCK (kept over a restart).
    #[serde(default)]
    forced: bool,
}

impl Default for FallbackFile {
    fn default() -> Self {
        FallbackFile {
            key: None,
            after_s: super::commands::default_fallback_after_s(),
            reauth_per_s: super::commands::default_reauth_per_s(),
            episodes: Vec::new(),
            forced: false,
        }
    }
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
                .map(|(issi, v)| (issi, v.iter().filter_map(StoredSet::from_wire).collect()))
                .collect();
            self.drop_expired(now_ms());
            tracing::info!("Key management: {} authentication data sets for {} radios loaded", self.total(), self.sets.len());
            self.sck = f.sck;
            self.cck = f.cck;
            self.fallback = f.fallback;
        }
        self.path = Some(path);
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let f = File {
            known: self.known.iter().copied().collect(),
            sets: self.sets.iter().map(|(i, v)| (*i, v.iter().map(StoredSet::wire).collect())).collect(),
            sck: self.sck.clone(),
            cck: self.cck.clone(),
            fallback: self.fallback.clone(),
        };
        let Ok(bytes) = serde_json::to_vec(&f) else { return };
        if let Err(e) = write_private(path, &bytes) {
            tracing::warn!("Key management: cannot write {}: {}", path.display(), e);
        }
    }

    /// The server's list of radios with K; sets of radios not listed or in `drop` (K changed) go.
    /// Returns the stock for the server.
    pub fn subscribers(&mut self, issis: &[u32], drop: &[u32]) -> ControlResponse {
        self.synced = true;
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
        let now = now_ms();
        let new: Vec<StoredSet> = vectors.iter().filter_map(StoredSet::from_wire).filter(|s| s.valid(now)).collect();
        let q = self.sets.entry(issi).or_default();
        // Sets made from an older K revision are no longer good (the radio's K changed).
        // Sets of an older revision arriving late are not taken either.
        if let Some(rev) = new.iter().chain(q.iter()).map(|s| s.rev).max() {
            if q.iter().any(|s| s.rev < rev) {
                tracing::info!("Key management: K of {} changed (revision {}), older sets dropped", issi, rev);
                q.retain(|s| s.rev >= rev);
            }
            q.extend(new.into_iter().filter(|s| s.rev >= rev));
        }
        if q.is_empty() {
            self.sets.remove(&issi);
        }
        self.arrived.insert(issi);
        self.save();
    }

    /// Drop sets whose validity has ended. Returns how many went.
    fn drop_expired(&mut self, now_ms: u64) -> u32 {
        let mut n = 0;
        self.sets.retain(|_, q| {
            let before = q.len();
            q.retain(|s| s.valid(now_ms));
            n += (before - q.len()) as u32;
            !q.is_empty()
        });
        if n > 0 {
            tracing::info!("Key management: {} authentication data sets expired unused", n);
            // The server's count of this station's stock is lower now: it tops up.
            let stock = self.stock();
            self.outbox.push(stock);
            self.save();
        }
        n
    }

    /// Drop expired sets, at most once a minute (called from MM's periodic work).
    pub fn expire(&mut self, now: Instant) {
        if self.expiry_checked.is_some_and(|t| now.duration_since(t) < Duration::from_secs(60)) {
            return;
        }
        self.expiry_checked = Some(now);
        self.drop_expired(now_ms());
    }

    /// The server has a K for this radio.
    pub fn is_known(&self, issi: u32) -> bool {
        self.known.contains(&issi)
    }

    /// Sets still valid for `issi`.
    pub fn count(&self, issi: u32) -> u32 {
        let now = now_ms();
        self.sets.get(&issi).map_or(0, |q| q.iter().filter(|s| s.valid(now)).count() as u32)
    }

    pub fn total(&self) -> u32 {
        let now = now_ms();
        self.sets.values().map(|q| q.iter().filter(|s| s.valid(now)).count() as u32).sum()
    }

    pub fn known_count(&self) -> u32 {
        self.known.len() as u32
    }

    /// One set for an authentication of `issi` (removed from the stock).
    /// Expired sets are skipped and dropped.
    pub fn take(&mut self, issi: u32) -> Option<AuthVector> {
        self.drop_expired(now_ms());
        let v = self.sets.get_mut(&issi)?.pop_front()?;
        if self.sets.get(&issi).is_some_and(|q| q.is_empty()) {
            self.sets.remove(&issi);
        }
        self.save();
        Some(v.v)
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
    /// The first success completes a switch to server keys: the station's own K list goes.
    pub fn report(&mut self, issi: u32, rs: &[u8; 10], ok: bool, mutual: bool) {
        let left = Some(self.count(issi));
        self.outbox.push(ControlResponse::AuthReport { issi, rs: hex(rs), ok, mutual, left });
        if ok && let Some(path) = self.parked.take() {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::warn!("Key management: first authentication with the server's data succeeded (ISSI {}), the station's own keys removed", issi),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!("Key management: cannot remove {}: {}", path.display(), e);
                    self.parked = Some(path);
                }
            }
        }
    }

    /// The station still keeps its own K list from a switch to server keys.
    pub fn keeps_local_keys(&self) -> bool {
        self.parked.is_some()
    }

    /// The stock per radio, for the server.
    pub fn stock(&self) -> ControlResponse {
        let now = now_ms();
        let counts = self
            .sets
            .iter()
            .map(|(i, q)| IssiCount { issi: *i, count: q.iter().filter(|s| s.valid(now)).count() as u32 })
            .filter(|c| c.count > 0)
            .collect();
        ControlResponse::AuthStock { counts }
    }

    /// A class 3 radio authenticated here: its DCK goes to the server (`dck-v1`).
    pub fn dck_report(&mut self, issi: u32, dck: &[u8; 10]) {
        self.outbox.push(ControlResponse::DckReport { key: DckWire { issi, dck: hex(dck) } });
    }

    /// DCKs forwarded by the server, as the cipher holds them; unreadable entries are skipped.
    pub fn dck_keys(keys: &[DckWire]) -> Vec<(u32, CipherKey)> {
        keys.iter().filter_map(|w| Some((w.issi, CipherKey(unhex::<10>(&w.dck.to_ascii_lowercase())?)))).collect()
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
        self.fallback = FallbackFile::default();
        self.save();
    }

    // ───────────── fallback (`fallback-v1`, phase 8d) ─────────────

    /// The control worker reports the link to the key server. Down: the server's data stops
    /// until it sends its radio list again.
    pub fn set_link(&mut self, up: bool) {
        self.link_up = up;
        if !up {
            self.synced = false;
        }
    }

    /// The key server is reachable and has sent its radio list on this connection.
    pub fn server_ready(&self) -> bool {
        self.link_up && self.synced
    }

    /// `FallbackKeys` from the server. Returns the state for the server.
    pub fn set_fallback(&mut self, key: Option<SckWire>, after_s: u32, reauth_per_s: u8, forced: bool) -> ControlResponse {
        let key = key.filter(|k| matches!(k.sckn, 31 | 32) && sck_key(k).is_some());
        self.fallback.key = key;
        self.fallback.forced = forced;
        self.fallback.after_s = after_s.clamp(60, 3600);
        self.fallback.reauth_per_s = reauth_per_s.clamp(1, 20);
        let state = self.fallback_state();
        // The server has seen the periods now.
        self.fallback.episodes.retain(|e| e.to_ms.is_none());
        self.save();
        state
    }

    /// The fallback SCK (SCKN 31 or 32) the server sent.
    pub fn fallback_key(&self) -> Option<SckKey> {
        self.fallback.key.as_ref().and_then(sck_key)
    }

    /// The operator asked for class 2 on the fallback SCK.
    pub fn fallback_forced(&self) -> bool {
        self.fallback.forced
    }

    /// How long without the server before a cell may go to fallback.
    pub fn fallback_after(&self) -> Duration {
        Duration::from_secs(self.fallback.after_s as u64)
    }

    /// Radios authenticated per second once the server is back.
    pub fn reauth_per_s(&self) -> u8 {
        self.fallback.reauth_per_s
    }

    /// MM changed the fallback phase. `episode`: start (`Some(from)` without `to`) or end of a
    /// period. The state goes to the server (dropped while it is away; it gets the periods with
    /// the answer to its next `FallbackKeys`).
    pub fn fallback_phase(&mut self, phase: &str, start: Option<(u64, bool, bool)>, end: Option<(u64, u32)>) {
        self.fallback_phase_lost(phase, start, None, end);
    }

    /// Like [`Self::fallback_phase`], with the reason of an automatic fallback: when the key
    /// server was lost (Unix ms). A running operator fallback that becomes automatic gets it too.
    pub fn fallback_phase_lost(&mut self, phase: &str, start: Option<(u64, bool, bool)>, lost_ms: Option<u64>, end: Option<(u64, u32)>) {
        self.phase = phase.to_string();
        if let (None, Some(lost)) = (start, lost_ms)
            && let Some(e) = self.fallback.episodes.iter_mut().rev().find(|e| e.to_ms.is_none())
        {
            e.lost_ms = Some(lost);
        }
        if let Some((from_ms, class2, manual)) = start {
            self.fallback.episodes.push(FallbackEpisode { from_ms, to_ms: None, class2, temporary: 0, manual, lost_ms });
            let n = self.fallback.episodes.len();
            if n > EPISODES_KEPT {
                self.fallback.episodes.drain(..n - EPISODES_KEPT);
            }
        }
        if let Some((to_ms, temporary)) = end
            && let Some(e) = self.fallback.episodes.iter_mut().rev().find(|e| e.to_ms.is_none())
        {
            e.to_ms = Some(to_ms);
            e.temporary = temporary;
        }
        self.save();
        let state = self.fallback_state();
        self.outbox.push(state);
    }

    pub fn fallback_state(&self) -> ControlResponse {
        ControlResponse::FallbackState {
            phase: if self.phase.is_empty() { "normal".into() } else { self.phase.clone() },
            key: self.fallback_key().as_ref().map(sck_ref),
            episodes: self.fallback.episodes.clone(),
        }
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

    /// The server's current CCK of each location area it sent (`None`: every LA).
    pub fn cck_currents(&self) -> Vec<(Option<u16>, SckKey)> {
        self.cck.keys.iter().filter(|k| !k.next).filter_map(|k| Some((k.la, cck_key(k)?))).collect()
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
        AuthVectorWire { rs: hex(&v.rs), ks: hex(&v.ks), ks_p: hex(&v.ks_p), exp_ms: 0, rev: 0 }
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    write_private_file(path, bytes)
}

/// Write a file readable by the owner only (mode 600), atomically and on disk.
pub(crate) fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    // On disk before the rename, and the rename itself on disk (a power cut on a Pi must not
    // leave an empty or old stock behind).
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
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
    fn expired_sets_are_not_used() {
        let k: AuthKey = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let mut s = AucStore::default();
        s.subscribers(&[1], &[]);
        let now = now_ms();
        let old = AuthVectorWire { exp_ms: now - 1, ..wire(&k, 1) };
        let good = AuthVectorWire { exp_ms: now + 60_000, ..wire(&k, 2) };
        s.add(1, &[old.clone(), good]);
        assert_eq!(s.count(1), 1, "an expired set never enters the stock");
        // A set that expires while in stock is skipped.
        s.sets.get_mut(&1).unwrap().push_front(StoredSet::from_wire(&old).unwrap());
        assert_eq!(s.count(1), 1);
        assert!(matches!(s.stock(), ControlResponse::AuthStock { counts } if counts == vec![IssiCount { issi: 1, count: 1 }]));
        assert_eq!(s.take(1).unwrap().rs, [2; 10]);
        assert!(s.take(1).is_none());
    }

    #[test]
    fn a_newer_k_revision_drops_the_older_sets() {
        let k: AuthKey = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let mut s = AucStore::default();
        s.subscribers(&[1], &[]);
        s.add(1, &[AuthVectorWire { rev: 1, ..wire(&k, 1) }, AuthVectorWire { rev: 1, ..wire(&k, 2) }]);
        s.add(1, &[AuthVectorWire { rev: 2, ..wire(&k, 3) }]);
        assert_eq!(s.count(1), 1);
        assert_eq!(s.take(1).unwrap().rs, [3; 10]);
        // A late set of the old revision is not taken.
        s.add(1, &[AuthVectorWire { rev: 2, ..wire(&k, 4) }]);
        s.add(1, &[AuthVectorWire { rev: 1, ..wire(&k, 5) }]);
        assert_eq!(s.count(1), 1);
        assert_eq!(s.take(1).unwrap().rs, [4; 10]);
    }

    #[test]
    fn the_first_server_authentication_removes_the_kept_local_keys() {
        let dir = std::env::temp_dir().join(format!("auc-park-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let parked = dir.join("config.toml.local-keys");
        std::fs::write(&parked, "x").unwrap();
        let mut s = AucStore { parked: Some(parked.clone()), ..Default::default() };
        s.report(1, &[0; 10], false, false);
        assert!(parked.exists() && s.keeps_local_keys(), "a failed authentication keeps them");
        s.report(1, &[0; 10], true, false);
        assert!(!parked.exists() && !s.keeps_local_keys());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_fallback_episode_carries_its_reason() {
        let mut s = AucStore::default();
        s.fallback_phase("manual", Some((1000, true, true)), None);
        assert_eq!(s.fallback.episodes[0].lost_ms, None, "operator: no lost server");
        // The server goes away during the operator's fallback: the episode gets the reason.
        s.fallback_phase_lost("fallback", None, Some(900), None);
        s.fallback_phase("normal", None, Some((2000, 0)));
        s.fallback_phase_lost("fallback", Some((3000, false, false)), Some(2500), None);
        let e: Vec<_> = s.fallback.episodes.iter().map(|e| (e.manual, e.lost_ms)).collect();
        assert_eq!(e, vec![(true, Some(900)), (false, Some(2500))]);
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
