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

use super::commands::{AuthVectorWire, ControlResponse, IssiCount};

/// Station capability: understands `AuthSubscribers` / `AuthVectors`.
pub const CAP_KEYS: &str = "keys-v1";

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
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    known: Vec<u32>,
    sets: BTreeMap<u32, Vec<AuthVectorWire>>,
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
        }
        self.path = Some(path);
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let f = File {
            known: self.known.iter().copied().collect(),
            sets: self.sets.iter().map(|(i, v)| (*i, v.iter().map(AuthVectorWire::from_vector).collect())).collect(),
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
        self.save();
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
