//! Fleet Control key fallback (phase 8d): what a station with `key_source = "server"` does while
//! its key server (the Brew server as authentication centre) is unreachable, and how it comes
//! back. Design worked out with Patrick, OE1LHP.
//!
//! - Server away: radios are authenticated from the stock of data sets as before.
//! - Server away for `after` (default 5 min) and a radio known to the server could not be
//!   authenticated (no set left): fallback. The cell broadcasts "system wide services
//!   temporarily not supported" (TS 100 392-2 clause 18.5.2) and answers such radios with
//!   "temporary registration" (clause 16.4.8, NOTE 2). A class 3 cell holding the fallback SCK
//!   changes to class 2 on it (EN 300 392-7 clauses 4.2.4.0, 4.5.6.2).
//! - Server back: first fresh data sets, then the radios registered without authentication are
//!   authenticated again by the SwMI (clause 4.1.2), at most `rate` per second, and only then
//!   the cell returns to class 3 (clause 4.5.6.3) and to normal mode. Radios with a temporary
//!   registration register again by themselves (clause 16.4.8); the random access of the MAC
//!   spreads them (clause 23.5.1).
//!
//! This module holds the decisions only; MM carries them out.

use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

/// Longest wait for fresh data sets after the server is back.
pub const SETS_WAIT: Duration = Duration::from_secs(30);
/// After the last re-authentication went out: time for it to finish before normal mode.
pub const REAUTH_SETTLE: Duration = Duration::from_secs(5);
/// Longest return phase; then the cell goes back to normal mode in any case.
pub const RETURN_MAX: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Normal,
    Fallback,
    Returning {
        /// The cell is in fallback (else only radios registered unauthenticated are caught up).
        fallback: bool,
        since: Instant,
        /// Data sets are in (or the wait is over): re-authentication runs.
        sets_in: bool,
        last_sent: Option<Instant>,
    },
}

/// What MM has to do after [`KeyFallback::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Go to fallback now.
    Enter,
    /// The server is back: return phase started (nothing to send yet).
    Returning,
    /// Authenticate this radio (SwMI initiated, clause 4.1.2).
    Reauth(u32),
    /// Back to normal mode (`fallback`: the cell was in fallback and returns to its class).
    Back { fallback: bool },
    /// The server went away again during the return: stay in fallback.
    Lost,
}

#[derive(Debug)]
pub struct KeyFallback {
    phase: Phase,
    /// The server has been unreachable since.
    lost_since: Option<Instant>,
    /// A radio known to the server could not be authenticated since the server went away.
    starved: bool,
    /// Radios registered without authentication while the server was away (no temporary
    /// registration): authenticated again once it is back.
    unauthenticated: BTreeSet<u32>,
    /// Radios answered with "temporary registration" in this fallback period.
    temporary: BTreeSet<u32>,
    /// Temporary registrations given in this fallback period (for the report).
    temporary_total: u32,
    queue: VecDeque<u32>,
    next_reauth: Option<Instant>,
}

impl Default for KeyFallback {
    fn default() -> Self {
        KeyFallback {
            phase: Phase::Normal,
            lost_since: None,
            starved: false,
            unauthenticated: BTreeSet::new(),
            temporary: BTreeSet::new(),
            temporary_total: 0,
            queue: VecDeque::new(),
            next_reauth: None,
        }
    }
}

impl KeyFallback {
    /// In fallback (including the return phase while the cell is still in fallback).
    pub fn active(&self) -> bool {
        matches!(self.phase, Phase::Fallback | Phase::Returning { fallback: true, .. })
    }

    /// `normal`, `fallback` or `returning`, for the server and the dashboard.
    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Normal => "normal",
            Phase::Fallback => "fallback",
            Phase::Returning { .. } => "returning",
        }
    }

    /// The server is unreachable now (as last seen by [`Self::step`]).
    pub fn server_lost(&self) -> bool {
        self.lost_since.is_some()
    }

    /// A radio known to the server has no data set left while the server is away.
    pub fn note_starved(&mut self) {
        if self.lost_since.is_some() {
            self.starved = true;
        }
    }

    /// A radio known to the server registered without authentication while the server was away.
    pub fn note_unauthenticated(&mut self, issi: u32) {
        self.unauthenticated.insert(issi);
    }

    /// A radio got "temporary registration".
    pub fn note_temporary(&mut self, issi: u32) {
        if self.temporary.insert(issi) {
            self.temporary_total += 1;
        }
        self.unauthenticated.remove(&issi);
    }

    pub fn is_temporary(&self, issi: u32) -> bool {
        self.temporary.contains(&issi)
    }

    /// Temporary registrations given in this fallback period.
    pub fn temporary_count(&self) -> u32 {
        self.temporary_total
    }

    /// The radio authenticated (or left): nothing to catch up for it.
    pub fn note_authenticated(&mut self, issi: u32) {
        self.unauthenticated.remove(&issi);
        self.temporary.remove(&issi);
        self.queue.retain(|i| *i != issi);
    }

    /// One step. `server_ready`: the server is reachable and sent its radio list on this
    /// connection. `sets_ready`: every registered radio known to the server has a data set
    /// again. `after`: time without the server before fallback; `rate`: re-authentications per
    /// second.
    pub fn step(&mut self, now: Instant, server_ready: bool, sets_ready: bool, after: Duration, rate: u8) -> Action {
        if !server_ready {
            let since = *self.lost_since.get_or_insert(now);
            match self.phase {
                Phase::Normal if self.starved && now.duration_since(since) >= after => {
                    self.phase = Phase::Fallback;
                    return Action::Enter;
                }
                Phase::Returning { fallback, .. } => {
                    self.queue.clear();
                    self.next_reauth = None;
                    if fallback {
                        self.phase = Phase::Fallback;
                        return Action::Lost;
                    }
                    self.phase = Phase::Normal;
                }
                _ => {}
            }
            return Action::None;
        }
        self.lost_since = None;
        match self.phase.clone() {
            Phase::Normal => {
                self.starved = false;
                if self.unauthenticated.is_empty() {
                    return Action::None;
                }
                self.start_return(now, false);
                Action::Returning
            }
            Phase::Fallback => {
                self.start_return(now, true);
                Action::Returning
            }
            Phase::Returning { fallback, since, sets_in, last_sent } => {
                if now.duration_since(since) >= RETURN_MAX {
                    return self.finish(fallback);
                }
                if !sets_in {
                    if !sets_ready && now.duration_since(since) < SETS_WAIT {
                        return Action::None;
                    }
                    self.phase = Phase::Returning { fallback, since, sets_in: true, last_sent };
                }
                if self.next_reauth.is_some_and(|t| now < t) {
                    return Action::None;
                }
                if let Some(issi) = self.queue.pop_front() {
                    self.next_reauth = Some(now + Duration::from_millis(1000 / rate.clamp(1, 20) as u64));
                    self.phase = Phase::Returning { fallback, since, sets_in: true, last_sent: Some(now) };
                    return Action::Reauth(issi);
                }
                if last_sent.is_some_and(|t| now.duration_since(t) < REAUTH_SETTLE) {
                    return Action::None;
                }
                self.finish(fallback)
            }
        }
    }

    /// Radios still waiting for their re-authentication.
    pub fn waiting(&self) -> impl Iterator<Item = &u32> {
        self.queue.iter()
    }

    /// Tests: pretend `d` has passed (every stored time moves back by `d`).
    #[cfg(test)]
    pub fn skip(&mut self, d: Duration) {
        let back = |t: &mut Instant| *t = t.checked_sub(d).unwrap_or(*t);
        if let Some(t) = self.lost_since.as_mut() {
            back(t);
        }
        if let Some(t) = self.next_reauth.as_mut() {
            back(t);
        }
        if let Phase::Returning { since, last_sent, .. } = &mut self.phase {
            back(since);
            if let Some(t) = last_sent.as_mut() {
                back(t);
            }
        }
    }

    fn start_return(&mut self, now: Instant, fallback: bool) {
        self.queue = self.unauthenticated.iter().copied().collect();
        self.next_reauth = None;
        self.phase = Phase::Returning { fallback, since: now, sets_in: false, last_sent: None };
    }

    fn finish(&mut self, fallback: bool) -> Action {
        self.phase = Phase::Normal;
        self.starved = false;
        self.unauthenticated.clear();
        self.temporary.clear();
        self.temporary_total = 0;
        self.queue.clear();
        self.next_reauth = None;
        Action::Back { fallback }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AFTER: Duration = Duration::from_secs(300);

    #[test]
    fn no_fallback_before_the_time_or_without_a_starved_radio() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        assert_eq!(f.step(t0, false, false, AFTER, 2), Action::None);
        // Five minutes without the server, but every radio still had a set.
        assert_eq!(f.step(t0 + AFTER, false, false, AFTER, 2), Action::None);
        f.note_starved();
        assert_eq!(f.step(t0 + AFTER - Duration::from_secs(1), false, false, AFTER, 2), Action::None);
        assert_eq!(f.step(t0 + AFTER, false, false, AFTER, 2), Action::Enter);
        assert!(f.active());
        assert_eq!(f.phase_name(), "fallback");
    }

    #[test]
    fn starved_only_counts_while_the_server_is_away() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.note_starved();
        assert_eq!(f.step(t0, false, false, AFTER, 2), Action::None);
        assert_eq!(f.step(t0 + AFTER, false, false, AFTER, 2), Action::None, "starved before the loss is not counted");
    }

    #[test]
    fn return_waits_for_sets_then_reauthenticates_throttled_then_goes_back() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.step(t0, false, false, AFTER, 2);
        f.note_starved();
        f.note_unauthenticated(100);
        f.note_unauthenticated(200);
        f.note_unauthenticated(300);
        f.note_temporary(300);
        assert_eq!(f.step(t0 + AFTER, false, false, AFTER, 2), Action::Enter);
        let back = t0 + AFTER + Duration::from_secs(60);
        assert_eq!(f.step(back, true, false, AFTER, 2), Action::Returning);
        assert!(f.active(), "still in fallback while returning");
        // Sets not in yet.
        assert_eq!(f.step(back + Duration::from_secs(1), true, false, AFTER, 2), Action::None);
        let t = back + Duration::from_secs(2);
        assert_eq!(f.step(t, true, true, AFTER, 2), Action::Reauth(100));
        // 2 per second: the next one 500 ms later.
        assert_eq!(f.step(t + Duration::from_millis(400), true, true, AFTER, 2), Action::None);
        assert_eq!(f.step(t + Duration::from_millis(500), true, true, AFTER, 2), Action::Reauth(200));
        // Temporary radios register again by themselves (16.4.8): not in the queue.
        assert_eq!(f.step(t + Duration::from_millis(1000), true, true, AFTER, 2), Action::None);
        assert_eq!(f.step(t + Duration::from_millis(500) + REAUTH_SETTLE, true, true, AFTER, 2), Action::Back { fallback: true });
        assert!(!f.active());
        assert_eq!(f.temporary_count(), 0);
    }

    #[test]
    fn sets_wait_is_capped() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.step(t0, false, false, AFTER, 2);
        f.note_starved();
        f.step(t0 + AFTER, false, false, AFTER, 2);
        f.step(t0 + AFTER, true, false, AFTER, 2);
        assert_eq!(f.step(t0 + AFTER + SETS_WAIT, true, false, AFTER, 2), Action::Back { fallback: true });
    }

    #[test]
    fn server_lost_again_during_return_stays_in_fallback() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.step(t0, false, false, AFTER, 2);
        f.note_starved();
        f.step(t0 + AFTER, false, false, AFTER, 2);
        f.step(t0 + AFTER, true, false, AFTER, 2);
        assert_eq!(f.step(t0 + AFTER + Duration::from_secs(1), false, false, AFTER, 2), Action::Lost);
        assert_eq!(f.phase_name(), "fallback");
    }

    #[test]
    fn unauthenticated_radios_are_caught_up_without_a_fallback() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.step(t0, false, false, AFTER, 2);
        f.note_starved();
        f.note_unauthenticated(100);
        // Back after one minute: no fallback, but the radio gets authenticated.
        let t = t0 + Duration::from_secs(60);
        assert_eq!(f.step(t, true, true, AFTER, 2), Action::Returning);
        assert!(!f.active());
        assert_eq!(f.step(t, true, true, AFTER, 2), Action::Reauth(100));
        assert_eq!(f.step(t + REAUTH_SETTLE, true, true, AFTER, 2), Action::Back { fallback: false });
    }

    #[test]
    fn return_phase_is_capped() {
        let mut f = KeyFallback::default();
        let t0 = Instant::now();
        f.step(t0, false, false, AFTER, 1);
        f.note_starved();
        for i in 0..1000 {
            f.note_unauthenticated(i);
        }
        f.step(t0 + AFTER, false, false, AFTER, 1);
        let t = t0 + AFTER;
        f.step(t, true, true, AFTER, 1);
        assert!(matches!(f.step(t, true, true, AFTER, 1), Action::Reauth(_)));
        assert_eq!(f.step(t + RETURN_MAX, true, true, AFTER, 1), Action::Back { fallback: true });
    }
}
