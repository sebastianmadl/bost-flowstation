//! Command worker thread — receives commands from a remote server via a
//! pluggable network transport, dispatches them to the appropriate entity
//! through per-entity [`CommandDispatcher`] links, collects
//! [`CommandResponse`]s, and sends them back over the network.
//!
//! - decodes inbound messages as [`Command`]s, interprets how command must be handled, dispatches via per-entity links
//! - collects [`CommandResponse`]s from entities and sends them back

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;

use crate::{
    net_control::{
        channel::CommandDispatcher,
        codec::ControlCodecJson,
        commands::{ControlCommand, ControlResponse},
        auc, fleet, fleet_config, metrics,
    },
    network::transports::NetworkTransport,
};

/// How long to block on transport receive before running a maintenance cycle.
const POLL_TIMEOUT: Duration = Duration::from_millis(500);

/// How long to wait between reconnection attempts when the transport is down.
const RECONNECT_DELAY: Duration = Duration::from_secs(15);

pub struct ControlWorker<T: NetworkTransport> {
    dispatchers: HashMap<TetraEntity, CommandDispatcher>,
    transport: T,
    connected: bool,
    last_connect_attempt: Option<Instant>,
    /// Station config and state for Fleet Control (`None` in plain tests: no hello is sent).
    shared: Option<SharedConfig>,
    /// The server offered `fleet-control` on this connection.
    fleet_offered: bool,
    /// The switch value the last hello on this connection announced (`None`: none sent yet).
    hello_announced: Option<bool>,
    /// Whether that hello listed `update-v1` (an OTA was available).
    hello_ota: bool,
    /// Answers produced off the loop (update checks), sent by the loop.
    async_tx: std::sync::mpsc::Sender<ControlResponse>,
    async_rx: std::sync::mpsc::Receiver<ControlResponse>,
    /// Stage and percent of the last `UpdateProgress` sent on this connection, with the time.
    last_progress: Option<(String, u8, Instant)>,
    /// Config hash and "waits for confirmation" as told in the last hello (`config-v1`).
    hello_config: (Option<String>, bool),
    last_config_check: Option<Instant>,
    /// CPU load between two metrics reports (`metrics-v1`).
    cpu: metrics::CpuSampler,
    /// When the next metrics report is due (`None`: not reporting, the switch is off or the server
    /// does not offer Fleet Control).
    next_metrics: Option<Instant>,
    /// Source of the reports (replaced in tests).
    metrics_source: fn(&mut metrics::CpuSampler) -> ControlResponse,
    /// Stock of authentication data sets (`keys-v1`, `key_source = "server"`).
    auc: auc::Handle,
}

impl<T: NetworkTransport> ControlWorker<T> {
    pub fn new(dispatchers: HashMap<TetraEntity, CommandDispatcher>, transport: T) -> Self {
        let (async_tx, async_rx) = std::sync::mpsc::channel();
        Self {
            dispatchers,
            transport,
            connected: false,
            last_connect_attempt: None,
            shared: None,
            fleet_offered: false,
            hello_announced: None,
            hello_ota: false,
            async_tx,
            async_rx,
            last_progress: None,
            hello_config: (None, false),
            last_config_check: None,
            cpu: metrics::CpuSampler::default(),
            next_metrics: None,
            metrics_source: metrics::collect,
            auc: auc::global(),
        }
    }

    /// Give the worker the station's config and state, for Fleet Control (hello, switch).
    pub fn with_shared(mut self, shared: SharedConfig) -> Self {
        self.shared = Some(shared);
        self
    }

    /// Use this stock of authentication data sets instead of the process-wide one (tests).
    pub fn with_auc(mut self, auc: auc::Handle) -> Self {
        self.auc = auc;
        self
    }

    pub fn run(&mut self) {
        tracing::debug!("Control worker started");
        self.try_connect();

        loop {
            if self.connected {
                self.poll_commands();
                self.collect_responses();
                self.announce_switch_change();
                self.send_async_answers();
                self.report_update_progress();
                self.report_metrics(Instant::now());
                self.send_auc_outbox();
            } else {
                // Not connected — sleep briefly to avoid busy-spinning
                std::thread::sleep(POLL_TIMEOUT);
            }

            // Detect fresh disconnection
            if !self.transport.is_connected() && self.connected {
                tracing::warn!("Control transport disconnected");
                self.connected = false;
                self.set_fleet_link(false);
            }

            // Periodically retry connection when disconnected
            if !self.connected {
                let should_retry = match self.last_connect_attempt {
                    Some(last) => last.elapsed() >= RECONNECT_DELAY,
                    None => true,
                };
                if should_retry {
                    self.try_connect();
                }
            }
        }
    }

    /// Poll the transport for inbound commands, decode them, and dispatch
    /// to the appropriate entity through its [`CommandDispatcher`] link.
    fn poll_commands(&mut self) {
        let msgs = self.transport.receive_reliable();

        for msg in msgs {
            let codec = ControlCodecJson;
            match codec.decode_command(&msg.payload) {
                Ok(command) => {
                    tracing::debug!("command received: {:?}", command);
                    self.dispatch_command(command);
                }
                Err(e) => {
                    tracing::warn!("Command: failed to decode inbound message ({} bytes): {}", msg.payload.len(), e);
                }
            }
        }
    }

    /// Route a command to the correct entity's dispatcher.
    /// Override this mapping as real command variants are added.
    fn dispatch_command(&mut self, command: ControlCommand) {
        // Fleet Control commands are answered here, with the local switch; everything else goes to
        // the stack as before (independent of the switch).
        if let Some(response) = fleet::answer(&command, self.fleet_enabled()) {
            self.send_response(&response);
            return;
        }
        if matches!(
            command,
            ControlCommand::AuthSubscribers { .. }
                | ControlCommand::AuthVectors { .. }
                | ControlCommand::SckKeys { .. }
                | ControlCommand::SckSealed { .. }
                | ControlCommand::SckActivate { .. }
                | ControlCommand::CckKeys { .. }
                | ControlCommand::CckActivate { .. }
                | ControlCommand::DckKeys { .. }
        ) {
            self.auc_command(command);
            return;
        }
        let updating = crate::net_dashboard::ota_remote::progress().is_some_and(|p| p.running);
        let now = fleet_config::StationNow { enabled: self.fleet_enabled(), calls: crate::net_dashboard::ota_remote::active_calls(), updating };
        if let Some(response) = fleet_config::config_command(&command, now, self.shared.as_ref()) {
            let confirmed = matches!(command, ControlCommand::ConfirmConfig { .. });
            self.send_response(&response);
            if confirmed {
                // The next hello says that nothing waits any more.
                self.last_config_check = None;
            }
            return;
        }
        if let Some(response) =
            fleet::restart_command(&command, self.fleet_enabled(), crate::net_dashboard::ota_remote::active_calls(), updating, fleet::schedule_restart)
        {
            self.send_response(&response);
            return;
        }
        let ota = crate::net_dashboard::ota_remote::available();
        match fleet::update_command(&command, self.fleet_enabled(), ota, crate::net_dashboard::ota_remote::start) {
            Some(fleet::UpdateAction::Reply(response)) => {
                self.send_response(&response);
                return;
            }
            Some(fleet::UpdateAction::Check { handle }) => {
                // The check asks GitHub (seconds): run it off the loop, the loop sends the answer.
                let tx = self.async_tx.clone();
                let _ = std::thread::Builder::new().name("fleet-update-check".into()).spawn(move || {
                    let _ = tx.send(fleet::update_info(handle, crate::net_dashboard::ota_remote::check()));
                });
                return;
            }
            None => {}
        }
        let target = Self::route_control_command(&command);
        match self.dispatchers.get(&target) {
            Some(dispatcher) => {
                tracing::debug!("dispatching command to {:?}", target);
                dispatcher.send(command);
            }
            None => {
                tracing::warn!("no dispatcher registered for {:?}, dropping command", target);
            }
        }
    }

    /// Determine which entity should handle a given command. The mapping lives on
    /// `ControlCommand` so every command ingress (remote worker, dashboard, etc.) uses
    /// the same routing policy.
    fn route_control_command(command: &ControlCommand) -> TetraEntity {
        command.target_entity()
    }

    /// Drain pending responses from all entity dispatchers and send them
    /// back to the command server.
    fn collect_responses(&mut self) {
        let responses: Vec<ControlResponse> = self.dispatchers.values().flat_map(|d| d.try_recv_responses()).collect();

        for response in &responses {
            tracing::debug!("response collected: {:?}", response);
            self.send_response(response);
        }
    }

    fn send_response(&mut self, response: &ControlResponse) {
        if !self.connected {
            return;
        }

        let codec = ControlCodecJson;
        let payload = codec.encode_response(response);
        if let Err(e) = self.transport.send_reliable(&payload) {
            tracing::warn!("Control transport send failed: {}, will reconnect", e);
            self.connected = false;
            self.set_fleet_link(false);
            self.try_connect();
        }
    }

    /// The local Fleet Control switch (off without station state).
    fn fleet_enabled(&self) -> bool {
        self.shared.as_ref().is_some_and(|s| s.state_read().fleet_control.enabled)
    }

    /// Record the control link for the dashboard (sidebar field, Server features list).
    fn set_fleet_link(&mut self, connected: bool) {
        if !connected {
            self.hello_announced = None;
            self.last_progress = None;
            self.next_metrics = None;
        }
        if let Some(shared) = &self.shared {
            let mut state = shared.state_write();
            state.fleet_control.connected = connected;
            if connected {
                state.fleet_control.offered = self.fleet_offered;
            }
        }
    }

    /// Send a hello when the server offers Fleet Control and the switch differs from what the
    /// last hello on this connection said (first hello after connecting, or the switch changed on
    /// the dashboard).
    fn announce_switch_change(&mut self) {
        if !self.connected || !self.fleet_offered {
            return;
        }
        let Some(shared) = self.shared.clone() else { return };
        let enabled = shared.state_read().fleet_control.enabled;
        // The capabilities change too when the dashboard (and with it the OTA) comes up later.
        let ota = crate::net_dashboard::ota_remote::available();
        // The config hash changes with a save on the station; "waits for confirmation" ends with
        // the confirmation. Looked at every 5 s (it reads the file).
        let config_changed = enabled && self.hello_announced == Some(true) && {
            let due = self.last_config_check.is_none_or(|t| t.elapsed() >= Duration::from_secs(5));
            due && {
                self.last_config_check = Some(Instant::now());
                (fleet_config::current_hash(), fleet_config::pending_secs().is_some()) != self.hello_config
            }
        };
        if self.hello_announced == Some(enabled) && (!enabled || self.hello_ota == ota) && !config_changed {
            return;
        }
        let hello = fleet::station_hello(&shared);
        if self.hello_announced.is_some_and(|was| was != enabled) {
            tracing::info!("Fleet Control switched {} on this station, telling the server", if enabled { "on" } else { "off" });
        }
        self.hello_announced = Some(enabled);
        self.hello_ota = ota;
        if let ControlResponse::StationHello { config_hash, config_pending, .. } = &hello {
            self.hello_config = (config_hash.clone(), config_pending.is_some());
        }
        self.last_config_check = Some(Instant::now());
        self.send_response(&hello);
    }

    /// The station takes its authentication data from the server (`key_source = "server"`) and
    /// Fleet Control is on.
    fn uses_server_keys(&self) -> bool {
        self.fleet_enabled()
            && self.shared.as_ref().is_some_and(|s| s.config().security.key_source == tetra_config::bluestation::KeySource::Server)
    }

    /// `AuthSubscribers` / `AuthVectors` (`keys-v1`). Ignored unless the station uses the server's
    /// keys, so a station with local keys never stores data sets.
    fn auc_command(&mut self, command: ControlCommand) {
        if !self.uses_server_keys() {
            tracing::debug!("Key management: command ignored, key_source is not server or Fleet Control is off");
            return;
        }
        let config_key = self.shared.as_ref().and_then(|s| auc::config_sck(&s.config()));
        let config_cck = self.shared.as_ref().and_then(|s| auc::config_cck(&s.config()));
        let cell_la = self.shared.as_ref().map_or(0, |s| s.config().cell.location_area);
        let answer = {
            let mut store = self.auc.lock().unwrap_or_else(|e| e.into_inner());
            match &command {
                ControlCommand::AuthSubscribers { issis, drop } => {
                    tracing::info!("Key management: server holds keys for {} radios", issis.len());
                    Some(store.subscribers(issis, drop))
                }
                ControlCommand::AuthVectors { issi, vectors } => {
                    tracing::debug!("Key management: {} authentication data sets for {}", vectors.len(), issi);
                    store.add(*issi, vectors);
                    None
                }
                ControlCommand::SckKeys { keys } => {
                    tracing::info!("Key management: server sent {} SCK(s)", keys.len());
                    store.set_sck_keys(keys);
                    Some(store.sck_state(config_key.as_ref()))
                }
                ControlCommand::SckSealed { issi, rso, keys } => {
                    tracing::debug!("Key management: {} sealed SCK(s) for {}", keys.len(), issi);
                    store.push_sealed(*issi, rso.clone(), keys.clone());
                    None
                }
                ControlCommand::SckActivate { sckn, vn, at_ms } => match store.sck_activate(*sckn, *vn, *at_ms) {
                    Ok(()) => {
                        tracing::info!("Key management: SCK {} version {} planned for server time {}", sckn, vn, at_ms);
                        Some(store.sck_state(config_key.as_ref()))
                    }
                    Err(e) => {
                        tracing::warn!("Key management: SCK {} version {} cannot be activated: {}", sckn, vn, e);
                        Some(store.sck_state(config_key.as_ref()))
                    }
                },
                ControlCommand::CckKeys { keys } => {
                    tracing::info!("Key management: server sent {} CCK(s)", keys.len());
                    store.set_cck_keys(keys);
                    if let Some(shared) = &self.shared {
                        shared.state_write().cck_server = store.cck_currents();
                    }
                    Some(store.cck_state(cell_la, config_cck.as_ref()))
                }
                ControlCommand::DckKeys { keys, drop } => {
                    if let Some(shared) = &self.shared {
                        let mut state = shared.state_write();
                        for issi in drop {
                            state.dck_roam.remove(issi);
                        }
                        // A DCK this station runs itself stays first: it ends when the radio
                        // registers elsewhere (the server's "moved" clears it).
                        for (issi, dck) in auc::AucStore::dck_keys(keys) {
                            state.dck_roam.insert(issi, dck);
                        }
                    }
                    tracing::info!("Key management: server forwarded {} DCK(s), dropped {}", keys.len(), drop.len());
                    None
                }
                ControlCommand::CckActivate { la, cck_id, at_ms, overlap_s } => match store.cck_activate(cell_la, *la, *cck_id, *at_ms, *overlap_s) {
                    Ok(true) => {
                        tracing::info!("Key management: CCK {} planned for server time {} (overlap {} s)", cck_id, at_ms, overlap_s);
                        Some(store.cck_state(cell_la, config_cck.as_ref()))
                    }
                    Ok(false) => None,
                    Err(e) => {
                        tracing::warn!("Key management: CCK {} cannot be activated: {}", cck_id, e);
                        Some(store.cck_state(cell_la, config_cck.as_ref()))
                    }
                },
                _ => None,
            }
        };
        if let Some(answer) = answer {
            self.send_response(&answer);
        }
    }

    /// Send what MM queued for the server (set requests, reports). Dropped while the server does
    /// not take them: the stock sent after the next `AuthSubscribers` corrects the server's count.
    fn send_auc_outbox(&mut self) {
        let out = self.auc.lock().unwrap_or_else(|e| e.into_inner()).drain_outbox();
        if out.is_empty() || !self.fleet_offered || !self.uses_server_keys() {
            return;
        }
        for response in &out {
            self.send_response(response);
        }
    }

    /// Send the answers of finished update checks.
    fn send_async_answers(&mut self) {
        while let Ok(response) = self.async_rx.try_recv() {
            self.send_response(&response);
        }
    }

    /// Send the metrics report every minute to a server offering Fleet Control while the switch is
    /// on (`metrics-v1`). The first one comes a few seconds after the connect or the switch-on.
    fn report_metrics(&mut self, now: Instant) {
        if !self.connected || !self.fleet_offered || !self.fleet_enabled() {
            self.next_metrics = None;
            return;
        }
        let Some(due) = self.next_metrics else {
            // Start the CPU sample now, so the first report already has a load value.
            self.cpu.sample();
            self.next_metrics = Some(now + metrics::FIRST_METRICS_DELAY);
            return;
        };
        if now < due {
            return;
        }
        self.next_metrics = Some(now + metrics::METRICS_INTERVAL);
        let report = (self.metrics_source)(&mut self.cpu);
        self.send_response(&report);
    }

    /// Report the OTA progress to a server offering Fleet Control while the switch is on.
    fn report_update_progress(&mut self) {
        if !self.connected || !self.fleet_offered || !self.fleet_enabled() {
            return;
        }
        let Some(p) = crate::net_dashboard::ota_remote::progress() else { return };
        let now = Instant::now();
        if !fleet::progress_due(&p, self.last_progress.as_ref(), now) {
            return;
        }
        self.last_progress = Some((p.stage.as_str().to_string(), p.percent, now));
        self.send_response(&fleet::update_progress(&p));
    }

    fn try_connect(&mut self) {
        self.last_connect_attempt = Some(Instant::now());
        match self.transport.connect() {
            Ok(()) => {
                tracing::info!("Control transport connected");
                self.connected = true;
                self.fleet_offered = fleet::offered(self.transport.server_brew_extensions());
                if self.fleet_offered {
                    tracing::info!("Control server offers Fleet Control");
                }
                self.hello_announced = None;
                // The hello goes out from the run loop (`announce_switch_change`), not from here:
                // a failed send reconnects through this function.
                self.set_fleet_link(true);
            }
            Err(e) => {
                tracing::warn!("Control transport connection failed: {}, will retry in {:?}", e, RECONNECT_DELAY);
                self.connected = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tetra_core::debug::setup_logging_verbose;

    use super::*;
    use crate::net_control::channel::make_control_link;
    use crate::network::transports::mock::MockTransport;

    #[test]
    fn test_route_command_a_to_mm() {
        let target = ControlWorker::<MockTransport>::route_control_command(&ControlCommand::CommandA { handle: 1, parameter: 1 });
        assert_eq!(target, TetraEntity::Mm);
    }

    #[test]
    fn test_route_otar_sck_to_mm() {
        let target =
            ControlWorker::<MockTransport>::route_control_command(&ControlCommand::OtarSck { issi: 200 });
        assert_eq!(target, TetraEntity::Mm);
    }

    #[test]
    fn test_route_dgna_to_mm() {
        let target = ControlWorker::<MockTransport>::route_control_command(&ControlCommand::Dgna {
            issi: 200,
            gssi: 1001,
            mnemonic: None,
            attachment_mode: 0,
            attach: true,
        });
        assert_eq!(target, TetraEntity::Mm);
    }

    #[test]
    fn test_route_command_b_to_cmce() {
        let target = ControlWorker::<MockTransport>::route_control_command(&ControlCommand::TestCmdB {
            handle: 2,
            source_ssi: 12345,
            is_group: false,
            payload: vec![],
        });
        assert_eq!(target, TetraEntity::Cmce);
    }

    #[test]
    fn test_route_ambience_listen_to_cmce() {
        let target = ControlWorker::<MockTransport>::route_control_command(&ControlCommand::AmbienceListen { issi: 2001, enable: true });
        assert_eq!(target, TetraEntity::Cmce);
    }

    #[test]
    fn test_route_raw_sds_type4_to_cmce() {
        let target = ControlWorker::<MockTransport>::route_control_command(&ControlCommand::SendRawSdsType4 {
            handle: 3,
            source_ssi: 9999,
            dest_ssi: 2260571,
            dest_is_group: false,
            len_bits: 16,
            payload: vec![0xC3, 0x00],
        });
        assert_eq!(target, TetraEntity::Cmce);
    }

    #[test]
    fn test_worker_dispatches_command_and_collects_response() {
        setup_logging_verbose();

        // Set up per-entity links
        let (mm_dispatcher, mm_endpoint) = make_control_link();
        let mut dispatchers = HashMap::new();
        dispatchers.insert(TetraEntity::Mm, mm_dispatcher);

        // Pre-load a CommandA (routed to Mm) into the mock transport
        let codec = ControlCodecJson;
        let cmd = ControlCommand::CommandA { handle: 1, parameter: 99 };
        let payload = codec.encode_command(&cmd);

        let mut mock = MockTransport::new();
        mock.push_inbound(payload);

        let handle = std::thread::spawn(move || {
            let mut worker = ControlWorker::new(dispatchers, mock);
            worker.try_connect();
            worker.poll_commands();

            // Simulate entity processing: endpoint receives command, sends response
            let received = mm_endpoint.try_recv().expect("Mm should receive CommandA");
            assert!(matches!(received, ControlCommand::CommandA { handle: 1, parameter: 99 }));
            mm_endpoint.respond(ControlResponse::CommandAResponse { handle: 1, result: 99 });

            // Worker collects responses and sends them back over the transport
            worker.collect_responses();

            // Verify the response was sent through the transport
            assert_eq!(worker.transport.sent_payloads().len(), 1);
            let sent = &worker.transport.sent_payloads()[0];
            let decoded = codec.decode_response(sent).unwrap();
            assert!(matches!(decoded, ControlResponse::CommandAResponse { handle: 1, result: 99 }));
        });

        handle.join().expect("command worker panicked");
    }

    #[test]
    fn test_worker_drops_command_without_dispatcher() {
        setup_logging_verbose();

        // No dispatchers registered — command should be dropped with a warning
        let dispatchers = HashMap::new();

        let codec = ControlCodecJson;
        let cmd = ControlCommand::CommandA { handle: 1, parameter: 1 };
        let payload = codec.encode_command(&cmd);

        let mut mock = MockTransport::new();
        mock.push_inbound(payload);

        let handle = std::thread::spawn(move || {
            let mut worker = ControlWorker::new(dispatchers, mock);
            worker.try_connect();
            worker.poll_commands(); // should log warning and not panic
        });

        handle.join().expect("command worker panicked");
    }

    fn station(fleet_control: bool) -> SharedConfig {
        let cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
        let shared = SharedConfig::from_parts(cfg, None);
        shared.state_write().fleet_control.enabled = fleet_control;
        shared
    }

    fn sent(worker: &ControlWorker<MockTransport>) -> Vec<ControlResponse> {
        worker.transport.sent_payloads().iter().map(|p| ControlCodecJson.decode_response(p).unwrap()).collect()
    }

    #[test]
    fn no_hello_to_a_server_without_fleet_control() {
        // Older servers never see the new messages: nothing is sent unless `fleet-control` is offered.
        let shared = station(true);
        let mut worker = ControlWorker::new(HashMap::new(), MockTransport::new().with_brew_extensions(&["bts-info"])).with_shared(shared.clone());
        worker.try_connect();
        worker.announce_switch_change();
        assert!(worker.transport.sent_payloads().is_empty());
        let fc = shared.state_read().fleet_control.clone();
        assert!(fc.connected && !fc.offered && fc.enabled);
    }

    #[test]
    fn hello_after_connect_and_on_every_switch_change() {
        let shared = station(false);
        let mut worker =
            ControlWorker::new(HashMap::new(), MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL])).with_shared(shared.clone());
        worker.try_connect();
        assert!(shared.state_read().fleet_control.offered);
        worker.announce_switch_change();
        worker.announce_switch_change(); // unchanged: no second hello
        shared.state_write().fleet_control.enabled = true;
        worker.announce_switch_change();
        shared.state_write().fleet_control.enabled = false;
        worker.announce_switch_change();
        let hellos: Vec<(bool, Vec<String>)> = sent(&worker)
            .into_iter()
            .map(|r| match r {
                ControlResponse::StationHello { fleet_control, capabilities, protocol, version, .. } => {
                    assert_eq!(protocol, fleet::FLEET_PROTOCOL);
                    assert_eq!(version, tetra_core::STACK_VERSION);
                    (fleet_control, capabilities)
                }
                other => panic!("expected a hello, got {other:?}"),
            })
            .collect();
        assert_eq!(hellos, vec![(false, vec![]), (true, vec!["fleet-v1".to_string(), "maintenance-v1".to_string(), "restart-v1".to_string(), "metrics-v1".to_string(), "keys-v1".to_string(), "sck-v1".to_string(), "cck-v1".to_string(), "dck-v1".to_string()]), (false, vec![])]);
    }

    fn fake_metrics(_: &mut metrics::CpuSampler) -> ControlResponse {
        metrics::report(Some(7.5), Some(50.0), vec![], 2, 0, "ok")
    }

    fn metrics_sent(worker: &ControlWorker<MockTransport>) -> usize {
        sent(worker).into_iter().filter(|r| matches!(r, ControlResponse::FleetMetrics { .. })).count()
    }

    #[test]
    fn metrics_every_minute_only_with_the_switch_and_a_fleet_server() {
        // A server without Fleet Control never gets metrics.
        let mut old = ControlWorker::new(HashMap::new(), MockTransport::new().with_brew_extensions(&["bts-info"])).with_shared(station(true));
        old.metrics_source = fake_metrics;
        old.try_connect();
        let t0 = Instant::now();
        for s in [0, 10, 70, 200] {
            old.report_metrics(t0 + Duration::from_secs(s));
        }
        assert_eq!(metrics_sent(&old), 0);

        let shared = station(false);
        let mut worker =
            ControlWorker::new(HashMap::new(), MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL])).with_shared(shared.clone());
        worker.metrics_source = fake_metrics;
        worker.try_connect();
        worker.report_metrics(t0);
        worker.report_metrics(t0 + Duration::from_secs(10));
        assert_eq!(metrics_sent(&worker), 0, "switch off: no metrics");
        shared.state_write().fleet_control.enabled = true;
        worker.report_metrics(t0 + Duration::from_secs(20)); // starts the clock
        worker.report_metrics(t0 + Duration::from_secs(24));
        assert_eq!(metrics_sent(&worker), 0);
        worker.report_metrics(t0 + Duration::from_secs(25)); // first report 5 s after the switch-on
        assert_eq!(metrics_sent(&worker), 1);
        worker.report_metrics(t0 + Duration::from_secs(60));
        assert_eq!(metrics_sent(&worker), 1);
        worker.report_metrics(t0 + Duration::from_secs(85)); // then every 60 s
        assert_eq!(metrics_sent(&worker), 2);
        let last = sent(&worker).into_iter().rev().find(|r| matches!(r, ControlResponse::FleetMetrics { .. })).unwrap();
        assert!(matches!(last, ControlResponse::FleetMetrics { interval_secs: 60, radios: 2, .. }));
        shared.state_write().fleet_control.enabled = false;
        worker.report_metrics(t0 + Duration::from_secs(200));
        assert_eq!(metrics_sent(&worker), 2, "switch off again: no more metrics");
    }

    #[test]
    fn key_commands_only_with_server_key_source_and_the_switch() {
        for (server, fleet) in [(false, true), (true, false), (true, true)] {
            let mut cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
            if server {
                cfg.security.key_source = tetra_config::bluestation::KeySource::Server;
            }
            let shared = SharedConfig::from_parts(cfg, None);
            shared.state_write().fleet_control.enabled = fleet;
            let auc: auc::Handle = std::sync::Arc::new(std::sync::Mutex::new(auc::AucStore::default()));
            let (cmce, cmce_endpoint) = make_control_link();
            let mut dispatchers = HashMap::new();
            dispatchers.insert(TetraEntity::Cmce, cmce);
            let mut mock = MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL]);
            mock.push_inbound(br#"{"AuthSubscribers":{"issis":[100]}}"#.to_vec());
            mock.push_inbound(
                br#"{"AuthVectors":{"issi":100,"vectors":[{"rs":"00112233445566778899","ks":"000102030405060708090a0b0c0d0e0f","ks_p":"101112131415161718191a1b1c1d1e1f"}]}}"#
                    .to_vec(),
            );
            let mut worker = ControlWorker::new(dispatchers, mock).with_shared(shared).with_auc(auc.clone());
            worker.try_connect();
            worker.poll_commands();
            assert!(cmce_endpoint.try_recv().is_none(), "key commands never reach the stack");
            let used = server && fleet;
            assert_eq!(auc.lock().unwrap().count(100), used as u32);
            let stock: Vec<_> = sent(&worker).into_iter().filter(|r| matches!(r, ControlResponse::AuthStock { .. })).collect();
            assert_eq!(stock.len(), used as usize);
            // Requests from MM go out only while the station uses the server's keys.
            auc.lock().unwrap().request(200, Instant::now());
            worker.send_auc_outbox();
            let requests = sent(&worker).into_iter().filter(|r| matches!(r, ControlResponse::AuthVectorRequest { issi: 200 })).count();
            assert_eq!(requests, used as usize);
        }
    }

    /// `dck-v1`: forwarded DCKs land in the shared state (only with server keys and the switch),
    /// `drop` removes them, a CCK set fills the per-LA list for neighbour requests.
    #[test]
    fn forwarded_dcks_and_server_ccks_reach_the_shared_state() {
        for used in [false, true] {
            let mut cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
            if used {
                cfg.security.key_source = tetra_config::bluestation::KeySource::Server;
            }
            let shared = SharedConfig::from_parts(cfg, None);
            shared.state_write().fleet_control.enabled = true;
            let auc: auc::Handle = std::sync::Arc::new(std::sync::Mutex::new(auc::AucStore::default()));
            let mut mock = MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL]);
            mock.push_inbound(br#"{"DckKeys":{"keys":[{"issi":100,"dck":"0102030405060708090A"},{"issi":101,"dck":"11111111111111111111"}]}}"#.to_vec());
            mock.push_inbound(br#"{"DckKeys":{"drop":[101]}}"#.to_vec());
            mock.push_inbound(br#"{"CckKeys":{"keys":[{"la":7,"cck_id":5,"key":"22222222222222222222"},{"la":7,"cck_id":6,"key":"33333333333333333333","next":true}]}}"#.to_vec());
            let mut worker = ControlWorker::new(HashMap::new(), mock).with_shared(shared.clone()).with_auc(auc);
            worker.try_connect();
            worker.poll_commands();
            let st = shared.state_read();
            assert_eq!(st.dck_roam.get(&100).map(|k| k.0), used.then_some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
            assert!(!st.dck_roam.contains_key(&101), "dropped");
            assert_eq!(st.cck_server.iter().map(|(la, k)| (*la, k.vn)).collect::<Vec<_>>(), if used { vec![(Some(7), 5)] } else { vec![] }, "current keys only");
        }
    }

    #[test]
    fn fleet_ping_answered_by_the_worker_with_the_switch() {
        let shared = station(false);
        let (mm_dispatcher, mm_endpoint) = make_control_link();
        let mut dispatchers = HashMap::new();
        dispatchers.insert(TetraEntity::Cmce, mm_dispatcher);
        let mut mock = MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL]);
        mock.push_inbound(br#"{"FleetPing":{"handle":11}}"#.to_vec());
        let mut worker = ControlWorker::new(dispatchers, mock).with_shared(shared.clone());
        worker.try_connect();
        worker.poll_commands();
        shared.state_write().fleet_control.enabled = true;
        worker.transport.push_inbound(br#"{"FleetPing":{"handle":12}}"#.to_vec());
        worker.poll_commands();
        assert!(mm_endpoint.try_recv().is_none(), "Fleet Control commands never reach the stack");
        let results: Vec<(u32, bool, String)> = sent(&worker)
            .into_iter()
            .map(|r| match r {
                ControlResponse::CommandResult { handle, ok, code, .. } => (handle, ok, code),
                other => panic!("expected a result, got {other:?}"),
            })
            .collect();
        assert_eq!(results, vec![(11, false, "fleet_control_off".to_string()), (12, true, "ok".to_string())]);
    }

    #[test]
    fn existing_commands_do_not_need_the_switch() {
        let shared = station(false);
        let (dispatcher, endpoint) = make_control_link();
        let mut dispatchers = HashMap::new();
        dispatchers.insert(TetraEntity::Cmce, dispatcher);
        let mut mock = MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL]);
        mock.push_inbound(ControlCodecJson.encode_command(&ControlCommand::KickMs { issi: 2001 }));
        let mut worker = ControlWorker::new(dispatchers, mock).with_shared(shared);
        worker.try_connect();
        worker.poll_commands();
        assert!(matches!(endpoint.try_recv(), Some(ControlCommand::KickMs { issi: 2001 })));
    }

    #[test]
    fn config_commands_are_answered_by_the_worker_with_the_switch() {
        let shared = station(false);
        let (dispatcher, endpoint) = make_control_link();
        let mut dispatchers = HashMap::new();
        dispatchers.insert(TetraEntity::Cmce, dispatcher);
        let mut mock = MockTransport::new().with_brew_extensions(&[fleet::EXT_FLEET_CONTROL]);
        mock.push_inbound(br#"{"GetConfig":{"handle":21}}"#.to_vec());
        mock.push_inbound(br#"{"ConfirmConfig":{"handle":22}}"#.to_vec());
        let mut worker = ControlWorker::new(dispatchers, mock).with_shared(shared);
        worker.try_connect();
        worker.poll_commands();
        assert!(endpoint.try_recv().is_none(), "config commands never reach the stack");
        let got: Vec<(u32, bool, String)> = sent(&worker)
            .into_iter()
            .map(|r| match r {
                ControlResponse::ConfigInfo { handle, ok, code, .. } | ControlResponse::CommandResult { handle, ok, code, .. } => (handle, ok, code),
                other => panic!("expected an answer, got {other:?}"),
            })
            .collect();
        assert_eq!(got, vec![(21, false, "fleet_control_off".to_string()), (22, false, "fleet_control_off".to_string())]);
    }
}
