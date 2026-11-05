//! Brew worker thread: transport-agnostic message loop for Brew protocol exchange
//!
//! Generic over any [`NetworkTransport`] implementation (WebSocket, QUIC, TCP, etc.).
//! The transport handles connection lifecycle and heartbeat; this worker handles
//! Brew protocol parsing, command dispatch, and event generation.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use tetra_config::bluestation::BrewDirectoryNeighbour;
use tetra_config::bluestation::CfgBrew;
use tetra_config::bluestation::SharedConfig;
use tetra_config::bluestation::StackConfig;
use tetra_core::CellId;
use uuid::Uuid;

use crate::net_brew;
use crate::network::transports::NetworkTransport;

use super::protocol::*;

// ─── Events passed from worker to entity ─────────────────────────

/// Capacity of the worker→entity event channel.
///
/// The channel MUST stay bounded: the entity drains it from the single TDMA thread, so an
/// unbounded queue lets a remote core (or an on-path attacker when `tls = false`) stream
/// frames faster than one tick can drain and grow it until the box runs out of memory.
/// Sized for roughly a second of worst-case traffic — the entity drains MAX_EVENTS_PER_TICK
/// events per timeslot (see `entity.rs`), so it empties far faster than that.
pub const BREW_EVENT_CHANNEL_CAPACITY: usize = 512;

/// How long a *signalling* event may wait for room on a full event channel before being
/// dropped. Blocking here is deliberate: it stops us reading the socket, which is what
/// applies backpressure to the peer. Bounded so the worker still reaches its heartbeat.
const EVENT_SEND_BACKPRESSURE: Duration = Duration::from_millis(100);

/// Minimum spacing between "voice dropped" warnings — the condition is per-frame, the log
/// must not become the next flood.
const VOICE_DROP_WARN_INTERVAL: Duration = Duration::from_secs(5);

/// Events the Brew worker sends to the BrewEntity
#[derive(Debug)]
pub enum BrewEvent {
    /// Successfully connected to TetraPack server
    Connected { server_version: u8 },
    /// Brew protocol version detected from incoming message length (mnemonic presence)
    VersionDetected { version: u8 },

    /// Disconnected (with reason)
    Disconnected(String),

    /// Group call started
    GroupCallStart {
        uuid: Uuid,
        source_issi: u32,
        dest_gssi: u32,
        priority: u8,
        service: u16,
    },

    /// Group call ended
    GroupCallEnd { uuid: Uuid, cause: u8 },

    /// Voice frame received (ACELP traffic)
    VoiceFrame { uuid: Uuid, length_bits: u16, data: Vec<u8> },

    /// Subscriber event received
    SubscriberEvent { msg_type: u8, issi: u32, groups: Vec<u32> },

    /// SDS transfer received (SHORT_TRANSFER + SDS_TRANSFER combined)
    SdsTransfer {
        uuid: Uuid,
        source: u32,
        destination: u32,
        data: Vec<u8>,
        length_bits: u16,
    },

    /// SDS report received
    SdsReport { uuid: Uuid, status: u8 },

    // ── Circuit / individual call events ──────────────────────────
    /// TetraPack initiates a circuit call to a local MS (inbound SETUP_REQUEST)
    CircuitSetupRequest {
        uuid: Uuid,
        call: super::protocol::BrewCircularCall,
    },

    /// TetraPack accepted our outbound circuit call (SETUP_ACCEPT)
    CircuitSetupAccept { uuid: Uuid },

    /// TetraPack rejected our outbound circuit call (SETUP_REJECT)
    CircuitSetupReject { uuid: Uuid, cause: u8 },

    /// Remote side is alerting/ringing (CALL_ALERT)
    CircuitCallAlert { uuid: Uuid },

    /// Remote side accepted the call and sent CONNECT_REQUEST
    CircuitConnectRequest {
        uuid: Uuid,
        call: super::protocol::BrewCircularCall,
    },

    /// TetraPack confirmed connect (CONNECT_CONFIRM)
    CircuitConnectConfirm { uuid: Uuid, grant: u8, permission: u8 },

    /// Network granted simplex floor to the local side.
    CircuitSimplexGranted { uuid: Uuid, grant: u8, permission: u8 },

    /// Network released simplex floor / returned to idle.
    CircuitSimplexIdle { uuid: Uuid, grant: u8, permission: u8 },

    /// Circuit call released (CALL_RELEASE, inbound)
    CircuitCallRelease { uuid: Uuid, cause: u8 },

    /// DTMF digits received from network
    CircuitDtmf { uuid: Uuid, length_bits: u16, data: Vec<u8> },

    /// A serving station asks this station (the target) to prepare an announced cell reselection
    /// (`SERVICE_HO_PREPARE` / `SERVICE_HO_FORWARD_REG`, relayed by the server)
    HandoverRequest(BrewHoRequest),

    /// Answer to a handover request this station sent (`SERVICE_HO_RESULT`)
    HandoverResult(BrewHoResult),

    /// A radio registered here registered on another station without a prepared handover
    /// (`SERVICE_MS_MOVED`, only from a server that offered `ms-moved`)
    MsMoved { issi: u32 },

    /// The server's answer to `RequestCallRestore` (`SERVICE_CALL_RESTORE`), or the worker's own
    /// "no call" when the server cannot move calls
    CallRestoreAnswer {
        issi: u32,
        peer: u32,
        call: Option<tetra_saps::control::call_control::NetworkRestoredCall>,
    },

    /// The server asks for the local individual call between `issi` (gone to another station)
    /// and `peer` (`SERVICE_CALL_HANDOFF`, only from a server that offered `call-handoff`)
    CallHandoffRequest { issi: u32, peer: u32 },

    /// Error from server
    ServerError { error_type: u8, data: Vec<u8> },
}

/// Commands the BrewEntity sends to the worker
#[derive(Debug)]
pub enum BrewCommand {
    /// Register a subscriber (ISSI)
    RegisterSubscriber { issi: u32 },

    /// Tell the server which cell of this station a just registered subscriber is on (only to a
    /// server that offered `ms-cell`)
    ReportMsCell { issi: u32, cell: CellId },

    /// Tell the server how a radio left this station (only to a server that offered
    /// `ms-reselection`)
    ReportReselection {
        issi: u32,
        reselection: tetra_saps::control::call_control::CellReselection,
    },

    /// Ask the server for the individual call `issi` restores here with `peer` (only a server
    /// that offered `call-restore`; otherwise answered "no call" at once)
    RequestCallRestore { issi: u32, peer: u32 },
    /// `issi` registered with a plain roaming location update: it has no call to restore
    /// (`SERVICE_CALL_NOT_RESTORED`, only to a server that moves calls)
    ReportRegisteredWithoutCall { issi: u32 },
    /// Answer a `CallHandoffRequest`: the call handed to the network, or `None`
    /// (`SERVICE_CALL_HANDOFF`, only to a server that offered `call-handoff`)
    SendCallHandoff {
        issi: u32,
        peer: u32,
        call: Option<tetra_saps::control::call_control::HandedOffCall>,
    },

    /// Deregister a subscriber (ISSI)
    DeregisterSubscriber { issi: u32 },

    /// Affiliate subscriber to groups
    AffiliateGroups { issi: u32, groups: Vec<u32> },

    /// Deaffiliate subscriber from groups
    DeaffiliateGroups { issi: u32, groups: Vec<u32> },

    /// Send GROUP_TX to TetraPack (local radio started transmitting on subscribed group)
    SendGroupTx {
        uuid: Uuid,
        source_issi: u32,
        dest_gssi: u32,
        priority: u8,
        service: u16,
    },

    /// Send a voice frame to TetraPack (ACELP data from UL)
    SendVoiceFrame { uuid: Uuid, length_bits: u16, data: Vec<u8> },

    /// Send GROUP_IDLE to TetraPack (transmission ended)
    SendGroupIdle { uuid: Uuid, cause: u8 },

    /// Send SDS to TetraPack (SHORT_TRANSFER + SDS_TRANSFER)
    SendSds {
        uuid: Uuid,
        source: u32,
        destination: u32,
        data: Vec<u8>,
        length_bits: u16,
    },

    /// Send SDS report to Brew (delivery acknowledgement)
    SendSdsReport { uuid: Uuid, status: u8 },

    // ── Circuit / individual call commands ────────────────────────
    /// CMCE → Brew: initiate a circuit call setup to TetraPack (outbound)
    SendSetupRequest {
        uuid: Uuid,
        call: super::protocol::BrewCircularCall,
    },

    /// CMCE → Brew: accept an inbound circuit call (BS is the called side)
    SendSetupAccept { uuid: Uuid },

    /// CMCE → Brew: reject an inbound circuit call
    SendSetupReject { uuid: Uuid, cause: u8 },

    /// CMCE → Brew: called MS is ringing
    SendCallAlert { uuid: Uuid },

    /// CMCE → Brew: called MS accepted the call
    SendConnectRequest {
        uuid: Uuid,
        call: super::protocol::BrewCircularCall,
    },

    /// CMCE → Brew: call confirmed and connected
    SendConnectConfirm { uuid: Uuid, grant: u8, permission: u8 },

    /// CMCE → Brew: local simplex side granted the floor.
    SendSimplexGranted { uuid: Uuid, grant: u8, permission: u8 },

    /// CMCE → Brew: local simplex side released the floor.
    SendSimplexIdle { uuid: Uuid, grant: u8, permission: u8 },

    /// CMCE → Brew: release/terminate a circuit call
    SendCallRelease { uuid: Uuid, cause: u8 },

    /// CMCE → Brew: forward DTMF digits from MS
    SendDtmf { uuid: Uuid, length_bits: u16, data: Vec<u8> },

    /// MM → Brew: send RSSI measurement for an MS to the Brew server (Service 0xf4)
    SendRssiUpdate { issi: u32, rssi_dbfs: f32 },

    /// Answer a handover request the server relayed to this station (only to a server that
    /// offered `handover-v1`)
    SendHandoverResult(BrewHoResult),

    /// Ask the station serving a neighbour cell to prepare an MS's arrival (serving side). To a
    /// server without `handover-v1` nothing is sent; the worker answers "no target" itself.
    SendHandoverRequest(BrewHoRequest),

    /// Disconnect gracefully
    Disconnect,
}

/// Offer one event to the bounded entity channel. Returns the event back on failure.
///
/// Voice never waits: it is lossy by nature and a stalled entity must not stall the socket
/// reader. Signalling waits up to `backpressure` for room — that pause is the point, it stops
/// us draining the socket and lets TCP push back on the peer instead of us buffering for it.
fn offer_event(sender: &Sender<BrewEvent>, event: BrewEvent, backpressure: Duration) -> Result<(), BrewEvent> {
    if matches!(event, BrewEvent::VoiceFrame { .. }) {
        return sender.try_send(event).map_err(|e| e.into_inner());
    }
    sender.send_timeout(event, backpressure).map_err(|e| e.into_inner())
}

// ─── Worker ───────────────────────────────────────────────────────

/// SERVICE_BTS_INFO announcing every cell of this station (one Brew connection serves them all),
/// or `None` when the server did not offer the `bts-info` extension: TetraPack and BrandMeister
/// never get it. A cell whose frequency offset has no band-plan code is left out.
fn bts_info_message(config: &StackConfig, server_extensions: &[String]) -> Option<Vec<u8>> {
    if !server_extensions.iter().any(|e| e == BREW_EXT_BTS_INFO) {
        return None;
    }
    let directory = server_extensions.iter().any(|e| e == BREW_EXT_CELL_DIRECTORY);
    let cells: Vec<BrewBtsCell> = config
        .cells()
        .into_iter()
        .filter_map(|(id, cell, _)| {
            let carrier_ext = tetra_config::bluestation::carrier_band_plan(cell)?;
            let mut entry = BrewBtsCell { cell: id.0, carrier: cell.main_carrier, carrier_ext, location_area: cell.location_area, ..Default::default() };
            if directory {
                // What the cell broadcasts, for the other stations' neighbour lists.
                broadcast_values(config, cell, carrier_ext, &mut entry);
            }
            Some(entry)
        })
        .collect();
    let mut capabilities: Vec<&str> = Vec::new();
    if directory {
        capabilities.push(BREW_EXT_CELL_DIRECTORY);
    }
    if handles_handover(config, server_extensions) {
        capabilities.push(BREW_EXT_HANDOVER);
        if server_extensions.iter().any(|e| e == BREW_EXT_MS_MOVED) {
            capabilities.push(BREW_EXT_MS_MOVED);
        }
        if server_extensions.iter().any(|e| e == BREW_EXT_CALL_RESTORE) {
            capabilities.push(BREW_EXT_CALL_RESTORE);
        }
        if hands_off_calls(config, server_extensions) {
            capabilities.push(BREW_EXT_CALL_HANDOFF);
        }
    }
    Some(build_service_bts_info(config.net.mcc, config.net.mnc, &cells, &capabilities))
}

/// The optional `SERVICE_BTS_INFO` fields of `cell`: MS_TXPWR_MAX_CELL (code 1-7 = 15-45 dBm,
/// table 18.57; 0 is reserved and left out), RXLEV_ACCESS_MIN, the BS service details as broadcast
/// (system wide services while the network link is configured, as the SYSINFO sends them) and the
/// neighbour list with siblings. An element a neighbour entry leaves out is the serving cell's own
/// (TS 100 392-2 table 18.64 notes 1 and 2), so the network, band plan and LA are filled in.
fn broadcast_values(config: &StackConfig, cell: &tetra_config::bluestation::CfgCellInfo, carrier_ext: u16, entry: &mut BrewBtsCell) {
    entry.ms_txpwr_max_dbm = (1..=7).contains(&cell.ms_txpwr_max_cell).then(|| 10 + 5 * cell.ms_txpwr_max_cell);
    entry.rxlev_access_min_dbm = Some(cell.rxlev_access_min_dbm);
    entry.service_details = Some(vec![
        ("registration", cell.registration),
        ("deregistration", cell.deregistration),
        ("priority_cell", cell.priority_cell),
        ("no_minimum_mode", cell.no_minimum_mode),
        ("migration", cell.migration),
        ("system_wide_services", cell.system_wide_services || config.has_network_link()),
        ("voice_service", cell.voice_service),
        ("circuit_mode_data_service", cell.circuit_mode_data_service),
        ("sndcp_service", cell.sndcp_service),
        ("aie_service", cell.aie_service),
        ("advanced_link", cell.advanced_link),
    ]);
    entry.neighbours = Some(
        cell.neighbor_cells_ca
            .iter()
            .map(|n| BrewDirectoryNeighbour {
                mcc: n.mcc.unwrap_or(config.net.mcc),
                mnc: n.mnc.unwrap_or(config.net.mnc),
                carrier: n.main_carrier_number,
                carrier_ext: n.main_carrier_number_extension.unwrap_or(carrier_ext),
                location_area: Some(n.location_area.unwrap_or(cell.location_area)),
            })
            .collect(),
    );
}

/// This station takes part in announced reselection with other stations: the server relays the
/// requests (`handover-v1` offered). A linked multi-cell station too: its site switch hands each
/// request to the cell of the target carrier and each answer back to the asking cell (between its
/// own cells it never asks the server).
fn handles_handover(_config: &StackConfig, server_extensions: &[String]) -> bool {
    server_extensions.iter().any(|e| e == BREW_EXT_HANDOVER)
}

/// This station restores individual calls of radios that come from another station: it takes
/// part in handover and the server moves calls (`call-restore`).
fn restores_calls(config: &StackConfig, server_extensions: &[String]) -> bool {
    handles_handover(config, server_extensions) && server_extensions.iter().any(|e| e == BREW_EXT_CALL_RESTORE)
}

/// This station hands local individual calls to the network and joins network calls of two of
/// its radios locally (`call-handoff`): it restores calls and the server offers the extension.
/// Not on a multi-cell station yet: its site switch does not route the handoff to a cell.
pub(crate) fn hands_off_calls(config: &StackConfig, server_extensions: &[String]) -> bool {
    !config.is_site_linked()
        && restores_calls(config, server_extensions)
        && server_extensions.iter().any(|e| e == BREW_EXT_CALL_HANDOFF)
}

/// SERVICE_MS_CELL placing `issi` on this station's cell `cell`, or `None` when the server did not
/// offer the `ms-cell` extension (TetraPack and BrandMeister never get it), or the cell is unknown
/// or has no band-plan code.
fn ms_cell_message(config: &StackConfig, server_extensions: &[String], issi: u32, cell: CellId) -> Option<Vec<u8>> {
    if !server_extensions.iter().any(|e| e == BREW_EXT_MS_CELL) {
        return None;
    }
    let (_, info, _) = config.cells().into_iter().find(|(id, _, _)| *id == cell)?;
    Some(build_service_ms_cell(
        issi,
        info.main_carrier,
        tetra_config::bluestation::carrier_band_plan(info)?,
    ))
}

/// Pending SDS header data (from CALL_STATE_SHORT_TRANSFER), awaiting matching FRAME_TYPE_SDS_TRANSFER
#[derive(Debug)]
struct PendingSds {
    source: u32,
    destination: u32,
    received_at: Instant,
}

/// Brew protocol worker, generic over the network transport.
///
/// Runs in a separate thread. Communicates with [`super::entity::BrewEntity`] via
/// crossbeam channels ([`BrewEvent`] and [`BrewCommand`]).
pub struct BrewWorker<T: NetworkTransport> {
    config: SharedConfig,
    brew_config: CfgBrew,
    /// Network transport (WebSocket, QUIC, TCP, …)
    transport: T,
    /// Send events to the BrewEntity
    event_sender: Sender<BrewEvent>,
    /// Receive commands from the BrewEntity
    command_receiver: Receiver<BrewCommand>,
    /// Registered subscribers and their affiliated groups (tracked from commands)
    subscriber_groups: HashMap<u32, HashSet<u32>>,
    /// Pending SDS transfers keyed by UUID, awaiting matching SDS_TRANSFER frame
    pending_sds: HashMap<Uuid, PendingSds>,
    /// Voice frames dropped because the entity channel was full, since the last warning
    voice_dropped: u64,
    /// When we last warned about dropped voice
    last_voice_drop_warn: Option<Instant>,
}

impl<T: NetworkTransport> BrewWorker<T> {
    pub fn new(config: SharedConfig, event_sender: Sender<BrewEvent>, command_receiver: Receiver<BrewCommand>, transport: T) -> Self {
        let brew_config = config.config().brew.clone().unwrap(); // Never fails
        Self {
            config,
            brew_config,
            transport,
            event_sender,
            command_receiver,
            subscriber_groups: HashMap::new(),
            pending_sds: HashMap::new(),
            voice_dropped: 0,
            last_voice_drop_warn: None,
        }
    }

    /// Hand an event to the entity over the bounded channel.
    ///
    /// Voice is lossy — a dropped ACELP frame is a click the jitter buffer hides — so it is
    /// discarded immediately when the entity is behind. Signalling is not lossy: it waits a
    /// short, bounded moment for room (which stops us draining the socket and pushes back on
    /// the peer) and is only dropped if the entity is still stuck after that.
    fn send_event(&mut self, event: BrewEvent) {
        let lossy = matches!(event, BrewEvent::VoiceFrame { .. });
        if offer_event(&self.event_sender, event, EVENT_SEND_BACKPRESSURE).is_err() {
            if lossy {
                self.voice_dropped += 1;
                let due = self
                    .last_voice_drop_warn
                    .is_none_or(|last| last.elapsed() >= VOICE_DROP_WARN_INTERVAL);
                if due {
                    tracing::warn!(
                        "BrewWorker: entity event channel full — dropped {} voice frames (core sending faster than the TDMA tick drains)",
                        self.voice_dropped
                    );
                    self.voice_dropped = 0;
                    self.last_voice_drop_warn = Some(Instant::now());
                }
            } else {
                tracing::error!("BrewWorker: entity event channel still full after backpressure — dropped a signalling event");
            }
        }
    }

    /// Main worker entry point — runs until disconnect or fatal error
    pub fn run(&mut self) {
        tracing::info!("BrewWorker: starting");

        loop {
            // A (re)connection to the core starts with a clean registration slate: the core may have
            // restarted while we were disconnected and no longer knows any of our subscribers.
            // Clearing this map makes the post-reconnect resync (BrewEntity::resync_subscribers) emit
            // REGISTER — not REREGISTER — for every subscriber, so a REREGISTER-for-unknown is never
            // sent to a fresh core (which can leave local MS unregistered until a power-cycle). The
            // entity re-drives all affiliations right after Connected, so no group state is lost.
            self.subscriber_groups.clear();

            // Attempt connection via transport
            match self.transport.connect() {
                Ok(()) => {
                    tracing::info!("BrewWorker: transport connected");
                    let server_version = self.transport.server_brew_version();
                    {
                        let mut state = self.config.state_write();
                        state.brew_server_extensions = self.transport.server_brew_extensions().to_vec();
                        // A new list comes after the announcement, if the server offers one.
                        state.brew_cell_directory = None;
                    }
                    self.send_event(BrewEvent::Connected { server_version });
                    self.announce_cells();
                }
                Err(e) => {
                    tracing::error!(
                        "BrewWorker: connection error: {}, reconnecting in {:?}",
                        e,
                        self.brew_config.reconnect_delay
                    );
                    self.send_event(BrewEvent::Disconnected(e.to_string()));
                    std::thread::sleep(self.brew_config.reconnect_delay);
                    continue;
                }
            }

            // Run the message loop until error or clean shutdown
            match self.message_loop() {
                Ok(()) => {
                    tracing::info!("BrewWorker: connection closed normally");
                    break;
                }
                Err(e) => {
                    tracing::error!(
                        "BrewWorker: connection error: {}, reconnecting in {:?}",
                        e,
                        self.brew_config.reconnect_delay
                    );
                    self.send_event(BrewEvent::Disconnected(e));
                    std::thread::sleep(self.brew_config.reconnect_delay);
                }
            }
        }
    }

    /// Tell the server which cells this station serves, if it understands that (see
    /// [`bts_info_message`]).
    fn announce_cells(&mut self) {
        let Some(msg) = bts_info_message(&self.config.config(), self.transport.server_brew_extensions()) else {
            return;
        };
        if let Err(e) = self.transport.send_reliable(&msg) {
            tracing::error!("BrewWorker: failed to send BTS info: {}", e);
        } else {
            tracing::info!("BrewWorker: announced cells to the server (BTS info)");
        }
    }

    /// Graceful teardown: DEAFFILIATE → DEREGISTER → transport disconnect
    fn graceful_teardown(&mut self) {
        for (issi, groups) in &self.subscriber_groups {
            if !groups.is_empty() {
                let mut group_list: Vec<u32> = groups.iter().copied().collect();
                group_list.sort_unstable();
                let deaff_msg = build_subscriber_deaffiliate(*issi, &group_list);
                if let Err(e) = self.transport.send_reliable(&deaff_msg) {
                    tracing::error!("BrewWorker: failed to send deaffiliation: {}", e);
                } else {
                    tracing::info!("BrewWorker: deaffiliated issi={} groups={:?}", issi, group_list);
                }
            }

            let dereg_msg = build_subscriber_deregister(*issi);
            if let Err(e) = self.transport.send_reliable(&dereg_msg) {
                tracing::error!("BrewWorker: failed to send deregistration: {}", e);
            } else {
                tracing::info!("BrewWorker: deregistered ISSI {}", issi);
            }
        }
        self.transport.disconnect();
    }

    /// Main message processing loop (transport-agnostic)
    fn message_loop(&mut self) -> Result<(), String> {
        loop {
            let now = Instant::now();

            // Expire stale pending SDS entries (SHORT_TRANSFER without matching SDS_TRANSFER)
            self.pending_sds.retain(|uuid, pending| {
                let age = now.duration_since(pending.received_at);
                if age > Duration::from_secs(30) {
                    tracing::warn!("BrewWorker: expiring stale pending SDS uuid={}", uuid);
                    false
                } else {
                    true
                }
            });

            // ── Receive incoming messages from transport ──
            let messages = self.transport.receive_reliable();
            for msg in messages {
                self.handle_incoming_binary(&msg.payload);
            }

            // Check if transport is still connected (may have been dropped during receive)
            if !self.transport.is_connected() {
                return Err("transport disconnected".to_string());
            }

            // ── Check for commands from the BrewEntity ──
            loop {
                let cmd = match self.command_receiver.try_recv() {
                    Ok(cmd) => cmd,
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        // Entity was dropped — do graceful teardown
                        tracing::info!("BrewWorker: command channel closed, performing graceful teardown");
                        self.graceful_teardown();
                        return Ok(());
                    }
                };
                match cmd {
                    BrewCommand::RegisterSubscriber { issi } => {
                        let already_registered = self.subscriber_groups.contains_key(&issi);
                        self.subscriber_groups.entry(issi).or_insert_with(HashSet::new);
                        let msg = if already_registered {
                            build_subscriber_reregister(issi)
                        } else {
                            build_subscriber_register(issi, &[])
                        };
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send registration: {}", e);
                        } else {
                            tracing::debug!(
                                "BrewWorker: sent {} issi={}",
                                if already_registered { "REREGISTER" } else { "REGISTER" },
                                issi
                            );
                        }
                    }
                    BrewCommand::DeregisterSubscriber { issi } => {
                        self.subscriber_groups.remove(&issi);
                        let msg = build_subscriber_deregister(issi);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send deregistration: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent DEREGISTER issi={}", issi);
                        }
                    }
                    BrewCommand::AffiliateGroups { issi, groups } => {
                        let entry = self.subscriber_groups.entry(issi).or_insert_with(HashSet::new);
                        for gssi in &groups {
                            entry.insert(*gssi);
                        }
                        let msg = build_subscriber_affiliate(issi, &groups);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send affiliation: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent AFFILIATE issi={} groups={:?}", issi, groups);
                        }
                    }
                    BrewCommand::DeaffiliateGroups { issi, groups } => {
                        if let Some(entry) = self.subscriber_groups.get_mut(&issi) {
                            for gssi in &groups {
                                entry.remove(gssi);
                            }
                        }
                        let msg = build_subscriber_deaffiliate(issi, &groups);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send deaffiliation: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent DEAFFILIATE issi={} groups={:?}", issi, groups);
                        }
                    }
                    BrewCommand::SendGroupTx {
                        uuid,
                        source_issi,
                        dest_gssi,
                        priority,
                        service,
                    } => {
                        let msg = build_group_tx(&uuid, source_issi, dest_gssi, priority, service, None);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send GROUP_TX: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent GROUP_TX uuid={} src={} dst={}", uuid, source_issi, dest_gssi);
                        }
                    }
                    BrewCommand::SendVoiceFrame { uuid, length_bits, data } => {
                        let msg = build_voice_frame(&uuid, length_bits, &data);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send voice frame: {}", e);
                        }
                    }
                    BrewCommand::SendGroupIdle { uuid, cause } => {
                        let msg = build_group_idle(&uuid, cause);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send GROUP_IDLE: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent GROUP_IDLE uuid={} cause={}", uuid, cause);
                        }
                    }
                    BrewCommand::SendSds {
                        uuid,
                        source,
                        destination,
                        data,
                        length_bits,
                    } => {
                        if !net_brew::feature_sds_enabled(&self.config) {
                            tracing::warn!("BrewWorker: ignoring SendSds command because SDS over Brew is disabled in config");
                            continue;
                        }

                        // Send SHORT_TRANSFER first (header with source/dest)
                        let short_msg = build_short_transfer(&uuid, source, destination);
                        if let Err(e) = self.transport.send_reliable(&short_msg) {
                            tracing::error!("BrewWorker: failed to send SHORT_TRANSFER: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent SHORT_TRANSFER uuid={} src={} dst={}", uuid, source, destination);
                            // Then send SDS_TRANSFER with the payload
                            let sds_msg = build_sds_frame(&uuid, length_bits, &data);
                            if let Err(e) = self.transport.send_reliable(&sds_msg) {
                                tracing::error!("BrewWorker: failed to send SDS_TRANSFER: {}", e);
                            } else {
                                tracing::debug!("BrewWorker: sent SDS_TRANSFER uuid={} {} bytes", uuid, data.len());
                            }
                        }
                    }
                    BrewCommand::SendSdsReport { uuid, status } => {
                        if !net_brew::feature_sds_enabled(&self.config) {
                            tracing::warn!("BrewWorker: ignoring SendSdsReport command because SDS over Brew is disabled in config");
                            continue;
                        }

                        let msg = build_sds_report(&uuid, status);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::warn!("BrewWorker: failed to send SDS_REPORT: {}", e);
                        } else {
                            tracing::debug!("BrewWorker: sent SDS_REPORT uuid={} status={}", uuid, status);
                        }
                    }
                    BrewCommand::SendSetupRequest { uuid, call } => {
                        let data = build_setup_request(&uuid, &call);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send SETUP_REQUEST: {}", e);
                        } else {
                            tracing::debug!("Brew: sent SETUP_REQUEST uuid={}", uuid);
                        }
                    }
                    BrewCommand::SendSetupAccept { uuid } => {
                        let data = build_setup_accept(&uuid);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send SETUP_ACCEPT: {}", e);
                        } else {
                            tracing::debug!("Brew: sent SETUP_ACCEPT uuid={}", uuid);
                        }
                    }
                    BrewCommand::SendSetupReject { uuid, cause } => {
                        let data = build_setup_reject(&uuid, cause);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send SETUP_REJECT: {}", e);
                        } else {
                            tracing::debug!("Brew: sent SETUP_REJECT uuid={} cause={}", uuid, cause);
                        }
                    }
                    BrewCommand::SendCallAlert { uuid } => {
                        let data = build_call_alert(&uuid);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send CALL_ALERT: {}", e);
                        } else {
                            tracing::debug!("Brew: sent CALL_ALERT uuid={}", uuid);
                        }
                    }
                    BrewCommand::SendConnectRequest { uuid, call } => {
                        let data = build_connect_request(&uuid, &call);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send CONNECT_REQUEST: {}", e);
                        } else {
                            tracing::debug!("Brew: sent CONNECT_REQUEST uuid={}", uuid);
                        }
                    }
                    BrewCommand::SendConnectConfirm { uuid, grant, permission } => {
                        let data = build_connect_confirm(&uuid, grant, permission);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send CONNECT_CONFIRM: {}", e);
                        } else {
                            tracing::debug!("Brew: sent CONNECT_CONFIRM uuid={} grant={} perm={}", uuid, grant, permission);
                        }
                    }
                    BrewCommand::SendSimplexGranted { uuid, grant, permission } => {
                        let data = build_simplex_granted(&uuid, grant, permission);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send SIMPLEX_GRANTED: {}", e);
                        } else {
                            tracing::debug!("Brew: sent SIMPLEX_GRANTED uuid={} grant={} perm={}", uuid, grant, permission);
                        }
                    }
                    BrewCommand::SendSimplexIdle { uuid, grant, permission } => {
                        let data = build_simplex_idle(&uuid, grant, permission);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send SIMPLEX_IDLE: {}", e);
                        } else {
                            tracing::debug!("Brew: sent SIMPLEX_IDLE uuid={} grant={} perm={}", uuid, grant, permission);
                        }
                    }
                    BrewCommand::SendCallRelease { uuid, cause } => {
                        let data = build_call_release(&uuid, cause);
                        if let Err(e) = self.transport.send_reliable(&data) {
                            tracing::error!("BrewWorker: failed to send CALL_RELEASE: {}", e);
                        } else {
                            tracing::debug!("Brew: sent CALL_RELEASE uuid={} cause={}", uuid, cause);
                        }
                    }
                    BrewCommand::SendDtmf { uuid, length_bits, data } => {
                        let msg = build_dtmf_frame(&uuid, length_bits, &data);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send DTMF: {}", e);
                        } else {
                            tracing::debug!("Brew: sent DTMF uuid={} bits={}", uuid, length_bits);
                        }
                    }
                    BrewCommand::ReportMsCell { issi, cell } => {
                        let Some(msg) = ms_cell_message(&self.config.config(), self.transport.server_brew_extensions(), issi, cell) else {
                            continue;
                        };
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send MS cell for ISSI {}: {}", issi, e);
                        } else {
                            tracing::debug!("BrewWorker: sent MS cell issi={} cell={}", issi, cell.0);
                        }
                    }
                    BrewCommand::ReportReselection { issi, reselection } => {
                        if !self.transport.server_brew_extensions().iter().any(|e| e == BREW_EXT_MS_RESELECTION) {
                            continue;
                        }
                        let msg = build_service_ms_reselection(issi, reselection);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send MS reselection for ISSI {}: {}", issi, e);
                        } else {
                            tracing::debug!("BrewWorker: sent MS reselection issi={} type={}", issi, reselection_name(reselection));
                        }
                    }
                    BrewCommand::SendRssiUpdate { issi, rssi_dbfs } => {
                        let msg = build_service_rssi(issi, rssi_dbfs);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send RSSI update for ISSI {}: {}", issi, e);
                        } else {
                            tracing::debug!("BrewWorker: sent RSSI issi={} rssi={:.1}dBFS", issi, rssi_dbfs);
                        }
                    }
                    BrewCommand::RequestCallRestore { issi, peer } => {
                        if !restores_calls(&self.config.config(), self.transport.server_brew_extensions()) {
                            self.send_event(BrewEvent::CallRestoreAnswer { issi, peer, call: None });
                            continue;
                        }
                        let msg = build_service_call_restore(issi, peer);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send call restore request for ISSI {}: {}", issi, e);
                            self.send_event(BrewEvent::CallRestoreAnswer { issi, peer, call: None });
                        } else {
                            tracing::info!("BrewWorker: asked the server for ISSI {}'s call with peer {}", issi, peer);
                        }
                    }
                    BrewCommand::SendCallHandoff { issi, peer, call } => {
                        if !hands_off_calls(&self.config.config(), self.transport.server_brew_extensions()) {
                            continue;
                        }
                        let msg = build_service_call_handoff(issi, peer, call.as_ref());
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to answer the call handoff for ISSI {}: {}", issi, e);
                        } else {
                            tracing::info!("BrewWorker: call handoff answer issi={} peer={} call={:?}", issi, peer, call);
                        }
                    }
                    BrewCommand::ReportRegisteredWithoutCall { issi } => {
                        if !restores_calls(&self.config.config(), self.transport.server_brew_extensions()) {
                            continue;
                        }
                        let msg = build_service_call_not_restored(issi);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to report ISSI {} registered without a call: {}", issi, e);
                        } else {
                            tracing::debug!("BrewWorker: ISSI {} registered by roaming, no call to restore", issi);
                        }
                    }
                    BrewCommand::SendHandoverResult(result) => {
                        if !handles_handover(&self.config.config(), self.transport.server_brew_extensions()) {
                            continue;
                        }
                        let msg = build_service_ho_result(&result);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send handover result for ISSI {}: {}", result.issi, e);
                        } else {
                            tracing::info!(
                                "BrewWorker: sent handover result issi={} transaction={} status={}",
                                result.issi,
                                result.transaction_id,
                                result.status
                            );
                        }
                    }
                    BrewCommand::SendHandoverRequest(req) => {
                        if !handles_handover(&self.config.config(), self.transport.server_brew_extensions()) {
                            self.send_event(BrewEvent::HandoverResult(BrewHoResult {
                                transaction_id: req.transaction_id,
                                issi: req.issi,
                                status: BREW_HO_STATUS_NO_TARGET,
                                reason: Some("not_capable".to_string()),
                                sdu: None,
                                channel: None,
                            }));
                            continue;
                        }
                        let msg = build_service_ho_request(&req);
                        if let Err(e) = self.transport.send_reliable(&msg) {
                            tracing::error!("BrewWorker: failed to send handover request for ISSI {}: {}", req.issi, e);
                        } else {
                            tracing::info!(
                                "BrewWorker: sent handover request issi={} transaction={} target_carrier={}",
                                req.issi,
                                req.transaction_id,
                                req.target_carrier
                            );
                        }
                    }
                    BrewCommand::Disconnect => {
                        self.graceful_teardown();
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Parse an incoming binary Brew message and forward as event
    fn handle_incoming_binary(&mut self, data: &[u8]) {
        match parse_brew_message(data) {
            Ok(msg) => match msg {
                BrewMessage::CallControl(cc) => self.handle_call_control(cc),
                BrewMessage::Frame(frame) => self.handle_frame(frame),
                BrewMessage::Subscriber(sub) => {
                    tracing::debug!("BrewWorker: subscriber event type={}", sub.msg_type);
                    // TODO FIXME we could check whether this call is indeed a brew ssi here
                    self.send_event(BrewEvent::SubscriberEvent {
                        msg_type: sub.msg_type,
                        issi: sub.number,
                        groups: sub.groups,
                    });
                }
                BrewMessage::Error(err) => {
                    // Log the payload, not just its length: Brew echoes the offending request in
                    // the error (e.g. f1 03 = CALL_CONTROL/GROUP_IDLE + the 16-byte call UUID + 00),
                    // which is what you need to tie a rejection to a specific call (#48). Hex is the
                    // primary view; the lossy text is handy when the payload is actually a string.
                    tracing::warn!(
                        "BrewWorker: server error type={}: {} bytes: {:?} | hex={:02x?}",
                        err.error_type,
                        err.data.len(),
                        String::from_utf8_lossy(&err.data),
                        err.data
                    );
                    // TODO FIXME we could check whether this call is indeed a brew ssi here
                    self.send_event(BrewEvent::ServerError {
                        error_type: err.error_type,
                        data: err.data,
                    });
                }
                BrewMessage::Service(svc) => self.handle_service(svc),
            },
            Err(e) => {
                tracing::warn!("BrewWorker: failed to parse message ({} bytes): {}", data.len(), e);
            }
        }
    }

    /// Handle a service message. Only the handover messages are acted on, and only when this
    /// station announced `handover-v1` (the server sends them to no one else).
    fn handle_service(&mut self, svc: BrewServiceMessage) {
        match svc.service_type {
            BREW_SERVICE_HO_PREPARE | BREW_SERVICE_HO_FORWARD_REG | BREW_SERVICE_HO_RESULT
                if handles_handover(&self.config.config(), self.transport.server_brew_extensions()) =>
            {
                let parsed = if svc.service_type == BREW_SERVICE_HO_RESULT {
                    parse_ho_result(&svc.json_data).map(BrewEvent::HandoverResult)
                } else {
                    parse_ho_request(svc.service_type, &svc.json_data).map(BrewEvent::HandoverRequest)
                };
                match parsed {
                    Ok(event) => self.send_event(event),
                    Err(e) => tracing::warn!("BrewWorker: malformed handover message type={:#x}: {}", svc.service_type, e),
                }
            }
            BREW_SERVICE_CALL_RESTORE if restores_calls(&self.config.config(), self.transport.server_brew_extensions()) => {
                match parse_call_restore_answer(&svc.json_data) {
                    Ok((issi, peer, call)) => {
                        tracing::info!("BrewWorker: call restore answer issi={} peer={} call={:?}", issi, peer, call);
                        self.send_event(BrewEvent::CallRestoreAnswer { issi, peer, call });
                    }
                    Err(e) => tracing::warn!("BrewWorker: malformed call restore answer: {}", e),
                }
            }
            BREW_SERVICE_CALL_HANDOFF if hands_off_calls(&self.config.config(), self.transport.server_brew_extensions()) => {
                match parse_call_handoff_request(&svc.json_data) {
                    Ok((issi, peer)) => {
                        tracing::info!("BrewWorker: the server asks for the local call of ISSI {} with peer {}", issi, peer);
                        self.send_event(BrewEvent::CallHandoffRequest { issi, peer });
                    }
                    Err(e) => tracing::warn!("BrewWorker: malformed call handoff request: {}", e),
                }
            }
            BREW_SERVICE_MS_MOVED
                if handles_handover(&self.config.config(), self.transport.server_brew_extensions())
                    && self.transport.server_brew_extensions().iter().any(|e| e == BREW_EXT_MS_MOVED) =>
            {
                match parse_ms_moved(&svc.json_data) {
                    Ok(issi) => self.send_event(BrewEvent::MsMoved { issi }),
                    Err(e) => tracing::warn!("BrewWorker: malformed MS moved message: {}", e),
                }
            }
            BREW_SERVICE_CELL_DIRECTORY if self.transport.server_brew_extensions().iter().any(|e| e == BREW_EXT_CELL_DIRECTORY) => {
                match parse_cell_directory(&svc.json_data) {
                    Ok(cells) => {
                        tracing::info!("BrewWorker: cell directory from the server: {} cells", cells.len());
                        self.config.state_write().brew_cell_directory = Some(cells);
                    }
                    Err(e) => tracing::warn!("BrewWorker: malformed cell directory: {}", e),
                }
            }
            _ => tracing::debug!("BrewWorker: service type={}: {}", svc.service_type, svc.json_data),
        }
    }

    /// Handle a parsed call control message
    fn handle_call_control(&mut self, cc: BrewCallControlMessage) {
        match cc.call_state {
            CALL_STATE_GROUP_TX => {
                if let BrewCallPayload::GroupTransmission(gt) = cc.payload {
                    tracing::info!(
                        "BrewWorker: GROUP_TX uuid={} src={} dst={} prio={} service={} mnemonic={}",
                        cc.identifier,
                        gt.source,
                        gt.destination,
                        gt.priority,
                        gt.service,
                        gt.mnemonic.is_some()
                    );
                    // Detect server version from mnemonic presence (v1 includes 34-byte mnemonic)
                    if gt.mnemonic.is_some() {
                        self.send_event(BrewEvent::VersionDetected { version: 1 });
                    }
                    // Inbound admission (FH-FEAT-032 R3): a Brew-originated group call must NOT be
                    // gated by the outbound-only `whitelisted_ssis`; only `local_ssi_ranges` reject it.
                    if !net_brew::is_brew_inbound_allowed(&self.config, gt.destination) {
                        tracing::warn!("BrewWorker: dropping GROUP_TX to inactive/local-only GSSI {}", gt.destination);
                        return;
                    };
                    self.send_event(BrewEvent::GroupCallStart {
                        uuid: cc.identifier,
                        source_issi: gt.source,
                        dest_gssi: gt.destination,
                        priority: gt.priority,
                        service: gt.service,
                    });
                }
            }
            CALL_STATE_GROUP_IDLE => {
                let cause = if let BrewCallPayload::Cause(c) = cc.payload { c } else { 0 };
                tracing::info!("BrewWorker: GROUP_IDLE uuid={} cause={}", cc.identifier, cause);
                // TODO FIXME we could check whether this call is indeed a brew call here
                self.send_event(BrewEvent::GroupCallEnd {
                    uuid: cc.identifier,
                    cause,
                });
            }

            CALL_STATE_SETUP_REQUEST => {
                if let BrewCallPayload::CircularCall(call) = cc.payload {
                    tracing::info!(
                        "BrewWorker: SETUP_REQUEST uuid={} src={} dst={} number='{}' duplex={}",
                        cc.identifier,
                        call.source,
                        call.destination,
                        call.number,
                        call.duplex
                    );
                    self.send_event(BrewEvent::CircuitSetupRequest { uuid: cc.identifier, call });
                }
            }
            CALL_STATE_SETUP_ACCEPT => {
                tracing::info!("BrewWorker: SETUP_ACCEPT uuid={}", cc.identifier);
                self.send_event(BrewEvent::CircuitSetupAccept { uuid: cc.identifier });
            }
            CALL_STATE_SETUP_REJECT => {
                let cause = if let BrewCallPayload::Cause(c) = cc.payload { c } else { 0 };
                tracing::info!("BrewWorker: SETUP_REJECT uuid={} cause={}", cc.identifier, cause);
                self.send_event(BrewEvent::CircuitSetupReject {
                    uuid: cc.identifier,
                    cause,
                });
            }
            CALL_STATE_CALL_ALERT => {
                tracing::info!("BrewWorker: CALL_ALERT uuid={}", cc.identifier);
                self.send_event(BrewEvent::CircuitCallAlert { uuid: cc.identifier });
            }
            CALL_STATE_CONNECT_REQUEST => {
                if let BrewCallPayload::CircularCall(call) = cc.payload {
                    tracing::info!(
                        "BrewWorker: CONNECT_REQUEST uuid={} src={} dst={} duplex={}",
                        cc.identifier,
                        call.source,
                        call.destination,
                        call.duplex
                    );
                    self.send_event(BrewEvent::CircuitConnectRequest { uuid: cc.identifier, call });
                }
            }
            CALL_STATE_CONNECT_CONFIRM => {
                let (grant, permission) = if let BrewCallPayload::CircularGrant(g) = cc.payload {
                    (g.grant, g.permission)
                } else {
                    (0, 0)
                };
                tracing::info!(
                    "BrewWorker: CONNECT_CONFIRM uuid={} grant={} perm={}",
                    cc.identifier,
                    grant,
                    permission
                );
                self.send_event(BrewEvent::CircuitConnectConfirm {
                    uuid: cc.identifier,
                    grant,
                    permission,
                });
            }
            CALL_STATE_SIMPLEX_GRANTED => {
                let (grant, permission) = if let BrewCallPayload::CircularGrant(g) = cc.payload {
                    (g.grant, g.permission)
                } else {
                    (0, 0)
                };
                tracing::info!(
                    "BrewWorker: SIMPLEX_GRANTED uuid={} grant={} perm={}",
                    cc.identifier,
                    grant,
                    permission
                );
                self.send_event(BrewEvent::CircuitSimplexGranted {
                    uuid: cc.identifier,
                    grant,
                    permission,
                });
            }
            CALL_STATE_SIMPLEX_IDLE => {
                let (grant, permission) = if let BrewCallPayload::CircularGrant(g) = cc.payload {
                    (g.grant, g.permission)
                } else {
                    (0, 0)
                };
                tracing::info!(
                    "BrewWorker: SIMPLEX_IDLE uuid={} grant={} perm={}",
                    cc.identifier,
                    grant,
                    permission
                );
                self.send_event(BrewEvent::CircuitSimplexIdle {
                    uuid: cc.identifier,
                    grant,
                    permission,
                });
            }
            CALL_STATE_CALL_RELEASE => {
                let cause = if let BrewCallPayload::Cause(c) = cc.payload { c } else { 0 };
                tracing::info!("BrewWorker: CALL_RELEASE uuid={} cause={}", cc.identifier, cause);
                // Send both events — entity will handle whichever is relevant
                self.send_event(BrewEvent::GroupCallEnd {
                    uuid: cc.identifier,
                    cause,
                });
                self.send_event(BrewEvent::CircuitCallRelease {
                    uuid: cc.identifier,
                    cause,
                });
            }
            CALL_STATE_SHORT_TRANSFER => {
                if let BrewCallPayload::ShortTransfer { source, destination } = cc.payload {
                    tracing::info!(
                        "BrewWorker: SHORT_TRANSFER uuid={} src={} dst={}",
                        cc.identifier,
                        source,
                        destination
                    );
                    // Stash for matching with upcoming SDS_TRANSFER frame
                    self.pending_sds.insert(
                        cc.identifier,
                        PendingSds {
                            source,
                            destination,
                            received_at: Instant::now(),
                        },
                    );
                }
            }
            state => {
                tracing::debug!("BrewWorker: unhandled call state {} uuid={}", state, cc.identifier);
            }
        }
    }

    /// Handle a parsed voice/data frame
    fn handle_frame(&mut self, frame: BrewFrameMessage) {
        match frame.frame_type {
            FRAME_TYPE_TRAFFIC_CHANNEL => {
                // Forward ACELP voice frame to entity
                // TODO FIXME we could check whether this call is indeed a brew call here
                self.send_event(BrewEvent::VoiceFrame {
                    uuid: frame.identifier,
                    length_bits: frame.length_bits,
                    data: frame.data,
                });
            }
            FRAME_TYPE_SDS_TRANSFER => {
                if !net_brew::feature_sds_enabled(&self.config) {
                    tracing::warn!("BrewWorker: ignoring incoming SDS_TRANSFER because SDS over Brew is disabled in config");
                    return;
                }

                if frame.length_bits > 2047 {
                    // TODO FIXME we could split into multiple SDS messages here
                    tracing::warn!(
                        "BrewWorker: ignoring SDS_TRANSFER with excessive length_bits={} ({} bytes)",
                        frame.length_bits,
                        frame.data.len()
                    );
                    return;
                }

                // Reject frames whose declared bit-length exceeds the actual payload:
                // length_bits and data are independent wire fields, and the downstream
                // D-SDS-DATA serializer indexes the payload by length_bits — an
                // over-claimed length would otherwise panic the base station (OOB).
                if (frame.length_bits as usize).div_ceil(8) > frame.data.len() {
                    tracing::warn!(
                        "BrewWorker: ignoring SDS_TRANSFER with length_bits={} exceeding payload of {} bytes",
                        frame.length_bits,
                        frame.data.len()
                    );
                    return;
                }

                // Match with pending SHORT_TRANSFER by UUID
                if let Some(pending) = self.pending_sds.remove(&frame.identifier) {
                    tracing::info!(
                        "BrewWorker: SDS_TRANSFER uuid={} src={} dst={} {} bytes",
                        frame.identifier,
                        pending.source,
                        pending.destination,
                        frame.data.len()
                    );
                    self.send_event(BrewEvent::SdsTransfer {
                        uuid: frame.identifier,
                        source: pending.source,
                        destination: pending.destination,
                        data: frame.data,
                        length_bits: frame.length_bits,
                    });
                } else {
                    tracing::warn!(
                        "BrewWorker: SDS_TRANSFER uuid={} without matching SHORT_TRANSFER, {} bytes",
                        frame.identifier,
                        frame.data.len()
                    );
                }
            }
            FRAME_TYPE_SDS_REPORT => {
                let status = if frame.data.is_empty() { 0 } else { frame.data[0] };
                tracing::debug!("BrewWorker: SDS_REPORT uuid={} status={}", frame.identifier, status);
                self.send_event(BrewEvent::SdsReport {
                    uuid: frame.identifier,
                    status,
                });
            }
            ft => {
                tracing::debug!("BrewWorker: unhandled frame type {} uuid={}", ft, frame.identifier);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::transports::mock::MockTransport;
    use crossbeam_channel::bounded;

    fn voice() -> BrewEvent {
        BrewEvent::VoiceFrame {
            uuid: Uuid::nil(),
            length_bits: 288,
            data: vec![0u8; 36],
        }
    }

    fn signalling() -> BrewEvent {
        BrewEvent::GroupCallEnd {
            uuid: Uuid::nil(),
            cause: 0,
        }
    }

    #[test]
    fn full_channel_drops_voice_instead_of_growing() {
        let (tx, rx) = bounded::<BrewEvent>(2);
        assert!(offer_event(&tx, voice(), Duration::ZERO).is_ok());
        assert!(offer_event(&tx, voice(), Duration::ZERO).is_ok());

        // Third frame has nowhere to go — it is dropped and the queue does NOT grow.
        assert!(offer_event(&tx, voice(), Duration::ZERO).is_err());
        assert_eq!(rx.len(), 2);
    }

    #[test]
    fn signalling_is_delivered_while_there_is_room() {
        let (tx, rx) = bounded::<BrewEvent>(1);
        assert!(offer_event(&tx, signalling(), Duration::ZERO).is_ok());
        // Full: with no backpressure window it is reported as undelivered rather than queued.
        assert!(offer_event(&tx, signalling(), Duration::ZERO).is_err());
        assert_eq!(rx.len(), 1);
    }

    const CONFIG: &str = r#"
config_version = "0.6"
stack_mode = "Bs"

[phy_io]
backend = "None"

[net_info]
mcc = 232
mnc = 5

[cell_info]
main_carrier = 1528
freq_band = 4
freq_offset = 0
duplex_spacing = 4
reverse_operation = false
location_area = 10

[brew]
host = "brew.example"
port = 3000
tls = false
username = 1
password = "x"
"#;

    fn config(extra: &str) -> SharedConfig {
        let cfg = tetra_config::bluestation::parsing::from_toml_str(&format!("{CONFIG}{extra}")).expect("test config parses");
        SharedConfig::from_parts(cfg, None)
    }

    fn json_of(msg: &[u8]) -> serde_json::Value {
        assert_eq!(&msg[..2], &[BREW_CLASS_SERVICE, BREW_SERVICE_BTS_INFO]);
        assert_eq!(msg.last(), Some(&0), "NULL-terminated");
        serde_json::from_slice(&msg[2..msg.len() - 1]).unwrap()
    }

    #[test]
    fn bts_info_lists_the_cell_with_its_absolute_band_plan() {
        let msg = bts_info_message(&config("").config(), &["bts-info".to_string()]).unwrap();
        // band 4, offset 0, duplex spacing 4, no reverse operation: (4 << 6) | (4 << 1)
        assert_eq!(
            json_of(&msg),
            serde_json::json!({
                "mcc": 232, "mnc": 5,
                "cells": [{ "cell": 0, "carrier": 1528, "carrier_ext": 264, "location_area": 10 }],
                "capabilities": []
            })
        );
    }

    #[test]
    fn bts_info_lists_every_cell_of_a_multi_cell_station() {
        let cfg = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        let msg = bts_info_message(&cfg.config(), &["bts-info".to_string()]).unwrap();
        let cells = json_of(&msg)["cells"].clone();
        assert_eq!(cells[0]["carrier"], 1528);
        assert_eq!(cells[1]["carrier"], 1530);
        assert_eq!(cells[1]["cell"], 3, "the [[cells]] id, not the position");
        assert_eq!(cells[1]["location_area"], 11);
        assert_eq!(cells[1]["carrier_ext"], 264);
    }

    #[test]
    fn ms_cell_names_the_cell_by_carrier_and_band_plan() {
        let cfg = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        let offered = ["bts-info".to_string(), "ms-cell".to_string()];
        let msg = ms_cell_message(&cfg.config(), &offered, 2320001, CellId(3)).unwrap();
        assert_eq!(&msg[..2], &[BREW_CLASS_SERVICE, BREW_SERVICE_MS_CELL]);
        assert_eq!(msg.last(), Some(&0), "NULL-terminated");
        let json: serde_json::Value = serde_json::from_slice(&msg[2..msg.len() - 1]).unwrap();
        assert_eq!(json, serde_json::json!({ "issi": 2320001, "carrier": 1530, "carrier_ext": 264 }));
        let primary = ms_cell_message(&cfg.config(), &offered, 7, CellId::PRIMARY).unwrap();
        assert!(String::from_utf8_lossy(&primary).contains("\"carrier\":1528"));
        assert!(ms_cell_message(&cfg.config(), &offered, 7, CellId(5)).is_none(), "no such cell");
    }

    #[test]
    fn ms_cell_only_for_a_server_that_offers_it() {
        let cfg = config("").config();
        assert!(
            ms_cell_message(&cfg, &[], 7, CellId::PRIMARY).is_none(),
            "TetraPack / BrandMeister offer no extensions"
        );
        assert!(
            ms_cell_message(&cfg, &["bts-info".to_string()], 7, CellId::PRIMARY).is_none(),
            "a server with bts-info only (milestone 2) does not get it"
        );
    }

    /// Runs the worker's message loop over `commands` (ending with a disconnect) and returns what
    /// it sent.
    fn run_commands(transport: MockTransport, commands: Vec<BrewCommand>) -> Vec<Vec<u8>> {
        let (event_tx, _event_rx) = bounded(16);
        let (command_tx, command_rx) = bounded(16);
        let mut worker = BrewWorker::new(config(""), event_tx, command_rx, transport);
        worker.transport.connect().unwrap();
        for c in commands {
            command_tx.send(c).unwrap();
        }
        command_tx.send(BrewCommand::Disconnect).unwrap();
        worker.message_loop().unwrap();
        worker.transport.sent_payloads().to_vec()
    }

    #[test]
    fn registration_is_followed_by_the_cell_only_where_offered() {
        let commands = || {
            vec![
                BrewCommand::RegisterSubscriber { issi: 7 },
                BrewCommand::ReportMsCell {
                    issi: 7,
                    cell: CellId::PRIMARY,
                },
            ]
        };
        let offered = run_commands(MockTransport::new().with_brew_extensions(&["bts-info", "ms-cell"]), commands());
        let kinds: Vec<(u8, u8)> = offered.iter().map(|p| (p[0], p[1])).collect();
        assert_eq!(kinds[0].0, BREW_CLASS_SUBSCRIBER);
        assert_eq!(kinds[1], (BREW_CLASS_SERVICE, BREW_SERVICE_MS_CELL));

        let plain = run_commands(MockTransport::new(), commands());
        assert!(
            plain.iter().all(|p| p[0] != BREW_CLASS_SERVICE),
            "nothing new towards a plain Brew server"
        );
        assert_eq!(plain.len(), offered.len() - 1, "otherwise the same messages");
    }

    #[test]
    fn reselection_reports_go_only_to_a_server_that_offers_them() {
        use tetra_saps::control::call_control::CellReselection;
        let commands = || {
            vec![
                BrewCommand::ReportReselection {
                    issi: 7,
                    reselection: CellReselection::AnnouncedType3,
                },
                BrewCommand::ReportReselection {
                    issi: 8,
                    reselection: CellReselection::Undeclared,
                },
            ]
        };
        let offered = run_commands(MockTransport::new().with_brew_extensions(&["bts-info", BREW_EXT_MS_RESELECTION]), commands());
        assert_eq!(offered.len(), 2);
        assert_eq!((offered[0][0], offered[0][1]), (BREW_CLASS_SERVICE, BREW_SERVICE_MS_RESELECTION));
        let json = |m: &[u8]| serde_json::from_slice::<serde_json::Value>(&m[2..m.len() - 1]).unwrap();
        assert_eq!(json(&offered[0]), serde_json::json!({ "issi": 7, "type": "announced_type_3" }));
        assert_eq!(json(&offered[1]), serde_json::json!({ "issi": 8, "type": "undeclared" }));

        assert!(run_commands(MockTransport::new(), commands()).is_empty(), "nothing towards a plain Brew server");
        let older = run_commands(MockTransport::new().with_brew_extensions(&["bts-info", "handover-v1", "ms-cell", "ms-moved"]), commands());
        assert!(older.is_empty(), "nor towards a server without the extension");
    }

    #[test]
    fn bts_info_only_for_a_server_that_offers_it() {
        let cfg = config("").config();
        assert!(bts_info_message(&cfg, &[]).is_none(), "TetraPack / BrandMeister offer no extensions");
        assert!(bts_info_message(&cfg, &["something-else".to_string()]).is_none());
    }

    fn worker(transport: MockTransport) -> BrewWorker<MockTransport> {
        let (event_tx, _event_rx) = bounded(16);
        let (_command_tx, command_rx) = bounded(16);
        BrewWorker::new(config(""), event_tx, command_rx, transport)
    }

    #[test]
    fn connect_announces_cells_only_where_offered() {
        let mut offered = worker(MockTransport::new().with_brew_extensions(&["bts-info"]));
        offered.transport.connect().unwrap();
        offered.announce_cells();
        assert_eq!(offered.transport.sent_payloads().len(), 1);
        assert_eq!(json_of(&offered.transport.sent_payloads()[0])["cells"][0]["carrier"], 1528);

        let mut plain = worker(MockTransport::new());
        plain.transport.connect().unwrap();
        plain.announce_cells();
        assert!(plain.transport.sent_payloads().is_empty(), "nothing new towards a plain Brew server");
    }

    // ── Cell directory (cell-directory) ──

    const NEIGHBOUR: &str = "ms_txpwr_max_cell = 4\nrxlev_access_min_dbm = -100\n\n[[cell_info.neighbor_cells_ca]]\ncell_identifier_ca = 1\ncell_reselection_types_supported = 2\nneighbor_cell_synchronized = false\ncell_load_ca = 0\nmain_carrier_number = 1530\nlocation_area = 1\n\n[[cell_info.neighbor_cells_ca]]\ncell_identifier_ca = 2\ncell_reselection_types_supported = 2\nneighbor_cell_synchronized = false\ncell_load_ca = 0\nmain_carrier_number = 1600\nmain_carrier_number_extension = 280\nmcc = 901\nmnc = 9\n";

    /// `NEIGHBOUR` goes into `[cell_info]`, before `[brew]`.
    fn config_with_neighbours(extra: &str) -> SharedConfig {
        let base = CONFIG.replace("location_area = 10\n", &format!("location_area = 10\n{NEIGHBOUR}"));
        let mut cfg = tetra_config::bluestation::parsing::from_toml_str(&format!("{base}{extra}")).expect("test config parses");
        cfg.add_sibling_neighbours();
        SharedConfig::from_parts(cfg, None)
    }

    #[test]
    fn bts_info_reports_what_the_cells_broadcast_only_with_cell_directory() {
        let offered = ["bts-info".to_string(), BREW_EXT_CELL_DIRECTORY.to_string()];
        let msg = json_of(&bts_info_message(&config_with_neighbours("").config(), &offered).unwrap());
        assert_eq!(msg["capabilities"], serde_json::json!(["cell-directory"]));
        let cell = &msg["cells"][0];
        assert_eq!(cell["ms_txpwr_max_dbm"], 30, "code 4 = 30 dBm (table 18.57)");
        assert_eq!(cell["rxlev_access_min_dbm"], -100);
        assert_eq!(cell["service_details"]["registration"], true);
        assert_eq!(cell["service_details"]["system_wide_services"], true, "broadcast while the Brew link is configured");
        assert_eq!(cell["service_details"].as_object().unwrap().len(), 11);
        assert_eq!(
            cell["neighbours"],
            serde_json::json!([
                {"mcc": 232, "mnc": 5, "carrier": 1530, "carrier_ext": 264, "location_area": 1},
                {"mcc": 901, "mnc": 9, "carrier": 1600, "carrier_ext": 280, "location_area": 10},
            ]),
            "an element left out is the serving cell's own (table 18.64 notes 1, 2)"
        );

        // A second cell lists its sibling.
        let multi = config_with_neighbours("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1532\n");
        let msg = json_of(&bts_info_message(&multi.config(), &offered).unwrap());
        assert!(msg["cells"][1]["neighbours"].as_array().unwrap().iter().any(|n| n["carrier"] == 1528), "{msg}");

        // Not offered: the message stays as before.
        let plain = json_of(&bts_info_message(&config_with_neighbours("").config(), &["bts-info".to_string()]).unwrap());
        assert_eq!(plain["capabilities"], serde_json::json!([]));
        assert_eq!(plain["cells"][0], serde_json::json!({"cell": 0, "carrier": 1528, "carrier_ext": 264, "location_area": 10}));
    }

    fn cell_directory(json: &str) -> Vec<u8> {
        let mut msg = vec![BREW_CLASS_SERVICE, BREW_SERVICE_CELL_DIRECTORY];
        msg.extend_from_slice(json.as_bytes());
        msg.push(0);
        msg
    }

    const DIRECTORY: &str = r#"{"cells":[
        {"id":"1000002/0","station":"1000002","cell":0,"online":true,"mcc":232,"mnc":5,"carrier":1530,"carrier_ext":264,"location_area":1,
         "rxlev_access_min_dbm":-100,"ms_txpwr_max_dbm":32,"neighbours":[{"mcc":232,"mnc":5,"carrier":1528,"carrier_ext":264}],"later":1},
        {"id":"1000003/0","station":"1000003","cell":0,"online":false,"last_seen_ms":5,"mcc":232,"mnc":5,"carrier":1532,"carrier_ext":264,"location_area":1},
        {"id":"bad","station":"x","cell":0,"online":true,"mcc":232,"mnc":5,"carrier":5000,"carrier_ext":264,"location_area":1},
        {"id":"also bad"}
    ]}"#;

    #[test]
    fn the_cell_directory_reaches_the_dashboard_state_only_where_offered() {
        let mut w = worker(MockTransport::new().with_brew_extensions(&["bts-info", BREW_EXT_CELL_DIRECTORY]));
        w.transport.connect().unwrap();
        w.handle_incoming_binary(&cell_directory(DIRECTORY));
        let dir = w.config.state_read().brew_cell_directory.clone().expect("stored");
        assert_eq!(dir.iter().map(|c| (c.id.as_str(), c.online)).collect::<Vec<_>>(), [("1000002/0", true), ("1000003/0", false)]);
        assert_eq!(dir[0].rxlev_access_min_dbm, Some(-100));
        assert_eq!(dir[0].ms_txpwr_max_dbm, None, "32 dBm is no table 18.57 value");
        assert_eq!(dir[0].neighbours.as_ref().unwrap()[0].carrier, 1528);
        assert_eq!(dir[1].last_seen_ms, Some(5));
        w.handle_incoming_binary(&cell_directory("not json"));
        assert_eq!(w.config.state_read().brew_cell_directory.as_ref().map(|d| d.len()), Some(2), "a broken list keeps the last one");

        let mut plain = worker(MockTransport::new().with_brew_extensions(&["bts-info"]));
        plain.transport.connect().unwrap();
        plain.handle_incoming_binary(&cell_directory(DIRECTORY));
        assert!(plain.config.state_read().brew_cell_directory.is_none());
    }

    // ── Handover messages (target side) ──

    const HANDOVER: [&str; 3] = ["bts-info", "handover-v1", "ms-cell"];

    #[test]
    fn bts_info_announces_handover_only_where_offered() {
        let offered: Vec<String> = HANDOVER.iter().map(|e| e.to_string()).collect();
        let single = bts_info_message(&config("").config(), &offered).unwrap();
        assert_eq!(json_of(&single)["capabilities"], serde_json::json!(["handover-v1"]));

        let no_ho = bts_info_message(&config("").config(), &["bts-info".to_string(), "ms-cell".to_string()]).unwrap();
        assert_eq!(json_of(&no_ho)["capabilities"], serde_json::json!([]), "milestone 3 server: no capability");

        let multi = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        assert!(multi.config().is_site_linked());
        let multi = bts_info_message(&multi.config(), &offered).unwrap();
        assert_eq!(json_of(&multi)["capabilities"], serde_json::json!(["handover-v1"]), "a multi-cell station is a target too");
    }

    #[test]
    fn bts_info_asks_for_ms_moved_only_where_offered() {
        let mut offered: Vec<String> = HANDOVER.iter().map(|e| e.to_string()).collect();
        offered.push(BREW_EXT_MS_MOVED.to_string());
        let single = bts_info_message(&config("").config(), &offered).unwrap();
        assert_eq!(json_of(&single)["capabilities"], serde_json::json!(["handover-v1", "ms-moved"]));

        let multi = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        let multi = bts_info_message(&multi.config(), &offered).unwrap();
        assert_eq!(json_of(&multi)["capabilities"], serde_json::json!(["handover-v1", "ms-moved"]), "multi-cell too");

        offered.retain(|e| e != BREW_EXT_HANDOVER);
        let no_ho = bts_info_message(&config("").config(), &offered).unwrap();
        assert_eq!(json_of(&no_ho)["capabilities"], serde_json::json!([]), "only with handover-v1");
    }

    fn ms_moved(json: &str) -> Vec<u8> {
        let mut msg = vec![BREW_CLASS_SERVICE, BREW_SERVICE_MS_MOVED];
        msg.extend_from_slice(json.as_bytes());
        msg.push(0);
        msg
    }

    #[test]
    fn ms_moved_reaches_the_entity_only_where_offered() {
        let mut offered: Vec<&str> = HANDOVER.to_vec();
        offered.push(BREW_EXT_MS_MOVED);
        let (mut w, events) = worker_with_events(MockTransport::new().with_brew_extensions(&offered));
        w.transport.connect().unwrap();
        w.handle_incoming_binary(&ms_moved(r#"{"issi":2320001,"later":true}"#));
        assert!(matches!(events.try_recv(), Ok(BrewEvent::MsMoved { issi: 2320001 })));
        for bad in [r#"{"issi":"x"}"#, r#"{"issi":16777216}"#, r#"{}"#, "not json"] {
            w.handle_incoming_binary(&ms_moved(bad));
            assert!(events.try_recv().is_err(), "malformed {bad} is dropped");
        }

        // A server that did not offer ms-moved cannot have meant this station.
        let (mut plain, events) = worker_with_events(MockTransport::new().with_brew_extensions(&HANDOVER));
        plain.transport.connect().unwrap();
        plain.handle_incoming_binary(&ms_moved(r#"{"issi":2320001}"#));
        assert!(events.try_recv().is_err());
    }

    // ── Individual call restore (call-restore) ──

    fn call_restore(json: &str) -> Vec<u8> {
        let mut msg = vec![BREW_CLASS_SERVICE, BREW_SERVICE_CALL_RESTORE];
        msg.extend_from_slice(json.as_bytes());
        msg.push(0);
        msg
    }

    #[test]
    fn bts_info_asks_for_call_restore_only_where_offered() {
        let mut offered: Vec<String> = HANDOVER.iter().map(|e| e.to_string()).collect();
        offered.push(BREW_EXT_MS_MOVED.to_string());
        offered.push(BREW_EXT_CALL_RESTORE.to_string());
        let single = bts_info_message(&config("").config(), &offered).unwrap();
        assert_eq!(json_of(&single)["capabilities"], serde_json::json!(["handover-v1", "ms-moved", "call-restore"]));
        let multi = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        let multi = bts_info_message(&multi.config(), &offered).unwrap();
        assert_eq!(json_of(&multi)["capabilities"], serde_json::json!(["handover-v1", "ms-moved", "call-restore"]), "multi-cell too");
    }

    #[test]
    fn a_call_restore_request_goes_only_to_a_server_that_moves_calls() {
        let commands = || vec![BrewCommand::RequestCallRestore { issi: 2320972, peer: 2320997 }];
        let offered = run_commands(
            MockTransport::new().with_brew_extensions(&["bts-info", "handover-v1", "ms-moved", BREW_EXT_CALL_RESTORE]),
            commands(),
        );
        assert_eq!(offered.len(), 1);
        assert_eq!((offered[0][0], offered[0][1]), (BREW_CLASS_SERVICE, BREW_SERVICE_CALL_RESTORE));
        let json = serde_json::from_slice::<serde_json::Value>(&offered[0][2..offered[0].len() - 1]).unwrap();
        assert_eq!(json, serde_json::json!({ "issi": 2320972, "peer": 2320997 }));
        assert!(run_commands(MockTransport::new().with_brew_extensions(&["bts-info", "handover-v1", "ms-moved"]), commands()).is_empty());
        assert!(run_commands(MockTransport::new(), commands()).is_empty());
    }

    #[test]
    fn a_registration_without_a_call_is_reported_only_to_a_server_that_moves_calls() {
        let commands = || vec![BrewCommand::ReportRegisteredWithoutCall { issi: 2320972 }];
        let offered = run_commands(
            MockTransport::new().with_brew_extensions(&["bts-info", "handover-v1", "ms-moved", BREW_EXT_CALL_RESTORE]),
            commands(),
        );
        assert_eq!(offered.len(), 1);
        assert_eq!((offered[0][0], offered[0][1]), (BREW_CLASS_SERVICE, BREW_SERVICE_CALL_NOT_RESTORED));
        let json = serde_json::from_slice::<serde_json::Value>(&offered[0][2..offered[0].len() - 1]).unwrap();
        assert_eq!(json, serde_json::json!({ "issi": 2320972 }));
        assert!(run_commands(MockTransport::new().with_brew_extensions(&["bts-info", "handover-v1", "ms-moved"]), commands()).is_empty());
        assert!(run_commands(MockTransport::new(), commands()).is_empty());
    }

    #[test]
    fn without_call_restore_the_worker_answers_no_call_itself() {
        let (event_tx, event_rx) = bounded(16);
        let (command_tx, command_rx) = bounded(16);
        let mut worker = BrewWorker::new(config(""), event_tx, command_rx, MockTransport::new().with_brew_extensions(&HANDOVER));
        worker.transport.connect().unwrap();
        command_tx.send(BrewCommand::RequestCallRestore { issi: 7, peer: 8 }).unwrap();
        command_tx.send(BrewCommand::Disconnect).unwrap();
        worker.message_loop().unwrap();
        let answer = std::iter::from_fn(|| event_rx.try_recv().ok()).find(|e| matches!(e, BrewEvent::CallRestoreAnswer { .. }));
        assert!(matches!(answer, Some(BrewEvent::CallRestoreAnswer { issi: 7, peer: 8, call: None })));
    }

    #[test]
    fn call_restore_answers_reach_the_entity_only_where_offered() {
        let mut offered: Vec<&str> = HANDOVER.to_vec();
        offered.push(BREW_EXT_CALL_RESTORE);
        let (mut w, events) = worker_with_events(MockTransport::new().with_brew_extensions(&offered));
        w.transport.connect().unwrap();
        w.handle_incoming_binary(&call_restore(
            r#"{"issi":2320972,"peer":2320997,"uuid":"57c22f65-c8cb-4008-ac84-6fb79023888f","duplex":false,"priority":2,"floor":2320997,"later":1}"#,
        ));
        let Ok(BrewEvent::CallRestoreAnswer { issi, peer, call: Some(call) }) = events.try_recv() else { panic!("call expected") };
        assert_eq!((issi, peer), (2320972, 2320997));
        assert_eq!(call.brew_uuid.to_string(), "57c22f65-c8cb-4008-ac84-6fb79023888f");
        assert_eq!((call.simplex_duplex, call.priority, call.floor_issi), (false, 2, Some(2320997)));
        w.handle_incoming_binary(&call_restore(r#"{"issi":2320972,"peer":2320997,"uuid":"57c22f65-c8cb-4008-ac84-6fb79023888f","duplex":true,"priority":0,"floor":0}"#));
        assert!(matches!(events.try_recv(), Ok(BrewEvent::CallRestoreAnswer { call: Some(c), .. }) if c.floor_issi.is_none() && c.simplex_duplex));
        w.handle_incoming_binary(&call_restore(r#"{"issi":2320972,"peer":2320997}"#));
        assert!(matches!(events.try_recv(), Ok(BrewEvent::CallRestoreAnswer { issi: 2320972, peer: 2320997, call: None })));
        for bad in [r#"{"peer":1}"#, r#"{"issi":1,"uuid":"nope","duplex":true}"#, r#"{"issi":1,"uuid":"57c22f65-c8cb-4008-ac84-6fb79023888f"}"#, "x"] {
            w.handle_incoming_binary(&call_restore(bad));
            assert!(events.try_recv().is_err(), "malformed {bad} is dropped");
        }
        let (mut plain, events) = worker_with_events(MockTransport::new().with_brew_extensions(&HANDOVER));
        plain.transport.connect().unwrap();
        plain.handle_incoming_binary(&call_restore(r#"{"issi":2320972,"peer":2320997}"#));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn call_handoff_is_announced_and_used_only_where_offered() {
        const RESTORE: [&str; 4] = ["bts-info", "handover-v1", "ms-moved", BREW_EXT_CALL_RESTORE];
        let mut offered: Vec<String> = RESTORE.iter().map(|e| e.to_string()).collect();
        offered.push(BREW_EXT_CALL_HANDOFF.to_string());
        let info = bts_info_message(&config("").config(), &offered).unwrap();
        assert_eq!(json_of(&info)["capabilities"], serde_json::json!(["handover-v1", "ms-moved", "call-restore", "call-handoff"]));
        // Without call-restore the station restores nothing, so it hands nothing off either.
        let no_restore: Vec<String> = ["bts-info", "handover-v1", BREW_EXT_CALL_HANDOFF].iter().map(|e| e.to_string()).collect();
        let info = bts_info_message(&config("").config(), &no_restore).unwrap();
        assert_eq!(json_of(&info)["capabilities"], serde_json::json!(["handover-v1"]));
        // A multi-cell station restores calls, but its site switch does not route a handoff yet.
        let multi = config("\n[[cells]]\nid = 3\n[cells.cell_info]\nmain_carrier = 1530\nlocation_area = 11\n");
        let info = bts_info_message(&multi.config(), &offered).unwrap();
        assert_eq!(json_of(&info)["capabilities"], serde_json::json!(["handover-v1", "ms-moved", "call-restore"]));

        // The answer goes out only to a server that offered the extension.
        let call = tetra_saps::control::call_control::HandedOffCall {
            brew_uuid: Uuid::from_u128(9),
            calling_issi: 2320997,
            simplex_duplex: true,
            priority: 0,
            floor_issi: None,
        };
        let commands = || vec![BrewCommand::SendCallHandoff { issi: 2320972, peer: 2320997, call: Some(call) }];
        let mut with: Vec<&str> = RESTORE.to_vec();
        with.push(BREW_EXT_CALL_HANDOFF);
        let sent = run_commands(MockTransport::new().with_brew_extensions(&with), commands());
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0][0], sent[0][1]), (BREW_CLASS_SERVICE, BREW_SERVICE_CALL_HANDOFF));
        let json = serde_json::from_slice::<serde_json::Value>(&sent[0][2..sent[0].len() - 1]).unwrap();
        assert_eq!(json["uuid"], Uuid::from_u128(9).to_string());
        assert_eq!(json["calling"], 2320997);
        assert!(run_commands(MockTransport::new().with_brew_extensions(&RESTORE), commands()).is_empty());

        // Requests reach the entity only from a server that offered it.
        let request = |json: &str| {
            let mut msg = vec![BREW_CLASS_SERVICE, BREW_SERVICE_CALL_HANDOFF];
            msg.extend_from_slice(json.as_bytes());
            msg.push(0);
            msg
        };
        let (mut w, events) = worker_with_events(MockTransport::new().with_brew_extensions(&with));
        w.transport.connect().unwrap();
        w.handle_incoming_binary(&request(r#"{"issi":2320972,"peer":2320997}"#));
        assert!(matches!(events.try_recv(), Ok(BrewEvent::CallHandoffRequest { issi: 2320972, peer: 2320997 })));
        w.handle_incoming_binary(&request(r#"{"issi":2320972}"#));
        assert!(events.try_recv().is_err(), "malformed request dropped");
        let (mut plain, events) = worker_with_events(MockTransport::new().with_brew_extensions(&RESTORE));
        plain.transport.connect().unwrap();
        plain.handle_incoming_binary(&request(r#"{"issi":2320972,"peer":2320997}"#));
        assert!(events.try_recv().is_err());
    }

    fn worker_with_events(transport: MockTransport) -> (BrewWorker<MockTransport>, Receiver<BrewEvent>) {
        let (event_tx, event_rx) = bounded(16);
        let (_command_tx, command_rx) = bounded(16);
        (BrewWorker::new(config(""), event_tx, command_rx, transport), event_rx)
    }

    fn forward_reg() -> BrewHoRequest {
        BrewHoRequest {
            transaction_id: 77,
            issi: 2320001,
            target_carrier: 1528,
            target_carrier_ext: 264,
            target_mcc: Some(232),
            target_mnc: Some(5),
            target_location_area: Some(10),
            sdu: Some(BrewHoSdu { bytes: vec![0xa1, 0xb2, 0xc0], len_bits: 18 }),
            call_gssi: None,
        }
    }

    #[test]
    fn handover_request_reaches_the_entity_only_where_offered() {
        let (mut offered, events) = worker_with_events(MockTransport::new().with_brew_extensions(&HANDOVER));
        offered.transport.connect().unwrap();
        offered.handle_incoming_binary(&build_service_ho_request(&forward_reg()));
        match events.try_recv() {
            Ok(BrewEvent::HandoverRequest(req)) => assert_eq!(req, forward_reg()),
            other => panic!("expected the handover request, got {other:?}"),
        }

        // A server that never offered handover-v1 cannot have meant this station.
        let (mut plain, events) = worker_with_events(MockTransport::new().with_brew_extensions(&["bts-info", "ms-cell"]));
        plain.transport.connect().unwrap();
        plain.handle_incoming_binary(&build_service_ho_request(&forward_reg()));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn malformed_handover_request_is_dropped() {
        let (mut w, events) = worker_with_events(MockTransport::new().with_brew_extensions(&HANDOVER));
        w.transport.connect().unwrap();
        let mut bad = vec![BREW_CLASS_SERVICE, BREW_SERVICE_HO_FORWARD_REG];
        let json = r#"{"transaction_id":1,"issi":5,"target_carrier":1528,"target_carrier_ext":264,"sdu":"a1","sdu_len_bits":18}"#;
        bad.extend_from_slice(json.as_bytes());
        bad.push(0);
        w.handle_incoming_binary(&bad);
        assert!(events.try_recv().is_err(), "sdu shorter than sdu_len_bits");
    }

    #[test]
    fn handover_result_is_sent_only_where_offered() {
        let result = || {
            vec![BrewCommand::SendHandoverResult(BrewHoResult {
                transaction_id: 77,
                issi: 2320001,
                status: BREW_HO_STATUS_OK,
                reason: None,
                sdu: Some(BrewHoSdu { bytes: vec![0x0f, 0x80], len_bits: 9 }),
                channel: None,
            })]
        };
        let sent = run_commands(MockTransport::new().with_brew_extensions(&HANDOVER), result());
        let msg = sent.iter().find(|p| p[..2] == [BREW_CLASS_SERVICE, BREW_SERVICE_HO_RESULT]).expect("HO_RESULT sent");
        let json: serde_json::Value = serde_json::from_slice(&msg[2..msg.len() - 1]).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "transaction_id": 77, "issi": 2320001, "status": 0, "sdu": "0f80", "sdu_len_bits": 9 })
        );

        let plain = run_commands(MockTransport::new(), result());
        assert!(plain.iter().all(|p| p[0] != BREW_CLASS_SERVICE), "never towards TetraPack / BrandMeister");
    }

    // ── Handover messages (serving side) ──

    #[test]
    fn handover_request_is_sent_only_where_offered_else_answered_not_capable() {
        let sent = run_commands(
            MockTransport::new().with_brew_extensions(&HANDOVER),
            vec![BrewCommand::SendHandoverRequest(forward_reg())],
        );
        assert!(sent.contains(&build_service_ho_request(&forward_reg())), "HO_FORWARD_REG sent");

        let (event_tx, event_rx) = bounded(16);
        let (command_tx, command_rx) = bounded(16);
        let mut plain = BrewWorker::new(config(""), event_tx, command_rx, MockTransport::new());
        plain.transport.connect().unwrap();
        command_tx.send(BrewCommand::SendHandoverRequest(forward_reg())).unwrap();
        command_tx.send(BrewCommand::Disconnect).unwrap();
        plain.message_loop().unwrap();
        assert!(plain.transport.sent_payloads().iter().all(|p| p[0] != BREW_CLASS_SERVICE), "never towards TetraPack / BrandMeister");
        let answer = std::iter::from_fn(|| event_rx.try_recv().ok()).find_map(|e| match e {
            BrewEvent::HandoverResult(r) => Some(r),
            _ => None,
        });
        assert_eq!(
            answer,
            Some(BrewHoResult {
                transaction_id: 77,
                issi: 2320001,
                status: BREW_HO_STATUS_NO_TARGET,
                reason: Some("not_capable".into()),
                sdu: None,
                channel: None,
            }),
            "answered locally, so MLE does not wait for its fallback"
        );
    }
}
