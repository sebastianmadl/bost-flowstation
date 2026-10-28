//! Simulation: ten separate FlowStations (MLE, MM, CMCE and the real Brew entity with its worker
//! thread) on one Brew network, with thirty radios moving between them during group calls.
//!
//! The network is a small in-test relay that follows brew-server's rules where they matter here:
//! a registration moves the ISSI to the registering station and keeps its groups, a group call
//! goes to every station with a radio of that group, a station that gains such a radio mid-call
//! gets the call's GROUP_TX (late entry), and handover requests reach only stations that
//! announced `handover-v1`.
//!
//! Air interface per TS 100 392-2: U-RESTORE / U-CALL RESTORE after cell reselection (clauses
//! 18.4.1.4.7, 14.7.2.2), D-RESTORE-ACK with D-CALL RESTORE (18.4.1.4.4, 14.7.1.3), registration
//! only on a location area change (clause 16), D-LOCATION UPDATE COMMAND to ask for one.

mod common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tetra_config::bluestation::{CfgBrew, CfgNeighborCellCa, StackConfig, StackMode, WhitelistMode};
use tetra_core::ranges::SortedDisjointSsiRanges;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress};
use tetra_entities::net_brew::entity::BrewEntity;
use tetra_entities::net_brew::protocol::*;
use tetra_entities::network::transports::{NetworkAddress, NetworkError, NetworkMessage, NetworkTransport};
use tetra_pdus::cmce::enums::{
    cmce_pdu_type_dl::CmcePduTypeDl, party_type_identifier::PartyTypeIdentifier, transmission_grant::TransmissionGrant,
};
use tetra_pdus::cmce::fields::basic_service_information::BasicServiceInformation;
use tetra_pdus::cmce::pdus::{
    d_call_restore::DCallRestore, d_connect::DConnect, d_info::DInfo, d_setup::DSetup, u_call_restore::UCallRestore, u_setup::USetup,
    u_tx_ceased::UTxCeased,
};
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_pdus::mle::pdus::{u_prepare::UPrepare, u_restore::URestore};
use tetra_pdus::mm::enums::location_update_type::LocationUpdateType;
use tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use tetra_pdus::mm::fields::group_identity_location_demand::GroupIdentityLocationDemand;
use tetra_pdus::mm::fields::group_identity_uplink::GroupIdentityUplink;
use tetra_pdus::mm::pdus::u_attach_detach_group_identity::UAttachDetachGroupIdentity;
use tetra_pdus::mm::pdus::u_location_update_demand::ULocationUpdateDemand;
use tetra_saps::control::call_control::CallControl;
use tetra_saps::control::enums::{circuit_mode_type::CircuitModeType, communication_type::CommunicationType};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataIndBl, TlaTlDataReqBl};
use uuid::Uuid;

use crate::common::ComponentTest;

const STATIONS: usize = 10;
const RADIOS: u32 = 30;
const FIRST_ISSI: u32 = 3_000_001;
const GROUPS: [u32; 5] = [2001, 2002, 2003, 2004, 2005];
const EXTENSIONS: [&str; 3] = ["bts-info", "handover-v1", "ms-cell"];

// ─── Transport: one Brew connection per station, wired to the relay ─────────────────────────────

#[derive(Default)]
struct Wire {
    to_server: VecDeque<Vec<u8>>,
    to_station: VecDeque<Vec<u8>>,
}

struct ChannelTransport {
    wire: Arc<Mutex<Wire>>,
    extensions: Vec<String>,
    connected: bool,
}

impl NetworkTransport for ChannelTransport {
    fn connect(&mut self) -> Result<(), NetworkError> {
        self.connected = true;
        Ok(())
    }
    fn send_reliable(&mut self, payload: &[u8]) -> Result<(), NetworkError> {
        self.wire.lock().unwrap().to_server.push_back(payload.to_vec());
        Ok(())
    }
    fn send_unreliable(&mut self, payload: &[u8]) -> Result<(), NetworkError> {
        self.send_reliable(payload)
    }
    fn receive_reliable(&mut self) -> Vec<NetworkMessage> {
        let inbound: Vec<Vec<u8>> = self.wire.lock().unwrap().to_station.drain(..).collect();
        if inbound.is_empty() {
            // The worker polls in a tight loop; don't burn a core per station.
            std::thread::sleep(Duration::from_micros(300));
        }
        inbound
            .into_iter()
            .map(|payload| NetworkMessage {
                source: NetworkAddress::Custom {
                    scheme: "sim".into(),
                    address: "relay".into(),
                },
                payload,
                timestamp: Instant::now(),
            })
            .collect()
    }
    fn receive_unreliable(&mut self) -> Vec<NetworkMessage> {
        vec![]
    }
    fn wait_for_response_reliable(&mut self) -> Result<NetworkMessage, NetworkError> {
        Err(NetworkError::Timeout)
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn server_brew_extensions(&self) -> &[String] {
        &self.extensions
    }
}

// ─── The relay (brew-server rules, reduced to what the simulation needs) ────────────────────────

struct RelayCall {
    gssi: u32,
    owner: usize,
    talker: u32,
    group_tx: Vec<u8>,
    peers: HashSet<usize>,
}

#[derive(Default)]
struct Relay {
    /// ISSI -> station it is registered on
    location: HashMap<u32, usize>,
    /// ISSI -> groups (kept across registrations, as brew-server does)
    groups: HashMap<u32, HashSet<u32>>,
    /// station -> announced carriers and capabilities
    cells: HashMap<usize, (Vec<u16>, Vec<String>)>,
    calls: HashMap<Uuid, RelayCall>,
    /// Handover results the target stations sent: (station, result)
    ho_results: Vec<(usize, BrewHoResult)>,
    /// Every registration move: (issi, from, to)
    moves: Vec<(u32, Option<usize>, usize)>,
    /// Requests the relay forwarded for a serving station: relay id -> (serving station, its id)
    ho_open: HashMap<u32, (usize, u32)>,
    ho_last: u32,
    /// Every DEREGISTER a station sent: (issi, station)
    deregistrations: Vec<(u32, usize)>,
    /// Carriers whose station "goes away" after answering: the serving station gets status 2
    /// `gone` instead of the answer (the target may already have registered the radio).
    gone_carriers: HashSet<u16>,
    /// ISSIs a station asked to hand over (HO_PREPARE / HO_FORWARD_REG): their next move is a
    /// prepared one
    prepared: HashSet<u32>,
    /// Every MS_MOVED notice sent: (issi, station told)
    ms_moved: Vec<(u32, usize)>,
    /// GROUP_TX refused because another station's over held the group's floor: (station, gssi)
    floor_refused: Vec<(usize, u32)>,
}

impl Relay {
    fn handle(&mut self, from: usize, data: &[u8], wires: &[Arc<Mutex<Wire>>]) {
        let send = |to: usize, msg: &[u8]| wires[to].lock().unwrap().to_station.push_back(msg.to_vec());
        match parse_brew_message(data) {
            Ok(BrewMessage::Subscriber(sub)) => match sub.msg_type {
                BREW_SUBSCRIBER_REGISTER | BREW_SUBSCRIBER_REREGISTER => {
                    let old = self.location.insert(sub.number, from);
                    if old != Some(from) {
                        self.moves.push((sub.number, old, from));
                    }
                    self.groups.entry(sub.number).or_default().extend(sub.groups.iter().copied());
                    self.late_entry(sub.number, from, &send);
                    let prepared = self.prepared.remove(&sub.number);
                    if let Some(left) = old.filter(|o| *o != from && !prepared) {
                        self.radio_moved(sub.number, left, from, &send);
                    }
                }
                BREW_SUBSCRIBER_DEREGISTER => {
                    self.deregistrations.push((sub.number, from));
                    if self.location.get(&sub.number) == Some(&from) {
                        self.location.remove(&sub.number);
                    }
                }
                BREW_SUBSCRIBER_AFFILIATE if self.location.get(&sub.number) == Some(&from) => {
                    self.groups.entry(sub.number).or_default().extend(sub.groups.iter().copied());
                    self.late_entry(sub.number, from, &send);
                }
                BREW_SUBSCRIBER_DEAFFILIATE if self.location.get(&sub.number) == Some(&from) => {
                    if let Some(g) = self.groups.get_mut(&sub.number) {
                        for gssi in &sub.groups {
                            g.remove(gssi);
                        }
                    }
                }
                _ => {}
            },
            Ok(BrewMessage::CallControl(cc)) => match cc.payload {
                BrewCallPayload::GroupTransmission(gt) if cc.call_state == CALL_STATE_GROUP_TX => {
                    // brew-server: one over per group; another station's over keeps the floor.
                    if self.calls.iter().any(|(id, c)| *id != cc.identifier && c.gssi == gt.destination && c.owner != from) {
                        self.floor_refused.push((from, gt.destination));
                        return;
                    }
                    let peers: HashSet<usize> = self
                        .location
                        .iter()
                        .filter(|(issi, s)| **s != from && self.groups.get(*issi).is_some_and(|g| g.contains(&gt.destination)))
                        .map(|(_, s)| *s)
                        .collect();
                    for p in &peers {
                        send(*p, data);
                    }
                    self.calls.insert(
                        cc.identifier,
                        RelayCall {
                            gssi: gt.destination,
                            owner: from,
                            talker: gt.source,
                            group_tx: data.to_vec(),
                            peers,
                        },
                    );
                }
                _ if cc.call_state == CALL_STATE_GROUP_IDLE => {
                    if let Some(call) = self.calls.remove(&cc.identifier) {
                        for p in &call.peers {
                            send(*p, data);
                        }
                    }
                }
                _ => {}
            },
            Ok(BrewMessage::Frame(frame)) => {
                if let Some(call) = self.calls.get(&frame.identifier) {
                    for p in &call.peers {
                        send(*p, data);
                    }
                }
            }
            Ok(BrewMessage::Service(svc)) => match svc.service_type {
                BREW_SERVICE_BTS_INFO => {
                    let json: serde_json::Value = serde_json::from_str(&svc.json_data).unwrap();
                    let carriers = json["cells"].as_array().unwrap().iter().map(|c| c["carrier"].as_u64().unwrap() as u16).collect();
                    let caps = json["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
                    self.cells.insert(from, (carriers, caps));
                }
                BREW_SERVICE_HO_RESULT => {
                    let result = parse_ho_result(&svc.json_data).unwrap();
                    self.ho_results.push((from, result.clone()));
                    // brew-server: relay the target's answer to the serving station under its id.
                    if let Some((serving, id)) = self.ho_open.remove(&result.transaction_id) {
                        let gone = self.cells.get(&from).is_some_and(|(c, _)| c.iter().any(|c| self.gone_carriers.contains(c)));
                        let result = if gone {
                            BrewHoResult {
                                status: BREW_HO_STATUS_NO_TARGET,
                                reason: Some("gone".into()),
                                sdu: None,
                                channel: None,
                                ..result
                            }
                        } else {
                            result
                        };
                        send(serving, &build_service_ho_result(&BrewHoResult { transaction_id: id, ..result }));
                    }
                }
                BREW_SERVICE_HO_PREPARE | BREW_SERVICE_HO_FORWARD_REG => {
                    // brew-server's relay: the capable station serving the carrier gets the request
                    // under the relay's own id; nobody → "no target" at once.
                    let mut req = parse_ho_request(svc.service_type, &svc.json_data).unwrap();
                    self.prepared.insert(req.issi);
                    let target = self.cells.iter().find(|(st, (carriers, caps))| {
                        **st != from && carriers.contains(&req.target_carrier) && caps.iter().any(|c| c == BREW_EXT_HANDOVER)
                    });
                    match target {
                        Some((&target, _)) => {
                            self.ho_last += 1;
                            let id = 1_000_000 + self.ho_last;
                            self.ho_open.insert(id, (from, req.transaction_id));
                            req.transaction_id = id;
                            send(target, &build_service_ho_request(&req));
                        }
                        None => send(
                            from,
                            &build_service_ho_result(&BrewHoResult {
                                transaction_id: req.transaction_id,
                                issi: req.issi,
                                status: BREW_HO_STATUS_NO_TARGET,
                                reason: Some("unknown".into()),
                                sdu: None,
                                channel: None,
                            }),
                        ),
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// brew-server late entry: a station that gains a radio of a running call's group gets the call.
    fn late_entry(&mut self, issi: u32, station: usize, send: &impl Fn(usize, &[u8])) {
        let groups = self.groups.get(&issi).cloned().unwrap_or_default();
        for call in self.calls.values_mut() {
            if groups.contains(&call.gssi) && call.owner != station && call.peers.insert(station) {
                send(station, &call.group_tx);
            }
        }
    }

    /// brew-server `handover::radio_moved`: the station a radio left unprepared is told (if it
    /// asked for `ms-moved`), and an over the radio was talking in there ends on the network (if
    /// the new station has handover-v1), so the radio can talk on from the new station.
    fn radio_moved(&mut self, issi: u32, left: usize, to: usize, send: &impl Fn(usize, &[u8])) {
        let caps = |st: usize| self.cells.get(&st).map(|(_, c)| c.clone()).unwrap_or_default();
        if caps(left).iter().any(|c| c == BREW_EXT_MS_MOVED) {
            let mut notice = vec![BREW_CLASS_SERVICE, BREW_SERVICE_MS_MOVED];
            notice.extend_from_slice(format!(r#"{{"issi":{issi}}}"#).as_bytes());
            notice.push(0);
            send(left, &notice);
            self.ms_moved.push((issi, left));
        }
        if !caps(to).iter().any(|c| c == BREW_EXT_HANDOVER) {
            return;
        }
        let talking: Vec<Uuid> = self.calls.iter().filter(|(_, c)| c.owner == left && c.talker == issi).map(|(id, _)| *id).collect();
        for id in talking {
            let call = self.calls.remove(&id).unwrap();
            for p in &call.peers {
                send(*p, &build_group_idle(&id, 0));
            }
        }
    }

    /// The server side of a forwarded registration towards the target (milestone 3 relay).
    fn forward_registration(&self, target_carrier: u16, req: &BrewHoRequest, wires: &[Arc<Mutex<Wire>>]) -> usize {
        let (target, _) = self
            .cells
            .iter()
            .find(|(_, (carriers, caps))| carriers.contains(&target_carrier) && caps.iter().any(|c| c == BREW_EXT_HANDOVER))
            .expect("a capable station serves the carrier");
        wires[*target].lock().unwrap().to_station.push_back(build_service_ho_request(req));
        *target
    }
}

// ─── Stations ───────────────────────────────────────────────────────────────────────────────────

fn relay_brew() -> CfgBrew {
    CfgBrew {
        host: "relay.sim".into(),
        port: 3000,
        tls: false,
        username: None,
        password: None,
        reconnect_delay: Duration::from_secs(1),
        jitter_initial_latency_frames: 0,
        feature_sds_enabled: true,
        whitelisted_ssis: None,
        feature_rssi_export: false,
        feature_lip_forward: false,
        lip_forward_issi: None,
        pbx_gateway_issis: None,
        backhaul_hysteresis_secs: 0,
    }
}

struct Station {
    test: ComponentTest,
    wire: Arc<Mutex<Wire>>,
    carrier: u16,
    /// Everything this station put on air (LLC sink), oldest first
    air: Vec<SapMsg>,
}

fn station(index: usize, location_area: u16, extensions: &[&str], configure: &dyn Fn(usize, &mut StackConfig)) -> Station {
    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    let carrier = 1521 + 2 * index as u16;
    config.cell.main_carrier = carrier;
    config.cell.location_area = location_area;
    config.cell.local_ssi_ranges = SortedDisjointSsiRanges::from_vec_ssirange(vec![]);
    config.brew = Some(relay_brew());
    configure(index, &mut config);
    let mut test = ComponentTest::from_config(config, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(
        vec![TetraEntity::Mle, TetraEntity::Mm, TetraEntity::Cmce],
        vec![TetraEntity::Llc, TetraEntity::Umac],
    );
    let wire = Arc::new(Mutex::new(Wire::default()));
    let transport = ChannelTransport {
        wire: wire.clone(),
        extensions: extensions.iter().map(|e| e.to_string()).collect(),
        connected: false,
    };
    test.register_entity(BrewEntity::new(test.get_shared_config(), transport));
    Station {
        test,
        wire,
        carrier,
        air: Vec::new(),
    }
}

/// Uplink PDU from `issi` as LLC hands it to MLE.
fn uplink(issi: u32, discriminator: MleProtocolDiscriminator, write: impl FnOnce(&mut BitBuffer)) -> SapMsg {
    let mut b = BitBuffer::new_autoexpand(128);
    b.write_bits(discriminator.into_raw(), 3);
    write(&mut b);
    let len = b.get_pos();
    b.seek(0);
    let mut sdu = BitBuffer::new(len);
    sdu.copy_bits(&mut b, len);
    sdu.seek(0);
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndBl(TlaTlDataIndBl {
            main_address: TetraAddress::new(issi, SsiType::Issi),
            link_id: 0,
            endpoint_id: 0,
            new_endpoint_id: None,
            css_endpoint_id: None,
            tl_sdu: Some(sdu),
            scrambling_code: 0,
            fcs_flag: false,
            air_interface_encryption: 0,
            chan_change_resp_req: false,
            chan_change_handle: None,
            chan_info: None,
            req_handle: 0,
        }),
    }
}

fn location_update_pdu(issi: u32, lu_type: LocationUpdateType, groups: &[u32]) -> ULocationUpdateDemand {
    ULocationUpdateDemand {
        location_update_type: lu_type,
        request_to_append_la: false,
        cipher_control: false,
        ciphering_parameters: None,
        class_of_ms: None,
        energy_saving_mode: None,
        la_information: None,
        ssi: Some(issi as u64),
        address_extension: None,
        group_identity_location_demand: (!groups.is_empty()).then(|| GroupIdentityLocationDemand {
            group_identity_attach_detach_mode: 0,
            group_identity_uplink: Some(
                groups
                    .iter()
                    .map(|g| GroupIdentityUplink {
                        class_of_usage: Some(4),
                        group_identity_detachment_uplink: None,
                        gssi: Some(*g),
                        address_extension: None,
                        vgssi: None,
                    })
                    .collect(),
            ),
        }),
        group_report_response: None,
        authentication_uplink: None,
        extended_capabilities: None,
        proprietary: None,
    }
}

/// U-ATTACH/DETACH GROUP IDENTITY with "detach all and attach" (table 16.49), as a radio sends
/// its group report.
fn u_attach_detach_all(issi: u32, groups: &[u32]) -> SapMsg {
    let lu = location_update_pdu(issi, LocationUpdateType::DemandLocationUpdating, groups);
    let pdu = UAttachDetachGroupIdentity {
        group_identity_report: false,
        group_identity_attach_detach_mode: true,
        group_report_response: None,
        group_identity_uplink: lu.group_identity_location_demand.and_then(|d| d.group_identity_uplink),
        proprietary: None,
    };
    uplink(issi, MleProtocolDiscriminator::Mm, |b| pdu.to_bitbuf(b).unwrap())
}

fn u_setup(issi: u32, gssi: u32) -> SapMsg {
    let pdu = USetup {
        area_selection: 0,
        hook_method_selection: false,
        simplex_duplex_selection: false,
        basic_service_information: BasicServiceInformation {
            circuit_mode_type: CircuitModeType::TchS,
            encryption_flag: false,
            communication_type: CommunicationType::P2Mp,
            slots_per_frame: None,
            speech_service: Some(0),
        },
        request_to_transmit_send_data: true,
        call_priority: 0,
        clir_control: 0,
        called_party_type_identifier: PartyTypeIdentifier::Ssi,
        called_party_ssi: Some(gssi as u64),
        called_party_short_number_address: None,
        called_party_extension: None,
        external_subscriber_number: None,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };
    uplink(issi, MleProtocolDiscriminator::Cmce, |b| pdu.to_bitbuf(b).unwrap())
}

fn u_tx_ceased(issi: u32, call_id: u16) -> SapMsg {
    let pdu = UTxCeased {
        call_identifier: call_id,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };
    uplink(issi, MleProtocolDiscriminator::Cmce, |b| pdu.to_bitbuf(b).unwrap())
}

/// U-RESTORE carrying U-CALL RESTORE. `old_la` is given when the radio moved to another LA
/// (note 1 to table 18.13); without it the PDU has O-bit 0 and the SDU right after (table E.29).
fn u_restore(issi: u32, call_id: u16, gssi: u32, old_la: Option<u64>) -> SapMsg {
    let call_restore = UCallRestore {
        call_identifier: call_id,
        // A listener: "request that other MS may transmit" (table 14.74).
        request_to_transmit_send_data: true,
        other_party_type_identifier: 1,
        other_party_short_number_address: None,
        other_party_ssi: Some(gssi as u64),
        other_party_extension: None,
        basic_service_information: None,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };
    let mut sdu = BitBuffer::new_autoexpand(64);
    call_restore.to_bitbuf(&mut sdu).unwrap();
    let len = sdu.get_pos();
    sdu.seek(0);
    let mut exact = BitBuffer::new(len);
    exact.copy_bits(&mut sdu, len);
    exact.seek(0);
    let restore = URestore {
        mcc: None,
        mnc: None,
        la: old_la,
        sdu: Some(exact),
    };
    uplink(issi, MleProtocolDiscriminator::Mle, |b| restore.to_bitbuf(b).unwrap())
}

/// What a station sent on air to `ssi`, as bit strings (discriminator included).
fn air_to(air: &[SapMsg], ssi: u32) -> Vec<String> {
    air.iter()
        .filter_map(|m| match &m.msg {
            SapMsgInner::TlaTlDataReqBl(r) if r.main_address.ssi == ssi => Some(r.tl_sdu.to_bitstr()),
            SapMsgInner::TlaTlUnitdataReqBl(r) if r.main_address.ssi == ssi => Some(r.tl_sdu.to_bitstr()),
            _ => None,
        })
        .collect()
}

const PD_MM: &str = "001";
const PD_CMCE: &str = "010";
const PD_MLE: &str = "101";

fn mm_pdu(t: MmPduTypeDl) -> String {
    format!("{PD_MM}{:04b}", t.into_raw())
}

/// The call identifier `issi` uses after D-RESTORE-ACK (the D-CALL RESTORE's new call
/// identifier, else its call identifier), if one was sent. Checks that the identifier the radio
/// restored with is echoed and that a channel allocation goes with it (clause 14.5.2.2.4).
fn restore_ack(air: &[SapMsg], issi: u32) -> Option<u16> {
    air.iter().find_map(|m| {
        let SapMsgInner::TlaTlDataReqBl(r) = &m.msg else {
            return None;
        };
        if r.main_address.ssi != issi {
            return None;
        }
        // D-RESTORE-ACK = MLE type 4, O-bit 0, then D-CALL RESTORE (table E.23).
        let rest = r.tl_sdu.to_bitstr().strip_prefix(&format!("{PD_MLE}1000"))?.to_string();
        let mut b = BitBuffer::from_bitstr(&rest);
        let restore = DCallRestore::from_bitbuf(&mut b).ok()?;
        assert!(r.chan_alloc.is_some(), "D-RESTORE-ACK to {issi} without channel allocation");
        Some(restore.new_call_identifier.map_or(restore.call_identifier, |id| id as u16))
    })
}

fn restore_fail(air: &[SapMsg], issi: u32) -> bool {
    air_to(air, issi).iter().any(|bits| bits.starts_with(&format!("{PD_MLE}101")))
}

fn group_release_sent(air: &[SapMsg], gssi: u32) -> bool {
    air_to(air, gssi).iter().any(|bits| {
        bits.strip_prefix(PD_CMCE)
            .is_some_and(|rest| BitBuffer::from_bitstr(rest).peek_bits(5) == Some(CmcePduTypeDl::DRelease.into_raw()))
    })
}

fn group_setup_call_id(air: &[SapMsg], gssi: u32) -> Option<u16> {
    air_to(air, gssi).iter().rev().find_map(|bits| {
        let rest = bits.strip_prefix(PD_CMCE)?;
        let mut b = BitBuffer::from_bitstr(rest);
        (b.peek_bits(5) == Some(CmcePduTypeDl::DSetup.into_raw())).then_some(())?;
        DSetup::from_bitbuf(&mut b).ok().map(|s| s.call_identifier)
    })
}

// ─── The network ────────────────────────────────────────────────────────────────────────────────

struct Sim {
    stations: Vec<Station>,
    wires: Vec<Arc<Mutex<Wire>>>,
    relay: Relay,
    /// TDMA ticks run so far
    ticks: usize,
}

impl Sim {
    /// `location_areas[i]` is station i's LA; neighbouring stations sharing an LA model the
    /// "reselection within the registered area" case.
    fn new(location_areas: &[u16], extensions: &[&str]) -> Self {
        Self::with_config(location_areas, extensions, &|_, _| {})
    }

    fn with_config(location_areas: &[u16], extensions: &[&str], configure: &dyn Fn(usize, &mut StackConfig)) -> Self {
        let stations: Vec<Station> = location_areas
            .iter()
            .enumerate()
            .map(|(i, la)| station(i, *la, extensions, configure))
            .collect();
        let wires = stations.iter().map(|s| s.wire.clone()).collect();
        let mut sim = Sim {
            stations,
            wires,
            relay: Relay::default(),
            ticks: 0,
        };
        sim.run_until("every station announced its cell", |s| s.relay.cells.len() == location_areas.len());
        sim
    }

    /// One TDMA tick on every station, then deliver what the stations sent to the relay. Paced so
    /// the stations' TDMA time does not outrun the worker threads (CMCE timers run on TDMA time).
    fn step(&mut self) {
        self.ticks += 1;
        for s in &mut self.stations {
            s.test.run_stack(Some(1));
            s.air.extend(s.test.dump_sinks().into_iter().filter(|m| m.dest == TetraEntity::Llc));
        }
        for i in 0..self.wires.len() {
            let out: Vec<Vec<u8>> = self.wires[i].lock().unwrap().to_server.drain(..).collect();
            for msg in out {
                self.relay.handle(i, &msg, &self.wires);
            }
        }
        std::thread::sleep(Duration::from_micros(500));
    }

    fn run_until(&mut self, what: &str, done: impl Fn(&Sim) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(self) {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            self.step();
        }
    }

    fn steps(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }

    fn submit(&mut self, station: usize, msg: SapMsg) {
        self.stations[station].test.submit_message(msg);
    }

    fn register(&mut self, station: usize, issi: u32, lu_type: LocationUpdateType, groups: &[u32]) {
        let lu = location_update_pdu(issi, lu_type, groups);
        self.submit(station, uplink(issi, MleProtocolDiscriminator::Mm, |b| lu.to_bitbuf(b).unwrap()));
        self.run_until(&format!("ISSI {issi} is registered on station {station} on the network"), |s| {
            s.relay.location.get(&issi) == Some(&station)
        });
    }

    /// A radio of `gssi` on `station` starts a group call; returns the Brew session.
    fn start_call(&mut self, station: usize, talker: u32, gssi: u32) -> Uuid {
        self.submit(station, u_setup(talker, gssi));
        self.run_until(&format!("the call on {gssi} reached the network"), |s| {
            s.relay.calls.values().any(|c| c.gssi == gssi && c.owner == station)
        });
        *self.relay.calls.iter().find(|(_, c)| c.gssi == gssi && c.owner == station).unwrap().0
    }

    /// The talker releases PTT: the station ends the over on the network (GROUP_IDLE) and every
    /// station releases its leg after hang time.
    fn end_call(&mut self, station: usize, talker: u32, gssi: u32, session: Uuid) {
        let call_id = self.local_call_id(station, gssi).expect("the talker's station set the call up");
        self.submit(station, u_tx_ceased(talker, call_id));
        self.run_until(&format!("the over on {gssi} ended on the network"), |s| !s.relay.calls.contains_key(&session));
        self.steps(600);
    }

    fn local_call_id(&self, station: usize, gssi: u32) -> Option<u16> {
        group_setup_call_id(&self.stations[station].air, gssi)
    }

    fn clear_air(&mut self) {
        for s in &mut self.stations {
            s.air.clear();
        }
    }
}

// ─── Scenarios ──────────────────────────────────────────────────────────────────────────────────

/// Ten stations, each its own location area. Thirty radios register; group calls run; every
/// listener moves to another station mid-call (unannounced reselection with a registration,
/// since the LA changes) and must be restored into the call there, although the new station had
/// no listener for the group before (the milestone 0 field failure).
#[test]
fn sim_ten_stations_thirty_radios_unannounced_reselection_keeps_calls() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::new(&las, &EXTENSIONS);
    assert!(
        sim.relay.cells.values().all(|(_, caps)| caps == &vec![BREW_EXT_HANDOVER.to_string()]),
        "single-cell stations announce handover-v1"
    );

    // Radio r sits on station r % 10, member of group r % 5.
    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    // Three rounds: in each, talkers on three groups start calls and every other member of those
    // groups moves two stations on and restores.
    let mut restored = 0;
    for round in 0..3usize {
        sim.clear_air();
        let groups = [GROUPS[round], GROUPS[(round + 1) % 5], GROUPS[(round + 3) % 5]];
        let mut talkers = HashSet::new();
        let mut sessions = Vec::new();
        for gssi in groups {
            // A different member talks each round.
            let &(talker, _, _) = radios.iter().filter(|(_, _, g)| *g == gssi).nth(round).unwrap();
            let st = sim.relay.location[&talker];
            talkers.insert(talker);
            sessions.push((gssi, st, talker, sim.start_call(st, talker, gssi)));
        }
        sim.steps(20);

        for &(issi, _, gssi) in &radios {
            if talkers.contains(&issi) || !groups.contains(&gssi) {
                continue;
            }
            let from = sim.relay.location[&issi];
            let to = (from + 2 + round) % STATIONS;
            // The call id the radio knows: its old station's (it listened there).
            let old_call_id = sim.local_call_id(from, gssi).unwrap_or(1);

            // New LA: the radio registers first (clause 16), then restores its call. Half the
            // radios report their group in the registration; the others leave it out, so the
            // station's MM asks for a group report (D-LOCATION UPDATE COMMAND), which those
            // radios answer only after the restore.
            let reports_group = issi % 2 == 0;
            let groups: &[u32] = if reports_group { &[gssi] } else { &[] };
            sim.register(to, issi, LocationUpdateType::RoamingLocationUpdating, groups);
            // Half the radios give the old LA in U-RESTORE, the others leave it out (both codings).
            let old_la = (issi % 4 < 2).then_some(from as u64 + 1);
            sim.submit(to, u_restore(issi, old_call_id, gssi, old_la));
            sim.run_until(&format!("ISSI {issi} gets an answer to its U-RESTORE on station {to}"), |s| {
                restore_ack(&s.stations[to].air, issi).is_some() || restore_fail(&s.stations[to].air, issi)
            });
            let ack = restore_ack(&sim.stations[to].air, issi).unwrap_or_else(|| panic!("ISSI {issi} was refused on station {to}"));
            assert_eq!(Some(ack), sim.local_call_id(to, gssi), "restored into station {to}'s call");
            if !reports_group {
                sim.register(to, issi, LocationUpdateType::DemandLocationUpdating, &[gssi]);
            }
            restored += 1;
        }

        // Calls end.
        for (gssi, st, talker, session) in sessions {
            sim.end_call(st, talker, gssi, session);
        }
    }
    assert!(restored >= 25, "only {restored} restores exercised");

    assert!(sim.relay.ms_moved.is_empty(), "nobody is told without ms-moved");
    // The network has every radio where it last went.
    for &(issi, _, _) in &radios {
        assert!(sim.relay.location.contains_key(&issi), "ISSI {issi} still registered");
    }
}

/// Stations 0..4 share LA 1 and 5..9 share LA 2. A radio moving within its LA does not register
/// (clause 16): the new station asks it to (D-LOCATION UPDATE COMMAND), the network moves the ISSI
/// on that registration and hands the station the call.
#[test]
fn sim_reselection_within_the_location_area_registers_and_restores() {
    let las = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2];
    let mut sim = Sim::new(&las, &EXTENSIONS);

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    let mut restored = 0;
    for gssi in GROUPS {
        sim.clear_air();
        let &(talker, st, _) = radios.iter().find(|(_, _, g)| *g == gssi).unwrap();
        let st = sim.relay.location.get(&talker).copied().unwrap_or(st);
        let session = sim.start_call(st, talker, gssi);
        sim.steps(20);

        for &(issi, _, g) in &radios {
            if g != gssi || issi == talker {
                continue;
            }
            let from = sim.relay.location[&issi];
            // Next station in the same LA (0→1→…→4→0, 5→6→…→9→5).
            let to = (from / 5) * 5 + (from % 5 + 1) % 5;
            let old_call_id = sim.local_call_id(from, gssi).unwrap_or(1);

            // Same LA: U-RESTORE without MCC/MNC/LA (table E.29).
            sim.submit(to, u_restore(issi, old_call_id, gssi, None));
            sim.steps(3);
            assert!(
                air_to(&sim.stations[to].air, issi).iter().any(|b| b.starts_with(&mm_pdu(MmPduTypeDl::DLocationUpdateCommand))),
                "station {to} asks unknown ISSI {issi} to register"
            );
            assert!(!restore_fail(&sim.stations[to].air, issi), "not refused while waiting");
            // The radio answers the command with a demand location update and its groups.
            sim.register(to, issi, LocationUpdateType::DemandLocationUpdating, &[gssi]);
            sim.run_until(&format!("ISSI {issi} restored on station {to}"), |s| {
                restore_ack(&s.stations[to].air, issi).is_some() || restore_fail(&s.stations[to].air, issi)
            });
            assert!(restore_ack(&sim.stations[to].air, issi).is_some(), "ISSI {issi} refused on station {to}");
            restored += 1;
        }
        sim.end_call(st, talker, gssi, session);
    }
    assert!(restored >= 20, "only {restored} restores exercised");
}

/// Forwarded registrations (announced reselection type 1) from the network: every target station
/// hands the MM PDU to its MM, registers the radio (which moves the ISSI on the network, keeping
/// its groups, and brings the running call along) and answers with MM's D-LOCATION UPDATE ACCEPT.
#[test]
fn sim_forwarded_registrations_are_answered_with_the_mm_accept() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::new(&las, &EXTENSIONS);

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }
    // A call on group 2001 runs while its members are handed over.
    let talker = radios[0].0;
    sim.start_call(radios[0].1, talker, GROUPS[0]);

    for (n, &(issi, _, gssi)) in radios.iter().enumerate().skip(1) {
        let from = sim.relay.location[&issi];
        let to = (from + 1 + n % 4) % STATIONS;
        let lu = location_update_pdu(issi, LocationUpdateType::RoamingLocationUpdating, &[]);
        let mut sdu = BitBuffer::new_autoexpand(64);
        lu.to_bitbuf(&mut sdu).unwrap();
        let len = sdu.get_pos();
        sdu.seek(0);
        let mut exact = BitBuffer::new(len);
        exact.copy_bits(&mut sdu, len);
        let req = BrewHoRequest {
            transaction_id: 1000 + n as u32,
            issi,
            target_carrier: sim.stations[to].carrier,
            target_carrier_ext: 264,
            target_mcc: Some(204),
            target_mnc: Some(1337),
            target_location_area: Some(las[to]),
            sdu: Some(BrewHoSdu::from_bitbuffer(&exact)),
            call_gssi: None,
        };
        let target = sim.relay.forward_registration(sim.stations[to].carrier, &req, &sim.wires.clone());
        assert_eq!(target, to);
        sim.run_until(&format!("station {to} answers ISSI {issi}'s forwarded registration"), |s| {
            s.relay.ho_results.iter().any(|(_, r)| r.transaction_id == 1000 + n as u32)
        });
        let (answered_by, result) = sim.relay.ho_results.iter().find(|(_, r)| r.transaction_id == 1000 + n as u32).unwrap().clone();
        assert_eq!(answered_by, to);
        assert_eq!((result.issi, result.status), (issi, BREW_HO_STATUS_OK));
        let answer = result.sdu.expect("MM answer for D-NEW-CELL").to_bitbuffer().to_bitstr();
        assert!(answer.starts_with(&format!("{:04b}", MmPduTypeDl::DLocationUpdateAccept.into_raw())), "D-LOCATION UPDATE ACCEPT");
        assert!(
            !air_to(&sim.stations[to].air, issi).iter().any(|b| b.starts_with(&mm_pdu(MmPduTypeDl::DLocationUpdateAccept))),
            "MM's accept goes back to the serving station, not on air at the target"
        );
        assert_eq!(sim.relay.location.get(&issi), Some(&to), "the ISSI moved before the radio left");
        assert!(sim.relay.groups[&issi].contains(&gssi), "groups kept");
        if gssi == GROUPS[0] {
            assert!(
                sim.relay.calls.values().any(|c| c.gssi == gssi && c.peers.contains(&to)),
                "the running call reaches the target station"
            );
        }
    }
    assert!(sim.relay.ho_results.len() >= 25);
}

/// A station on a server without `handover-v1` (or TetraPack / Brandmeister) announces nothing,
/// answers nothing, and still restores calls after an unannounced reselection.
#[test]
fn sim_without_the_extension_nothing_new_is_sent_and_restore_still_works() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::new(&las, &["bts-info", "ms-cell"]);
    assert!(sim.relay.cells.values().all(|(_, caps)| caps.is_empty()));

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[0])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }
    // A forwarded registration sent anyway is ignored (the station never offered to answer).
    let req = BrewHoRequest {
        transaction_id: 9,
        issi: FIRST_ISSI,
        target_carrier: sim.stations[3].carrier,
        target_carrier_ext: 264,
        target_mcc: None,
        target_mnc: None,
        target_location_area: None,
        sdu: Some(BrewHoSdu { bytes: vec![0x20, 0x03], len_bits: 16 }),
        call_gssi: None,
    };
    sim.wires[3].lock().unwrap().to_station.push_back(build_service_ho_request(&req));
    sim.steps(50);
    assert!(sim.relay.ho_results.is_empty());

    let session = sim.start_call(radios[0].1, radios[0].0, GROUPS[0]);
    sim.steps(20);
    let mover = radios[1].0;
    let from = sim.relay.location[&mover];
    let to = (from + 5) % STATIONS;
    let to = if to == radios[0].1 { (to + 1) % STATIONS } else { to };
    let old = sim.local_call_id(from, GROUPS[0]).unwrap_or(1);
    sim.register(to, mover, LocationUpdateType::RoamingLocationUpdating, &[]);
    sim.submit(to, u_restore(mover, old, GROUPS[0], Some(from as u64 + 1)));
    sim.run_until("the restore is answered", |s| restore_ack(&s.stations[to].air, mover).is_some());
    let _ = session;
}

/// A target whose MM rejects the radio (here: not on station 9's access list) answers "rejected"
/// with MM's D-LOCATION UPDATE REJECT, so the serving station sends D-PREPARE-FAIL with it
/// (clause 18.4.1.4.3). The ISSI stays where it was on the network.
#[test]
fn sim_forwarded_registration_rejected_by_the_target_mm() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let allowed: Vec<u32> = (0..RADIOS / 2).map(|r| FIRST_ISSI + r).collect();
    let mut sim = Sim::with_config(&las, &EXTENSIONS, &|i, cfg| {
        if i == 9 {
            cfg.security.whitelist_mode = WhitelistMode::Enforce;
            cfg.security.issi_whitelist = allowed.clone();
        }
    });
    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % 9, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    for (n, &(issi, from, _)) in radios.iter().enumerate() {
        let lu = location_update_pdu(issi, LocationUpdateType::RoamingLocationUpdating, &[]);
        let mut sdu = BitBuffer::new_autoexpand(64);
        lu.to_bitbuf(&mut sdu).unwrap();
        let len = sdu.get_pos();
        sdu.seek(0);
        let mut exact = BitBuffer::new(len);
        exact.copy_bits(&mut sdu, len);
        let req = BrewHoRequest {
            transaction_id: 5000 + n as u32,
            issi,
            target_carrier: sim.stations[9].carrier,
            target_carrier_ext: 264,
            target_mcc: None,
            target_mnc: None,
            target_location_area: Some(10),
            sdu: Some(BrewHoSdu::from_bitbuffer(&exact)),
            call_gssi: None,
        };
        sim.relay.forward_registration(sim.stations[9].carrier, &req, &sim.wires.clone());
        sim.run_until("station 9 answers", |s| s.relay.ho_results.iter().any(|(_, r)| r.transaction_id == 5000 + n as u32));
        let (_, result) = sim.relay.ho_results.iter().find(|(_, r)| r.transaction_id == 5000 + n as u32).unwrap().clone();
        let answer = result.sdu.expect("MM answer").to_bitbuffer().to_bitstr();
        if allowed.contains(&issi) {
            assert_eq!(result.status, BREW_HO_STATUS_OK);
            assert_eq!(sim.relay.location[&issi], 9);
        } else {
            assert_eq!(result.status, BREW_HO_STATUS_REJECTED, "ISSI {issi}");
            assert!(answer.starts_with(&format!("{:04b}", MmPduTypeDl::DLocationUpdateReject.into_raw())));
            assert_eq!(sim.relay.location[&issi], from, "nothing moved");
        }
    }
}

/// Milestone 4 field test case A: the radio moves to a station where nobody listens to the running
/// call and does not restore it. It answers the station's D-LOCATION UPDATE COMMAND with a demand
/// location update (detach all and attach, its group), which brings the call up there; then it
/// sends its own roaming location update and the same group report again as U-ATTACH/DETACH
/// GROUP IDENTITY (table 16.49). The call must keep running on the station (before: MM deaffiliated
/// the group for a moment, CMCE sent D-RELEASE and set the call up again with a new identifier).
#[test]
fn sim_group_report_after_reselection_keeps_the_call_running() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::new(&las, &EXTENSIONS);

    // Group g's members sit on stations g and g + 5, so the other eight stations have no listener.
    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    let mut moved = 0;
    for (g, gssi) in GROUPS.into_iter().enumerate() {
        sim.clear_air();
        let &(talker, _, _) = radios.iter().find(|(_, _, grp)| *grp == gssi).unwrap();
        let st = sim.relay.location[&talker];
        let session = sim.start_call(st, talker, gssi);
        sim.steps(20);

        let mut targets = (0..STATIONS).filter(|s| s % 5 != g);
        for &(issi, _, grp) in &radios {
            if grp != gssi || issi == talker {
                continue;
            }
            let to = targets.next().expect("a free station per listener");
            assert_eq!(sim.local_call_id(to, gssi), None, "nobody on station {to} listened before");

            let mut lu = location_update_pdu(issi, LocationUpdateType::DemandLocationUpdating, &[gssi]);
            lu.group_identity_location_demand.as_mut().unwrap().group_identity_attach_detach_mode = 1;
            sim.submit(to, uplink(issi, MleProtocolDiscriminator::Mm, |b| lu.to_bitbuf(b).unwrap()));
            sim.run_until(&format!("station {to} sets the call on {gssi} up for ISSI {issi}"), |s| {
                s.local_call_id(to, gssi).is_some()
            });
            let call_id = sim.local_call_id(to, gssi);

            sim.register(to, issi, LocationUpdateType::RoamingLocationUpdating, &[]);
            sim.submit(to, u_attach_detach_all(issi, &[gssi]));
            sim.steps(100);
            assert!(!group_release_sent(&sim.stations[to].air, gssi), "station {to} released the call on {gssi}");
            assert_eq!(sim.local_call_id(to, gssi), call_id, "station {to} kept the call identifier");
            assert!(sim.relay.calls.contains_key(&session), "the over on {gssi} still runs");
            moved += 1;
        }
        sim.end_call(st, talker, gssi, session);
    }
    assert!(moved >= 25, "only {moved} radios exercised");
}

/// Location update accept type of the last D-LOCATION UPDATE ACCEPT a station sent to `issi`
/// (3 bits after the PDU type, table 16.68).
fn accept_type(air: &[SapMsg], issi: u32) -> Option<u64> {
    let prefix = mm_pdu(MmPduTypeDl::DLocationUpdateAccept);
    air_to(air, issi)
        .iter()
        .rev()
        .find_map(|bits| bits.strip_prefix(&prefix).map(|rest| BitBuffer::from_bitstr(rest).peek_bits(3).unwrap()))
}

fn accepts(air: &[SapMsg], issi: u32) -> usize {
    let prefix = mm_pdu(MmPduTypeDl::DLocationUpdateAccept);
    air_to(air, issi).iter().filter(|bits| bits.starts_with(&prefix)).count()
}

/// `issi` registers on `station` with `lu_type`; returns the accept type of the answer.
fn register_accepted_as(sim: &mut Sim, station: usize, issi: u32, lu_type: LocationUpdateType, groups: &[u32]) -> Option<u64> {
    let before = accepts(&sim.stations[station].air, issi);
    sim.register(station, issi, lu_type, groups);
    sim.run_until(&format!("ISSI {issi} gets an accept on station {station}"), |s| {
        accepts(&s.stations[station].air, issi) > before
    });
    accept_type(&sim.stations[station].air, issi)
}

/// Transmission grant of the D-CALL RESTORE in the D-RESTORE-ACK a station sent to `issi`.
fn restore_grant(air: &[SapMsg], issi: u32) -> Option<u8> {
    air_to(air, issi).iter().find_map(|bits| {
        let rest = bits.strip_prefix(&format!("{PD_MLE}1000"))?;
        DCallRestore::from_bitbuf(&mut BitBuffer::from_bitstr(rest)).ok().map(|r| r.transmission_grant)
    })
}

/// Three stations (one LA each), five radios on one group. Every registration is accepted as the
/// type the radio asked for (clause 16.10.35a, table 16.68): roaming, demand (the answer to the
/// station's D-LOCATION UPDATE COMMAND) and periodic. Listeners that move mid-call restore with
/// "request that other MS may transmit" (table 14.74) and get "granted to another user" while
/// the talker talks, and "not granted" between overs (clause 14.5.2.2.4).
#[test]
fn sim_three_stations_five_radios_accept_types_and_restore_grants() {
    const GRANTED_TO_OTHER_USER: u8 = 3;
    const NOT_GRANTED: u8 = 1;
    let mut sim = Sim::new(&[1, 2, 3], &EXTENSIONS);
    let gssi = GROUPS[0];
    let radios: Vec<(u32, usize)> = (0..5u32).map(|r| (FIRST_ISSI + r, r as usize % 3)).collect();
    for &(issi, st) in &radios {
        let accepted = register_accepted_as(&mut sim, st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
        assert_eq!(accepted, Some(0b000), "roaming accept for {issi}");
    }

    // Periodic registration on the current station.
    let (periodic, st) = radios[1];
    let accepted = register_accepted_as(&mut sim, st, periodic, LocationUpdateType::PeriodicLocationUpdating, &[gssi]);
    assert_eq!(accepted, Some(0b010), "periodic accept");

    // Radio 0 talks on station 0; the others move one station on and restore as listeners.
    sim.clear_air();
    let (talker, talker_st) = radios[0];
    let session = sim.start_call(talker_st, talker, gssi);
    sim.steps(20);
    for &(issi, _) in &radios[1..] {
        let from = sim.relay.location[&issi];
        let to = (from + 1) % 3;
        let old_call_id = sim.local_call_id(from, gssi).unwrap_or(1);
        // Odd radios leave the group out, so the station commands a group report (demand).
        let reports_group = issi % 2 == 0;
        let reported = if reports_group { vec![gssi] } else { vec![] };
        let accepted = register_accepted_as(&mut sim, to, issi, LocationUpdateType::RoamingLocationUpdating, &reported);
        assert_eq!(accepted, Some(0b000), "roaming accept for {issi} on {to}");
        sim.submit(to, u_restore(issi, old_call_id, gssi, Some(from as u64 + 1)));
        sim.run_until(&format!("ISSI {issi} gets an answer on station {to}"), |s| {
            restore_ack(&s.stations[to].air, issi).is_some() || restore_fail(&s.stations[to].air, issi)
        });
        assert_eq!(restore_ack(&sim.stations[to].air, issi), sim.local_call_id(to, gssi), "{issi} restored on {to}");
        assert_eq!(restore_grant(&sim.stations[to].air, issi), Some(GRANTED_TO_OTHER_USER), "{issi} listens on {to}");
        if !reports_group {
            assert!(
                air_to(&sim.stations[to].air, issi).iter().any(|b| b.starts_with(&mm_pdu(MmPduTypeDl::DLocationUpdateCommand))),
                "station {to} asks {issi} for its groups"
            );
            let accepted = register_accepted_as(&mut sim, to, issi, LocationUpdateType::DemandLocationUpdating, &[gssi]);
            assert_eq!(accepted, Some(0b110), "demand accept for {issi} on {to}");
        }
    }

    // Between overs: the talker releases PTT, a listener moves to the talker's station within
    // hang time and restores without asking to transmit. The floor is free but not its to take.
    let call_id = sim.local_call_id(talker_st, gssi).unwrap();
    sim.submit(talker_st, u_tx_ceased(talker, call_id));
    sim.steps(2);
    let &(mover, _) = radios[1..].iter().find(|(issi, _)| sim.relay.location[issi] != talker_st).unwrap();
    let from = sim.relay.location[&mover];
    sim.stations[talker_st].air.clear();
    sim.register(talker_st, mover, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    sim.submit(talker_st, u_restore(mover, sim.local_call_id(from, gssi).unwrap_or(1), gssi, Some(from as u64 + 1)));
    sim.run_until(&format!("ISSI {mover} gets an answer between overs"), |s| {
        restore_ack(&s.stations[talker_st].air, mover).is_some() || restore_fail(&s.stations[talker_st].air, mover)
    });
    assert_eq!(restore_grant(&sim.stations[talker_st].air, mover), Some(NOT_GRANTED), "listener not granted between overs");

    sim.run_until("the over ended on the network", |s| !s.relay.calls.contains_key(&session));
    sim.steps(600);
    for &(issi, _) in &radios {
        assert!(sim.relay.location.contains_key(&issi), "ISSI {issi} still registered");
    }
}

// ─── Announced reselection between stations (milestone 5, serving side) ────────────────────────

fn neighbour(cell_identifier_ca: u8, carrier: u16, location_area: u16) -> CfgNeighborCellCa {
    CfgNeighborCellCa {
        cell_identifier_ca,
        // Forward registration supported (table 18.22).
        cell_reselection_types_supported: 2,
        neighbor_cell_synchronized: false,
        cell_load_ca: 0,
        main_carrier_number: carrier,
        main_carrier_number_extension: None,
        mcc: None,
        mnc: None,
        location_area: Some(location_area),
        maximum_ms_transmit_power: None,
        minimum_rx_access_level: None,
        subscriber_class: None,
        bs_service_details: None,
        timeshare_cell_information_or_security_parameters: None,
        tdma_frame_offset: None,
    }
}

/// Station i lists station i + 1 as neighbour 1 and station i - 1 as neighbour 2 (ring), plus
/// neighbour 3 on a carrier no station serves.
fn ring_neighbours(las: &[u16], i: usize, cfg: &mut StackConfig) {
    let n = las.len();
    let next = (i + 1) % n;
    let prev = (i + n - 1) % n;
    cfg.cell.neighbor_cells_ca = vec![
        neighbour(1, 1521 + 2 * next as u16, las[next]),
        neighbour(2, 1521 + 2 * prev as u16, las[prev]),
        neighbour(3, 1999, 99),
    ];
}

/// U-PREPARE naming neighbour `ci`, with a forward registration (roaming location update) when
/// `forward` (table 18.10; the MS supports forward registration and the LA changes, 18.3.4.7.5).
fn u_prepare(issi: u32, ci: u64, forward: bool) -> SapMsg {
    let sdu = forward.then(|| {
        let lu = location_update_pdu(issi, LocationUpdateType::RoamingLocationUpdating, &[]);
        let mut b = BitBuffer::new_autoexpand(64);
        lu.to_bitbuf(&mut b).unwrap();
        let len = b.get_pos();
        b.seek(0);
        let mut exact = BitBuffer::new(len);
        exact.copy_bits(&mut b, len);
        exact.seek(0);
        exact
    });
    let pdu = UPrepare {
        cell_identifier_ca: Some(ci),
        sdu,
    };
    uplink(issi, MleProtocolDiscriminator::Mle, |b| pdu.to_bitbuf(b).unwrap())
}

/// The serving station's answer to a U-PREPARE from `issi` (after the MLE discriminator):
/// D-NEW-CELL (type 000) or D-PREPARE-FAIL (type 001), if sent.
fn prepare_answer(air: &[SapMsg], issi: u32) -> Option<String> {
    air_to(air, issi).into_iter().find_map(|bits| {
        let rest = bits.strip_prefix(PD_MLE)?;
        (rest.starts_with("000") || rest.starts_with("001")).then(|| rest.to_string())
    })
}

const D_NEW_CELL_CHANGE_NOW: &str = "000010";
/// D-NEW-CELL "follow MAC channel change" (type 1, table 18.43) with an MM SDU.
const D_NEW_CELL_FOLLOW_MAC: &str = "000000";

/// The D-NEW-CELL `issi` got, as handed to layer 2 (with its channel allocation and STCH).
fn d_new_cells(air: &[SapMsg], issi: u32) -> Vec<&TlaTlDataReqBl> {
    air.iter()
        .filter_map(|m| match &m.msg {
            SapMsgInner::TlaTlDataReqBl(r) if r.main_address.ssi == issi && r.tl_sdu.to_bitstr().starts_with(&format!("{PD_MLE}000")) => Some(r),
            _ => None,
        })
        .collect()
}

/// New call identifiers sent to `issi` in D-INFO.
fn d_info_new_call_ids(air: &[SapMsg], issi: u32) -> Vec<u16> {
    air_to(air, issi)
        .iter()
        .filter_map(|bits| {
            let rest = bits.strip_prefix(PD_CMCE)?;
            let mut b = BitBuffer::from_bitstr(rest);
            (b.peek_bits(5) == Some(CmcePduTypeDl::DInfo.into_raw())).then_some(())?;
            DInfo::from_bitbuf(&mut b).ok()?.new_call_identifier.map(|id| id as u16)
        })
        .collect()
}

/// Carrier and timeslot of the station's channel for its latest call to `gssi`.
fn group_setup_channel(air: &[SapMsg], gssi: u32) -> Option<(u16, u8)> {
    air.iter().rev().find_map(|m| match &m.msg {
        SapMsgInner::TlaTlDataReqBl(r) if r.main_address.ssi == gssi && r.tl_sdu.to_bitstr().starts_with(PD_CMCE) => {
            let ca = r.chan_alloc.as_ref()?;
            let ts = ca.timeslots.iter().position(|&t| t)? as u8 + 1;
            Some((ca.carrier?, ts))
        }
        SapMsgInner::TlaTlUnitdataReqBl(r) if r.main_address.ssi == gssi && r.tl_sdu.to_bitstr().starts_with(PD_CMCE) => {
            let ca = r.chan_alloc.as_ref()?;
            let ts = ca.timeslots.iter().position(|&t| t)? as u8 + 1;
            Some((ca.carrier?, ts))
        }
        _ => None,
    })
}
/// D-LOCATION UPDATE REJECT, roaming, forward registration failure (table 16.81), O-bit 0.
const FRF_REJECT: &str = "01110000011100";

/// Ten stations in their own location areas, thirty radios. During a group call every listener
/// announces a reselection to the next station (U-PREPARE with forward registration): the serving
/// station asks the target through the network, holds D-NEW-CELL until the target's MM accepted
/// and the target runs the call, then grants type 1 (clause 18.3.4.7.5): the target's call
/// identifier in D-INFO if it differs, then D-NEW-CELL "follow MAC channel change" with the
/// accept and a channel allocation for the target's traffic channel ("cell change flag", clause
/// 23.5.4.1), stolen on the serving call's traffic channel. The radio goes straight to the new
/// channel without U-RESTORE (figure 18.14). Every fourth grant cannot go out on the traffic
/// channel: the serving station grants type 2 instead and the radio restores the call. The ISSI is
/// on the target before the radio leaves, and the station it left drops it without deregistering
/// it on the network.
#[test]
fn sim_announced_reselection_prepares_the_other_station() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::with_config(&las, &EXTENSIONS, &|i, cfg| ring_neighbours(&las, i, cfg));

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    let accept = format!("{:04b}", MmPduTypeDl::DLocationUpdateAccept.into_raw());
    let mut moved = Vec::new();
    let (mut type1, mut type2, mut d_infos) = (0, 0, 0);
    for gssi in GROUPS {
        sim.clear_air();
        let &(talker, _, _) = radios.iter().find(|(_, _, g)| *g == gssi).unwrap();
        let st = sim.relay.location[&talker];
        let session = sim.start_call(st, talker, gssi);
        sim.steps(20);

        for &(issi, _, g) in &radios {
            if g != gssi || issi == talker {
                continue;
            }
            let from = sim.relay.location[&issi];
            let to = (from + 1) % STATIONS;
            let old_call_id = sim.local_call_id(from, gssi).unwrap_or(1);
            let serving_channel = group_setup_channel(&sim.stations[from].air, gssi);
            sim.submit(from, u_prepare(issi, 1, true));
            sim.run_until(&format!("station {from} answers ISSI {issi}'s U-PREPARE"), |s| {
                prepare_answer(&s.stations[from].air, issi).is_some()
            });
            let answer = prepare_answer(&sim.stations[from].air, issi).unwrap();
            assert!(
                answer.starts_with(&format!("{D_NEW_CELL_FOLLOW_MAC}{accept}")),
                "ISSI {issi}: type 1 D-NEW-CELL with the target's accept, got {answer}"
            );
            assert_eq!(sim.relay.location.get(&issi), Some(&to), "registered on the target before leaving");
            let new_call_id = sim.local_call_id(to, gssi).expect("the target runs the call");
            let (carrier, ts) = group_setup_channel(&sim.stations[to].air, gssi).expect("the target's channel");

            let grant = d_new_cells(&sim.stations[from].air, issi)[0].clone();
            let alloc = grant.chan_alloc.as_ref().expect("channel allocation with the type 1 D-NEW-CELL");
            assert!(alloc.cell_change, "allocation for another cell");
            assert_eq!(alloc.carrier, Some(carrier), "the target's carrier");
            assert_eq!(alloc.carrier, Some(sim.stations[to].carrier));
            assert_eq!(alloc.timeslots.iter().position(|&t| t), Some(ts as usize - 1), "the target's timeslot");
            assert!(grant.stealing_permission);
            assert_eq!(grant.stealing_slot, serving_channel, "stolen on the call's traffic channel here");

            let infos = d_info_new_call_ids(&sim.stations[from].air, issi);
            if new_call_id != old_call_id {
                assert!(infos.len() >= 2 && infos.iter().all(|&id| id == new_call_id), "ISSI {issi}: D-INFO {infos:?}, want {new_call_id}");
                d_infos += 1;
            } else {
                assert!(infos.is_empty(), "no D-INFO when the call identifier stays");
            }

            let reporter = grant.tx_reporter.clone().expect("type 1 grant is tracked");
            if moved.len() % 4 == 3 {
                // Layer 2 could not steal the slot: type 2 with the same accept.
                reporter.mark_discarded();
                sim.run_until(&format!("station {from} falls back to type 2 for ISSI {issi}"), |s| d_new_cells(&s.stations[from].air, issi).len() == 2);
                let fallback = d_new_cells(&sim.stations[from].air, issi)[1].tl_sdu.to_bitstr();
                assert!(
                    fallback.strip_prefix(PD_MLE).unwrap().starts_with(&format!("{D_NEW_CELL_CHANGE_NOW}{accept}")),
                    "type 2 with the accept, got {fallback}"
                );
                // The radio arrives and restores its call (old LA given, table 18.13 note 1).
                sim.submit(to, u_restore(issi, new_call_id, gssi, Some(las[from] as u64)));
                sim.run_until(&format!("ISSI {issi} gets an answer to its U-RESTORE on station {to}"), |s| {
                    restore_ack(&s.stations[to].air, issi).is_some() || restore_fail(&s.stations[to].air, issi)
                });
                let ack = restore_ack(&sim.stations[to].air, issi).unwrap_or_else(|| panic!("ISSI {issi} was refused on station {to}"));
                assert_eq!(ack, new_call_id, "restored into station {to}'s call");
                type2 += 1;
            } else {
                reporter.mark_transmitted();
                sim.steps(5);
                assert_eq!(d_new_cells(&sim.stations[from].air, issi).len(), 1, "no second D-NEW-CELL after type 1 went out");
                type1 += 1;
            }
            moved.push((issi, from, to));
        }
        sim.end_call(st, talker, gssi, session);
    }
    assert!(moved.len() >= 25, "only {} announced reselections", moved.len());
    assert!(type1 >= 18 && type2 >= 6, "type 1 {type1}, type 2 {type2}");
    assert!(d_infos > 0, "no reselection changed the call identifier");

    // The stations they left drop them (after the departure delay) without deregistering them.
    sim.run_until("the serving stations dropped the radios that left", |s| {
        moved
            .iter()
            .all(|(issi, from, _)| !s.stations[*from].test.get_shared_config().state_read().subscribers.is_registered(*issi))
    });
    sim.steps(50);
    for (issi, from, to) in &moved {
        assert!(!sim.relay.deregistrations.contains(&(*issi, *from)), "station {from} deregistered ISSI {issi} on the network");
        assert_eq!(sim.relay.location.get(issi), Some(to));
    }
}

/// What the serving station answers when the target does not take the radio, per clause
/// 18.3.4.7.6: target MM rejects (station 9's access list) → D-PREPARE-FAIL "MS not allowed on
/// cell" with the reject; target registered the radio but went away (station 7) → D-PREPARE-FAIL
/// "temporary break in service" and the serving station claims the ISSI back; no station serves
/// the carrier → D-NEW-CELL type 2 with "forward registration failure" (figure 18.12), the radio
/// registers on arrival; without forward registration → plain D-NEW-CELL.
#[test]
fn sim_announced_reselection_that_the_target_does_not_take() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let allowed: Vec<u32> = (0..RADIOS / 2).map(|r| FIRST_ISSI + r).collect();
    let mut sim = Sim::with_config(&las, &EXTENSIONS, &|i, cfg| {
        ring_neighbours(&las, i, cfg);
        if i == 9 {
            cfg.security.whitelist_mode = WhitelistMode::Enforce;
            cfg.security.issi_whitelist = allowed.clone();
        }
    });
    sim.relay.gone_carriers.insert(sim.stations[7].carrier);
    // Everyone on station 8, whose neighbour 1 is station 9 and neighbour 2 station 7.
    let radios: Vec<u32> = (0..RADIOS).map(|r| FIRST_ISSI + r).collect();
    for &issi in &radios {
        sim.register(8, issi, LocationUpdateType::RoamingLocationUpdating, &[GROUPS[0]]);
    }

    let mut checked = 0;
    for (n, &issi) in radios.iter().enumerate() {
        sim.clear_air();
        let (ci, forward) = match n % 4 {
            0 => (1, true),
            1 => (3, true),
            2 => (3, false),
            _ => (2, true),
        };
        sim.submit(8, u_prepare(issi, ci, forward));
        sim.run_until(&format!("station 8 answers ISSI {issi}"), |s| prepare_answer(&s.stations[8].air, issi).is_some());
        let answer = prepare_answer(&sim.stations[8].air, issi).unwrap();
        match (ci, forward) {
            (1, _) if allowed.contains(&issi) => {
                assert!(answer.starts_with(D_NEW_CELL_CHANGE_NOW), "ISSI {issi}: {answer}");
                assert_eq!(sim.relay.location[&issi], 9);
            }
            (1, _) => {
                let reject = format!("{:04b}", MmPduTypeDl::DLocationUpdateReject.into_raw());
                assert!(answer.starts_with(&format!("001100{reject}")), "ISSI {issi}: fail cause 2 with the reject, got {answer}");
                sim.run_until("the ISSI is claimed back", |s| s.relay.location[&issi] == 8);
            }
            (2, _) => {
                assert_eq!(answer, format!("001000{FRF_REJECT}"), "ISSI {issi}: fail cause 0 with forward registration failure");
                sim.run_until("the ISSI is claimed back from the station that went away", |s| s.relay.location[&issi] == 8);
                assert!(sim.relay.moves.contains(&(issi, Some(7), 8)), "it had moved to station 7 first");
            }
            (_, true) => {
                assert_eq!(answer, format!("{D_NEW_CELL_CHANGE_NOW}{FRF_REJECT}"), "ISSI {issi}");
                assert_eq!(sim.relay.location[&issi], 8, "nothing moved");
            }
            (_, false) => assert_eq!(answer, D_NEW_CELL_CHANGE_NOW, "ISSI {issi}"),
        }
        checked += 1;
    }
    assert!(checked >= 25);
}

/// Last D-CONNECT sent to `issi`: its transmission grant.
fn d_connect_grant(air: &[SapMsg], issi: u32) -> Option<TransmissionGrant> {
    air_to(air, issi).iter().rev().find_map(|bits| {
        let mut b = BitBuffer::from_bitstr(bits.strip_prefix(PD_CMCE)?);
        (b.peek_bits(5) == Some(CmcePduTypeDl::DConnect.into_raw())).then_some(())?;
        DConnect::from_bitbuf(&mut b).ok().map(|c| c.transmission_grant)
    })
}

/// Field case C: a talker changes station unannounced in the middle of its over and presses PTT
/// again on the new station (U-SETUP, as the MTP6650 does). With `ms-moved` the network ends the
/// over on the station it left and tells that station, which drops the radio without
/// deregistering it; the new station gives the talker the floor (TS 100 392-2 clause
/// 14.5.2.2.1 a)) whether the network's end of the old over reaches it before or after the
/// U-SETUP, and the new over goes out on the network. Every one of the 30 radios talks once:
/// half move to a station with listeners of the group, half to one without.
#[test]
fn sim_talker_that_moves_unannounced_keeps_talking() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let extensions = ["bts-info", "handover-v1", "ms-cell", BREW_EXT_MS_MOVED];
    let mut sim = Sim::new(&las, &extensions);
    assert!(
        sim.relay
            .cells
            .values()
            .all(|(_, caps)| caps == &vec![BREW_EXT_HANDOVER.to_string(), BREW_EXT_MS_MOVED.to_string()]),
        "stations ask for ms-moved where the server offers it"
    );

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    let mut moved = Vec::new();
    for &(talker, _, gssi) in &radios {
        sim.clear_air();
        let from = sim.relay.location[&talker];
        let old_session = sim.start_call(from, talker, gssi);
        sim.steps(20);

        let to = (from + if talker % 2 == 0 { 5 } else { 3 }) % STATIONS;
        sim.register(to, talker, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
        sim.submit(to, u_setup(talker, gssi));
        sim.run_until(&format!("ISSI {talker} talks from station {to}"), |s| {
            s.relay.calls.values().any(|c| c.gssi == gssi && c.owner == to && c.talker == talker)
        });
        assert_eq!(
            d_connect_grant(&sim.stations[to].air, talker),
            Some(TransmissionGrant::Granted),
            "ISSI {talker} keeps the floor on station {to}"
        );
        assert!(!sim.relay.calls.contains_key(&old_session), "the over on station {from} ended on the network");
        assert!(sim.relay.ms_moved.contains(&(talker, from)), "station {from} was told");
        assert!(sim.relay.floor_refused.is_empty(), "no over was refused: {:?}", sim.relay.floor_refused);

        // The new over holds: the old over's late end (GROUP_IDLE from the station the radio
        // left, after it ends its own leg) must not take the floor away here.
        sim.steps(100);
        let session = *sim
            .relay
            .calls
            .iter()
            .find(|(_, c)| c.gssi == gssi && c.owner == to && c.talker == talker)
            .expect("the new over still runs")
            .0;
        sim.end_call(to, talker, gssi, session);
        moved.push((talker, from, to));
    }
    assert!(moved.len() >= 25);

    sim.run_until("the stations dropped the radios that left", |s| {
        moved.iter().all(|(issi, from, _)| {
            s.relay.location.get(issi) == Some(from)
                || !s.stations[*from].test.get_shared_config().state_read().subscribers.is_registered(*issi)
        })
    });
    for (issi, from, _) in &moved {
        assert!(!sim.relay.deregistrations.contains(&(*issi, *from)), "station {from} deregistered ISSI {issi} on the network");
    }
}

/// Announced type 3 (clause 18.3.4.7.4): a talker without a scanned or synchronized neighbour
/// announces the change with a U-PREPARE that names no cell (the MTP6650 does this while
/// transmitting when the cells are not synchronized). The serving station answers D-NEW-CELL
/// "change channel immediately", never D-PREPARE-FAIL, prepares nothing, and the radio then
/// goes on as after an unannounced change: it keeps the floor on the new station and the old
/// one is told.
#[test]
fn sim_type_3_announcement_by_a_talker_gets_d_new_cell_and_keeps_the_floor() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let extensions = ["bts-info", "handover-v1", "ms-cell", BREW_EXT_MS_MOVED];
    let mut sim = Sim::with_config(&las, &extensions, &|i, cfg| ring_neighbours(&las, i, cfg));

    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    let mut moved = 0;
    for &(talker, _, gssi) in &radios {
        sim.clear_air();
        let from = sim.relay.location[&talker];
        let old_session = sim.start_call(from, talker, gssi);
        sim.steps(20);

        let prepare = UPrepare {
            cell_identifier_ca: None,
            sdu: None,
        };
        sim.submit(from, uplink(talker, MleProtocolDiscriminator::Mle, |b| prepare.to_bitbuf(b).unwrap()));
        sim.run_until(&format!("station {from} answers ISSI {talker}'s type 3 U-PREPARE"), |s| {
            prepare_answer(&s.stations[from].air, talker).is_some()
        });
        assert_eq!(
            prepare_answer(&sim.stations[from].air, talker).as_deref(),
            Some(D_NEW_CELL_CHANGE_NOW),
            "ISSI {talker}: D-NEW-CELL change channel immediately"
        );
        assert!(!sim.relay.prepared.contains(&talker), "nothing is prepared for type 3");

        let to = (from + 1 + talker as usize % 3) % STATIONS;
        sim.register(to, talker, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
        sim.submit(to, u_setup(talker, gssi));
        sim.run_until(&format!("ISSI {talker} talks from station {to}"), |s| {
            s.relay.calls.values().any(|c| c.gssi == gssi && c.owner == to && c.talker == talker)
        });
        assert_eq!(d_connect_grant(&sim.stations[to].air, talker), Some(TransmissionGrant::Granted));
        assert!(!sim.relay.calls.contains_key(&old_session), "the over on station {from} ended");
        assert!(sim.relay.ms_moved.contains(&(talker, from)), "station {from} was told");
        let session = *sim
            .relay
            .calls
            .iter()
            .find(|(_, c)| c.gssi == gssi && c.owner == to && c.talker == talker)
            .expect("the new over runs")
            .0;
        sim.end_call(to, talker, gssi, session);
        moved += 1;
    }
    assert!(moved >= 25);
}

/// The Brew side of case C on the new station: once CMCE gives the moved talker the floor of the
/// over it was heard on, that network session is over here. The old station's GROUP_IDLE that
/// follows must not start a pending tail on the slot the talker now sends on (its playout and
/// NetworkCallEnd would hit the new over).
#[test]
fn moved_talker_floor_ends_its_network_session_on_the_new_station() {
    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    config.brew = Some(relay_brew());
    let mut test = ComponentTest::from_config(config, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![], vec![TetraEntity::Cmce, TetraEntity::Umac]);
    let wire = Arc::new(Mutex::new(Wire::default()));
    let transport = ChannelTransport {
        wire: wire.clone(),
        extensions: EXTENSIONS.iter().map(|e| e.to_string()).collect(),
        connected: false,
    };
    test.register_entity(BrewEntity::new(test.get_shared_config(), transport));
    let (talker, gssi, other) = (3_100_001, 2001, 3_100_002);
    let old = Uuid::from_u128(0xC0);
    let to_cmce = |test: &mut ComponentTest, cc: CallControl| {
        test.submit_message(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Brew,
            msg: SapMsgInner::CmceCallControl(cc),
        })
    };
    let run = |test: &mut ComponentTest, wire: &Arc<Mutex<Wire>>, ms: u64| {
        let mut out = Vec::new();
        let until = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < until {
            test.run_stack(Some(1));
            out.extend(test.dump_sinks());
            wire.lock().unwrap().to_server.clear();
            std::thread::sleep(Duration::from_millis(2));
        }
        out
    };
    let ends = |msgs: &[SapMsg], uuid: Uuid| {
        msgs.iter()
            .any(|m| matches!(&m.msg, SapMsgInner::CmceCallControl(CallControl::NetworkCallEnd { brew_uuid }) if *brew_uuid == uuid))
    };
    run(&mut test, &wire, 50);

    for (round, (speaker, uuid)) in [(other, Uuid::from_u128(0xC1)), (talker, old)].into_iter().enumerate() {
        let group_tx = build_group_tx(&uuid, speaker, gssi, 0, 0, None);
        wire.lock().unwrap().to_station.push_back(group_tx);
        let msgs = run(&mut test, &wire, 100);
        assert!(msgs.iter().any(
            |m| matches!(&m.msg, SapMsgInner::CmceCallControl(CallControl::NetworkCallStart { brew_uuid, .. }) if *brew_uuid == uuid)
        ));
        let (call_id, ts) = (5 + round as u16, 2 + round as u8);
        to_cmce(
            &mut test,
            CallControl::NetworkCallReady {
                brew_uuid: uuid,
                call_id,
                carrier_num: 1521,
                ts,
                usage: 4,
            },
        );
        run(&mut test, &wire, 50);
        // CMCE hands the floor of that over to the talker that came here.
        to_cmce(
            &mut test,
            CallControl::FloorGranted {
                call_id,
                source_issi: talker,
                dest_gssi: gssi,
                carrier_num: 1521,
                ts,
            },
        );
        run(&mut test, &wire, 50);
        wire.lock().unwrap().to_station.push_back(build_group_idle(&uuid, 0));
        let msgs = run(&mut test, &wire, 1500);
        if speaker == talker {
            assert!(!ends(&msgs, uuid), "the moved talker's old session left a tail on its new over");
        } else {
            // Somebody else's over is not touched (CMCE would not hand its floor over anyway).
            assert!(ends(&msgs, uuid), "another talker's over ends as before");
        }
    }
}

/// Field cases A and B: listeners that leave unannounced. With `ms-moved` the station they left
/// stops serving them, and once no radio of the group is left there it releases its leg of the
/// network call instead of sending it to nobody until the call ends. Stations i and i + 5 hold
/// the three radios each of group i; the talker is on station i, the three on station i + 5 move
/// to three other stations and restore there.
#[test]
fn sim_station_left_by_all_listeners_releases_the_call() {
    let las: Vec<u16> = (1..=STATIONS as u16).collect();
    let mut sim = Sim::new(&las, &["bts-info", "handover-v1", "ms-cell", BREW_EXT_MS_MOVED]);
    let radios: Vec<(u32, usize, u32)> = (0..RADIOS).map(|r| (FIRST_ISSI + r, r as usize % STATIONS, GROUPS[r as usize % 5])).collect();
    for &(issi, st, gssi) in &radios {
        sim.register(st, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
    }

    for (i, gssi) in GROUPS.into_iter().enumerate() {
        sim.clear_air();
        let (talker, left) = (FIRST_ISSI + i as u32, i + 5);
        let session = sim.start_call(i, talker, gssi);
        let started = sim.ticks;
        sim.run_until(&format!("station {left} runs the call on {gssi}"), |s| s.local_call_id(left, gssi).is_some());
        let leavers: Vec<u32> = radios.iter().filter(|(_, st, _)| *st == left).map(|(issi, _, _)| *issi).collect();
        assert_eq!(leavers.len(), 3);
        for (n, &issi) in leavers.iter().enumerate() {
            let to = (left + 1 + n) % STATIONS;
            let old_call_id = sim.local_call_id(left, gssi).unwrap();
            assert!(!group_release_sent(&sim.stations[left].air, gssi), "station {left} released while radios of {gssi} are there");
            sim.register(to, issi, LocationUpdateType::RoamingLocationUpdating, &[gssi]);
            sim.submit(to, u_restore(issi, old_call_id, gssi, Some(las[left] as u64)));
            sim.run_until(&format!("ISSI {issi} is restored on station {to}"), |s| restore_ack(&s.stations[to].air, issi).is_some());
        }
        sim.run_until(&format!("station {left} released its leg of the call on {gssi}"), |s| {
            group_release_sent(&s.stations[left].air, gssi)
        });
        // The sim sends no voice, so CMCE's network media watchdog would release the leg after
        // 720 ticks anyway; the release must come well before that.
        assert!(sim.ticks - started < 500, "station {left} released only after {} ticks", sim.ticks - started);
        assert!(sim.relay.calls.contains_key(&session), "the call itself runs on");
        for &issi in &leavers {
            assert!(sim.relay.ms_moved.contains(&(issi, left)));
            assert!(!sim.relay.deregistrations.contains(&(issi, left)), "station {left} deregistered ISSI {issi}");
        }
        sim.end_call(i, talker, gssi, session);
    }
}
