//! Brew protocol binary message parsing and serialization (2-byte [kind, type] prefix, little-endian)

use tetra_saps::control::call_control::{CellReselection, NetworkRestoredCall};
use uuid::Uuid;

// ─── Message classes ───────────────────────────────────────────────

pub const BREW_CLASS_SUBSCRIBER: u8 = 0xf0;
pub const BREW_CLASS_CALL_CONTROL: u8 = 0xf1;
pub const BREW_CLASS_FRAME: u8 = 0xf2;
pub const BREW_CLASS_ERROR: u8 = 0xf3;
pub const BREW_CLASS_SERVICE: u8 = 0xf4;

// ─── Subscriber control types (0xf0) ──────────────────────────────

pub const BREW_SUBSCRIBER_DEREGISTER: u8 = 0;
pub const BREW_SUBSCRIBER_REGISTER: u8 = 1;
pub const BREW_SUBSCRIBER_REREGISTER: u8 = 2;
pub const BREW_SUBSCRIBER_AFFILIATE: u8 = 8;
pub const BREW_SUBSCRIBER_DEAFFILIATE: u8 = 9;

// ─── Call control types (0xf1) ────────────────────────────────────

pub const CALL_STATE_GROUP_TX: u8 = 2;
pub const CALL_STATE_GROUP_IDLE: u8 = 3;
pub const CALL_STATE_SETUP_REQUEST: u8 = 4;
pub const CALL_STATE_SETUP_ACCEPT: u8 = 5;
pub const CALL_STATE_SETUP_REJECT: u8 = 6;
pub const CALL_STATE_CALL_ALERT: u8 = 7;
pub const CALL_STATE_CONNECT_REQUEST: u8 = 8;
pub const CALL_STATE_CONNECT_CONFIRM: u8 = 9;
pub const CALL_STATE_CALL_RELEASE: u8 = 10;
pub const CALL_STATE_SHORT_TRANSFER: u8 = 11;
pub const CALL_STATE_SIMPLEX_GRANTED: u8 = 12;
pub const CALL_STATE_SIMPLEX_IDLE: u8 = 13;

// ─── Frame types (0xf2) ──────────────────────────────────────────

pub const FRAME_TYPE_TRAFFIC_CHANNEL: u8 = 0;
pub const FRAME_TYPE_SDS_TRANSFER: u8 = 1;
pub const FRAME_TYPE_SDS_REPORT: u8 = 2;
pub const FRAME_TYPE_DTMF_DATA: u8 = 3;
pub const FRAME_TYPE_PACKET_DATA: u8 = 4;

// ─── Circuit/individual call wire format ─────────────────────────
const CIRCULAR_NUMBER_LEN: usize = 32;
/// Total wire size of BrewCircularCall payload: source(4)+dest(4)+number(32)+11 single-byte fields
const CIRCULAR_CALL_LEN: usize = 4 + 4 + CIRCULAR_NUMBER_LEN + 11;

// ─── Error types (0xf3) ──────────────────────────────────────────

pub const BREW_TYPE_MALFORMED: u8 = 0;
pub const BREW_TYPE_RESTRICTED: u8 = 1;

// ─── Parsed message types ─────────────────────────────────────────

/// Top-level parsed Brew message
#[derive(Debug, Clone)]
pub enum BrewMessage {
    Subscriber(BrewSubscriberMessage),
    CallControl(BrewCallControlMessage),
    Frame(BrewFrameMessage),
    Error(BrewErrorMessage),
    Service(BrewServiceMessage),
}

/// Subscriber control (0xf0)
#[derive(Debug, Clone)]
pub struct BrewSubscriberMessage {
    pub msg_type: u8,
    pub number: u32,      // ISSI
    pub time: u64,        // UNIX timestamp
    pub fraction: u32,    // Nanoseconds
    pub groups: Vec<u32>, // GSSIs (for affiliate/deaffiliate)
}

/// Group transmission data, part of CALL_STATE_GROUP_TX
#[derive(Debug, Clone)]
pub struct BrewGroupTransmission {
    pub source: u32,      // ISSI of caller
    pub destination: u32, // GSSI of group
    pub priority: u8,
    pub access: u8,
    pub service: u16, // Speech service
    /// SS-TPI mnemonic name (Brew v1+, optional). Raw 34-byte field:
    /// byte 0: text coding scheme (7-bit), bytes 1+: encoded name.
    /// None when server is v0 or mnemonic not present in message.
    pub mnemonic: Option<[u8; 34]>,
}

/// Circuit/PBX/phone call data, part of SETUP_REQUEST / CONNECT_REQUEST
/// (ETSI EN 300 392-2 §14 individual call fields mapped to Brew wire format)
#[derive(Debug, Clone)]
pub struct BrewCircularCall {
    pub source: u32,
    pub destination: u32,
    pub number: String, // ASCII, up to 32 bytes, NUL-padded
    pub priority: u8,
    pub service: u8,
    pub mode: u8,
    pub duplex: u8,
    pub method: u8,
    pub communication: u8,
    pub grant: u8,
    pub permission: u8,
    pub timeout: u8,
    pub ownership: u8,
    pub queued: u8,
    /// SS-TPI mnemonic name (Brew v1+, optional). Present in SETUP_REQUEST only.
    /// None when server is v0 or mnemonic not present.
    pub mnemonic: Option<[u8; 34]>,
}

/// Circuit grant payload, part of CONNECT_CONFIRM / SIMPLEX_* states
#[derive(Debug, Clone)]
pub struct BrewCircularGrant {
    pub grant: u8,
    pub permission: u8,
}

/// Call control (0xf1)
#[derive(Debug, Clone)]
pub struct BrewCallControlMessage {
    pub call_state: u8,
    pub identifier: Uuid, // Call session UUID (16 bytes)
    pub payload: BrewCallPayload,
}

/// Union-like payload for call control messages
#[derive(Debug, Clone)]
pub enum BrewCallPayload {
    /// CALL_STATE_GROUP_TX
    GroupTransmission(BrewGroupTransmission),
    /// CALL_STATE_GROUP_IDLE, CALL_STATE_SETUP_REJECT, CALL_STATE_CALL_RELEASE
    Cause(u8),
    /// CALL_STATE_SETUP_ACCEPT, CALL_STATE_CALL_ALERT — no extra payload
    Empty,
    /// CALL_STATE_SHORT_TRANSFER (SDS header)
    ShortTransfer { source: u32, destination: u32 },
    /// CALL_STATE_SETUP_REQUEST, CALL_STATE_CONNECT_REQUEST (individual/circuit call)
    CircularCall(BrewCircularCall),
    /// CALL_STATE_CONNECT_CONFIRM, CALL_STATE_SIMPLEX_GRANTED, CALL_STATE_SIMPLEX_IDLE
    CircularGrant(BrewCircularGrant),
    /// Unknown/unhandled call state
    Raw(Vec<u8>),
}

/// Voice and data frames (0xf2)
#[derive(Debug, Clone)]
pub struct BrewFrameMessage {
    pub frame_type: u8,
    pub identifier: Uuid, // Call session UUID
    pub length_bits: u16, // Length of data in bits
    pub data: Vec<u8>,
}

/// Error messages (0xf3)
#[derive(Debug, Clone)]
pub struct BrewErrorMessage {
    pub error_type: u8,
    pub data: Vec<u8>,
}

/// Service messages (0xf4)
#[derive(Debug, Clone)]
pub struct BrewServiceMessage {
    pub service_type: u8,
    pub json_data: String,
}

// ─── Parsing ──────────────────────────────────────────────────────

/// Parse error
#[derive(Debug)]
pub enum BrewParseError {
    TooShort(usize),
    UnknownClass(u8),
    InvalidUtf8,
    InvalidUuid,
}

impl std::fmt::Display for BrewParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "message too short: {} bytes", n),
            Self::UnknownClass(c) => write!(f, "unknown message class: 0x{:02x}", c),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in service message"),
            Self::InvalidUuid => write!(f, "invalid UUID in call control message"),
        }
    }
}

/// Read a little-endian u16 from a byte slice
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian u64 from a byte slice
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Write a little-endian u16 to a byte vec
fn write_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 to a byte vec
fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u64 to a byte vec
fn write_u64_le(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Parse a raw binary Brew message into a typed BrewMessage
pub fn parse_brew_message(data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    if data.len() < 2 {
        return Err(BrewParseError::TooShort(data.len()));
    }

    let kind = data[0];
    let msg_type = data[1];

    match kind {
        BREW_CLASS_SUBSCRIBER => parse_subscriber(msg_type, data),
        BREW_CLASS_CALL_CONTROL => parse_call_control(msg_type, data),
        BREW_CLASS_FRAME => parse_frame(msg_type, data),
        BREW_CLASS_ERROR => parse_error(msg_type, data),
        BREW_CLASS_SERVICE => parse_service(msg_type, data),
        _ => Err(BrewParseError::UnknownClass(kind)),
    }
}

fn parse_subscriber(msg_type: u8, data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    // Minimum: kind(1) + type(1) + number(4) + time(8) + fraction(4) = 18 bytes
    if data.len() < 18 {
        return Err(BrewParseError::TooShort(data.len()));
    }

    let number = read_u32_le(data, 2);
    let time = read_u64_le(data, 6);
    let fraction = read_u32_le(data, 14);

    // Remaining bytes are GSSIs (4 bytes each) for affiliate/deaffiliate
    let mut groups = Vec::new();
    let mut offset = 18;
    while offset + 4 <= data.len() {
        groups.push(read_u32_le(data, offset));
        offset += 4;
    }

    Ok(BrewMessage::Subscriber(BrewSubscriberMessage {
        msg_type,
        number,
        time,
        fraction,
        groups,
    }))
}

fn parse_fixed_ascii(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes[..end].iter().copied().filter(|b| b.is_ascii()).map(char::from).collect()
}

fn write_fixed_ascii(buf: &mut Vec<u8>, value: &str, width: usize) {
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(width);
    buf.extend_from_slice(&bytes[..copy_len]);
    if width > copy_len {
        buf.resize(buf.len() + (width - copy_len), 0);
    }
}

fn parse_call_control(call_state: u8, data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    // Minimum: kind(1) + type(1) + uuid(16) = 18 bytes
    if data.len() < 18 {
        return Err(BrewParseError::TooShort(data.len()));
    }

    let uuid_bytes: [u8; 16] = data[2..18].try_into().map_err(|_| BrewParseError::InvalidUuid)?;
    let identifier = Uuid::from_bytes(uuid_bytes);

    let payload_data = &data[18..];

    let payload = match call_state {
        CALL_STATE_GROUP_TX => {
            // v0: source(4)+dest(4)+priority(1)+access(1)+service(2) = 12 bytes
            // v1: same + mnemonic(34) = 46 bytes
            if payload_data.len() < 12 {
                return Err(BrewParseError::TooShort(data.len()));
            }
            let mnemonic = if payload_data.len() >= 46 && payload_data[13] > 0 {
                // byte 12 = coding scheme, byte 13 = length in bits; 0 bits = no mnemonic
                let mut m = [0u8; 34];
                m.copy_from_slice(&payload_data[12..46]);
                Some(m)
            } else {
                None
            };
            BrewCallPayload::GroupTransmission(BrewGroupTransmission {
                source: read_u32_le(payload_data, 0),
                destination: read_u32_le(payload_data, 4),
                priority: payload_data[8],
                access: payload_data[9],
                service: read_u16_le(payload_data, 10),
                mnemonic,
            })
        }

        CALL_STATE_GROUP_IDLE | CALL_STATE_SETUP_REJECT | CALL_STATE_CALL_RELEASE => {
            // Single byte cause
            if payload_data.is_empty() {
                return Err(BrewParseError::TooShort(data.len()));
            }
            BrewCallPayload::Cause(payload_data[0])
        }

        CALL_STATE_SETUP_REQUEST | CALL_STATE_CONNECT_REQUEST => {
            // v0: source(4)+dest(4)+number(32)+11 single-byte fields = 51 bytes
            // v1 SETUP_REQUEST: same + mnemonic(34) = 85 bytes (CONNECT_REQUEST has no mnemonic)
            if payload_data.len() < CIRCULAR_CALL_LEN {
                return Err(BrewParseError::TooShort(data.len()));
            }
            let mnemonic = if call_state == CALL_STATE_SETUP_REQUEST
                && payload_data.len() >= CIRCULAR_CALL_LEN + 34
                && payload_data[CIRCULAR_CALL_LEN + 1] > 0
            {
                // byte 0 = coding scheme, byte 1 = length in bits; 0 bits = no mnemonic
                let mut m = [0u8; 34];
                m.copy_from_slice(&payload_data[CIRCULAR_CALL_LEN..CIRCULAR_CALL_LEN + 34]);
                Some(m)
            } else {
                None
            };
            BrewCallPayload::CircularCall(BrewCircularCall {
                source: read_u32_le(payload_data, 0),
                destination: read_u32_le(payload_data, 4),
                number: parse_fixed_ascii(&payload_data[8..8 + CIRCULAR_NUMBER_LEN]),
                priority: payload_data[40],
                service: payload_data[41],
                mode: payload_data[42],
                duplex: payload_data[43],
                method: payload_data[44],
                communication: payload_data[45],
                grant: payload_data[46],
                permission: payload_data[47],
                timeout: payload_data[48],
                ownership: payload_data[49],
                queued: payload_data[50],
                mnemonic,
            })
        }

        CALL_STATE_SETUP_ACCEPT | CALL_STATE_CALL_ALERT => {
            // No extra payload
            BrewCallPayload::Empty
        }

        CALL_STATE_CONNECT_CONFIRM | CALL_STATE_SIMPLEX_GRANTED | CALL_STATE_SIMPLEX_IDLE => {
            if payload_data.len() < 2 {
                return Err(BrewParseError::TooShort(data.len()));
            }
            BrewCallPayload::CircularGrant(BrewCircularGrant {
                grant: payload_data[0],
                permission: payload_data[1],
            })
        }

        CALL_STATE_SHORT_TRANSFER => {
            // BrewShortData: source(4) + destination(4) + number[32](char) = 40 bytes
            if payload_data.len() < 8 {
                return Err(BrewParseError::TooShort(data.len()));
            }
            BrewCallPayload::ShortTransfer {
                source: read_u32_le(payload_data, 0),
                destination: read_u32_le(payload_data, 4),
            }
        }

        _ => {
            // Store raw for unhandled types
            BrewCallPayload::Raw(payload_data.to_vec())
        }
    };

    Ok(BrewMessage::CallControl(BrewCallControlMessage {
        call_state,
        identifier,
        payload,
    }))
}

fn parse_frame(frame_type: u8, data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    // kind(1) + type(1) + uuid(16) + length(2) = 20 bytes minimum
    if data.len() < 20 {
        return Err(BrewParseError::TooShort(data.len()));
    }

    let uuid_bytes: [u8; 16] = data[2..18].try_into().map_err(|_| BrewParseError::InvalidUuid)?;
    let identifier = Uuid::from_bytes(uuid_bytes);

    let length_bits = read_u16_le(data, 18);
    let frame_data = data[20..].to_vec();

    Ok(BrewMessage::Frame(BrewFrameMessage {
        frame_type,
        identifier,
        length_bits,
        data: frame_data,
    }))
}

fn parse_error(error_type: u8, data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    Ok(BrewMessage::Error(BrewErrorMessage {
        error_type,
        data: data[2..].to_vec(),
    }))
}

fn parse_service(service_type: u8, data: &[u8]) -> Result<BrewMessage, BrewParseError> {
    // Data is NULL-terminated JSON
    let json_bytes = &data[2..];
    // Find NULL terminator or use full length
    let end = json_bytes.iter().position(|&b| b == 0).unwrap_or(json_bytes.len());
    let json_str = std::str::from_utf8(&json_bytes[..end]).map_err(|_| BrewParseError::InvalidUtf8)?;

    Ok(BrewMessage::Service(BrewServiceMessage {
        service_type,
        json_data: json_str.to_string(),
    }))
}

// ─── Building (outgoing messages) ─────────────────────────────────

/// Build a subscriber registration message

// ─── Circuit / individual call serializers ────────────────────────────────

fn build_circular_call(call_state: u8, session_uuid: &Uuid, call: &BrewCircularCall) -> Vec<u8> {
    // v1 mnemonic is only sent in SETUP_REQUEST, not CONNECT_REQUEST
    let include_mnemonic = call_state == CALL_STATE_SETUP_REQUEST && call.mnemonic.is_some();
    let cap = 2 + 16 + CIRCULAR_CALL_LEN + if include_mnemonic { 34 } else { 0 };
    let mut buf = Vec::with_capacity(cap);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(call_state);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u32_le(&mut buf, call.source);
    write_u32_le(&mut buf, call.destination);
    write_fixed_ascii(&mut buf, &call.number, CIRCULAR_NUMBER_LEN);
    buf.push(call.priority);
    buf.push(call.service);
    buf.push(call.mode);
    buf.push(call.duplex);
    buf.push(call.method);
    buf.push(call.communication);
    buf.push(call.grant);
    buf.push(call.permission);
    buf.push(call.timeout);
    buf.push(call.ownership);
    buf.push(call.queued);
    if include_mnemonic {
        if let Some(m) = &call.mnemonic {
            buf.extend_from_slice(m);
        }
    }
    buf
}

/// Build SETUP_REQUEST for circuit/PBX/phone call (ETSI 14.7.1 BS→TetraPack).
pub fn build_setup_request(session_uuid: &Uuid, call: &BrewCircularCall) -> Vec<u8> {
    build_circular_call(CALL_STATE_SETUP_REQUEST, session_uuid, call)
}

/// Build CONNECT_REQUEST for circuit/PBX/phone call (ETSI 14.7.5 BS→TetraPack).
pub fn build_connect_request(session_uuid: &Uuid, call: &BrewCircularCall) -> Vec<u8> {
    build_circular_call(CALL_STATE_CONNECT_REQUEST, session_uuid, call)
}

/// Build SETUP_ACCEPT — no payload (ETSI 14.7.2 BS→TetraPack).
pub fn build_setup_accept(session_uuid: &Uuid) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_SETUP_ACCEPT);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf
}

/// Build CALL_ALERT — no payload (ETSI 14.7.3 BS→TetraPack, called MS ringing).
pub fn build_call_alert(session_uuid: &Uuid) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_CALL_ALERT);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf
}

/// Build SETUP_REJECT with disconnect cause (ETSI 14.7.2 BS→TetraPack).
pub fn build_setup_reject(session_uuid: &Uuid, cause: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(19);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_SETUP_REJECT);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(cause);
    buf
}

/// Build CONNECT_CONFIRM with grant/permission (ETSI 14.7.6 BS→TetraPack).
pub fn build_connect_confirm(session_uuid: &Uuid, grant: u8, permission: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_CONNECT_CONFIRM);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(grant);
    buf.push(permission);
    buf
}

/// Build SIMPLEX_GRANTED with grant/permission.
pub fn build_simplex_granted(session_uuid: &Uuid, grant: u8, permission: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_SIMPLEX_GRANTED);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(grant);
    buf.push(permission);
    buf
}

/// Build SIMPLEX_IDLE with grant/permission.
pub fn build_simplex_idle(session_uuid: &Uuid, grant: u8, permission: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_SIMPLEX_IDLE);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(grant);
    buf.push(permission);
    buf
}

/// Build CALL_RELEASE with disconnect cause (ETSI 14.7.x both directions).
pub fn build_call_release(session_uuid: &Uuid, cause: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(19);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_CALL_RELEASE);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(cause);
    buf
}

/// Build DTMF data frame message.
pub fn build_dtmf_frame(session_uuid: &Uuid, length_bits: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + data.len());
    buf.push(BREW_CLASS_FRAME);
    buf.push(FRAME_TYPE_DTMF_DATA);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u16_le(&mut buf, length_bits);
    buf.extend_from_slice(data);
    buf
}

pub fn build_subscriber_register(issi: u32, groups: &[u32]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut buf = Vec::with_capacity(18 + groups.len() * 4);
    buf.push(BREW_CLASS_SUBSCRIBER);
    buf.push(BREW_SUBSCRIBER_REGISTER);
    write_u32_le(&mut buf, issi);
    write_u64_le(&mut buf, now.as_secs());
    write_u32_le(&mut buf, now.subsec_nanos());
    buf
}

/// Build a subscriber re-registration message (for already-registered subscribers)
pub fn build_subscriber_reregister(issi: u32) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut buf = Vec::with_capacity(18);
    buf.push(BREW_CLASS_SUBSCRIBER);
    buf.push(BREW_SUBSCRIBER_REREGISTER);
    write_u32_le(&mut buf, issi);
    write_u64_le(&mut buf, now.as_secs());
    write_u32_le(&mut buf, now.subsec_nanos());
    buf
}

/// Build a subscriber affiliation message
pub fn build_subscriber_affiliate(issi: u32, groups: &[u32]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut buf = Vec::with_capacity(18 + groups.len() * 4);
    buf.push(BREW_CLASS_SUBSCRIBER);
    buf.push(BREW_SUBSCRIBER_AFFILIATE);
    write_u32_le(&mut buf, issi);
    write_u64_le(&mut buf, now.as_secs());
    write_u32_le(&mut buf, now.subsec_nanos());
    for &gssi in groups {
        write_u32_le(&mut buf, gssi);
    }
    buf
}

/// Build a subscriber deaffiliation message
pub fn build_subscriber_deaffiliate(issi: u32, groups: &[u32]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut buf = Vec::with_capacity(18 + groups.len() * 4);
    buf.push(BREW_CLASS_SUBSCRIBER);
    buf.push(BREW_SUBSCRIBER_DEAFFILIATE);
    write_u32_le(&mut buf, issi);
    write_u64_le(&mut buf, now.as_secs());
    write_u32_le(&mut buf, now.subsec_nanos());
    for &gssi in groups {
        write_u32_le(&mut buf, gssi);
    }
    buf
}

/// Build a subscriber deregistration message
pub fn build_subscriber_deregister(issi: u32) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut buf = Vec::with_capacity(18);
    buf.push(BREW_CLASS_SUBSCRIBER);
    buf.push(BREW_SUBSCRIBER_DEREGISTER);
    write_u32_le(&mut buf, issi);
    write_u64_le(&mut buf, now.as_secs());
    write_u32_le(&mut buf, now.subsec_nanos());
    buf
}

/// Build a group call transmission start message (GROUP_TX)
/// Sent when a local radio starts transmitting on a subscribed group.
/// `mnemonic` is the optional SS-TPI talking party name (Brew v1, 34 bytes raw).
pub fn build_group_tx(
    session_uuid: &Uuid,
    source_issi: u32,
    dest_gssi: u32,
    priority: u8,
    service: u16,
    mnemonic: Option<&[u8; 34]>,
) -> Vec<u8> {
    // v0: kind(1)+type(1)+uuid(16)+source(4)+dest(4)+priority(1)+access(1)+service(2) = 30
    // v1: same + mnemonic(34) = 64
    let cap = if mnemonic.is_some() { 64 } else { 30 };
    let mut buf = Vec::with_capacity(cap);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_GROUP_TX);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u32_le(&mut buf, source_issi);
    write_u32_le(&mut buf, dest_gssi);
    buf.push(priority);
    buf.push(0); // access = 0 (normal)
    write_u16_le(&mut buf, service);
    if let Some(m) = mnemonic {
        buf.extend_from_slice(m);
    }
    buf
}

/// Build a voice frame message (ACELP traffic channel data)
/// `data` should be packed ACELP bits (1 bit per byte in STE format, with
/// a leading STE header byte prepended by the caller if needed)
pub fn build_voice_frame(session_uuid: &Uuid, length_bits: u16, data: &[u8]) -> Vec<u8> {
    // kind(1) + type(1) + uuid(16) + length(2) + data = 20 + data.len()
    let mut buf = Vec::with_capacity(20 + data.len());
    buf.push(BREW_CLASS_FRAME);
    buf.push(FRAME_TYPE_TRAFFIC_CHANNEL);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u16_le(&mut buf, length_bits);
    buf.extend_from_slice(data);
    buf
}

/// Build a group call idle (hangup) message
pub fn build_group_idle(session_uuid: &Uuid, cause: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(19);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_GROUP_IDLE);
    buf.extend_from_slice(session_uuid.as_bytes());
    buf.push(cause);
    buf
}

/// Build a CALL_STATE_SHORT_TRANSFER message (SDS header with source/dest/number)
pub fn build_short_transfer(session_uuid: &Uuid, source: u32, destination: u32) -> Vec<u8> {
    // kind(1) + type(1) + uuid(16) + source(4) + destination(4) + number[32](1 byte each) = 58
    let mut buf = Vec::with_capacity(58);
    buf.push(BREW_CLASS_CALL_CONTROL);
    buf.push(CALL_STATE_SHORT_TRANSFER);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u32_le(&mut buf, source);
    write_u32_le(&mut buf, destination);
    // number field: 32 bytes, zero-filled (external subscriber number not supported)
    buf.extend_from_slice(&[0u8; 32]);
    buf
}

/// Build a FRAME_TYPE_SDS_TRANSFER message (SDS Type 4 PDU payload)
pub fn build_sds_frame(session_uuid: &Uuid, length_bits: u16, data: &[u8]) -> Vec<u8> {
    // kind(1) + type(1) + uuid(16) + length(2) + data = 20 + data.len()
    let mut buf = Vec::with_capacity(20 + data.len());
    buf.push(BREW_CLASS_FRAME);
    buf.push(FRAME_TYPE_SDS_TRANSFER);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u16_le(&mut buf, length_bits);
    buf.extend_from_slice(data);
    buf
}

/// Build a FRAME_TYPE_SDS_REPORT message (delivery acknowledgement)
/// Wire: kind(1) + type(1) + uuid(16) + length_bits(2) + status(1) = 21 bytes
pub fn build_sds_report(session_uuid: &Uuid, status: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(21);
    buf.push(BREW_CLASS_FRAME);
    buf.push(FRAME_TYPE_SDS_REPORT);
    buf.extend_from_slice(session_uuid.as_bytes());
    write_u16_le(&mut buf, 8); // length_bits = 8 (1 byte status)
    buf.push(status);
    buf
}

/// Service type for RSSI measurements
pub const BREW_SERVICE_RSSI: u8 = 0x10;

/// Build a Service (0xf4) RSSI update message.
///
/// Sends the current RSSI reading for an MS to the Brew server as JSON:
/// `{"issi": 2260570, "rssi_dbfs": -42.3}`
///
/// Service type 0x10 is used to distinguish RSSI messages from subscriber
/// query messages (type 0x01). The JSON is NULL-terminated per SmartConnect convention.
pub fn build_service_rssi(issi: u32, rssi_dbfs: f32) -> Vec<u8> {
    let json = format!("{{\"issi\":{},\"rssi_dbfs\":{:.1}}}", issi, rssi_dbfs);
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(BREW_SERVICE_RSSI);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Service type announcing the cells this station serves (brew-server carrier registry)
pub const BREW_SERVICE_BTS_INFO: u8 = 0x14;

/// Brew extension a server offers (`X-Brew-Extensions`) when it accepts [`BREW_SERVICE_BTS_INFO`]
pub const BREW_EXT_BTS_INFO: &str = "bts-info";

/// One cell in a [`BREW_SERVICE_BTS_INFO`] message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewBtsCell {
    /// Cell number within the station (0 = primary, then the `[[cells]]` ids); the server names
    /// the cell `<login>/<cell>`
    pub cell: u8,
    pub carrier: u16,
    /// Absolute band plan in the "main carrier number extension" layout, never "same as serving"
    pub carrier_ext: u16,
    pub location_area: u16,
}

/// Build a Service (0xf4) BTS info message, NULL-terminated JSON:
/// `{"mcc":232,"mnc":5,"cells":[{"cell":0,"carrier":1528,"carrier_ext":264,"location_area":1}],"capabilities":[]}`
///
/// Not part of Brew as TetraPack / BrandMeister speak it: only send it to a server that offered
/// [`BREW_EXT_BTS_INFO`].
pub fn build_service_bts_info(mcc: u16, mnc: u16, cells: &[BrewBtsCell], capabilities: &[&str]) -> Vec<u8> {
    let cells: Vec<serde_json::Value> = cells
        .iter()
        .map(|c| serde_json::json!({ "cell": c.cell, "carrier": c.carrier, "carrier_ext": c.carrier_ext, "location_area": c.location_area }))
        .collect();
    let json = serde_json::json!({ "mcc": mcc, "mnc": mnc, "cells": cells, "capabilities": capabilities }).to_string();
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(BREW_SERVICE_BTS_INFO);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Service type reporting the cell (carrier) a radio registered on (brew-server)
pub const BREW_SERVICE_MS_CELL: u8 = 0x18;

/// Brew extension a server offers (`X-Brew-Extensions`) when it accepts [`BREW_SERVICE_MS_CELL`]
pub const BREW_EXT_MS_CELL: &str = "ms-cell";

/// Build a Service (0xf4) MS cell message, NULL-terminated JSON:
/// `{"issi":2320001,"carrier":1528,"carrier_ext":264}`. `carrier_ext` is the cell's absolute band
/// plan, as in [`BREW_SERVICE_BTS_INFO`].
///
/// Not part of Brew as TetraPack / BrandMeister speak it: only send it to a server that offered
/// [`BREW_EXT_MS_CELL`].
pub fn build_service_ms_cell(issi: u32, carrier: u16, carrier_ext: u16) -> Vec<u8> {
    let json = serde_json::json!({ "issi": issi, "carrier": carrier, "carrier_ext": carrier_ext }).to_string();
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(BREW_SERVICE_MS_CELL);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Service type the server sends to the station a radio was registered on when it registered on
/// another station without a handover prepared through the server: `{"issi":2320001}`
/// (brew-server)
pub const BREW_SERVICE_MS_MOVED: u8 = 0x19;

/// Brew extension a server offers (`X-Brew-Extensions`) when it can send
/// [`BREW_SERVICE_MS_MOVED`]; the station then names it in its `SERVICE_BTS_INFO` capabilities
/// to get them
pub const BREW_EXT_MS_MOVED: &str = "ms-moved";

/// Parse a [`BREW_SERVICE_MS_MOVED`] payload: the ISSI that left (unknown fields ignored).
pub fn parse_ms_moved(json_data: &str) -> Result<u32, String> {
    let json: serde_json::Value = serde_json::from_str(json_data).map_err(|e| e.to_string())?;
    Ok(json_uint(&json, "issi", 0xff_ffff)? as u32)
}

/// Service type a station sends when a radio left it, naming the category of cell reselection:
/// `{"issi":2320001,"type":"announced_type_3"}` (brew-server)
pub const BREW_SERVICE_MS_RESELECTION: u8 = 0x1A;

/// Brew extension a server offers (`X-Brew-Extensions`) when it accepts
/// [`BREW_SERVICE_MS_RESELECTION`]
pub const BREW_EXT_MS_RESELECTION: &str = "ms-reselection";

/// The `type` of a [`BREW_SERVICE_MS_RESELECTION`].
pub fn reselection_name(reselection: CellReselection) -> &'static str {
    match reselection {
        CellReselection::Undeclared => "undeclared",
        CellReselection::Unannounced => "unannounced",
        CellReselection::AnnouncedType1 => "announced_type_1",
        CellReselection::AnnouncedType2 => "announced_type_2",
        CellReselection::AnnouncedType3 => "announced_type_3",
    }
}

/// Build a Service (0xf4) MS reselection message, NULL-terminated JSON. Not part of Brew as
/// TetraPack / BrandMeister speak it: only send it to a server that offered
/// [`BREW_EXT_MS_RESELECTION`].
pub fn build_service_ms_reselection(issi: u32, reselection: CellReselection) -> Vec<u8> {
    let json = serde_json::json!({ "issi": issi, "type": reselection_name(reselection) }).to_string();
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(BREW_SERVICE_MS_RESELECTION);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Service type for restoring an individual call that ran on the station a radio left: this
/// station asks `{"issi":2320972,"peer":2320997}` (peer 0 for the dummy address) when the radio
/// sends U-CALL RESTORE for a call it does not hold, and the server answers with the call
/// (`uuid`, `duplex`, `priority`, `floor`: ISSI holding a simplex floor or 0) or without `uuid`
/// (brew-server)
pub const BREW_SERVICE_CALL_RESTORE: u8 = 0x1B;

/// Brew extension a server offers (`X-Brew-Extensions`) when it moves individual calls with their
/// radio ([`BREW_SERVICE_CALL_RESTORE`]); the station then names it in its `SERVICE_BTS_INFO`
/// capabilities
pub const BREW_EXT_CALL_RESTORE: &str = "call-restore";

/// Build a Service (0xf4) call restore request, NULL-terminated JSON. Only for a server that
/// offered [`BREW_EXT_CALL_RESTORE`].
pub fn build_service_call_restore(issi: u32, peer: u32) -> Vec<u8> {
    let json = serde_json::json!({ "issi": issi, "peer": peer }).to_string();
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(BREW_SERVICE_CALL_RESTORE);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Parse a [`BREW_SERVICE_CALL_RESTORE`] answer: (issi, peer, the call or `None`). Unknown
/// fields are ignored.
pub fn parse_call_restore_answer(json_data: &str) -> Result<(u32, u32, Option<NetworkRestoredCall>), String> {
    let json: serde_json::Value = serde_json::from_str(json_data).map_err(|e| e.to_string())?;
    let issi = json_uint(&json, "issi", 0xff_ffff)? as u32;
    let peer = json_opt_uint(&json, "peer", 0xff_ffff)?.unwrap_or(0) as u32;
    let call = match json.get("uuid").and_then(|v| v.as_str()) {
        None => None,
        Some(id) => Some(NetworkRestoredCall {
            brew_uuid: Uuid::parse_str(id).map_err(|e| format!("uuid: {e}"))?,
            simplex_duplex: json.get("duplex").and_then(|v| v.as_bool()).ok_or("missing duplex")?,
            priority: json_opt_uint(&json, "priority", 15)?.unwrap_or(0) as u8,
            floor_issi: json_opt_uint(&json, "floor", 0xff_ffff)?.filter(|f| *f != 0).map(|f| f as u32),
        }),
    };
    Ok((issi, peer, call))
}

/// Service type: serving station asks the target to prepare an announced cell reselection
/// (U-PREPARE without a registration, TS 100 392-2 clause 18.4.1.4.6)
pub const BREW_SERVICE_HO_PREPARE: u8 = 0x15;
/// Service type: as [`BREW_SERVICE_HO_PREPARE`], carrying the MM registration from U-PREPARE
pub const BREW_SERVICE_HO_FORWARD_REG: u8 = 0x16;
/// Service type: the target's answer to [`BREW_SERVICE_HO_PREPARE`] / [`BREW_SERVICE_HO_FORWARD_REG`]
pub const BREW_SERVICE_HO_RESULT: u8 = 0x17;

/// Brew extension a server offers (`X-Brew-Extensions`) when it relays the handover messages, and
/// the capability this station announces in [`BREW_SERVICE_BTS_INFO`] when it answers them
pub const BREW_EXT_HANDOVER: &str = "handover-v1";

/// `SERVICE_HO_RESULT` status: the target registered the radio (or is prepared)
pub const BREW_HO_STATUS_OK: u8 = 0;
/// `SERVICE_HO_RESULT` status: the target's MM rejected the registration
pub const BREW_HO_STATUS_REJECTED: u8 = 1;
/// `SERVICE_HO_RESULT` status (server only): no Basestation serves the target cell
pub const BREW_HO_STATUS_NO_TARGET: u8 = 2;
/// `SERVICE_HO_RESULT` status (server only): the target did not answer in time
pub const BREW_HO_STATUS_TIMEOUT: u8 = 3;

/// Largest MM SDU carried in a handover message
pub const BREW_HO_MAX_SDU_BITS: u16 = 4096;

/// An MM PDU inside a handover message: `sdu` (hex) plus `sdu_len_bits`, padding at the end
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewHoSdu {
    pub bytes: Vec<u8>,
    pub len_bits: u16,
}

impl BrewHoSdu {
    /// Pack the bits of `bits` from its start to its end (at most [`BREW_HO_MAX_SDU_BITS`]).
    pub fn from_bitbuffer(bits: &tetra_core::BitBuffer) -> Self {
        let bitstr = bits.to_bitstr();
        let len = bitstr.len().min(BREW_HO_MAX_SDU_BITS as usize);
        let mut bytes = vec![0u8; len.div_ceil(8)];
        for (i, bit) in bitstr.bytes().take(len).enumerate() {
            if bit == b'1' {
                bytes[i / 8] |= 0x80 >> (i % 8);
            }
        }
        Self { bytes, len_bits: len as u16 }
    }

    pub fn to_bitbuffer(&self) -> tetra_core::BitBuffer {
        let bits: String = (0..self.len_bits as usize)
            .map(|i| if self.bytes[i / 8] & (0x80 >> (i % 8)) != 0 { '1' } else { '0' })
            .collect();
        tetra_core::BitBuffer::from_bitstr(&bits)
    }

    fn hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn parse(json: &serde_json::Value) -> Result<Option<Self>, String> {
        match (json.get("sdu"), json.get("sdu_len_bits")) {
            (None, None) => Ok(None),
            (Some(sdu), Some(len)) => {
                let hex = sdu.as_str().ok_or("sdu is not a string")?;
                let len_bits = len.as_u64().filter(|l| *l <= BREW_HO_MAX_SDU_BITS as u64).ok_or("bad sdu_len_bits")? as u16;
                if hex.len() % 2 != 0 || hex.len() / 2 != (len_bits as usize).div_ceil(8) {
                    return Err("sdu length does not match sdu_len_bits".into());
                }
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| "sdu is not hex")?;
                Ok(Some(Self { bytes, len_bits }))
            }
            _ => Err("sdu and sdu_len_bits go together".into()),
        }
    }
}

/// `SERVICE_HO_PREPARE` (no `sdu`) or `SERVICE_HO_FORWARD_REG` (with `sdu`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewHoRequest {
    pub transaction_id: u32,
    pub issi: u32,
    pub target_carrier: u16,
    /// Absolute band plan of the target cell, as in [`BREW_SERVICE_BTS_INFO`]
    pub target_carrier_ext: u16,
    pub target_mcc: Option<u16>,
    pub target_mnc: Option<u16>,
    pub target_location_area: Option<u16>,
    /// The MM PDU from U-PREPARE: present for `SERVICE_HO_FORWARD_REG`
    pub sdu: Option<BrewHoSdu>,
    /// `call.gssi`: the group call the MS is in on the serving cell, when the serving station
    /// can use a channel on the target for it (announced type 1 cell reselection)
    pub call_gssi: Option<u32>,
}

/// `channel` in `SERVICE_HO_RESULT`: where the target runs the MS's call (type 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrewHoChannel {
    /// The target cell's call identifier (14 bits)
    pub call_id: u16,
    pub carrier: u16,
    /// Timeslot 1 to 4
    pub timeslot: u8,
    /// Traffic usage marker (4 to 63)
    pub usage: u8,
}

/// `SERVICE_HO_RESULT`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewHoResult {
    pub transaction_id: u32,
    pub issi: u32,
    pub status: u8,
    /// Why there is no target (server, with [`BREW_HO_STATUS_NO_TARGET`]), e.g. `gone`
    pub reason: Option<String>,
    /// The target's MM answer for D-NEW-CELL
    pub sdu: Option<BrewHoSdu>,
    /// The target's traffic channel for the call named in the request
    pub channel: Option<BrewHoChannel>,
}

fn json_uint(json: &serde_json::Value, key: &str, max: u64) -> Result<u64, String> {
    json.get(key)
        .and_then(|v| v.as_u64())
        .filter(|v| *v <= max)
        .ok_or_else(|| format!("missing or out of range: {key}"))
}

fn json_opt_uint(json: &serde_json::Value, key: &str, max: u64) -> Result<Option<u64>, String> {
    match json.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(_) => json_uint(json, key, max).map(Some),
    }
}

/// Parse a `SERVICE_HO_PREPARE` / `SERVICE_HO_FORWARD_REG` payload (unknown fields ignored).
pub fn parse_ho_request(service_type: u8, json_data: &str) -> Result<BrewHoRequest, String> {
    let json: serde_json::Value = serde_json::from_str(json_data).map_err(|e| e.to_string())?;
    let sdu = BrewHoSdu::parse(&json)?;
    match (service_type, &sdu) {
        (BREW_SERVICE_HO_PREPARE, None) | (BREW_SERVICE_HO_FORWARD_REG, Some(_)) => {}
        (BREW_SERVICE_HO_FORWARD_REG, None) => return Err("forward registration without sdu".into()),
        (BREW_SERVICE_HO_PREPARE, Some(_)) => return Err("prepare with sdu".into()),
        _ => return Err(format!("not a handover request: service type {service_type:#x}")),
    }
    Ok(BrewHoRequest {
        transaction_id: json_uint(&json, "transaction_id", u32::MAX as u64)? as u32,
        issi: json_uint(&json, "issi", 0xff_ffff)? as u32,
        target_carrier: json_uint(&json, "target_carrier", 4095)? as u16,
        target_carrier_ext: json_uint(&json, "target_carrier_ext", 1023)? as u16,
        target_mcc: json_opt_uint(&json, "target_mcc", 1023)?.map(|v| v as u16),
        target_mnc: json_opt_uint(&json, "target_mnc", 16383)?.map(|v| v as u16),
        target_location_area: json_opt_uint(&json, "target_location_area", 16383)?.map(|v| v as u16),
        sdu,
        call_gssi: json.get("call").and_then(|c| json_uint(c, "gssi", 0xff_ffff).ok()).map(|g| g as u32),
    })
}

/// `channel` of a result; a malformed one counts as none (the serving station then uses type 2).
fn parse_ho_channel(json: &serde_json::Value) -> Option<BrewHoChannel> {
    let c = json.get("channel").filter(|c| !c.is_null())?;
    let channel = (|| {
        Ok::<_, String>(BrewHoChannel {
            call_id: json_uint(c, "call_id", 16383)? as u16,
            carrier: json_uint(c, "carrier", 4095)? as u16,
            timeslot: json_uint(c, "timeslot", 4)? as u8,
            usage: json_uint(c, "usage", 63)? as u8,
        })
    })();
    match channel {
        Ok(ch) if ch.timeslot >= 1 && ch.usage >= 4 => Some(ch),
        other => {
            tracing::warn!("malformed handover channel {}: {:?}", c, other);
            None
        }
    }
}

/// Parse a `SERVICE_HO_RESULT` payload (unknown fields ignored).
pub fn parse_ho_result(json_data: &str) -> Result<BrewHoResult, String> {
    let json: serde_json::Value = serde_json::from_str(json_data).map_err(|e| e.to_string())?;
    Ok(BrewHoResult {
        transaction_id: json_uint(&json, "transaction_id", u32::MAX as u64)? as u32,
        issi: json_uint(&json, "issi", 0xff_ffff)? as u32,
        status: json_uint(&json, "status", u8::MAX as u64)? as u8,
        reason: json.get("reason").and_then(|r| r.as_str()).map(str::to_string),
        sdu: BrewHoSdu::parse(&json)?,
        channel: parse_ho_channel(&json),
    })
}

fn service_json(service_type: u8, json: serde_json::Value) -> Vec<u8> {
    let json = json.to_string();
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(service_type);
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

/// Build `SERVICE_HO_PREPARE` (no SDU) or `SERVICE_HO_FORWARD_REG` (with SDU).
///
/// Not part of Brew as TetraPack / BrandMeister speak it: only send it to a server that offered
/// [`BREW_EXT_HANDOVER`].
pub fn build_service_ho_request(req: &BrewHoRequest) -> Vec<u8> {
    let mut json = serde_json::json!({
        "transaction_id": req.transaction_id,
        "issi": req.issi,
        "target_carrier": req.target_carrier,
        "target_carrier_ext": req.target_carrier_ext,
    });
    let target = [
        ("target_mcc", req.target_mcc),
        ("target_mnc", req.target_mnc),
        ("target_location_area", req.target_location_area),
    ];
    for (key, value) in target {
        if let Some(v) = value {
            json[key] = v.into();
        }
    }
    let service_type = match &req.sdu {
        Some(sdu) => {
            json["sdu"] = sdu.hex().into();
            json["sdu_len_bits"] = sdu.len_bits.into();
            BREW_SERVICE_HO_FORWARD_REG
        }
        None => BREW_SERVICE_HO_PREPARE,
    };
    if let Some(gssi) = req.call_gssi {
        json["call"] = serde_json::json!({ "gssi": gssi });
    }
    service_json(service_type, json)
}

/// Build `SERVICE_HO_RESULT`. Only sent in answer to a handover request the server relayed.
pub fn build_service_ho_result(res: &BrewHoResult) -> Vec<u8> {
    let mut json = serde_json::json!({ "transaction_id": res.transaction_id, "issi": res.issi, "status": res.status });
    if let Some(reason) = &res.reason {
        json["reason"] = reason.as_str().into();
    }
    if let Some(sdu) = &res.sdu {
        json["sdu"] = sdu.hex().into();
        json["sdu_len_bits"] = sdu.len_bits.into();
    }
    if let Some(c) = &res.channel {
        json["channel"] = serde_json::json!({
            "call_id": c.call_id, "carrier": c.carrier, "timeslot": c.timeslot, "usage": c.usage
        });
    }
    service_json(BREW_SERVICE_HO_RESULT, json)
}

/// Build a query subscribers service message
pub fn build_query_subscribers(issis: &[u32]) -> Vec<u8> {
    let json = serde_json::to_string(issis).unwrap_or_else(|_| "[]".to_string());
    let mut buf = Vec::with_capacity(3 + json.len());
    buf.push(BREW_CLASS_SERVICE);
    buf.push(1); // Query subscribers type
    buf.extend_from_slice(json.as_bytes());
    buf.push(0); // NULL terminator
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Handover messages (docs/protocol.md of the handover project) ──

    #[test]
    fn ho_sdu_keeps_odd_bit_lengths() {
        let bits = tetra_core::BitBuffer::from_bitstr("101000011011001011");
        let sdu = BrewHoSdu::from_bitbuffer(&bits);
        assert_eq!(sdu, BrewHoSdu { bytes: vec![0xa1, 0xb2, 0xc0], len_bits: 18 });
        assert_eq!(sdu.to_bitbuffer().to_bitstr(), "101000011011001011");
    }

    #[test]
    fn ho_request_roundtrip_both_kinds() {
        let mut req = BrewHoRequest {
            transaction_id: 7,
            issi: 2320001,
            target_carrier: 1530,
            target_carrier_ext: 264,
            target_mcc: None,
            target_mnc: None,
            target_location_area: Some(1),
            sdu: Some(BrewHoSdu { bytes: vec![0xa1, 0xb2, 0xc0], len_bits: 18 }),
            call_gssi: None,
        };
        let msg = build_service_ho_request(&req);
        assert_eq!(&msg[..2], &[BREW_CLASS_SERVICE, BREW_SERVICE_HO_FORWARD_REG]);
        let BrewMessage::Service(svc) = parse_brew_message(&msg).unwrap() else { panic!() };
        assert!(svc.json_data.contains("\"sdu\":\"a1b2c0\""), "lower-case hex: {}", svc.json_data);
        assert_eq!(parse_ho_request(svc.service_type, &svc.json_data).unwrap(), req);

        req.sdu = None;
        let msg = build_service_ho_request(&req);
        assert_eq!(msg[1], BREW_SERVICE_HO_PREPARE);
        let BrewMessage::Service(svc) = parse_brew_message(&msg).unwrap() else { panic!() };
        assert_eq!(parse_ho_request(svc.service_type, &svc.json_data).unwrap(), req);
    }

    #[test]
    fn ho_request_from_the_server_parses() {
        // As brew-server forwards it to the target: its own id, network filled in, unknown field.
        let json = r#"{"transaction_id":4000000000,"issi":2320001,"target_carrier":1528,"target_carrier_ext":264,
            "target_mcc":232,"target_mnc":5,"target_location_area":2,"sdu":"A1B2C0","sdu_len_bits":18,"future":true}"#;
        let req = parse_ho_request(BREW_SERVICE_HO_FORWARD_REG, json).unwrap();
        assert_eq!(req.transaction_id, 4_000_000_000);
        assert_eq!((req.target_mcc, req.target_mnc, req.target_location_area), (Some(232), Some(5), Some(2)));
        assert_eq!(req.sdu.unwrap().bytes, vec![0xa1, 0xb2, 0xc0], "upper-case hex accepted");
    }

    #[test]
    fn ho_request_rejects_bad_input() {
        let base = r#""transaction_id":1,"issi":5,"target_carrier":1528,"target_carrier_ext":264"#;
        let bad = [
            (BREW_SERVICE_HO_FORWARD_REG, format!("{{{base}}}")),                                    // no sdu
            (BREW_SERVICE_HO_PREPARE, format!(r#"{{{base},"sdu":"a0","sdu_len_bits":3}}"#)),        // prepare with sdu
            (BREW_SERVICE_HO_FORWARD_REG, format!(r#"{{{base},"sdu":"a0"}}"#)),                     // half the pair
            (BREW_SERVICE_HO_FORWARD_REG, format!(r#"{{{base},"sdu":"a0b0","sdu_len_bits":3}}"#)),  // too long
            (BREW_SERVICE_HO_FORWARD_REG, format!(r#"{{{base},"sdu":"zz","sdu_len_bits":3}}"#)),    // not hex
            (BREW_SERVICE_HO_FORWARD_REG, format!(r#"{{{base},"sdu":"a0","sdu_len_bits":5000}}"#)), // too big
            (BREW_SERVICE_HO_PREPARE, r#"{"transaction_id":1,"issi":16777216,"target_carrier":1528,"target_carrier_ext":264}"#.to_string()),
            (BREW_SERVICE_HO_PREPARE, r#"{"transaction_id":1,"issi":5,"target_carrier":4096,"target_carrier_ext":264}"#.to_string()),
            (BREW_SERVICE_HO_PREPARE, r#"{"transaction_id":1,"issi":5,"target_carrier":1528,"target_carrier_ext":1024}"#.to_string()),
            (BREW_SERVICE_HO_PREPARE, format!(r#"{{{base},"target_location_area":16384}}"#)),
            (BREW_SERVICE_HO_RESULT, format!("{{{base}}}")),                                         // not a request
            (BREW_SERVICE_HO_PREPARE, "not json".to_string()),
        ];
        for (service_type, json) in bad {
            assert!(parse_ho_request(service_type, &json).is_err(), "accepted {json}");
        }
    }

    #[test]
    fn ho_result_roundtrip_and_server_reason() {
        let res = BrewHoResult {
            transaction_id: 7,
            issi: 2320001,
            status: BREW_HO_STATUS_REJECTED,
            reason: None,
            sdu: Some(BrewHoSdu { bytes: vec![0x0f, 0x80], len_bits: 9 }),
            channel: None,
        };
        let msg = build_service_ho_result(&res);
        assert_eq!(&msg[..2], &[BREW_CLASS_SERVICE, BREW_SERVICE_HO_RESULT]);
        let BrewMessage::Service(svc) = parse_brew_message(&msg).unwrap() else { panic!() };
        assert_eq!(parse_ho_result(&svc.json_data).unwrap(), res);

        let gone = parse_ho_result(r#"{"transaction_id":7,"issi":2320001,"status":2,"reason":"gone"}"#).unwrap();
        assert_eq!((gone.status, gone.reason.as_deref(), gone.sdu), (BREW_HO_STATUS_NO_TARGET, Some("gone"), None));
    }

    #[test]
    fn test_parse_group_tx_v0_no_mnemonic() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_CALL_CONTROL, CALL_STATE_GROUP_TX];
        data.extend_from_slice(uuid.as_bytes());
        write_u32_le(&mut data, 1001);
        write_u32_le(&mut data, 26);
        data.push(3); // priority
        data.push(0); // access
        write_u16_le(&mut data, 0); // service

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            if let BrewCallPayload::GroupTransmission(gt) = cc.payload {
                assert_eq!(gt.source, 1001);
                assert!(gt.mnemonic.is_none(), "v0 should have no mnemonic");
            } else {
                panic!("Expected GroupTransmission");
            }
        } else {
            panic!("Expected CallControl");
        }
    }

    #[test]
    fn test_parse_group_tx_v1_with_mnemonic() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_CALL_CONTROL, CALL_STATE_GROUP_TX];
        data.extend_from_slice(uuid.as_bytes());
        write_u32_le(&mut data, 1001);
        write_u32_le(&mut data, 26);
        data.push(3); // priority
        data.push(0); // access
        write_u16_le(&mut data, 0); // service
        // mnemonic: coding_scheme=0x01 (ISO-8859-1), length=32 bits (4 chars), "TEST"
        let mut mnemonic = [0u8; 34];
        mnemonic[0] = 0x01; // coding scheme
        mnemonic[1] = 32; // length in bits
        mnemonic[2..6].copy_from_slice(b"TEST");
        data.extend_from_slice(&mnemonic);

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            if let BrewCallPayload::GroupTransmission(gt) = cc.payload {
                assert_eq!(gt.source, 1001);
                let m = gt.mnemonic.expect("v1 should have mnemonic");
                assert_eq!(m[0], 0x01);
                assert_eq!(&m[2..6], b"TEST");
            } else {
                panic!("Expected GroupTransmission");
            }
        } else {
            panic!("Expected CallControl");
        }
    }

    #[test]
    fn test_parse_setup_request_v1_with_mnemonic() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_CALL_CONTROL, CALL_STATE_SETUP_REQUEST];
        data.extend_from_slice(uuid.as_bytes());
        // BrewCircularCall: source(4)+dest(4)+number(32)+11 bytes
        write_u32_le(&mut data, 2001); // source
        write_u32_le(&mut data, 3001); // destination
        let mut number = [0u8; 32];
        number[..3].copy_from_slice(b"600");
        data.extend_from_slice(&number);
        data.extend_from_slice(&[0u8; 11]); // 11 single-byte fields
        // mnemonic
        let mut mnemonic = [0u8; 34];
        mnemonic[0] = 0x01;
        mnemonic[1] = 40;
        mnemonic[2..7].copy_from_slice(b"RADIO");
        data.extend_from_slice(&mnemonic);

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            if let BrewCallPayload::CircularCall(c) = cc.payload {
                assert_eq!(c.source, 2001);
                let m = c.mnemonic.expect("v1 SETUP_REQUEST should have mnemonic");
                assert_eq!(&m[2..7], b"RADIO");
            } else {
                panic!("Expected CircularCall");
            }
        } else {
            panic!("Expected CallControl");
        }
    }

    #[test]
    fn test_build_group_tx_v1_roundtrip() {
        let uuid = Uuid::new_v4();
        let mut mnemonic = [0u8; 34];
        mnemonic[0] = 0x01;
        mnemonic[1] = 24;
        mnemonic[2..5].copy_from_slice(b"YO6");

        let built = build_group_tx(&uuid, 9001, 26, 2, 0, Some(&mnemonic));
        assert_eq!(built.len(), 64, "v1 GROUP_TX should be 64 bytes");

        let msg = parse_brew_message(&built).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            if let BrewCallPayload::GroupTransmission(gt) = cc.payload {
                assert_eq!(gt.source, 9001);
                let m = gt.mnemonic.unwrap();
                assert_eq!(&m[2..5], b"YO6");
            } else {
                panic!();
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_voice_frame() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_FRAME, FRAME_TYPE_TRAFFIC_CHANNEL];
        data.extend_from_slice(uuid.as_bytes());
        write_u16_le(&mut data, 274); // length in bits
        // 36 bytes of fake ACELP data
        let acelp = vec![0x80; 36];
        data.extend_from_slice(&acelp);

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::Frame(frame) = msg {
            assert_eq!(frame.frame_type, FRAME_TYPE_TRAFFIC_CHANNEL);
            assert_eq!(frame.identifier, uuid);
            assert_eq!(frame.length_bits, 274);
            assert_eq!(frame.data.len(), 36);
        } else {
            panic!("Expected Frame message");
        }
    }

    #[test]
    fn test_parse_short_transfer() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_CALL_CONTROL, CALL_STATE_SHORT_TRANSFER];
        data.extend_from_slice(uuid.as_bytes());
        write_u32_le(&mut data, 5001); // source
        write_u32_le(&mut data, 6001); // destination
        // number field (32 bytes)
        let number_str = b"6001";
        data.extend_from_slice(number_str);
        data.resize(data.len() + (32 - number_str.len()), 0);

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            assert_eq!(cc.call_state, CALL_STATE_SHORT_TRANSFER);
            assert_eq!(cc.identifier, uuid);
            if let BrewCallPayload::ShortTransfer { source, destination } = cc.payload {
                assert_eq!(source, 5001);
                assert_eq!(destination, 6001);
            } else {
                panic!("Expected ShortTransfer payload");
            }
        } else {
            panic!("Expected CallControl message");
        }
    }

    #[test]
    fn test_build_parse_sds_frame() {
        let uuid = Uuid::new_v4();
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let built = build_sds_frame(&uuid, 32, &payload);

        let msg = parse_brew_message(&built).unwrap();
        if let BrewMessage::Frame(frame) = msg {
            assert_eq!(frame.frame_type, FRAME_TYPE_SDS_TRANSFER);
            assert_eq!(frame.identifier, uuid);
            assert_eq!(frame.length_bits, 32);
            assert_eq!(frame.data, payload);
        } else {
            panic!("Expected Frame message");
        }
    }

    #[test]
    fn test_build_parse_short_transfer() {
        let uuid = Uuid::new_v4();
        let built = build_short_transfer(&uuid, 1001, 2002);

        let msg = parse_brew_message(&built).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            assert_eq!(cc.call_state, CALL_STATE_SHORT_TRANSFER);
            assert_eq!(cc.identifier, uuid);
            if let BrewCallPayload::ShortTransfer { source, destination } = cc.payload {
                assert_eq!(source, 1001);
                assert_eq!(destination, 2002);
            } else {
                panic!("Expected ShortTransfer payload");
            }
        } else {
            panic!("Expected CallControl message");
        }
    }

    #[test]
    fn test_parse_group_idle() {
        let uuid = Uuid::new_v4();
        let mut data = vec![BREW_CLASS_CALL_CONTROL, CALL_STATE_GROUP_IDLE];
        data.extend_from_slice(uuid.as_bytes());
        data.push(0); // cause = normal

        let msg = parse_brew_message(&data).unwrap();
        if let BrewMessage::CallControl(cc) = msg {
            assert_eq!(cc.call_state, CALL_STATE_GROUP_IDLE);
            if let BrewCallPayload::Cause(cause) = cc.payload {
                assert_eq!(cause, 0);
            } else {
                panic!("Expected Cause payload");
            }
        } else {
            panic!("Expected CallControl message");
        }
    }

    #[test]
    fn test_build_parse_sds_report() {
        let uuid = Uuid::new_v4();
        let built = build_sds_report(&uuid, 0);

        assert_eq!(built.len(), 21);
        assert_eq!(built[0], BREW_CLASS_FRAME);
        assert_eq!(built[1], FRAME_TYPE_SDS_REPORT);

        let msg = parse_brew_message(&built).unwrap();
        if let BrewMessage::Frame(frame) = msg {
            assert_eq!(frame.frame_type, FRAME_TYPE_SDS_REPORT);
            assert_eq!(frame.identifier, uuid);
            assert_eq!(frame.length_bits, 8);
            assert_eq!(frame.data, vec![0]);
        } else {
            panic!("Expected Frame message");
        }
    }
}
