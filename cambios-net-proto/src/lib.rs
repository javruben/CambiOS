// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! The network IPC contract — one wire format for the NIC drivers, the
//! stack and its clients (ADR-039 § 2 and § 3).
//!
//! Everything here is a fixed encoding of one 256-byte control message
//! ([ADR-005](../../docs/adr/005-ipc-primitives-control-and-bulk.md)):
//! frames and stream bytes never travel on this path, they go through
//! the channel rings of `user/net-seam`. The crate is pure wire format —
//! no transport, no rings, no protocol state — so every side encodes and
//! decodes the same bytes from the same definitions, and a malformed
//! message is a typed [`DecodeError`], never a guess.
//!
//! **Endpoints.** [`NIC_ENDPOINT`] (20) is the driver's control endpoint.
//! The stack registers [`SEAM_ENDPOINT`] (36) first, then
//! [`UDP_ENDPOINT`] (21, the compatibility surface, kept verbatim), then
//! [`TCP_ENDPOINT`] (34, socket control). [`TEST_CLIENT_ENDPOINT`] (35)
//! is the on-demand test client's.
//!
//! **Byte order.** Ports and addresses are in network order, as on the
//! wire and on ep 21. Handles, channel ids and counters are
//! little-endian, as in every other CambiOS protocol crate
//! (`cambios-blk-proto`, `libfs-proto`). ADR-039 does not fix byte
//! order; this is the choice, made once here.
//!
//! **Replies.** A reply whose status is not [`Status::Ok`] is the status
//! byte alone; its decoder returns the `refused` form, so a client never
//! reads zeroed fields as a socket.

#![no_std]

// ============================================================================
// Endpoints and sizes
// ============================================================================

/// The NIC driver's control endpoint (virtio-net and i219-net, unchanged).
pub const NIC_ENDPOINT: u32 = 20;
/// The stack's UDP compatibility endpoint (the former udp-stack's ep 21
/// protocol, kept verbatim).
pub const UDP_ENDPOINT: u32 = 21;
/// The stack's socket control endpoint.
pub const TCP_ENDPOINT: u32 = 34;
/// The on-demand test client's endpoint.
pub const TEST_CLIENT_ENDPOINT: u32 = 35;
/// Driver → stack doorbells land here; the stack registers it first.
pub const SEAM_ENDPOINT: u32 = 36;

/// HARDWARE: the kernel's fixed control-IPC payload (ADR-005 § 1); every
/// message in this crate fits one.
pub const MAX_MESSAGE: usize = 256;

/// TUNING (ADR-039 § 8 `STREAM_PAGES`): data pages of one per-socket
/// stream channel; the channel is one control page plus these, and its
/// byte ring holds `STREAM_PAGES` × 4 KiB octets (16 KiB, the socket
/// buffer). Both ends size their mappings from this.
pub const STREAM_PAGES: u32 = 4;

/// ARCHITECTURAL: `[family:1][addr:16]` (ADR-039 § 3: dual-stack from the
/// first byte).
pub const ADDRESS_LEN: usize = 17;

// ============================================================================
// Command bytes
// ============================================================================

/// ep 20 `GET_MAC`: `[cmd]` → `[status][mac:6]`.
pub const NIC_GET_MAC: u8 = 3;
/// ep 20 `GET_STATUS`: `[cmd]` → unchanged driver reply.
pub const NIC_GET_STATUS: u8 = 4;
/// ep 20 `OPEN_SEAM`: `[cmd][tx_chan:8][rx_chan:8]` → `[status]`.
pub const NIC_OPEN_SEAM: u8 = 5;
/// ep 20 `CLOSE_SEAM`: `[cmd]` → `[status]`.
pub const NIC_CLOSE_SEAM: u8 = 6;
/// ep 20 `DOORBELL_TX`: `[cmd]`, no reply ("TX ring went non-empty").
pub const NIC_DOORBELL_TX: u8 = 7;
/// ep 36 `DOORBELL_RX`: `[cmd]`, no reply.
pub const SEAM_DOORBELL_RX: u8 = 7;

/// ep 34 commands.
pub const SOCK_CONNECT: u8 = 1;
pub const SOCK_LISTEN: u8 = 2;
pub const SOCK_ACCEPT: u8 = 3;
pub const SOCK_CLOSE: u8 = 4;
pub const SOCK_STATUS: u8 = 5;
pub const SOCK_DOORBELL: u8 = 6;
pub const SOCK_GET_CONFIG: u8 = 7;
/// Stack → client, to the client's reply endpoint: `[cmd][sock:4]`.
pub const NOTICE_DATA_READY: u8 = 6;

// ============================================================================
// Errors
// ============================================================================

/// Why a message could not be decoded. One variant per rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the message's layout.
    Truncated,
    /// Bytes after the end of the layout.
    TrailingBytes,
    UnknownCommand(u8),
    BadStatus(u8),
    /// An address family other than 4 or 6.
    BadFamily(u8),
    /// An IPv4 address with non-zero octets in its 12 padding bytes.
    NonZeroPadding,
    /// A prefix length longer than the family's address.
    BadPrefix(u8),
    /// A connection state outside RFC 4022's 1..=11.
    BadState(u8),
}

/// Why a message could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
    /// A configuration whose gateway is not in the address's family.
    FamilyMismatch,
}

// ============================================================================
// Shared field types
// ============================================================================

/// Status bytes shared by every endpoint (ADR-039 § 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    Error = 1,
    NoData = 2,
    NoDevice = 3,
    Busy = 4,
    Denied = 5,
    Full = 6,
    BadState = 7,
}

impl Status {
    pub const fn from_u8(b: u8) -> Option<Status> {
        Some(match b {
            0 => Status::Ok,
            1 => Status::Error,
            2 => Status::NoData,
            3 => Status::NoDevice,
            4 => Status::Busy,
            5 => Status::Denied,
            6 => Status::Full,
            7 => Status::BadState,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    V4 = 4,
    V6 = 6,
}

impl Family {
    pub const fn from_u8(b: u8) -> Option<Family> {
        match b {
            4 => Some(Family::V4),
            6 => Some(Family::V6),
            _ => None,
        }
    }
    /// Bits in an address of this family.
    pub const fn max_prefix(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }
}

/// An IP address as it travels: `[family:1][addr:16]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Address {
    pub const fn family(&self) -> Family {
        match self {
            Address::V4(_) => Family::V4,
            Address::V6(_) => Family::V6,
        }
    }

    /// The 16 address octets (an IPv4 address in the first four, the
    /// rest zero).
    fn octets(&self) -> [u8; 16] {
        match *self {
            Address::V4([a, b, c, d]) => [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Address::V6(o) => o,
        }
    }

    fn from_octets(family: Family, o: [u8; 16]) -> Result<Address, DecodeError> {
        match family {
            Family::V6 => Ok(Address::V6(o)),
            Family::V4 => {
                let [a, b, c, d, rest @ ..] = o;
                if rest.iter().any(|&x| x != 0) {
                    return Err(DecodeError::NonZeroPadding);
                }
                Ok(Address::V4([a, b, c, d]))
            }
        }
    }

    /// Write the 17-octet form into the front of `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), EncodeError> {
        let mut w = Writer::new(out);
        w.address(self)?;
        Ok(())
    }

    /// Read the 17-octet form from the front of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Address, DecodeError> {
        Reader::new(bytes).address()
    }
}

/// A socket or listener handle: the engine's 4-octet wire form
/// (`cambios_netcore` `SocketId::to_wire`), opaque to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle(pub u32);

/// The RFC 4022 `tcpConnectionState` numbers (ADR-039 § 3). RFC 9293
/// names the states and assigns no numbers; 0 is never a state, so a
/// zeroed byte fails decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    LastAck = 9,
    Closing = 10,
    TimeWait = 11,
}

impl TcpState {
    pub const fn from_u8(b: u8) -> Option<TcpState> {
        Some(match b {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynReceived,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Closing,
            11 => TcpState::TimeWait,
            _ => return None,
        })
    }
}

// ============================================================================
// Bounded reader and writer (no indexing, no unchecked arithmetic)
// ============================================================================

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        let (&b, rest) = self.rest.split_first().ok_or(DecodeError::Truncated)?;
        self.rest = rest;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self.rest.split_at_checked(N).ok_or(DecodeError::Truncated)?;
        self.rest = rest;
        <[u8; N]>::try_from(head).map_err(|_| DecodeError::Truncated)
    }
    fn port(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn handle(&mut self) -> Result<Handle, DecodeError> {
        Ok(Handle(self.u32()?))
    }
    fn status(&mut self) -> Result<Status, DecodeError> {
        let b = self.u8()?;
        Status::from_u8(b).ok_or(DecodeError::BadStatus(b))
    }
    fn family(&mut self) -> Result<Family, DecodeError> {
        let b = self.u8()?;
        Family::from_u8(b).ok_or(DecodeError::BadFamily(b))
    }
    fn address(&mut self) -> Result<Address, DecodeError> {
        let family = self.family()?;
        Address::from_octets(family, self.array()?)
    }
    fn end(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Writer { out, len: 0 }
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let end = self.len.checked_add(b.len()).ok_or(EncodeError::BufferTooSmall)?;
        let dst = self.out.get_mut(self.len..end).ok_or(EncodeError::BufferTooSmall)?;
        dst.copy_from_slice(b);
        self.len = end;
        Ok(())
    }
    fn u8(&mut self, b: u8) -> Result<(), EncodeError> {
        self.bytes(&[b])
    }
    fn port(&mut self, p: u16) -> Result<(), EncodeError> {
        self.bytes(&p.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> Result<(), EncodeError> {
        self.bytes(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<(), EncodeError> {
        self.bytes(&v.to_le_bytes())
    }
    fn handle(&mut self, h: Handle) -> Result<(), EncodeError> {
        self.u32(h.0)
    }
    fn address(&mut self, a: &Address) -> Result<(), EncodeError> {
        self.u8(a.family() as u8)?;
        self.bytes(&a.octets())
    }
    fn done(self) -> usize {
        self.len
    }
}

// ============================================================================
// ep 20: stack → driver
// ============================================================================

/// A request to the NIC driver on [`NIC_ENDPOINT`]. `SEND_PACKET` (1) and
/// `RECV_PACKET` (2) are removed, not kept beside the ring: they decode
/// as [`DecodeError::UnknownCommand`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicRequest {
    GetMac,
    GetStatus,
    /// The stack created both channels with the driver's AID as peer.
    OpenSeam { tx_chan: u64, rx_chan: u64 },
    CloseSeam,
    DoorbellTx,
}

impl NicRequest {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        match *self {
            NicRequest::GetMac => w.u8(NIC_GET_MAC)?,
            NicRequest::GetStatus => w.u8(NIC_GET_STATUS)?,
            NicRequest::OpenSeam { tx_chan, rx_chan } => {
                w.u8(NIC_OPEN_SEAM)?;
                w.u64(tx_chan)?;
                w.u64(rx_chan)?;
            }
            NicRequest::CloseSeam => w.u8(NIC_CLOSE_SEAM)?,
            NicRequest::DoorbellTx => w.u8(NIC_DOORBELL_TX)?,
        }
        Ok(w.done())
    }

    pub fn decode(bytes: &[u8]) -> Result<NicRequest, DecodeError> {
        let mut r = Reader::new(bytes);
        let req = match r.u8()? {
            NIC_GET_MAC => NicRequest::GetMac,
            NIC_GET_STATUS => NicRequest::GetStatus,
            NIC_OPEN_SEAM => NicRequest::OpenSeam { tx_chan: r.u64()?, rx_chan: r.u64()? },
            NIC_CLOSE_SEAM => NicRequest::CloseSeam,
            NIC_DOORBELL_TX => NicRequest::DoorbellTx,
            other => return Err(DecodeError::UnknownCommand(other)),
        };
        r.end()?;
        Ok(req)
    }
}

/// The driver's `GET_MAC` reply: `[status][mac:6]`, or `[status]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacReply {
    pub status: Status,
    pub mac: [u8; 6],
}

impl MacReply {
    pub const fn refused(status: Status) -> Self {
        MacReply { status, mac: [0; 6] }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.bytes(&self.mac)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok { MacReply { status, mac: r.array()? } } else { MacReply::refused(status) };
        r.end()?;
        Ok(reply)
    }
}

/// A one-status-byte reply (`OPEN_SEAM`, `CLOSE_SEAM`, `CLOSE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusOnly(pub Status);

impl StatusOnly {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.0 as u8)?;
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let s = r.status()?;
        r.end()?;
        Ok(StatusOnly(s))
    }
}

// ============================================================================
// ep 36: driver → stack
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeamMessage {
    /// The RX ring went non-empty.
    DoorbellRx,
}

impl SeamMessage {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        match self {
            SeamMessage::DoorbellRx => w.u8(SEAM_DOORBELL_RX)?,
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let m = match r.u8()? {
            SEAM_DOORBELL_RX => SeamMessage::DoorbellRx,
            other => return Err(DecodeError::UnknownCommand(other)),
        };
        r.end()?;
        Ok(m)
    }
}

// ============================================================================
// ep 34: client → stack
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockRequest {
    Connect { remote: Address, port: u16 },
    Listen { port: u16 },
    Accept { listener: Handle },
    /// Closes a socket or a listener.
    Close { handle: Handle },
    Status { sock: Handle },
    /// "I wrote to my TX ring"; no reply.
    Doorbell { sock: Handle },
    GetConfig { family: Family },
}

impl SockRequest {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        match *self {
            SockRequest::Connect { remote, port } => {
                w.u8(SOCK_CONNECT)?;
                w.address(&remote)?;
                w.port(port)?;
            }
            SockRequest::Listen { port } => {
                w.u8(SOCK_LISTEN)?;
                w.port(port)?;
            }
            SockRequest::Accept { listener } => {
                w.u8(SOCK_ACCEPT)?;
                w.handle(listener)?;
            }
            SockRequest::Close { handle } => {
                w.u8(SOCK_CLOSE)?;
                w.handle(handle)?;
            }
            SockRequest::Status { sock } => {
                w.u8(SOCK_STATUS)?;
                w.handle(sock)?;
            }
            SockRequest::Doorbell { sock } => {
                w.u8(SOCK_DOORBELL)?;
                w.handle(sock)?;
            }
            SockRequest::GetConfig { family } => {
                w.u8(SOCK_GET_CONFIG)?;
                w.u8(family as u8)?;
            }
        }
        Ok(w.done())
    }

    pub fn decode(bytes: &[u8]) -> Result<SockRequest, DecodeError> {
        let mut r = Reader::new(bytes);
        let req = match r.u8()? {
            SOCK_CONNECT => SockRequest::Connect { remote: r.address()?, port: r.port()? },
            SOCK_LISTEN => SockRequest::Listen { port: r.port()? },
            SOCK_ACCEPT => SockRequest::Accept { listener: r.handle()? },
            SOCK_CLOSE => SockRequest::Close { handle: r.handle()? },
            SOCK_STATUS => SockRequest::Status { sock: r.handle()? },
            SOCK_DOORBELL => SockRequest::Doorbell { sock: r.handle()? },
            SOCK_GET_CONFIG => SockRequest::GetConfig { family: r.family()? },
            other => return Err(DecodeError::UnknownCommand(other)),
        };
        r.end()?;
        Ok(req)
    }
}

/// `CONNECT` reply: `[status][sock:4][tx_chan:8][rx_chan:8]`. `Ok` means
/// the SYN was sent; poll `STATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectReply {
    pub status: Status,
    pub sock: Handle,
    pub tx_chan: u64,
    pub rx_chan: u64,
}

impl ConnectReply {
    pub const fn refused(status: Status) -> Self {
        ConnectReply { status, sock: Handle(0), tx_chan: 0, rx_chan: 0 }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.handle(self.sock)?;
            w.u64(self.tx_chan)?;
            w.u64(self.rx_chan)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok {
            ConnectReply { status, sock: r.handle()?, tx_chan: r.u64()?, rx_chan: r.u64()? }
        } else {
            ConnectReply::refused(status)
        };
        r.end()?;
        Ok(reply)
    }
}

/// `LISTEN` reply: `[status][listener:4]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenReply {
    pub status: Status,
    pub listener: Handle,
}

impl ListenReply {
    pub const fn refused(status: Status) -> Self {
        ListenReply { status, listener: Handle(0) }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.handle(self.listener)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok { ListenReply { status, listener: r.handle()? } } else { ListenReply::refused(status) };
        r.end()?;
        Ok(reply)
    }
}

/// `ACCEPT` reply:
/// `[status][sock:4][tx_chan:8][rx_chan:8][family:1][peer_addr:16][peer_port:2]`,
/// or `[NO_DATA]` when nothing is waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptReply {
    pub status: Status,
    pub sock: Handle,
    pub tx_chan: u64,
    pub rx_chan: u64,
    pub peer: Address,
    pub peer_port: u16,
}

impl AcceptReply {
    pub const fn refused(status: Status) -> Self {
        AcceptReply { status, sock: Handle(0), tx_chan: 0, rx_chan: 0, peer: Address::V4([0; 4]), peer_port: 0 }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.handle(self.sock)?;
            w.u64(self.tx_chan)?;
            w.u64(self.rx_chan)?;
            w.address(&self.peer)?;
            w.port(self.peer_port)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok {
            AcceptReply { status, sock: r.handle()?, tx_chan: r.u64()?, rx_chan: r.u64()?, peer: r.address()?, peer_port: r.port()? }
        } else {
            AcceptReply::refused(status)
        };
        r.end()?;
        Ok(reply)
    }
}

/// `STATUS` reply: `[status][state:1][rx_avail:4][tx_free:4]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusReply {
    pub status: Status,
    pub state: TcpState,
    pub rx_avail: u32,
    pub tx_free: u32,
}

impl StatusReply {
    pub const fn refused(status: Status) -> Self {
        StatusReply { status, state: TcpState::Closed, rx_avail: 0, tx_free: 0 }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.u8(self.state as u8)?;
            w.u32(self.rx_avail)?;
            w.u32(self.tx_free)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok {
            let b = r.u8()?;
            let state = TcpState::from_u8(b).ok_or(DecodeError::BadState(b))?;
            StatusReply { status, state, rx_avail: r.u32()?, tx_free: r.u32()? }
        } else {
            StatusReply::refused(status)
        };
        r.end()?;
        Ok(reply)
    }
}

/// `GET_CONFIG` reply:
/// `[status][family:1][addr:16][prefix_len:1][gw:16][mac:6]`. The gateway
/// is in the address's family (an all-zero gateway: none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigReply {
    pub status: Status,
    pub address: Address,
    pub prefix_len: u8,
    pub gateway: Address,
    pub mac: [u8; 6],
}

impl ConfigReply {
    pub const fn refused(status: Status) -> Self {
        ConfigReply { status, address: Address::V4([0; 4]), prefix_len: 0, gateway: Address::V4([0; 4]), mac: [0; 6] }
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        if self.status == Status::Ok && self.gateway.family() != self.address.family() {
            return Err(EncodeError::FamilyMismatch);
        }
        let mut w = Writer::new(out);
        w.u8(self.status as u8)?;
        if self.status == Status::Ok {
            w.address(&self.address)?;
            w.u8(self.prefix_len)?;
            w.bytes(&self.gateway.octets())?;
            w.bytes(&self.mac)?;
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let status = r.status()?;
        let reply = if status == Status::Ok {
            let address = r.address()?;
            let prefix_len = r.u8()?;
            if prefix_len > address.family().max_prefix() {
                return Err(DecodeError::BadPrefix(prefix_len));
            }
            let gateway = Address::from_octets(address.family(), r.array()?)?;
            ConfigReply { status, address, prefix_len, gateway, mac: r.array()? }
        } else {
            ConfigReply::refused(status)
        };
        r.end()?;
        Ok(reply)
    }
}

// ============================================================================
// Stack → client notices
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientNotice {
    /// Coalesced: the client's RX ring went non-empty, or the socket
    /// changed state.
    DataReady { sock: Handle },
}

impl ClientNotice {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        match *self {
            ClientNotice::DataReady { sock } => {
                w.u8(NOTICE_DATA_READY)?;
                w.handle(sock)?;
            }
        }
        Ok(w.done())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let n = match r.u8()? {
            NOTICE_DATA_READY => ClientNotice::DataReady { sock: r.handle()? },
            other => return Err(DecodeError::UnknownCommand(other)),
        };
        r.end()?;
        Ok(n)
    }
}
