// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The engine (ADR-039 § 5.1): all of one interface's protocol state
//! behind one entry point, [`Engine::step`]`(now, Event) -> Actions`.
//!
//! `step` is pure: the shell supplies time and inputs and applies the
//! returned actions (transmit the frame in [`Actions::tx_frame`], notify
//! and reply to clients, copy delivered ranges into client rings, wake no
//! later than the armed instant). No I/O, no allocation, no `unsafe`,
//! and every loop runs over a fixed-size table. Capacities are const
//! generics; the shell instantiates them with the ADR-039 § 8 values.
//!
//! State: sockets (`SOCKETS`), listeners (`LISTENERS`), the neighbor cache
//! (`NEIGHBORS`), UDP endpoints (`UDP`), and one transmit frame buffer;
//! plus a borrowed store (split evenly per socket into transmit octets and
//! an out-of-order hold area).
//!
//! # Memory accounting
//!
//! The engine value is the fixed tables (one `Slot` per socket, a few
//! hundred octets each; listeners; the neighbor table; UDP bindings) and
//! one 1514-octet frame: tens of KiB at ADR-039 § 8's sizes, which fits
//! the 64 KiB user stack (`DEFAULT_STACK_PAGES`). The transmit octets,
//! `SOCKETS × per-socket` (1 MiB at 64 × 16 KiB), are NOT in the value:
//! the shell allocates them zeroed from its `libsys-rt` `heap:` arena and
//! lends them to [`Engine::new`], so nothing that large is ever built on
//! a stack. A failed allocation is the shell's to handle (it does not
//! start the engine).
//!
//! # Behaviour
//!
//! - **One emitted frame per step.** The engine owns one transmit buffer;
//!   when more frames are due than one step can emit, the step arms
//!   `now`, and the shell steps again at once. Every queue of due work is
//!   therefore a field of a fixed-size table, never hidden shell state.
//! - **Ownership** (ADR-039 § 1, ADR-025). A socket, listener or UDP
//!   endpoint belongs to the Principal whose control op created or
//!   accepted it; any other Principal's op on it is `Denied`. A passively
//!   opened connection is owned by nobody until its listener's owner
//!   accepts it.
//! - **Neighbors** (ADR-039 § 5.2). The cache is solicit-only
//!   ([`NeighborTable`]): an ARP reply resolves only an address the
//!   engine asked about. An active open to an unresolved next hop sends a
//!   broadcast request and waits in `Resolving`; ticks retry it up to
//!   `arp_attempts` times, then fail the socket with `NoRoute`. A UDP send
//!   to an unresolved next hop sends the request and is refused with
//!   `WouldBlock`; no payload is held. ARP requests for this interface's
//!   address are answered.
//! - **Routing**: one IPv4 prefix and an optional default gateway.
//! - **ISS** (RFC 6528): `M + F(4-tuple, key)`, `M` a 4 µs clock derived
//!   from `now`, `F` SipHash-2-4 under the configured key.
//! - **TIME-WAIT** lasts 2 × [`MSL_MS`], then frees the slot.
//! - **Retransmission of control segments** (RFC 6298 with the ADR-039
//!   § 5.2 bounds, [`RtoEstimator`]): an unacknowledged SYN, SYN-ACK or
//!   FIN is resent at the RTO with × 2 backoff, at most
//!   `max_retransmits` times, then the connection fails `TimedOut`. RTT
//!   samples come only from segments never resent (Karn); a handshake
//!   that needed a resend sets the RTO to 3 s (§ 5.7).
//! - **Challenge ACKs** (RFC 5961 § 7) are sent at most once per
//!   `challenge_ack_interval_ms` per socket.
//! - **Half-open budget** (B-12): a SYN beyond a listener's
//!   `half_open_per_listener` is dropped, not answered.
//! - **Sending** (RFC 9293 § 3.10.2): `Op::Send` appends to the socket's
//!   bounded transmit buffer (`Sent(n)`, or `WouldBlock` when full); each
//!   step sends at most one segment of at most one SMSS, within
//!   min(peer window, congestion window) ([`sendable`]); an ACK releases
//!   acknowledged octets and grows the window (RFC 5681 slow start and
//!   congestion avoidance, [`Reno`]); the third duplicate ACK resends the
//!   first unacknowledged segment at once and enters fast recovery
//!   (RFC 5681 § 3.2); the RTO resends the oldest
//!   unacknowledged octets and collapses the window to one SMSS; a zero
//!   window is probed with one octet at the RTO, and probes answered by
//!   the peer never count toward `max_retransmits`; a CLOSE with unsent
//!   data sends its FIN after the last octet.
//! - **Out-of-order reassembly** (ADR-039 § 5.2, at most `OOO` segments
//!   per socket, default 4): the connection block still reports a segment
//!   past RCV.NXT as out of order; the engine holds it in the socket's
//!   hold area if it lies in the receive window and fits one chunk, and
//!   once in-order text reaches it, replays it into the block as an
//!   ordinary in-order segment (one per step), emitting one cumulative
//!   ACK. Held octets reach the shell as `Action::DeliverHeld` over
//!   [`Actions::held_data`]. The block itself is unchanged.
//! - **Window updates** (RFC 9293 § 3.8.6.2.2): when the shell reports
//!   consumed octets (`Op::Consumed`) and RCV.WND rises from below
//!   min(buffer / 2, SMSS) to at least it, an ACK announces it.
//! - **Received text** is a range of the input frame (`Action::Deliver`);
//!   the shell copies it into the socket's stream ring before the next
//!   step, including for a connection not yet accepted.
//!
//! # Not implemented yet
//!
//! Sender silly-window avoidance and Nagle (RFC 9293 § 3.8.6.2.1,
//! § 3.7.4), CUBIC, SACK, ICMP beyond echo replies (no errors are
//! generated or acted on), the DHCPv4 client inside the engine (it exists
//! separately in [`crate::dhcp`]), IPv4 fragments, and every IPv6 behaviour. Per-Principal socket limits, and the policy
//! query on CONNECT / LISTEN (ADR-039 § 10), are not enforced here.

use crate::addr::{IpAddress, Ipv4Address, MacAddress, SocketAddress};
use crate::error::{NetError, ParseError};
use crate::neighbor::{Learn, NeighborError, NeighborTable};
use crate::siphash::siphash24;
use crate::tcp::congestion::Reno;
use crate::tcp::rto::RtoEstimator;
use crate::tcp::send::sendable;
use crate::tcp::seq::SeqNum;
use crate::tcp::state::TcpState;
use crate::tcp::tcb::{reset_for_unmatched, Delivery, DropReason, Emit, Outcome, Tcb, TcbConfig, TcbEvent};
use crate::wire::arp::{ArpOperation, ArpPacket};
use crate::wire::ethernet;
use crate::wire::frame::{self, Classified, Ipv4Route};
use crate::wire::icmpv4::{Echo, EchoKind, Icmpv4Message};
use crate::wire::ipv4::{self, Ipv4Packet};
use crate::wire::tcp::{TcpFlags, TcpOptions, TcpRepr, TcpSegment};
use crate::wire::udp::{self, UdpDatagram, UdpRepr};

/// ARCHITECTURAL: the most actions one step returns (ADR-039 § 8): one
/// emit, a reply, an arm, and the per-socket notifications of one input.
pub const MAX_ACTIONS_PER_STEP: usize = 8;

/// HARDWARE: the largest Ethernet II frame without FCS at the default
/// 1500-octet MTU. Jumbo frames are not supported (ADR-039's 2048-octet
/// ring slot); a configured MTU above 1500 is refused.
pub const MAX_FRAME_LEN: usize = 1514;

/// HARDWARE: Ethernet II payload limit this engine accepts as its MTU.
const MAX_MTU: u16 = 1500;

/// HARDWARE: the IPv4 default sender MSS (RFC 9293 § 3.7.1), used for
/// the congestion window until the handshake reveals the peer's MSS.
const DEFAULT_SMSS: u16 = 536;
/// HARDWARE: IPv4 + TCP header octets without options, subtracted from
/// the MTU to bound a segment's payload.
const IPV4_TCP_HEADERS: u16 = 40;

/// TUNING: maximum segment lifetime, fixed by ADR-039 § 5.2 and § 8
/// (30 s, matching Linux); TIME-WAIT is twice this.
pub const MSL_MS: u64 = 30_000;

/// Milliseconds on the shell's monotonic clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(pub u64);

impl Instant {
    const fn after(self, ms: u64) -> Instant {
        Instant(self.0.saturating_add(ms))
    }
}

/// The RFC 6528 ISS secret. Its `Debug` output is redacted, and the
/// engine exposes no read path to it, so it cannot reach a log or a
/// client.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IssKey(pub [u8; 16]);

impl core::fmt::Debug for IssKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IssKey(<redacted>)")
    }
}

/// A kernel-stamped sender identity (ADR-025: the 32-byte AID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Principal(pub [u8; 32]);

/// The interface and the shell's chosen limits and intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    pub mac: MacAddress,
    pub ipv4: Ipv4Address,
    /// On-link prefix length, 0..=32.
    pub prefix_len: u8,
    /// Next hop for every off-link destination; `None`: off-link is
    /// unreachable.
    pub gateway: Option<Ipv4Address>,
    pub ttl: u8,
    /// Interface MTU, at most 1500.
    pub mtu: u16,
    /// Per-connection parameters (advertised MSS, receive window).
    pub tcb: TcbConfig,
    /// RFC 6528 secret, drawn by the shell from a hardware random source
    /// at start. `None` when no such source exists: TCP then fails
    /// closed (active and passive opens are refused `Unsupported`, so a
    /// peer's SYN finds no listener and is reset) and UDP, ARP, ICMP
    /// and DHCP still run. There is never a fixed or derived fallback.
    pub iss_key: Option<IssKey>,
    /// SYN-RECEIVED connections allowed per listener (ADR-039 § 8).
    pub half_open_per_listener: u16,
    /// How long an ARP answer is used.
    pub neighbor_ttl_ms: u64,
    /// How long one ARP question waits for its answer.
    pub arp_timeout_ms: u64,
    /// ARP requests sent for one active open before it fails; at least 1.
    pub arp_attempts: u8,
    /// Minimum interval between challenge ACKs on one socket (ADR-039 § 8).
    pub challenge_ack_interval_ms: u64,
    /// Retransmissions of one control segment (SYN, SYN-ACK, FIN) before
    /// the connection fails with `TimedOut` (ADR-039 § 5.2: "bounded
    /// retries"; the count is the shell's).
    pub max_retransmits: u8,
    /// Octets of each socket's store region set aside for holding
    /// out-of-order segments, split into `OOO` equal chunks (a segment
    /// longer than a chunk is not held). 0: nothing is held.
    pub hold_per_socket: usize,
}

/// A connection handle: slot and generation, so a handle to a freed slot
/// never names the slot's next connection (until the 16-bit generation
/// wraps).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketId {
    slot: u16,
    generation: u16,
}

/// A listener handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListenerId {
    slot: u16,
    generation: u16,
}

/// A UDP endpoint handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpId {
    slot: u16,
    generation: u16,
}

macro_rules! wire_handle {
    ($t:ident) => {
        impl $t {
            /// The 4-octet wire form (ADR-039 § 3 `sock:4` / `listener:4`).
            pub const fn to_wire(self) -> u32 {
                ((self.generation as u32) << 16) | self.slot as u32
            }
            pub const fn from_wire(w: u32) -> $t {
                $t { slot: (w & 0xFFFF) as u16, generation: (w >> 16) as u16 }
            }
        }
    };
}
wire_handle!(SocketId);
wire_handle!(ListenerId);
wire_handle!(UdpId);

/// A socket as its owner sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketState {
    /// Waiting for the next hop's link address; no SYN sent yet.
    Resolving,
    Tcp(TcpState),
}

/// What a socket's owner should learn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    Connected,
    /// New stream octets were delivered (see `Action::Deliver`).
    DataReady,
    /// The peer's FIN arrived: no more data will.
    PeerClosed,
    /// Orderly close completed; the handle is now stale.
    Closed,
    /// Reset by the peer; the handle is now stale.
    Reset,
    /// The active open was refused by the peer; the handle is now stale.
    Refused,
    /// The socket failed and was freed.
    Error(NetError),
}

/// The reply to one control op (ADR-039 § 3, encoded by the shell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlReply {
    Socket(SocketId),
    Listener(ListenerId),
    Endpoint(UdpId),
    Accepted { socket: SocketId, peer: SocketAddress },
    /// Octets of a SEND accepted into the transmit buffer.
    Sent(u32),
    NoData,
    Done,
    State(SocketState),
    Refused(NetError),
}

/// One client request, already authenticated by the kernel stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op<'a> {
    Connect { remote: SocketAddress, local_port: u16 },
    Listen { port: u16 },
    Unlisten { listener: ListenerId },
    Accept { listener: ListenerId },
    Close { socket: SocketId },
    /// Queue `data` for transmission; as much as the buffer holds is
    /// accepted (`Sent(n)`), nothing at all is `WouldBlock`.
    Send { socket: SocketId, data: &'a [u8] },
    Status { socket: SocketId },
    /// The shell saw the owner consume `octets` from the socket's ring.
    Consumed { socket: SocketId, octets: u32 },
    UdpBind { port: u16 },
    UdpUnbind { endpoint: UdpId },
    UdpSend { endpoint: UdpId, remote: SocketAddress, payload: &'a [u8] },
    /// An operator-pinned neighbor (NET-V-030). The shell decides who may
    /// issue it; the engine applies it.
    PinNeighbor { ip: Ipv4Address, mac: MacAddress },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control<'a> {
    pub from: Principal,
    pub op: Op<'a>,
}

/// The interface's IPv4 configuration, as an accepted DHCP lease gives
/// it (codex D1). Applied by the shell through [`Event::Interface`],
/// never by a client op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub ipv4: Ipv4Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Address>,
}

impl InterfaceConfig {
    /// Usable as an interface configuration: a unicast address that is
    /// neither the network nor the broadcast address of a /1../30 prefix
    /// (/31 and /32 have neither), and a gateway, if any, that is a
    /// different unicast host on the same subnet.
    pub fn is_valid(&self) -> bool {
        let Some(shift) = 32u32.checked_sub(u32::from(self.prefix_len)) else { return false };
        if self.prefix_len == 0 || !valid_unicast(self.ipv4) {
            return false;
        }
        let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
        let host = |a: u32| a & !mask;
        let a = u32::from_be_bytes(self.ipv4.0);
        let edges = self.prefix_len <= 30;
        if edges && (host(a) == 0 || host(a) == !mask) {
            return false;
        }
        match self.gateway {
            None => true,
            Some(g) => {
                let gw = u32::from_be_bytes(g.0);
                valid_unicast(g) && gw != a && gw & mask == a & mask && !(edges && (host(gw) == 0 || host(gw) == !mask))
            }
        }
    }
}

/// One input to the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// One received Ethernet frame.
    Frame(&'a [u8]),
    /// Time advanced; fire what is due. The step's `now` governs.
    Tick(Instant),
    Control(Control<'a>),
    /// Apply an accepted DHCP lease (codex D1). An invalid configuration
    /// is `Err(EngineError::Config)` and changes nothing. The same address
    /// and prefix (a renewal, or a new gateway) keeps every socket. A new
    /// address or prefix is committed at once and every TCP socket is
    /// freed, since its local address is no longer ours: each claimed one
    /// is notified `Error(NoAddress)` (over later steps if this one is
    /// full; `Arm(now)` until all are out). Listeners and UDP endpoints
    /// name only a port and stay. Also ends an [`Event::AddressLost`].
    Interface(InterfaceConfig),
    /// The lease is gone (expired, or NAKed while renewing): the engine
    /// holds no address until the next `Interface`. Every TCP socket is
    /// freed and notified as for an address change; meanwhile every IPv4
    /// frame is `NotForUs`, ARP is ignored (not answered, not learned),
    /// and opens and UDP sends are refused `NoAddress`. Never refused.
    AddressLost,
}

/// One thing the shell must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Transmit `actions.tx_frame()[..frame_len]`.
    Emit { frame_len: u16 },
    Notify { socket: SocketId, what: Notify },
    Reply { to: Principal, msg: ControlReply },
    /// Step again with a `Tick` no later than this instant.
    Arm(Instant),
    /// New in-order stream octets: `frame[offset .. offset + len]` of the
    /// input frame, for the socket's receive ring.
    Deliver { socket: SocketId, offset: usize, len: usize },
    /// Held out-of-order octets now in order:
    /// `actions.held_data()[offset .. offset + len]`.
    DeliverHeld { socket: SocketId, offset: usize, len: usize },
    /// A UDP datagram's payload: `frame[offset .. offset + len]`.
    Datagram { endpoint: UdpId, from: SocketAddress, offset: usize, len: usize },
}

/// Why a received frame changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed(ParseError),
    NotIpv4,
    /// IPv4, but neither TCP nor UDP.
    UnsupportedProtocol,
    NotForUs,
    /// A SYN while every socket slot is in use: dropped, not answered.
    SocketTableFull,
    /// A SYN beyond its listener's half-open budget: dropped.
    HalfOpenFull,
    /// A UDP datagram for an unbound port.
    NoEndpoint,
    /// An ICMP message other than an echo request for us: not acted on.
    IcmpIgnored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The configuration is outside what the engine supports.
    Config,
    /// The frame was dropped before any state changed.
    Refused(Refusal),
}

/// The actions of one step, at most [`MAX_ACTIONS_PER_STEP`].
#[derive(Debug)]
pub struct Actions<'a> {
    items: [Option<Action>; MAX_ACTIONS_PER_STEP],
    tx: &'a [u8],
    held: &'a [u8],
}

impl<'a> Actions<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.items.iter().flatten()
    }
    /// The frame an `Emit` refers to.
    pub fn tx_frame(&self) -> &'a [u8] {
        self.tx
    }
    /// The held segment a `DeliverHeld` refers to (empty otherwise).
    pub fn held_data(&self) -> &'a [u8] {
        self.held
    }
}

/// Actions under construction.
struct Acts {
    items: [Option<Action>; MAX_ACTIONS_PER_STEP],
    len: usize,
    emitted: bool,
    /// The store range of the segment replayed this step, if any.
    held: Option<(usize, usize)>,
}

impl Acts {
    const fn new() -> Acts {
        Acts { items: [None; MAX_ACTIONS_PER_STEP], len: 0, emitted: false, held: None }
    }
    fn push(&mut self, a: Action) -> bool {
        match self.items.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(a);
                self.len = self.len.saturating_add(1);
                true
            }
            None => false,
        }
    }
    /// Room left after keeping one place for the closing `Arm`.
    fn room_before_arm(&self) -> usize {
        MAX_ACTIONS_PER_STEP.saturating_sub(self.len).saturating_sub(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Client(Principal),
    /// Passively opened, not yet accepted from listener slot `listener`.
    Unclaimed { listener: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    /// ARP question open for `next_hop`; `syn` is sent once answered.
    Resolving { next_hop: Ipv4Address, attempts: u8, deadline: Instant, syn: TcpRepr },
    /// Answered; the SYN waits for a step with a free emit.
    SynQueued { mac: MacAddress, syn: TcpRepr },
    Resolved(MacAddress),
}

/// Which kind of control segment a retransmission timer guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Guarding {
    /// SYN or SYN-ACK.
    Handshake,
    /// Stream data in flight (and possibly a FIN after it).
    Data,
    /// A FIN alone.
    Fin,
    /// Nothing in flight, data waiting, the peer's window zero: the timer
    /// sends a one-octet window probe (RFC 9293 § 3.8.6.1).
    Probe,
}

/// The retransmission / persist timer (RFC 6298 § 5, RFC 9293 § 3.8.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rtx {
    Idle,
    /// Something is unacknowledged (or a probe is due); it has been resent
    /// `retries` times since the last progress. `first_sent` is when the
    /// timed transmission went out, and `None` once anything was resent:
    /// Karn's rule, no RTT sample from a retransmission.
    Pending { guarding: Guarding, first_sent: Option<Instant>, deadline: Instant, retries: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    owner: Owner,
    tcb: Tcb,
    link: Link,
    rtx: Rtx,
    rto: RtoEstimator,
    cc: Reno,
    /// Consecutive duplicate ACKs (RFC 5681 § 2).
    dup_acks: u8,
    recovery: Recovery,
    closing: Closing,
    /// Set when the block enters TIME-WAIT.
    time_wait_until: Option<Instant>,
    last_challenge: Option<Instant>,
}

/// One held out-of-order segment: its octets are in its chunk of the
/// socket's hold area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Held {
    seq: SeqNum,
    len: usize,
    /// The segment carried a FIN (a wire bit, replayed with it).
    fin: bool,
}

/// RFC 5681 § 3.2 fast recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    Normal,
    /// Entered on the third duplicate ACK; left on the next ACK of new
    /// data or an RTO.
    Fast,
}

/// HARDWARE: duplicate ACKs that trigger a fast retransmit (RFC 5681
/// § 3.2).
const DUP_ACK_THRESHOLD: u8 = 3;

/// Whether a local CLOSE is waiting for the transmit buffer to drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Closing {
    Open,
    /// CLOSE was called with unsent data: the FIN goes once it is sent.
    Queued,
}

/// A socket's transmit ring: the bookkeeping for its `cap` octets of the
/// engine's transmit store, holding the stream from SND.UNA on: the first
/// `sent` octets are in flight, the rest unsent. Released from the front
/// as the peer acknowledges. The octets live in the caller's store, so
/// this value is small and copied freely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TxRing {
    start: usize,
    len: usize,
    sent: usize,
}

impl TxRing {
    const EMPTY: TxRing = TxRing { start: 0, len: 0, sent: 0 };

    fn unsent(&self) -> usize {
        self.len.saturating_sub(self.sent)
    }
    fn index(&self, k: usize, cap: usize) -> usize {
        self.start.checked_add(k).and_then(|x| x.checked_rem(cap)).unwrap_or(0)
    }
    /// Append as much of `data` as fits into `mem` (this socket's part of
    /// the store); returns how much.
    fn push(&mut self, mem: &mut [u8], data: &[u8]) -> usize {
        let cap = mem.len();
        let n = data.len().min(cap.saturating_sub(self.len));
        for (k, &b) in data.iter().take(n).enumerate() {
            let at = self.index(self.len.saturating_add(k), cap);
            if let Some(slot) = mem.get_mut(at) {
                *slot = b;
            }
        }
        self.len = self.len.saturating_add(n);
        n
    }
    /// The contiguous octets from `offset` past SND.UNA, at most `max`,
    /// stopping at the end of `mem`.
    fn run<'m>(&self, mem: &'m [u8], offset: usize, max: usize) -> &'m [u8] {
        let cap = mem.len();
        let from = self.index(offset, cap);
        let n = max.min(self.len.saturating_sub(offset)).min(cap.saturating_sub(from));
        mem.get(from..from.saturating_add(n)).unwrap_or(&[])
    }
    /// Release `n` acknowledged octets from the front.
    fn release(&mut self, n: usize, cap: usize) {
        let n = n.min(self.sent);
        self.start = self.index(n, cap);
        self.len = self.len.saturating_sub(n);
        self.sent = self.sent.saturating_sub(n);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bound {
    owner: Principal,
    port: u16,
}

/// All protocol state for one interface.
#[derive(Debug, PartialEq, Eq)]
pub struct Engine<'a, const SOCKETS: usize, const LISTENERS: usize, const NEIGHBORS: usize, const UDP: usize, const OOO: usize = 4> {
    config: EngineConfig,
    sockets: [Option<Slot>; SOCKETS],
    socket_gen: [u16; SOCKETS],
    listeners: [Option<Bound>; LISTENERS],
    listener_gen: [u16; LISTENERS],
    udp: [Option<Bound>; UDP],
    udp_gen: [u16; UDP],
    neighbors: NeighborTable<NEIGHBORS>,
    /// Per-socket transmit ring bookkeeping.
    tx_rings: [TxRing; SOCKETS],
    /// Held out-of-order segments, at most `OOO` per socket (ADR-039 § 8
    /// `MAX_OOO_SEGMENTS`; the default 4 is that row's value).
    holds: [[Option<Held>; OOO]; SOCKETS],
    /// The caller's store: socket `i` owns `i * stride .. (i + 1) *
    /// stride`, transmit octets first (`tx_per`), then its hold area
    /// (`hold_per`). Caller-provided so the engine value stays small.
    store: &'a mut [u8],
    stride: usize,
    tx_per: usize,
    hold_per: usize,
    tx: [u8; MAX_FRAME_LEN],
    /// Per slot: the handle of a socket freed by an address change or
    /// loss whose owner is still owed `Notify::Error(NoAddress)`. The slot
    /// is not reused until the notice is out, so none is ever dropped.
    retired: [Option<SocketId>; SOCKETS],
    /// False after `AddressLost` until the next `Interface`.
    addressed: bool,
}

/// Index of a live entry named by a (slot, generation) handle.
fn live<T>(table: &[Option<T>], gens: &[u16], slot: u16, generation: u16) -> Option<usize> {
    let i = usize::from(slot);
    match (table.get(i), gens.get(i)) {
        (Some(Some(_)), Some(&g)) if g == generation => Some(i),
        _ => None,
    }
}

fn free<T>(table: &mut [Option<T>], gens: &mut [u16], i: usize) {
    if let Some(e) = table.get_mut(i) {
        *e = None;
    }
    if let Some(g) = gens.get_mut(i) {
        *g = g.wrapping_add(1);
    }
}

const fn valid_unicast(ip: Ipv4Address) -> bool {
    let unspecified = ip.0[0] | ip.0[1] | ip.0[2] | ip.0[3] == 0;
    !unspecified && !ip.is_broadcast() && !ip.is_multicast()
}

impl<'a, const SOCKETS: usize, const LISTENERS: usize, const NEIGHBORS: usize, const UDP: usize, const OOO: usize>
    Engine<'a, SOCKETS, LISTENERS, NEIGHBORS, UDP, OOO>
{
    /// An engine with empty tables over `store`, split evenly per socket
    /// (`store.len() / SOCKETS` each; any remainder is unused): the first
    /// part is the socket's transmit buffer, the last
    /// `config.hold_per_socket` octets its out-of-order hold area.
    /// `Config` for an MTU above 1500, a prefix above 32, zero ARP
    /// attempts, a table larger than its 16-bit handle can name, or a
    /// store that leaves a socket no transmit octets.
    ///
    /// Memory: the engine value holds only fixed tables and one 1514-octet
    /// frame; the transmit and hold octets are the caller's `store`, which the
    /// shell takes from its heap (a zeroed allocation, so nothing large is
    /// built on its stack). The allocation's failure is the shell's to
    /// handle before calling this.
    pub fn new(config: EngineConfig, store: &'a mut [u8]) -> Result<Self, EngineError> {
        let stride = store.len().checked_div(SOCKETS).unwrap_or(0);
        let hold_per = config.hold_per_socket;
        let tx_per = stride.saturating_sub(hold_per);
        if SOCKETS > 0 && (tx_per == 0 || hold_per > stride) {
            return Err(EngineError::Config);
        }
        let handles = usize::from(u16::MAX);
        if config.mtu > MAX_MTU
            || config.prefix_len > 32
            || config.arp_attempts == 0
            || SOCKETS > handles
            || LISTENERS > handles
            || UDP > handles
        {
            return Err(EngineError::Config);
        }
        Ok(Engine {
            config,
            sockets: [None; SOCKETS],
            socket_gen: [0; SOCKETS],
            listeners: [None; LISTENERS],
            listener_gen: [0; LISTENERS],
            udp: [None; UDP],
            udp_gen: [0; UDP],
            neighbors: NeighborTable::new(),
            tx_rings: [TxRing::EMPTY; SOCKETS],
            holds: [[None; OOO]; SOCKETS],
            store,
            stride,
            tx_per,
            hold_per,
            tx: [0; MAX_FRAME_LEN],
            retired: [None; SOCKETS],
            addressed: true,
        })
    }

    // ---- read-only views ----

    fn socket_index(&self, id: SocketId) -> Option<usize> {
        live(&self.sockets, &self.socket_gen, id.slot, id.generation)
    }

    fn slot(&self, id: SocketId) -> Option<&Slot> {
        self.socket_index(id).and_then(|i| self.sockets.get(i)).and_then(Option::as_ref)
    }

    fn id_of(&self, i: usize) -> Option<SocketId> {
        let generation = *self.socket_gen.get(i)?;
        Some(SocketId { slot: u16::try_from(i).ok()?, generation })
    }

    pub fn state(&self, id: SocketId) -> Option<SocketState> {
        self.slot(id).map(|s| match s.link {
            Link::Resolving { .. } => SocketState::Resolving,
            Link::SynQueued { .. } | Link::Resolved(_) => SocketState::Tcp(s.tcb.state()),
        })
    }

    pub fn tcb(&self, id: SocketId) -> Option<&Tcb> {
        self.slot(id).map(|s| &s.tcb)
    }

    /// The owning Principal; `None` for a stale handle or an unaccepted
    /// connection.
    pub fn owner(&self, id: SocketId) -> Option<Principal> {
        match self.slot(id)?.owner {
            Owner::Client(p) => Some(p),
            Owner::Unclaimed { .. } => None,
        }
    }

    pub fn udp_owner(&self, id: UdpId) -> Option<Principal> {
        let i = live(&self.udp, &self.udp_gen, id.slot, id.generation)?;
        self.udp.get(i).copied().flatten().map(|b| b.owner)
    }

    // ---- the entry point ----

    /// Apply one input. `Ok` carries what the shell must do; `Err` means
    /// the frame was dropped and nothing changed.
    pub fn step(&mut self, now: Instant, event: Event<'_>) -> Result<Actions<'_>, EngineError> {
        let mut acts = Acts::new();
        match event {
            Event::Frame(f) => self.on_frame(now, f, &mut acts)?,
            Event::Tick(_) => self.on_tick(now, &mut acts),
            Event::Control(c) => {
                let msg = self.on_control(now, &c, &mut acts);
                acts.push(Action::Reply { to: c.from, msg });
            }
            Event::Interface(c) => self.on_interface(c)?,
            Event::AddressLost => self.on_address_lost(),
        }
        let owed = self.drain_retired(&mut acts);
        if let Some(t) = if owed { Some(now) } else { self.next_deadline(now) } {
            acts.push(Action::Arm(t));
        }
        let held = acts.held.and_then(|(from, to)| self.store.get(from..to)).unwrap_or(&[]);
        Ok(Actions { items: acts.items, tx: &self.tx, held })
    }

    // ---- interface (codex D1) ----

    fn on_interface(&mut self, c: InterfaceConfig) -> Result<(), EngineError> {
        if !c.is_valid() {
            return Err(EngineError::Config);
        }
        let moved = c.ipv4 != self.config.ipv4 || c.prefix_len != self.config.prefix_len;
        self.config.ipv4 = c.ipv4;
        self.config.prefix_len = c.prefix_len;
        self.config.gateway = c.gateway;
        self.addressed = true;
        if moved {
            self.retire_all();
        }
        Ok(())
    }

    fn on_address_lost(&mut self) {
        self.addressed = false;
        self.retire_all();
    }

    /// Free every TCP socket; claimed ones are owed `Error(NoAddress)`.
    fn retire_all(&mut self) {
        for i in 0..SOCKETS {
            let Some(Some(s)) = self.sockets.get(i).copied() else { continue };
            let id = self.id_of(i);
            self.free_socket(i);
            if let (Owner::Client(_), Some(id), Some(r)) = (s.owner, id, self.retired.get_mut(i)) {
                *r = Some(id);
            }
        }
    }

    /// A slot free for a new socket: empty, and no notice owed for it.
    fn free_slot(&self) -> Option<usize> {
        (0..SOCKETS).find(|&i| matches!(self.sockets.get(i), Some(None)) && matches!(self.retired.get(i), Some(None)))
    }

    /// Hand out owed `Error(NoAddress)` notices while the step has room.
    /// True while some are still owed.
    fn drain_retired(&mut self, acts: &mut Acts) -> bool {
        for r in self.retired.iter_mut() {
            if r.is_none() {
                continue;
            }
            if acts.room_before_arm() == 0 {
                return true;
            }
            if let Some(socket) = r.take() {
                acts.push(Action::Notify { socket, what: Notify::Error(NetError::NoAddress) });
            }
        }
        false
    }

    // ---- helpers ----

    fn local(&self, port: u16) -> SocketAddress {
        SocketAddress { address: IpAddress::V4(self.config.ipv4), port }
    }

    fn route(&self, destination_mac: MacAddress, destination: Ipv4Address) -> Ipv4Route {
        Ipv4Route { source_mac: self.config.mac, destination_mac, source: self.config.ipv4, destination, ttl: self.config.ttl }
    }

    /// The next hop for `dst`: itself on-link, else the gateway.
    fn next_hop(&self, dst: Ipv4Address) -> Option<Ipv4Address> {
        let shift = 32u32.checked_sub(u32::from(self.config.prefix_len))?;
        let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
        let ours = u32::from_be_bytes(self.config.ipv4.0);
        if u32::from_be_bytes(dst.0) & mask == ours & mask {
            Some(dst)
        } else {
            self.config.gateway
        }
    }

    /// RFC 6528: a 4 µs clock plus a keyed hash of the 4-tuple. `None`
    /// without a key: the caller refuses the open.
    fn iss(&self, now: Instant, local_port: u16, remote: Ipv4Address, remote_port: u16) -> Option<SeqNum> {
        let key = self.config.iss_key?;
        let mut msg = [0u8; 12];
        let parts: [(usize, &[u8]); 4] = [
            (0, &self.config.ipv4.0),
            (4, &local_port.to_be_bytes()),
            (6, &remote.0),
            (10, &remote_port.to_be_bytes()),
        ];
        for (at, bytes) in parts {
            if let Some(dst) = msg.get_mut(at..at.saturating_add(bytes.len())) {
                dst.copy_from_slice(bytes);
            }
        }
        let clock = now.0.wrapping_mul(250) as u32;
        Some(SeqNum(clock.wrapping_add(siphash24(&key.0, &msg) as u32)))
    }

    fn find(&self, local_port: u16, remote: SocketAddress) -> Option<usize> {
        self.sockets.iter().position(|s| match s {
            Some(s) => s.tcb.local().port == local_port && s.tcb.remote() == remote,
            None => false,
        })
    }

    fn set_emit(&mut self, acts: &mut Acts, written: usize) -> bool {
        match u16::try_from(written) {
            Ok(frame_len) if acts.push(Action::Emit { frame_len }) => {
                acts.emitted = true;
                true
            }
            _ => false,
        }
    }

    fn emit_tcp(&mut self, acts: &mut Acts, mac: MacAddress, ip: Ipv4Address, repr: &TcpRepr) -> bool {
        if acts.emitted {
            return false;
        }
        let route = self.route(mac, ip);
        match frame::emit_ipv4_tcp(&route, repr, &[], &mut self.tx) {
            Ok(n) => self.set_emit(acts, n),
            Err(_) => false,
        }
    }

    fn emit_arp(&mut self, acts: &mut Acts, destination: MacAddress, packet: &ArpPacket) -> bool {
        if acts.emitted {
            return false;
        }
        match frame::emit_arp(self.config.mac, destination, packet, &mut self.tx) {
            Ok(n) => self.set_emit(acts, n),
            Err(_) => false,
        }
    }

    fn who_has(&mut self, acts: &mut Acts, target: Ipv4Address) -> bool {
        let request = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: self.config.mac,
            sender_ip: self.config.ipv4,
            target_mac: MacAddress([0; 6]),
            target_ip: target,
        };
        self.emit_arp(acts, MacAddress::BROADCAST, &request)
    }

    fn notify(&self, acts: &mut Acts, owner: Owner, socket: Option<SocketId>, what: Notify) {
        if let (Owner::Client(_), Some(socket)) = (owner, socket) {
            acts.push(Action::Notify { socket, what });
        }
    }

    /// Start, keep or stop slot `i`'s timer after it may have sent or had
    /// acknowledged something. An acknowledgement of a segment that was
    /// never resent is an RTT sample (Karn's rule: none from a resent
    /// one); a handshake that needed a resend sets the RTO to 3 s (RFC 6298
    /// § 5.7).
    fn sync_rtx(&mut self, i: usize, now: Instant) {
        let outstanding = self.outstanding(i);
        let Some(Some(s)) = self.sockets.get_mut(i) else { return };
        let finish = |s: &mut Slot, guarding: Guarding, first_sent: Option<Instant>| match first_sent {
            Some(t) if guarding != Guarding::Probe => s.rto.sample(now.0.saturating_sub(t.0)),
            _ if guarding == Guarding::Handshake => s.rto.after_syn_loss(),
            _ => {}
        };
        match (s.rtx, outstanding) {
            (Rtx::Idle, Some(guarding)) => {
                s.rtx = Rtx::Pending { guarding, first_sent: Some(now), deadline: now.after(s.rto.rto_ms()), retries: 0 };
            }
            (Rtx::Pending { guarding, first_sent, .. }, None) => {
                finish(s, guarding, first_sent);
                s.rtx = Rtx::Idle;
            }
            (Rtx::Pending { guarding: Guarding::Handshake, first_sent, .. }, Some(next)) if next != Guarding::Handshake => {
                // The handshake completed and something else is already
                // outstanding: close the handshake's books, start afresh.
                finish(s, Guarding::Handshake, first_sent);
                s.rtx = Rtx::Pending { guarding: next, first_sent: Some(now), deadline: now.after(s.rto.rto_ms()), retries: 0 };
            }
            (Rtx::Pending { first_sent, deadline, retries, .. }, Some(guarding)) => {
                s.rtx = Rtx::Pending { guarding, first_sent, deadline, retries };
            }
            (Rtx::Idle, None) => {}
        }
    }

    /// Socket `i`'s part of the transmit store.
    fn tx_mem(&self, i: usize) -> &[u8] {
        let from = i.saturating_mul(self.stride);
        self.store.get(from..from.saturating_add(self.tx_per)).unwrap_or(&[])
    }

    /// Free socket slot `i` and its transmit buffer, retiring the handle.
    fn free_socket(&mut self, i: usize) {
        free(&mut self.sockets, &mut self.socket_gen, i);
        if let Some(r) = self.tx_rings.get_mut(i) {
            *r = TxRing::EMPTY;
        }
        if let Some(h) = self.holds.get_mut(i) {
            *h = [None; OOO];
        }
    }

    /// The sender MSS for a connection: the peer's MSS, at most what the
    /// interface MTU carries.
    fn smss(&self, tcb: &Tcb) -> u16 {
        tcb.peer_mss().min(self.config.mtu.saturating_sub(IPV4_TCP_HEADERS))
    }

    /// What, if anything, slot `i` has outstanding for its timer.
    fn outstanding(&self, i: usize) -> Option<Guarding> {
        let s = self.sockets.get(i).copied().flatten()?;
        if !matches!(s.link, Link::Resolved(_)) {
            return None;
        }
        let buf = self.tx_rings.get(i)?;
        let state = s.tcb.state();
        if s.tcb.snd_nxt() != s.tcb.snd_una() {
            return Some(match state {
                TcpState::SynSent | TcpState::SynReceived => Guarding::Handshake,
                _ if buf.sent > 0 => Guarding::Data,
                _ => Guarding::Fin,
            });
        }
        let can_send = matches!(state, TcpState::Established | TcpState::CloseWait);
        (can_send && s.tcb.snd_wnd() == 0 && buf.unsent() > 0).then_some(Guarding::Probe)
    }

    /// Slot `i` could transmit new data, or its queued FIN, right now.
    fn ready_to_send(&self, i: usize) -> bool {
        let (Some(Some(s)), Some(buf)) = (self.sockets.get(i), self.tx_rings.get(i)) else { return false };
        if !matches!(s.link, Link::Resolved(_)) || !matches!(s.tcb.state(), TcpState::Established | TcpState::CloseWait) {
            return false;
        }
        if buf.unsent() > 0 {
            let unsent = u32::try_from(buf.unsent()).unwrap_or(u32::MAX);
            sendable(s.tcb.snd_una(), s.tcb.snd_nxt(), s.tcb.snd_wnd(), s.cc.cwnd(), unsent) > 0
        } else {
            s.closing == Closing::Queued
        }
    }

    /// Emit one TCP segment whose payload is the transmit buffer's run at
    /// `offset`, `len` octets. True when a frame was written.
    #[allow(clippy::too_many_arguments)]
    fn emit_data(&mut self, i: usize, acts: &mut Acts, mac: MacAddress, ip: Ipv4Address, header: &TcpRepr, offset: usize, len: usize) -> bool {
        if acts.emitted {
            return false;
        }
        let route = self.route(mac, ip);
        let Some(ring) = self.tx_rings.get(i).copied() else { return false };
        let from = i.saturating_mul(self.stride);
        let mem = self.store.get(from..from.saturating_add(self.tx_per)).unwrap_or(&[]);
        let written = frame::emit_ipv4_tcp(&route, header, ring.run(mem, offset, len), &mut self.tx);
        match written {
            Ok(n) => match u16::try_from(n) {
                Ok(frame_len) if acts.push(Action::Emit { frame_len }) => {
                    acts.emitted = true;
                    true
                }
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Send the next segment of new data, or the queued FIN, if the
    /// windows allow and this step can still emit.
    fn transmit(&mut self, i: usize, now: Instant, acts: &mut Acts) {
        if acts.emitted || !self.ready_to_send(i) {
            return;
        }
        let Some(Some(s)) = self.sockets.get(i).copied() else { return };
        let (Link::Resolved(mac), IpAddress::V4(ip)) = (s.link, s.tcb.remote().address) else { return };
        let Some(ring) = self.tx_rings.get(i).copied() else { return };
        let (sent, unsent) = (ring.sent, ring.unsent());
        if unsent > 0 {
            let allowed = sendable(s.tcb.snd_una(), s.tcb.snd_nxt(), s.tcb.snd_wnd(), s.cc.cwnd(), u32::try_from(unsent).unwrap_or(u32::MAX));
            let want = usize::try_from(allowed).unwrap_or(usize::MAX).min(usize::from(self.smss(&s.tcb)));
            let len = ring.run(self.tx_mem(i), sent, want).len();
            let Ok(len32) = u32::try_from(len) else { return };
            if len == 0 {
                return;
            }
            let Some(Some(slot)) = self.sockets.get_mut(i) else { return };
            let Ok(header) = slot.tcb.send_data(len32) else { return };
            // Counted as sent even if the frame could not be written: the
            // sequence space is used, and the RTO resends from SND.UNA.
            self.emit_data(i, acts, mac, ip, &header, sent, len);
            if let Some(r) = self.tx_rings.get_mut(i) {
                r.sent = r.sent.saturating_add(len);
            }
        } else {
            let mut tcb = s.tcb;
            let Ok(out) = tcb.close() else { return };
            if let Some(e) = out.emit {
                self.emit_tcp(acts, mac, ip, e.repr());
            }
            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                slot.tcb = tcb;
                slot.closing = Closing::Open;
            }
        }
        self.sync_rtx(i, now);
    }

    /// The octet size of one hold chunk.
    fn chunk(&self) -> usize {
        self.hold_per.checked_div(OOO).unwrap_or(0)
    }

    /// Store offset of socket `i`'s hold chunk `k`.
    fn chunk_at(&self, i: usize, k: usize) -> usize {
        i.saturating_mul(self.stride).saturating_add(self.tx_per).saturating_add(k.saturating_mul(self.chunk()))
    }

    /// Hold an out-of-order segment for socket `i` if it lies inside the
    /// receive window, fits one chunk, is not already held and a chunk is
    /// free. Anything else stays dropped (it was acknowledged either way).
    fn hold(&mut self, i: usize, seg: &TcpSegment<'_>) {
        let chunk = self.chunk();
        let len = seg.payload.len();
        if chunk == 0 || len == 0 && !seg.flags.fin() || len > chunk {
            return;
        }
        let Some(Some(s)) = self.sockets.get(i) else { return };
        let ahead = seg.seq.distance_from(s.tcb.rcv_nxt());
        let span = u32::try_from(len).unwrap_or(u32::MAX).saturating_add(u32::from(seg.flags.fin()));
        if ahead == 0 || ahead.saturating_add(span) > s.tcb.rcv_wnd() {
            return;
        }
        let Some(table) = self.holds.get(i) else { return };
        if table.iter().flatten().any(|h| h.seq == seg.seq) {
            return;
        }
        let Some(k) = table.iter().position(Option::is_none) else { return };
        let at = self.chunk_at(i, k);
        let Some(dst) = self.store.get_mut(at..at.saturating_add(len)) else { return };
        dst.copy_from_slice(seg.payload);
        if let Some(entry) = self.holds.get_mut(i).and_then(|t| t.get_mut(k)) {
            *entry = Some(Held { seq: seg.seq, len, fin: seg.flags.fin() });
        }
    }

    /// The chunk of socket `i` whose held segment now starts at or before
    /// RCV.NXT and still reaches past it. Held segments wholly behind
    /// RCV.NXT are discarded on the way.
    fn held_ready(&mut self, i: usize) -> Option<usize> {
        let rcv_nxt = self.sockets.get(i).copied().flatten()?.tcb.rcv_nxt();
        let table = self.holds.get_mut(i)?;
        for (k, entry) in table.iter_mut().enumerate() {
            let Some(h) = *entry else { continue };
            let span = u32::try_from(h.len).unwrap_or(u32::MAX).saturating_add(u32::from(h.fin));
            let end = h.seq.add(span);
            if !h.seq.le(rcv_nxt) {
                continue;
            }
            if end.le(rcv_nxt) {
                *entry = None; // already delivered by later data
                continue;
            }
            return Some(k);
        }
        None
    }

    /// Replay one held segment that the stream has reached into socket
    /// `i`'s block, as an ordinary in-order segment, and apply what it
    /// yields: the cumulative ACK, the held delivery, events.
    fn replay_step(&mut self, i: usize, now: Instant, acts: &mut Acts) {
        if acts.emitted {
            return;
        }
        let Some(k) = self.held_ready(i) else { return };
        let Some(Some(h)) = self.holds.get(i).and_then(|t| t.get(k)).copied() else { return };
        if let Some(entry) = self.holds.get_mut(i).and_then(|t| t.get_mut(k)) {
            *entry = None;
        }
        let at = self.chunk_at(i, k);
        let range = (at, at.saturating_add(h.len));
        let id = self.id_of(i);
        let Some(Some(s)) = self.sockets.get_mut(i) else { return };
        let (Link::Resolved(mac), IpAddress::V4(ip)) = (s.link, s.tcb.remote().address) else { return };
        let Some(payload) = self.store.get(range.0..range.1) else { return };
        let flags = if h.fin { TcpFlags::ACK.union(TcpFlags::PSH).union(TcpFlags::FIN) } else { TcpFlags::ACK.union(TcpFlags::PSH) };
        // ACK = SND.UNA and the current window: the replay acknowledges
        // nothing new and moves no send state; only its text and FIN act.
        let replayed = TcpSegment {
            source_port: s.tcb.remote().port,
            destination_port: s.tcb.local().port,
            seq: h.seq,
            ack: s.tcb.snd_una(),
            flags,
            window: u16::try_from(s.tcb.snd_wnd()).unwrap_or(u16::MAX),
            urgent: 0,
            options: TcpOptions::default(),
            payload,
        };
        let out = s.tcb.on_segment(&replayed);
        let state = s.tcb.state();
        if state == TcpState::TimeWait && s.time_wait_until.is_none() {
            s.time_wait_until = Some(now.after(MSL_MS.saturating_mul(2)));
        }
        let owner = s.owner;
        acts.held = Some(range);
        if let Some(e) = out.emit {
            self.emit_tcp(acts, mac, ip, e.repr());
        }
        for (event, what) in [(TcbEvent::PeerClosed, Notify::PeerClosed), (TcbEvent::Closed, Notify::Closed)] {
            if out.events.contains(event) {
                self.notify(acts, owner, id, what);
            }
        }
        if let (Some(d), Some(socket)) = (out.deliver, id) {
            acts.push(Action::DeliverHeld { socket, offset: d.offset, len: d.len });
            self.notify(acts, owner, id, Notify::DataReady);
        }
        if state == TcpState::Closed {
            self.free_socket(i);
        }
    }

    /// Socket `i` has a held segment the stream has reached.
    fn replay_due(&self, i: usize) -> bool {
        let (Some(Some(s)), Some(table)) = (self.sockets.get(i), self.holds.get(i)) else { return false };
        let rcv_nxt = s.tcb.rcv_nxt();
        table.iter().flatten().any(|h| {
            let span = u32::try_from(h.len).unwrap_or(u32::MAX).saturating_add(u32::from(h.fin));
            h.seq.le(rcv_nxt) && !h.seq.add(span).le(rcv_nxt)
        })
    }

    /// The earliest instant something is due, if anything is pending.
    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for (i, s) in self.sockets.iter().enumerate() {
            let Some(s) = s else { continue };
            if self.ready_to_send(i) || self.replay_due(i) {
                return Some(now);
            }
            let due = match s.link {
                Link::Resolving { deadline, .. } => Some(deadline),
                Link::SynQueued { .. } => Some(now),
                Link::Resolved(_) => match (s.time_wait_until, s.rtx) {
                    (Some(t), _) => Some(t),
                    (None, Rtx::Pending { deadline, .. }) => Some(deadline),
                    (None, Rtx::Idle) => None,
                },
            };
            earliest = match (earliest, due) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        earliest.map(|t| t.max(now))
    }

    /// Send the first answered-but-unsent SYN, if this step can emit.
    fn flush_queued(&mut self, now: Instant, acts: &mut Acts) {
        if acts.emitted {
            return;
        }
        let queued = self.sockets.iter().position(|s| matches!(s, Some(Slot { link: Link::SynQueued { .. }, .. })));
        let Some(i) = queued else { return };
        let Some(Some(s)) = self.sockets.get(i).copied() else { return };
        let Link::SynQueued { mac, syn } = s.link else { return };
        let IpAddress::V4(ip) = s.tcb.remote().address else { return };
        if self.emit_tcp(acts, mac, ip, &syn) {
            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                slot.link = Link::Resolved(mac);
            }
            self.sync_rtx(i, now);
        }
    }

    // ---- frames ----

    fn on_frame(&mut self, now: Instant, f: &[u8], acts: &mut Acts) -> Result<(), EngineError> {
        match frame::classify(f, self.config.mtu) {
            Err(e) => Err(EngineError::Refused(Refusal::Malformed(e))),
            Ok(Classified::Arp { arp, .. }) => {
                self.on_arp(now, &arp, acts);
                Ok(())
            }
            Ok(Classified::OtherEtherType { .. }) => Err(EngineError::Refused(Refusal::NotIpv4)),
            Ok(Classified::Ipv4Other { .. }) => Err(EngineError::Refused(Refusal::UnsupportedProtocol)),
            Ok(Classified::Ipv4Icmp { link, ip, message }) => self.on_icmp(link.source, &ip, &message, acts),
            Ok(Classified::Ipv4Udp { ip, datagram, .. }) => self.on_datagram(&ip, &datagram, acts),
            Ok(Classified::Ipv4Tcp { link, ip, segment }) => self.on_segment(now, link.source, &ip, &segment, acts),
        }
    }

    fn on_arp(&mut self, now: Instant, arp: &ArpPacket, acts: &mut Acts) {
        if !self.addressed {
            return; // no address to answer for or to learn from
        }
        let expires = now.0.saturating_add(self.config.neighbor_ttl_ms);
        let learned = self.neighbors.on_arp(arp, self.config.ipv4, now.0, expires);
        let for_us = arp.operation == ArpOperation::Request
            && arp.target_ip == self.config.ipv4
            && !arp.sender_mac.is_group()
            && !arp.sender_mac.is_zero();
        if for_us {
            let reply = ArpPacket {
                operation: ArpOperation::Reply,
                sender_mac: self.config.mac,
                sender_ip: self.config.ipv4,
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            self.emit_arp(acts, arp.sender_mac, &reply);
        }
        if learned == Learn::Resolved {
            for s in self.sockets.iter_mut().flatten() {
                if let Link::Resolving { next_hop, syn, .. } = s.link {
                    if next_hop == arp.sender_ip {
                        s.link = Link::SynQueued { mac: arp.sender_mac, syn };
                    }
                }
            }
            self.flush_queued(now, acts);
        }
    }

    /// ICMPv4 (ADR-039 § 5.2): an echo request addressed to this
    /// interface's unicast address gets an echo reply carrying the same
    /// identifier, sequence and data (RFC 792, RFC 1122 § 3.2.2.6). The
    /// reply is the request's size, so it amplifies nothing. Every other
    /// message is refused uninterpreted.
    fn on_icmp(&mut self, src_mac: MacAddress, ip: &Ipv4Packet<'_>, message: &Icmpv4Message<'_>, acts: &mut Acts) -> Result<(), EngineError> {
        if !self.addressed || ip.destination != self.config.ipv4 {
            return Err(EngineError::Refused(Refusal::NotForUs));
        }
        let Icmpv4Message::Echo { echo, data } = message else {
            return Err(EngineError::Refused(Refusal::IcmpIgnored));
        };
        if echo.kind != EchoKind::Request {
            return Err(EngineError::Refused(Refusal::IcmpIgnored));
        }
        if acts.emitted {
            return Ok(());
        }
        let reply = Echo { kind: EchoKind::Reply, identifier: echo.identifier, sequence: echo.sequence };
        let route = self.route(src_mac, ip.source);
        if let Ok(n) = frame::emit_ipv4_icmp_echo(&route, &reply, data, &mut self.tx) {
            self.set_emit(acts, n);
        }
        Ok(())
    }

    fn on_datagram(&mut self, ip: &Ipv4Packet<'_>, d: &UdpDatagram<'_>, acts: &mut Acts) -> Result<(), EngineError> {
        if !self.addressed || ip.destination != self.config.ipv4 {
            return Err(EngineError::Refused(Refusal::NotForUs));
        }
        let i = self
            .udp
            .iter()
            .position(|b| matches!(b, Some(b) if b.port == d.destination_port))
            .ok_or(EngineError::Refused(Refusal::NoEndpoint))?;
        let generation = *self.udp_gen.get(i).ok_or(EngineError::Refused(Refusal::NoEndpoint))?;
        let slot = u16::try_from(i).map_err(|_| EngineError::Refused(Refusal::NoEndpoint))?;
        // Payload follows the Ethernet, IPv4 and UDP headers; each term is
        // bounded by the frame length.
        let offset = ethernet::HEADER_LEN
            .checked_add(ip.header_len)
            .and_then(|o| o.checked_add(udp::HEADER_LEN))
            .ok_or(EngineError::Refused(Refusal::NoEndpoint))?;
        acts.push(Action::Datagram {
            endpoint: UdpId { slot, generation },
            from: SocketAddress { address: IpAddress::V4(ip.source), port: d.source_port },
            offset,
            len: d.payload.len(),
        });
        Ok(())
    }

    fn on_segment(
        &mut self,
        now: Instant,
        src_mac: MacAddress,
        ip: &Ipv4Packet<'_>,
        seg: &TcpSegment<'_>,
        acts: &mut Acts,
    ) -> Result<(), EngineError> {
        if !self.addressed || ip.destination != self.config.ipv4 {
            return Err(EngineError::Refused(Refusal::NotForUs));
        }
        let remote = SocketAddress { address: IpAddress::V4(ip.source), port: seg.source_port };
        let matched = self.sockets.iter().position(|s| match s {
            Some(s) => {
                matches!(s.link, Link::Resolved(_))
                    && s.tcb.local().port == seg.destination_port
                    && s.tcb.remote() == remote
            }
            None => false,
        });
        if let Some(i) = matched {
            self.on_matched(now, i, src_mac, ip, seg, acts);
            return Ok(());
        }
        let listener = self.listeners.iter().position(|l| matches!(l, Some(l) if l.port == seg.destination_port));
        let Some(li) = listener else {
            if let Some(rst) = reset_for_unmatched(seg) {
                self.emit_tcp(acts, src_mac, ip.source, &rst);
            }
            return Ok(());
        };
        let is_syn = seg.flags.syn() && !seg.flags.ack() && !seg.flags.rst();
        let free_slot = self.free_slot();
        if is_syn {
            let half_open = self
                .sockets
                .iter()
                .flatten()
                .filter(|s| s.owner == Owner::Unclaimed { listener: li } && s.tcb.state() == TcpState::SynReceived)
                .count();
            if half_open >= usize::from(self.config.half_open_per_listener) {
                return Err(EngineError::Refused(Refusal::HalfOpenFull));
            }
            if free_slot.is_none() {
                return Err(EngineError::Refused(Refusal::SocketTableFull));
            }
        }
        // A listener exists only with a key (`listen` refuses without
        // one), so `None` here is unreachable; it is still answered as an
        // unmatched segment rather than opened with a weak sequence.
        let Some(iss) = self.iss(now, seg.destination_port, ip.source, seg.source_port) else {
            if let Some(rst) = reset_for_unmatched(seg) {
                self.emit_tcp(acts, src_mac, ip.source, &rst);
            }
            return Ok(());
        };
        match Tcb::accept_syn(self.config.tcb, self.local(seg.destination_port), remote, seg, iss) {
            Err(outcome) => {
                if let Some(e) = outcome.emit {
                    self.emit_tcp(acts, src_mac, ip.source, e.repr());
                }
                Ok(())
            }
            Ok((tcb, outcome)) => {
                let Some(i) = free_slot else {
                    return Err(EngineError::Refused(Refusal::SocketTableFull));
                };
                if let Some(entry) = self.sockets.get_mut(i) {
                    *entry = Some(Slot {
                        owner: Owner::Unclaimed { listener: li },
                        tcb,
                        link: Link::Resolved(src_mac),
                        time_wait_until: None,
                        last_challenge: None,
                        rtx: Rtx::Idle,
                        rto: RtoEstimator::new(),
                        cc: Reno::new(DEFAULT_SMSS),
                        dup_acks: 0,
                        recovery: Recovery::Normal,
                        closing: Closing::Open,
                    });
                }
                if let Some(e) = outcome.emit {
                    self.emit_tcp(acts, src_mac, ip.source, e.repr());
                }
                self.sync_rtx(i, now);
                Ok(())
            }
        }
    }

    fn on_matched(
        &mut self,
        now: Instant,
        i: usize,
        src_mac: MacAddress,
        ip: &Ipv4Packet<'_>,
        seg: &TcpSegment<'_>,
        acts: &mut Acts,
    ) {
        let id = self.id_of(i);
        let interval = self.config.challenge_ack_interval_ms;
        let mtu_mss = self.config.mtu.saturating_sub(IPV4_TCP_HEADERS);
        let Some(Some(s)) = self.sockets.get_mut(i) else { return };
        let una_before = s.tcb.snd_una();
        let wnd_before = s.tcb.snd_wnd();
        let mut out: Outcome = s.tcb.on_segment(seg);
        let smss = s.tcb.peer_mss().min(mtu_mss);
        if out.events.contains(TcbEvent::Connected) {
            s.cc = Reno::new(smss);
        }
        // New data acknowledged: release it, grow cwnd, and restart the
        // timer for what remains (RFC 6298 § 5.3). A peer that keeps
        // answering a zero window is alive: its probes are not failures.
        let advanced = usize::try_from(s.tcb.snd_una().distance_from(una_before)).unwrap_or(0);
        let acked = self.tx_rings.get(i).map_or(0, |r| advanced.min(r.sent));
        // RFC 5681 § 2: a duplicate ACK acknowledges nothing new, carries
        // no data, SYN or FIN, leaves the window unchanged, and arrives
        // while data is outstanding.
        let in_flight = self.tx_rings.get(i).map_or(0, |r| r.sent);
        let duplicate = advanced == 0
            && in_flight > 0
            && seg.payload.is_empty()
            && !seg.flags.syn()
            && !seg.flags.fin()
            && seg.flags.ack()
            && seg.ack == una_before
            && s.tcb.snd_wnd() == wnd_before
            && out.drop.is_none();
        let mut fast_retransmit = false;
        if acked > 0 {
            let cap = self.tx_per;
            if let Some(r) = self.tx_rings.get_mut(i) {
                r.release(acked, cap);
            }
            match s.recovery {
                Recovery::Fast => {
                    s.cc.deflate();
                    s.recovery = Recovery::Normal;
                }
                Recovery::Normal => s.cc.on_ack(u32::try_from(acked).unwrap_or(u32::MAX), smss),
            }
            s.dup_acks = 0;
        } else if duplicate {
            s.dup_acks = s.dup_acks.saturating_add(1);
            match s.recovery {
                Recovery::Fast => s.cc.inflate(smss),
                Recovery::Normal if s.dup_acks == DUP_ACK_THRESHOLD => {
                    let flight = s.tcb.snd_nxt().distance_from(s.tcb.snd_una());
                    s.cc.enter_fast_recovery(flight, smss);
                    s.recovery = Recovery::Fast;
                    fast_retransmit = true;
                }
                Recovery::Normal => {}
            }
        } else {
            s.dup_acks = 0;
        }
        if let Rtx::Pending { guarding, first_sent, retries, .. } = s.rtx {
            // New data acknowledged, or a probe answered while the peer's
            // window is still zero: restart the timer with fresh retries.
            if acked > 0 || (s.tcb.snd_wnd() == 0 && retries > 0) {
                s.rtx = Rtx::Pending { guarding, first_sent, deadline: now.after(s.rto.rto_ms()), retries: 0 };
            }
        }
        if let Some(Emit::ChallengeAck(_)) = out.emit {
            let too_soon = matches!(s.last_challenge, Some(t) if now < t.after(interval));
            if too_soon {
                out.emit = None;
            } else {
                s.last_challenge = Some(now);
            }
        }
        let state = s.tcb.state();
        if state == TcpState::TimeWait && s.time_wait_until.is_none() {
            s.time_wait_until = Some(now.after(MSL_MS.saturating_mul(2)));
        }
        let owner = s.owner;
        if state == TcpState::Closed {
            self.free_socket(i);
        } else {
            self.sync_rtx(i, now);
        }
        if out.drop == Some(DropReason::OutOfOrder) {
            self.hold(i, seg);
        }
        // New in-order text that reaches a held segment: the replay's ACK
        // is the cumulative one, so this segment's plain ACK is not sent.
        let replay = state != TcpState::Closed && out.deliver.is_some() && self.replay_due(i);
        if let (Some(e), false) = (out.emit, replay) {
            self.emit_tcp(acts, src_mac, ip.source, e.repr());
        }
        for (event, what) in [
            (TcbEvent::Connected, Notify::Connected),
            (TcbEvent::PeerClosed, Notify::PeerClosed),
            (TcbEvent::Reset, Notify::Reset),
            (TcbEvent::Refused, Notify::Refused),
            (TcbEvent::Closed, Notify::Closed),
        ] {
            if out.events.contains(event) {
                self.notify(acts, owner, id, what);
            }
        }
        if let (Some(d), Some(socket)) = (out.deliver.and_then(|d| rebase(d, ip, seg)), id) {
            acts.push(Action::Deliver { socket, offset: d.offset, len: d.len });
            self.notify(acts, owner, id, Notify::DataReady);
        }
        if fast_retransmit {
            self.resend_first(i, acts);
        }
        if replay {
            self.replay_step(i, now, acts);
        }
        if state != TcpState::Closed && self.sockets.get(i).is_some_and(Option::is_some) {
            self.transmit(i, now, acts);
        }
    }

    // ---- time ----

    fn on_tick(&mut self, now: Instant, acts: &mut Acts) {
        let timeout = self.config.arp_timeout_ms;
        let attempts_max = self.config.arp_attempts;
        for i in 0..SOCKETS {
            if acts.room_before_arm() == 0 {
                break;
            }
            let Some(Some(s)) = self.sockets.get(i).copied() else { continue };
            let id = self.id_of(i);
            match s.link {
                Link::Resolving { next_hop, attempts, deadline, syn } if deadline <= now => {
                    if attempts < attempts_max {
                        if acts.emitted {
                            continue; // still due; the closing Arm is `now`
                        }
                        let until = now.0.saturating_add(timeout);
                        if self.neighbors.request(next_hop, now.0, until).is_ok() && self.who_has(acts, next_hop) {
                            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                                slot.link = Link::Resolving {
                                    next_hop,
                                    attempts: attempts.saturating_add(1),
                                    deadline: now.after(timeout),
                                    syn,
                                };
                            }
                            continue;
                        }
                    }
                    self.free_socket(i);
                    self.notify(acts, s.owner, id, Notify::Error(NetError::NoRoute));
                }
                Link::Resolved(mac) => {
                    if matches!(s.time_wait_until, Some(t) if t <= now) {
                        self.free_socket(i);
                        self.notify(acts, s.owner, id, Notify::Closed);
                        continue;
                    }
                    if let Rtx::Pending { guarding, deadline, retries, .. } = s.rtx {
                        if deadline <= now {
                            if retries >= self.config.max_retransmits {
                                self.free_socket(i);
                                self.notify(acts, s.owner, id, Notify::Error(NetError::TimedOut));
                                continue;
                            }
                            if !self.expire(i, now, mac, guarding, retries, acts) {
                                continue; // still due; the closing Arm is `now`
                            }
                        }
                    }
                    self.replay_step(i, now, acts);
                    if self.sockets.get(i).is_some_and(Option::is_some) {
                        self.transmit(i, now, acts);
                    }
                }
                Link::Resolving { .. } | Link::SynQueued { .. } => {}
            }
        }
        self.flush_queued(now, acts);
    }

    /// Fast retransmit: resend the first unacknowledged segment now,
    /// without waiting for the RTO and without backing it off. It was
    /// resent, so no RTT sample may come from it (Karn).
    fn resend_first(&mut self, i: usize, acts: &mut Acts) {
        let Some(Some(s)) = self.sockets.get(i).copied() else { return };
        let (Link::Resolved(mac), IpAddress::V4(ip)) = (s.link, s.tcb.remote().address) else { return };
        let sent = self.tx_rings.get(i).map_or(0, |r| r.sent);
        let len = sent.min(usize::from(self.smss(&s.tcb)));
        let header = s.tcb.data_header(s.tcb.snd_una());
        if self.emit_data(i, acts, mac, ip, &header, 0, len) {
            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                if let Rtx::Pending { guarding, deadline, retries, .. } = slot.rtx {
                    slot.rtx = Rtx::Pending { guarding, first_sent: None, deadline, retries };
                }
            }
        }
    }

    /// Slot `i`'s timer fired: resend the oldest unacknowledged data (and
    /// collapse cwnd), send a zero-window probe, or resend the SYN,
    /// SYN-ACK or FIN; then back off. False if this step could not emit.
    #[allow(clippy::too_many_arguments)]
    fn expire(&mut self, i: usize, now: Instant, mac: MacAddress, guarding: Guarding, retries: u8, acts: &mut Acts) -> bool {
        if acts.emitted {
            return false;
        }
        let Some(Some(s)) = self.sockets.get(i).copied() else { return false };
        let IpAddress::V4(ip) = s.tcb.remote().address else { return false };
        let smss = self.smss(&s.tcb);
        let sent = self.tx_rings.get(i).map_or(0, |r| r.sent);
        let emitted = match guarding {
            Guarding::Data if sent > 0 => {
                let len = sent.min(usize::from(smss));
                let header = s.tcb.data_header(s.tcb.snd_una());
                let flight = s.tcb.snd_nxt().distance_from(s.tcb.snd_una());
                let ok = self.emit_data(i, acts, mac, ip, &header, 0, len);
                if ok {
                    if let Some(Some(slot)) = self.sockets.get_mut(i) {
                        slot.cc.on_timeout(flight, smss);
                        slot.recovery = Recovery::Normal;
                        slot.dup_acks = 0;
                    }
                }
                ok
            }
            Guarding::Probe => {
                let Some(Some(slot)) = self.sockets.get_mut(i) else { return false };
                let Ok(header) = slot.tcb.send_data(1) else { return false };
                let ok = self.emit_data(i, acts, mac, ip, &header, 0, 1);
                if let Some(r) = self.tx_rings.get_mut(i) {
                    r.sent = r.sent.saturating_add(1);
                }
                ok
            }
            Guarding::Handshake | Guarding::Fin | Guarding::Data => match s.tcb.retransmit() {
                Some(segment) => self.emit_tcp(acts, mac, ip, &segment),
                None => false,
            },
        };
        if emitted {
            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                slot.rto.back_off();
                let guarding = if guarding == Guarding::Probe { Guarding::Data } else { guarding };
                slot.rtx = Rtx::Pending { guarding, first_sent: None, deadline: now.after(slot.rto.rto_ms()), retries: retries.saturating_add(1) };
            }
        }
        emitted
    }

    // ---- control ----

    fn owned(&self, id: SocketId, from: Principal) -> Result<usize, NetError> {
        let i = self.socket_index(id).ok_or(NetError::Closed)?;
        match self.sockets.get(i).copied().flatten().map(|s| s.owner) {
            Some(Owner::Client(p)) if p == from => Ok(i),
            Some(_) => Err(NetError::Denied),
            None => Err(NetError::Closed),
        }
    }

    fn owned_listener(&self, id: ListenerId, from: Principal) -> Result<usize, NetError> {
        let i = live(&self.listeners, &self.listener_gen, id.slot, id.generation).ok_or(NetError::Closed)?;
        match self.listeners.get(i).copied().flatten() {
            Some(b) if b.owner == from => Ok(i),
            Some(_) => Err(NetError::Denied),
            None => Err(NetError::Closed),
        }
    }

    fn owned_udp(&self, id: UdpId, from: Principal) -> Result<(usize, u16), NetError> {
        let i = live(&self.udp, &self.udp_gen, id.slot, id.generation).ok_or(NetError::Closed)?;
        match self.udp.get(i).copied().flatten() {
            Some(b) if b.owner == from => Ok((i, b.port)),
            Some(_) => Err(NetError::Denied),
            None => Err(NetError::Closed),
        }
    }

    fn on_control(&mut self, now: Instant, c: &Control<'_>, acts: &mut Acts) -> ControlReply {
        let result = match c.op {
            Op::Connect { remote, local_port } => self.connect(now, c.from, remote, local_port, acts),
            Op::Listen { port } => self.listen(c.from, port),
            Op::Unlisten { listener } => self.unlisten(c.from, listener),
            Op::Accept { listener } => self.accept(c.from, listener),
            Op::Close { socket } => self.close(now, c.from, socket, acts),
            Op::Send { socket, data } => self.send(now, c.from, socket, data, acts),
            Op::Status { socket } => self
                .owned(socket, c.from)
                .and_then(|_| self.state(socket).ok_or(NetError::Closed))
                .map(ControlReply::State),
            Op::Consumed { socket, octets } => self.consumed(c.from, socket, octets, acts),
            Op::UdpBind { port } => self.udp_bind(c.from, port),
            Op::UdpUnbind { endpoint } => self.owned_udp(endpoint, c.from).map(|(i, _)| {
                free(&mut self.udp, &mut self.udp_gen, i);
                ControlReply::Done
            }),
            Op::UdpSend { endpoint, remote, payload } => self.udp_send(now, c.from, endpoint, remote, payload, acts),
            Op::PinNeighbor { ip, mac } => match self.neighbors.pin(ip, mac) {
                Ok(()) => Ok(ControlReply::Done),
                Err(NeighborError::InvalidAddress) => Err(NetError::Malformed),
                Err(NeighborError::TableFull) => Err(NetError::ResourceLimit),
            },
        };
        result.unwrap_or_else(ControlReply::Refused)
    }

    fn connect(
        &mut self,
        now: Instant,
        from: Principal,
        remote: SocketAddress,
        local_port: u16,
        acts: &mut Acts,
    ) -> Result<ControlReply, NetError> {
        if !self.addressed {
            return Err(NetError::NoAddress);
        }
        if self.config.iss_key.is_none() {
            return Err(NetError::Unsupported);
        }
        let IpAddress::V4(remote_ip) = remote.address else {
            return Err(NetError::Unsupported);
        };
        if !valid_unicast(remote_ip) {
            return Err(NetError::NoRoute);
        }
        // Port 0 is reserved (RFC 6335 § 6) and never goes on the wire;
        // the shell picks the ephemeral port.
        if local_port == 0 || remote.port == 0 {
            return Err(NetError::Malformed);
        }
        if self.find(local_port, remote).is_some() {
            return Err(NetError::AddressInUse);
        }
        let next_hop = self.next_hop(remote_ip).ok_or(NetError::NoRoute)?;
        let i = self.free_slot().ok_or(NetError::ResourceLimit)?;
        let id = self.id_of(i).ok_or(NetError::ResourceLimit)?;
        let iss = self.iss(now, local_port, remote_ip, remote.port).ok_or(NetError::Unsupported)?;
        let (tcb, syn) = Tcb::connect(self.config.tcb, self.local(local_port), remote, iss);
        let link = match self.neighbors.lookup(next_hop, now.0) {
            Some(mac) => {
                self.emit_tcp(acts, mac, remote_ip, &syn);
                Link::Resolved(mac)
            }
            None => {
                let timeout = self.config.arp_timeout_ms;
                self.neighbors.request(next_hop, now.0, now.0.saturating_add(timeout)).map_err(|e| match e {
                    NeighborError::InvalidAddress => NetError::NoRoute,
                    NeighborError::TableFull => NetError::ResourceLimit,
                })?;
                self.who_has(acts, next_hop);
                Link::Resolving { next_hop, attempts: 1, deadline: now.after(timeout), syn }
            }
        };
        if let Some(entry) = self.sockets.get_mut(i) {
            *entry = Some(Slot {
                owner: Owner::Client(from),
                tcb,
                link,
                time_wait_until: None,
                last_challenge: None,
                rtx: Rtx::Idle,
                rto: RtoEstimator::new(),
                cc: Reno::new(DEFAULT_SMSS),
                        dup_acks: 0,
                        recovery: Recovery::Normal,
                closing: Closing::Open,
            });
        }
        self.sync_rtx(i, now);
        Ok(ControlReply::Socket(id))
    }

    fn listen(&mut self, from: Principal, port: u16) -> Result<ControlReply, NetError> {
        if self.config.iss_key.is_none() {
            return Err(NetError::Unsupported);
        }
        if self.listeners.iter().any(|l| matches!(l, Some(l) if l.port == port)) {
            return Err(NetError::AddressInUse);
        }
        let i = self.listeners.iter().position(Option::is_none).ok_or(NetError::ResourceLimit)?;
        let generation = *self.listener_gen.get(i).ok_or(NetError::ResourceLimit)?;
        let slot = u16::try_from(i).map_err(|_| NetError::ResourceLimit)?;
        if let Some(entry) = self.listeners.get_mut(i) {
            *entry = Some(Bound { owner: from, port });
        }
        Ok(ControlReply::Listener(ListenerId { slot, generation }))
    }

    /// Close a listener. Its unaccepted connections are dropped without a
    /// reset; their peers time out.
    fn unlisten(&mut self, from: Principal, id: ListenerId) -> Result<ControlReply, NetError> {
        let li = self.owned_listener(id, from)?;
        free(&mut self.listeners, &mut self.listener_gen, li);
        for i in 0..SOCKETS {
            if matches!(self.sockets.get(i), Some(Some(s)) if s.owner == Owner::Unclaimed { listener: li }) {
                self.free_socket(i);
            }
        }
        Ok(ControlReply::Done)
    }

    fn accept(&mut self, from: Principal, id: ListenerId) -> Result<ControlReply, NetError> {
        let li = self.owned_listener(id, from)?;
        let ready = self.sockets.iter().position(|s| {
            matches!(s, Some(s) if s.owner == Owner::Unclaimed { listener: li }
                && matches!(s.tcb.state(), TcpState::Established | TcpState::CloseWait))
        });
        let Some(i) = ready else { return Ok(ControlReply::NoData) };
        let socket = self.id_of(i).ok_or(NetError::Closed)?;
        let Some(Some(s)) = self.sockets.get_mut(i) else { return Err(NetError::Closed) };
        s.owner = Owner::Client(from);
        Ok(ControlReply::Accepted { socket, peer: s.tcb.remote() })
    }

    fn close(&mut self, now: Instant, from: Principal, id: SocketId, acts: &mut Acts) -> Result<ControlReply, NetError> {
        let i = self.owned(id, from)?;
        let s = self.sockets.get(i).copied().flatten().ok_or(NetError::Closed)?;
        let Link::Resolved(mac) = s.link else {
            // No SYN on the wire yet: nothing to tell the peer.
            self.free_socket(i);
            return Ok(ControlReply::Done);
        };
        let unsent = self.tx_rings.get(i).map_or(0, TxRing::unsent);
        if s.closing == Closing::Queued {
            return Err(NetError::Closed);
        }
        if unsent > 0 {
            // The FIN must follow every octet: send it once the buffer has
            // been transmitted (`transmit`).
            if let Some(Some(slot)) = self.sockets.get_mut(i) {
                slot.closing = Closing::Queued;
            }
            return Ok(ControlReply::Done);
        }
        let mut tcb = s.tcb;
        let out = tcb.close()?;
        if let (Some(e), IpAddress::V4(ip)) = (out.emit, tcb.remote().address) {
            self.emit_tcp(acts, mac, ip, e.repr());
        }
        if tcb.state() == TcpState::Closed {
            self.free_socket(i);
        } else if let Some(Some(slot)) = self.sockets.get_mut(i) {
            slot.tcb = tcb;
            self.sync_rtx(i, now);
        }
        Ok(ControlReply::Done)
    }

    fn send(&mut self, now: Instant, from: Principal, id: SocketId, data: &[u8], acts: &mut Acts) -> Result<ControlReply, NetError> {
        let i = self.owned(id, from)?;
        let s = self.sockets.get(i).copied().flatten().ok_or(NetError::Closed)?;
        let open = matches!(s.tcb.state(), TcpState::SynSent | TcpState::SynReceived | TcpState::Established | TcpState::CloseWait);
        if s.closing == Closing::Queued || !open {
            return Err(NetError::Closed);
        }
        let from = i.saturating_mul(self.stride);
        let to = from.saturating_add(self.tx_per);
        let n = match (self.tx_rings.get_mut(i), self.store.get_mut(from..to)) {
            (Some(ring), Some(mem)) => ring.push(mem, data),
            _ => 0,
        };
        if n == 0 && !data.is_empty() {
            return Err(NetError::WouldBlock);
        }
        self.transmit(i, now, acts);
        self.sync_rtx(i, now);
        Ok(ControlReply::Sent(u32::try_from(n).unwrap_or(u32::MAX)))
    }

    /// The owner consumed `octets` from the socket's receive ring: reopen
    /// the window, and announce it when it crosses the receiver
    /// silly-window threshold min(buffer / 2, SMSS) from below (RFC 9293
    /// § 3.8.6.2.2). Smaller reopenings ride on later ACKs.
    fn consumed(&mut self, from: Principal, id: SocketId, octets: u32, acts: &mut Acts) -> Result<ControlReply, NetError> {
        let i = self.owned(id, from)?;
        let s = self.sockets.get(i).copied().flatten().ok_or(NetError::Closed)?;
        let capacity = u32::from(self.config.tcb.receive_window);
        let threshold = (capacity / 2).min(u32::from(self.smss(&s.tcb)));
        let before = s.tcb.rcv_wnd();
        let mut tcb = s.tcb;
        tcb.release_receive_space(octets);
        let after = tcb.rcv_wnd();
        if let Some(Some(slot)) = self.sockets.get_mut(i) {
            slot.tcb = tcb;
        }
        let receiving = matches!(tcb.state(), TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2);
        if let (Link::Resolved(mac), IpAddress::V4(ip), true) = (s.link, tcb.remote().address, receiving) {
            if before < threshold && after >= threshold {
                self.emit_tcp(acts, mac, ip, &tcb.ack_header());
            }
        }
        Ok(ControlReply::Done)
    }

    fn udp_bind(&mut self, from: Principal, port: u16) -> Result<ControlReply, NetError> {
        if self.udp.iter().any(|b| matches!(b, Some(b) if b.port == port)) {
            return Err(NetError::AddressInUse);
        }
        let i = self.udp.iter().position(Option::is_none).ok_or(NetError::ResourceLimit)?;
        let generation = *self.udp_gen.get(i).ok_or(NetError::ResourceLimit)?;
        let slot = u16::try_from(i).map_err(|_| NetError::ResourceLimit)?;
        if let Some(entry) = self.udp.get_mut(i) {
            *entry = Some(Bound { owner: from, port });
        }
        Ok(ControlReply::Endpoint(UdpId { slot, generation }))
    }

    fn udp_send(
        &mut self,
        now: Instant,
        from: Principal,
        endpoint: UdpId,
        remote: SocketAddress,
        payload: &[u8],
        acts: &mut Acts,
    ) -> Result<ControlReply, NetError> {
        let (_, port) = self.owned_udp(endpoint, from)?;
        if !self.addressed {
            return Err(NetError::NoAddress);
        }
        let IpAddress::V4(remote_ip) = remote.address else {
            return Err(NetError::Unsupported);
        };
        let packet = payload
            .len()
            .checked_add(ipv4::MIN_HEADER_LEN)
            .and_then(|n| n.checked_add(udp::HEADER_LEN))
            .ok_or(NetError::ResourceLimit)?;
        if packet > usize::from(self.config.mtu) {
            return Err(NetError::ResourceLimit);
        }
        if !valid_unicast(remote_ip) {
            return Err(NetError::NoRoute);
        }
        let next_hop = self.next_hop(remote_ip).ok_or(NetError::NoRoute)?;
        let Some(mac) = self.neighbors.lookup(next_hop, now.0) else {
            let until = now.0.saturating_add(self.config.arp_timeout_ms);
            if self.neighbors.request(next_hop, now.0, until).is_ok() {
                self.who_has(acts, next_hop);
            }
            return Err(NetError::WouldBlock);
        };
        let route = self.route(mac, remote_ip);
        let repr = UdpRepr { source_port: port, destination_port: remote.port };
        let n = frame::emit_ipv4_udp(&route, &repr, payload, &mut self.tx).map_err(|_| NetError::ResourceLimit)?;
        if self.set_emit(acts, n) {
            Ok(ControlReply::Done)
        } else {
            Err(NetError::WouldBlock)
        }
    }
}

/// Move a delivery range from the segment's payload to the frame: the
/// TCP payload is the tail of the IPv4 payload, after the Ethernet and
/// IPv4 headers. Every term is bounded by the frame length.
fn rebase(d: Delivery, ip: &Ipv4Packet<'_>, seg: &TcpSegment<'_>) -> Option<Delivery> {
    let tcp_header = ip.payload.len().checked_sub(seg.payload.len())?;
    let offset = ethernet::HEADER_LEN.checked_add(ip.header_len)?.checked_add(tcp_header)?.checked_add(d.offset)?;
    Some(Delivery { offset, len: d.len })
}

/// Bounded proofs (run with `cargo kani -Z stubbing`; compiled only under
/// `cfg(kani)`).
///
/// P6 for the engine (ADR-039 § 6.1 "step is total"), bounded: on an
/// engine with a listener and a UDP endpoint on symbolic ports, any
/// received frame of 0..=42 octets at any instant, then a tick, returns
/// without panic, out-of-bounds access or overflow; at most
/// `MAX_ACTIONS_PER_STEP` actions come back and any emitted frame fits the
/// transmit buffer. The TCP option walk and the checksum accumulator are
/// replaced by the sound over-approximating stubs that the parser proofs
/// establish (see `wire::frame::proofs`).
///
/// 42 octets is a full Ethernet + ARP frame and covers every Ethernet and
/// IPv4 header boundary; it does not reach a TCP header, so TCP options and
/// most valid TCP/UDP frames are not covered (codex ruling 2026-11-12; the
/// earlier 64-octet bound timed out and stays "no verdict").
///
/// What this does NOT cover: frames longer than 42 octets, engines with
/// established connections (the tables start empty but for the listener,
/// so only the open path is explored past the parsers), and control ops
/// beyond the two used for setup.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// SCAFFOLDING: frame length for the engine totality harness.
    /// Why: a full Ethernet + ARP frame and every Ethernet/IPv4 header
    /// boundary, while keeping the whole step solver-tractable (64 timed
    /// out at 1800 s).
    /// Replace when: this harness runs within the CI budget and a larger
    /// bound (up to `MAX_FRAME_LEN`) is affordable.
    const SMALL: usize = 42;

    fn config() -> EngineConfig {
        EngineConfig {
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            ipv4: Ipv4Address([192, 0, 2, 2]),
            prefix_len: 24,
            gateway: None,
            ttl: 64,
            mtu: 1500,
            tcb: TcbConfig { local_mss: 1460, receive_window: 4096 },
            iss_key: Some(IssKey([7; 16])),
            half_open_per_listener: 1,
            neighbor_ttl_ms: 60_000,
            arp_timeout_ms: 1_000,
            arp_attempts: 2,
            challenge_ack_interval_ms: 1_000,
            max_retransmits: 2,
            hold_per_socket: 0,
        }
    }

    /// Stand-in for `TxRing::push` in the engine harnesses.
    ///
    /// Contract (proved for `TxRing::push` by
    /// `p6_tx_ring_push_meets_its_contract` below, for every ring state):
    /// - the return value is `n = min(data.len(), mem.len() - len)`
    ///   (saturating), exactly as `push` computes it;
    /// - `len` grows by `n` (saturating); `start` and `sent` are unchanged;
    /// - `push` writes only inside `mem` and never panics.
    ///
    /// The stand-in keeps the first two points exactly and replaces the
    /// octets of `mem` with arbitrary values. `push` writes some of them
    /// and leaves the rest, so the stand-in allows every outcome `push` can
    /// produce, and more. It assumes nothing about its inputs. What the
    /// engine harness proves with it holds for the real `push`. The octet
    /// values themselves are the subject of
    /// `p6_tx_ring_push_copies_data_in_ring_order`.
    fn tx_ring_push_stub(ring: &mut TxRing, mem: &mut [u8], data: &[u8]) -> usize {
        let cap = mem.len();
        let n = data.len().min(cap.saturating_sub(ring.len));
        ring.len = ring.len.saturating_add(n);
        if cap <= HAVOC {
            let any: [u8; HAVOC] = kani::any();
            if let (Some(dst), Some(src)) = (mem.get_mut(..cap), any.get(..cap)) {
                dst.copy_from_slice(src);
            }
        } else {
            for b in mem.iter_mut() {
                *b = kani::any();
            }
        }
        n
    }

    /// SCAFFOLDING: widest `mem` the stand-in overwrites with one copy;
    /// wider slices take the per-octet path.
    /// Why: covers the 16-octet store of the engine harness.
    /// Replace when: an engine harness uses a store wider than 64 octets.
    const HAVOC: usize = 64;

    /// SCAFFOLDING: widest ring and data slice in the `push` harnesses.
    /// Why: one more than a wrap of a full ring; `push`'s loop is per
    /// octet, so the solver cost grows with this bound.
    /// Replace when: a larger bound is affordable, or `push` changes.
    const RING: usize = 8;

    /// `TxRing::push` meets the stand-in's contract for every ring state
    /// (any `start`, `len`, `sent`, no assumption) and any `mem` and
    /// `data` up to `RING` octets: the exact return value, the ring
    /// fields, writes only inside `mem`, no panic or overflow.
    #[kani::proof]
    #[kani::unwind(10)]
    fn p6_tx_ring_push_meets_its_contract() {
        let mut mem: [u8; RING] = kani::any();
        let data: [u8; RING] = kani::any();
        let (m, d): (usize, usize) = (kani::any(), kani::any());
        kani::assume(m <= RING && d <= RING);
        let mut ring = TxRing { start: kani::any(), len: kani::any(), sent: kani::any() };
        let before = ring;
        let n = ring.push(&mut mem[..m], &data[..d]);
        assert_eq!(n, d.min(m.saturating_sub(before.len)));
        assert_eq!(ring.len, before.len.saturating_add(n));
        assert_eq!(ring.start, before.start);
        assert_eq!(ring.sent, before.sent);
    }

    /// Octet semantics of `TxRing::push`, for ring states the engine
    /// creates (`start < cap`, `len <= cap`: `EMPTY`, then only `push`
    /// and `release`, which keep both): `data[k]` lands at
    /// `(start + len + k) mod cap` for each `k < n`, and every other
    /// octet of `mem` is unchanged. Only this property assumes that
    /// invariant; the stand-in above does not rely on it.
    #[kani::proof]
    #[kani::unwind(10)]
    fn p6_tx_ring_push_copies_data_in_ring_order() {
        let mut mem: [u8; RING] = kani::any();
        let data: [u8; RING] = kani::any();
        let (m, d): (usize, usize) = (kani::any(), kani::any());
        kani::assume(m >= 1 && m <= RING && d <= RING);
        let start: usize = kani::any();
        let len: usize = kani::any();
        kani::assume(start < m && len <= m);
        let mut ring = TxRing { start, len, sent: 0 };
        let old = mem;
        let n = ring.push(&mut mem[..m], &data[..d]);
        let p: usize = kani::any();
        kani::assume(p < m);
        // The k that writes position p, if any: p = (start + len + k) mod m.
        let k = (p + m + m - (start + len) % m) % m;
        if k < n {
            assert_eq!(mem[p], data[k]);
        } else {
            assert_eq!(mem[p], old[p]);
        }
    }

    #[kani::proof]
    #[kani::stub(crate::wire::tcp::parse_options, crate::wire::tcp::proofs::parse_options_stub)]
    #[kani::stub(crate::checksum::Checksum::add_bytes, crate::checksum::proofs::add_bytes_stub)]
    #[kani::stub(crate::checksum::Checksum::verifies, crate::checksum::proofs::verifies_stub)]
    #[kani::stub(TxRing::push, tx_ring_push_stub)]
    #[kani::unwind(70)]
    fn p6_step_on_any_small_frame_is_total() {
        let mut store = [0u8; 16];
        let Ok(mut e) = Engine::<1, 1, 1, 1>::new(config(), &mut store) else { return };
        let owner = Principal([1; 32]);
        let _ = e.step(Instant(0), Event::Control(Control { from: owner, op: Op::Listen { port: kani::any() } }));
        let _ = e.step(Instant(0), Event::Control(Control { from: owner, op: Op::UdpBind { port: kani::any() } }));
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        let now: u64 = kani::any();
        if let Ok(actions) = e.step(Instant(now), Event::Frame(&buf[..len])) {
            assert!(actions.iter().count() <= MAX_ACTIONS_PER_STEP);
            for a in actions.iter() {
                if let Action::Emit { frame_len } = a {
                    assert!(usize::from(*frame_len) <= MAX_FRAME_LEN);
                }
            }
        }
        let later: u64 = kani::any();
        let _ = e.step(Instant(later), Event::Tick(Instant(later)));
    }
}
