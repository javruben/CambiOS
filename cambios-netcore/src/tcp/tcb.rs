// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! One TCP connection: its transmission control block and the pure
//! transition function over arriving segments and local calls
//! (RFC 9293 § 3.10, RFC 5961 § 3–5; spec INV-net-007, INV-net-009).
//!
//! Every entry point takes the current block plus one input and returns
//! an [`Outcome`]: at most one segment to emit, at most one range of the
//! input's payload to deliver, the events the change produced, and the
//! reason anything was dropped. Nothing is sent, stored or timed here.
//! The initial send sequence number is an argument: choosing it
//! (RFC 9293 § 3.4.1, RFC 6528) needs a clock and a secret, which are the
//! shell's.
//!
//! Every state change goes through [`Tcb::enter`], which refuses any edge
//! not in [`state::TRANSITIONS`](super::state::TRANSITIONS).
//!
//! # Not implemented in this block yet
//!
//! - Out-of-order segments are not held: text that starts after RCV.NXT
//!   is dropped and acknowledged ([`DropReason::OutOfOrder`]); the peer
//!   retransmits. ADR-039 § 5.2 bounds the reassembly buffer; its size
//!   is open in crosswalk R-9.
//! - No timers: retransmission (RFC 6298) and TIME-WAIT expiry are the
//!   engine's; [`Tcb::retransmit`] regenerates the outstanding control
//!   segment for it.
//! - Challenge-ACK rate limiting (RFC 5961 § 7): the unit and value are
//!   open in crosswalk R-6. Challenge ACKs are returned as
//!   [`Emit::ChallengeAck`] so the layer that owns the limit can apply
//!   it; this block never decides to suppress one.
//! - Sending data: [`Tcb::send_data`] accounts for the sequence space of
//!   new data and [`Tcb::data_header`] builds headers to resend it; the
//!   buffer, the window and congestion decisions and the payload bytes
//!   are the engine's.
//! - Data carried on a SYN to a listener is not accepted (the peer
//!   retransmits it after the handshake).

use super::accept::{acceptable, ack_check, rst_check, AckCheck, RstCheck};
use super::seq::SeqNum;
use super::state::{is_allowed, TcpState};
use crate::addr::SocketAddress;
use crate::error::NetError;
use crate::wire::tcp::{TcpFlags, TcpRepr, TcpSegment};

/// HARDWARE: the MSS assumed when the peer sends no MSS option on IPv4
/// (RFC 9293 § 3.7.1).
pub const DEFAULT_IPV4_MSS: u16 = 536;

/// Per-connection parameters chosen by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcbConfig {
    /// MSS to advertise on our SYN (link MTU minus IP and TCP headers).
    pub local_mss: u16,
    /// Receive buffer capacity in octets; also the initial RCV.WND. A
    /// `u16` because window scaling is not negotiated (ADR-039 § 5.2).
    pub receive_window: u16,
}

/// Which side opened the connection. A passive block that is reset in
/// SYN-RECEIVED returns its listener to LISTEN; an active one is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Passive,
    Active,
}

/// Something the connection's owner should learn about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbEvent {
    /// The handshake completed (ESTABLISHED entered).
    Connected,
    /// An active open was refused by an acceptable RST.
    Refused,
    /// A synchronized connection was reset by an acceptable RST.
    Reset,
    /// The peer's FIN was received in order: no more data will arrive.
    PeerClosed,
    /// The connection reached CLOSED after an orderly close.
    Closed,
    /// A passive half-open block was abandoned; its listener stays.
    ReturnedToListen,
}

/// A small fixed set of [`TcbEvent`]s produced by one step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events(u8);

impl Events {
    const fn bit(e: TcbEvent) -> u8 {
        match e {
            TcbEvent::Connected => 1,
            TcbEvent::Refused => 2,
            TcbEvent::Reset => 4,
            TcbEvent::PeerClosed => 8,
            TcbEvent::Closed => 16,
            TcbEvent::ReturnedToListen => 32,
        }
    }
    pub fn insert(&mut self, e: TcbEvent) {
        self.0 |= Self::bit(e);
    }
    pub const fn contains(self, e: TcbEvent) -> bool {
        self.0 & Self::bit(e) != 0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A segment the step asks the caller to transmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emit {
    /// Send this segment.
    Segment(TcpRepr),
    /// An RFC 5961 challenge ACK. The caller applies the rate limit
    /// (RFC 5961 § 7) before sending; suppressing it changes no state.
    ChallengeAck(TcpRepr),
}

impl Emit {
    pub const fn repr(&self) -> &TcpRepr {
        match self {
            Emit::Segment(r) | Emit::ChallengeAck(r) => r,
        }
    }
}

/// Why a segment, or part of it, had no effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Failed the RFC 9293 acceptability test.
    Unacceptable,
    /// RST outside the receive window: dropped silently (RFC 5961 § 3.2).
    RstOutOfWindow,
    /// RST in the window but not at RCV.NXT: challenged (RFC 5961 § 3.2).
    RstInWindow,
    /// RST in SYN-SENT that does not acknowledge our SYN.
    RstWithoutAcceptableAck,
    /// SYN in a synchronized state: challenged (RFC 5961 § 4).
    SynInSynchronized,
    /// Neither SYN nor RST in SYN-SENT, or ACK bit off where one is due.
    NoAck,
    /// ACK of data never sent: challenged (RFC 5961 § 5.2).
    AckUnsent,
    /// ACK older than the RFC 5961 § 5 acceptable range: challenged.
    AckTooOld,
    /// ACK that does not cover our SYN: answered with a reset.
    AckUnacceptable,
    /// Text beginning after RCV.NXT; out-of-order holding is not
    /// implemented, so the segment's text and FIN are dropped and ACKed.
    OutOfOrder,
    /// Segment text arrived where none is accepted (after the peer's FIN).
    TextIgnored,
    /// RCV.WND is zero: the segment's ACK was processed, its text and
    /// FIN were not (RFC 9293 § 3.10.7.4 zero-window allowance).
    ZeroWindow,
    /// The block is CLOSED; the caller should answer as for no connection.
    BlockClosed,
    /// A computed change was not in the transition table. Never expected;
    /// state is left unchanged.
    IllegalTransition,
}

/// The result of one step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub emit: Option<Emit>,
    /// New in-order stream octets: `payload[offset .. offset + len]` of
    /// the segment just processed.
    pub deliver: Option<Delivery>,
    pub events: Events,
    pub drop: Option<DropReason>,
}

/// A range of the input segment's payload that is new stream data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub offset: usize,
    pub len: usize,
}

impl Outcome {
    fn dropped(reason: DropReason) -> Outcome {
        Outcome { drop: Some(reason), ..Outcome::default() }
    }
    fn dropped_with(reason: DropReason, emit: Emit) -> Outcome {
        Outcome { emit: Some(emit), drop: Some(reason), ..Outcome::default() }
    }
}

/// The reply to a segment that matches no connection, or a listener
/// that is absent or refused (RFC 9293 § 3.10.7.1; spec B-17: one
/// response class for both). `None` for an arriving RST.
pub fn reset_for_unmatched(seg: &TcpSegment<'_>) -> Option<TcpRepr> {
    if seg.flags.rst() {
        return None;
    }
    let (seq, ack, flags) = if seg.flags.ack() {
        (seg.ack, SeqNum(0), TcpFlags::RST)
    } else {
        (SeqNum(0), seg.seq.add(seg.seg_len()), TcpFlags::RST.union(TcpFlags::ACK))
    };
    Some(TcpRepr {
        source_port: seg.destination_port,
        destination_port: seg.source_port,
        seq,
        ack,
        flags,
        window: 0,
        mss: None,
    })
}

/// One connection's transmission control block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcb {
    state: TcpState,
    origin: Origin,
    local: SocketAddress,
    remote: SocketAddress,
    config: TcbConfig,
    iss: SeqNum,
    snd_una: SeqNum,
    snd_nxt: SeqNum,
    snd_wnd: u32,
    snd_wl1: SeqNum,
    snd_wl2: SeqNum,
    max_snd_wnd: u32,
    /// Sequence number our FIN occupies, once sent.
    fin_seq: Option<SeqNum>,
    irs: SeqNum,
    rcv_nxt: SeqNum,
    rcv_wnd: u32,
    peer_mss: u16,
}

impl Tcb {
    /// LISTEN-state processing of a segment addressed to a listener
    /// (RFC 9293 § 3.10.7.2). A SYN yields a new block in SYN-RECEIVED
    /// and its SYN,ACK; anything else yields the outcome for the caller
    /// (an RST for a stray ACK, nothing for an RST). Whether the listener
    /// has capacity for another half-open block is the caller's check.
    pub fn accept_syn(
        config: TcbConfig,
        local: SocketAddress,
        remote: SocketAddress,
        seg: &TcpSegment<'_>,
        iss: SeqNum,
    ) -> Result<(Tcb, Outcome), Outcome> {
        if seg.flags.rst() {
            return Err(Outcome::dropped(DropReason::RstOutOfWindow));
        }
        if seg.flags.ack() {
            let reset = reset_for_unmatched(seg).map(Emit::Segment);
            return Err(Outcome { emit: reset, drop: Some(DropReason::AckUnacceptable), ..Outcome::default() });
        }
        if !seg.flags.syn() {
            return Err(Outcome::dropped(DropReason::NoAck));
        }
        let rcv_nxt = seg.seq.add(1);
        let tcb = Tcb {
            state: TcpState::SynReceived,
            origin: Origin::Passive,
            local,
            remote,
            config,
            iss,
            snd_una: iss,
            snd_nxt: iss.add(1),
            snd_wnd: 0,
            snd_wl1: seg.seq,
            snd_wl2: iss,
            max_snd_wnd: 0,
            fin_seq: None,
            irs: seg.seq,
            rcv_nxt,
            rcv_wnd: u32::from(config.receive_window),
            peer_mss: seg.options.mss.unwrap_or(DEFAULT_IPV4_MSS),
        };
        let syn_ack = tcb.control(iss, TcpFlags::SYN.union(TcpFlags::ACK), Some(config.local_mss));
        Ok((tcb, Outcome { emit: Some(Emit::Segment(syn_ack)), ..Outcome::default() }))
    }

    /// Active OPEN (RFC 9293 § 3.10.1): a block in SYN-SENT and its SYN.
    pub fn connect(config: TcbConfig, local: SocketAddress, remote: SocketAddress, iss: SeqNum) -> (Tcb, TcpRepr) {
        let tcb = Tcb {
            state: TcpState::SynSent,
            origin: Origin::Active,
            local,
            remote,
            config,
            iss,
            snd_una: iss,
            snd_nxt: iss.add(1),
            snd_wnd: 0,
            snd_wl1: SeqNum(0),
            snd_wl2: iss,
            max_snd_wnd: 0,
            fin_seq: None,
            irs: SeqNum(0),
            rcv_nxt: SeqNum(0),
            rcv_wnd: u32::from(config.receive_window),
            peer_mss: DEFAULT_IPV4_MSS,
        };
        let syn = tcb.control(iss, TcpFlags::SYN, Some(config.local_mss));
        (tcb, syn)
    }

    // ---- read-only views ----

    pub const fn state(&self) -> TcpState {
        self.state
    }
    pub const fn origin(&self) -> Origin {
        self.origin
    }
    pub const fn local(&self) -> SocketAddress {
        self.local
    }
    pub const fn remote(&self) -> SocketAddress {
        self.remote
    }
    pub const fn iss(&self) -> SeqNum {
        self.iss
    }
    pub const fn irs(&self) -> SeqNum {
        self.irs
    }
    pub const fn snd_una(&self) -> SeqNum {
        self.snd_una
    }
    pub const fn snd_nxt(&self) -> SeqNum {
        self.snd_nxt
    }
    pub const fn snd_wnd(&self) -> u32 {
        self.snd_wnd
    }
    pub const fn rcv_nxt(&self) -> SeqNum {
        self.rcv_nxt
    }
    pub const fn rcv_wnd(&self) -> u32 {
        self.rcv_wnd
    }
    pub const fn peer_mss(&self) -> u16 {
        self.peer_mss
    }

    // ---- helpers ----

    fn advertised_window(&self) -> u16 {
        u16::try_from(self.rcv_wnd).unwrap_or(u16::MAX)
    }

    fn control(&self, seq: SeqNum, flags: TcpFlags, mss: Option<u16>) -> TcpRepr {
        TcpRepr {
            source_port: self.local.port,
            destination_port: self.remote.port,
            seq,
            ack: if flags.ack() { self.rcv_nxt } else { SeqNum(0) },
            flags,
            window: self.advertised_window(),
            mss,
        }
    }

    /// `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`: the acknowledgement and the
    /// challenge ACK have the same fields (RFC 5961 § 3.2).
    fn ack_now(&self) -> TcpRepr {
        self.control(self.snd_nxt, TcpFlags::ACK, None)
    }

    /// The only way state changes. Refuses edges outside the table.
    fn enter(&mut self, to: TcpState) -> Result<(), DropReason> {
        if is_allowed(self.state, to) {
            self.state = to;
            Ok(())
        } else {
            Err(DropReason::IllegalTransition)
        }
    }

    fn our_fin_acked(&self) -> bool {
        match self.fin_seq {
            Some(fin) => self.snd_una == fin.add(1),
            None => false,
        }
    }

    fn update_send_window(&mut self, seg: &TcpSegment<'_>, force: bool) {
        let newer = self.snd_wl1.lt(seg.seq) || (self.snd_wl1 == seg.seq && self.snd_wl2.le(seg.ack));
        if force || newer {
            self.snd_wnd = u32::from(seg.window);
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
        }
    }

    /// Return `n` octets of receive space after the owner consumed
    /// delivered data. RCV.WND never exceeds the configured capacity.
    pub fn release_receive_space(&mut self, n: u32) {
        let cap = u32::from(self.config.receive_window);
        self.rcv_wnd = self.rcv_wnd.saturating_add(n).min(cap);
    }

    /// The control segment still awaiting acknowledgement, regenerated
    /// for retransmission (RFC 9293 § 3.8.1): our SYN in SYN-SENT, our
    /// SYN,ACK in SYN-RECEIVED, our FIN until it is acknowledged. `None`
    /// when nothing we sent is outstanding. Pure: changes no state.
    pub fn retransmit(&self) -> Option<TcpRepr> {
        match self.state {
            TcpState::SynSent => Some(self.control(self.iss, TcpFlags::SYN, Some(self.config.local_mss))),
            TcpState::SynReceived => {
                Some(self.control(self.iss, TcpFlags::SYN.union(TcpFlags::ACK), Some(self.config.local_mss)))
            }
            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => match self.fin_seq {
                Some(fin) if !self.our_fin_acked() => Some(self.control(fin, TcpFlags::FIN.union(TcpFlags::ACK), None)),
                _ => None,
            },
            TcpState::Closed
            | TcpState::Listen
            | TcpState::Established
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::TimeWait => None,
        }
    }

    /// SEND (RFC 9293 § 3.10.2): the header for `len` new octets at
    /// SND.NXT, and SND.NXT advanced past them. The caller supplies the
    /// payload and decides `len` (window, congestion window, MSS); this
    /// block only accounts for the sequence space. Allowed in ESTABLISHED
    /// and CLOSE-WAIT; before the handshake completes it is `WouldBlock`
    /// (the caller queues), after a local close it is `Closed`.
    pub fn send_data(&mut self, len: u32) -> Result<TcpRepr, NetError> {
        match self.state {
            TcpState::Established | TcpState::CloseWait => {
                let header = self.data_header(self.snd_nxt);
                self.snd_nxt = self.snd_nxt.add(len);
                Ok(header)
            }
            TcpState::SynSent | TcpState::SynReceived => Err(NetError::WouldBlock),
            TcpState::Closed
            | TcpState::Listen
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => Err(NetError::Closed),
        }
    }

    /// A pure acknowledgement, `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` with
    /// the current window: for announcing a reopened window. Pure.
    pub fn ack_header(&self) -> TcpRepr {
        self.ack_now()
    }

    /// The header for (re)sending data that starts at `seq`
    /// (`<SEQ=seq><ACK=RCV.NXT><CTL=ACK,PSH>`). Pure: changes no state.
    pub fn data_header(&self, seq: SeqNum) -> TcpRepr {
        self.control(seq, TcpFlags::ACK.union(TcpFlags::PSH), None)
    }

    // ---- local calls ----

    /// Local CLOSE (RFC 9293 § 3.10.4). With no send buffer, a FIN is
    /// always "the next thing to send".
    pub fn close(&mut self) -> Result<Outcome, NetError> {
        match self.state {
            TcpState::SynSent => {
                self.enter(TcpState::Closed).map_err(|_| NetError::Closed)?;
                let mut out = Outcome::default();
                out.events.insert(TcbEvent::Closed);
                Ok(out)
            }
            TcpState::SynReceived | TcpState::Established => self.send_fin(TcpState::FinWait1),
            TcpState::CloseWait => self.send_fin(TcpState::LastAck),
            TcpState::Closed
            | TcpState::Listen
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => Err(NetError::Closed),
        }
    }

    fn send_fin(&mut self, to: TcpState) -> Result<Outcome, NetError> {
        self.enter(to).map_err(|_| NetError::Closed)?;
        let fin = self.control(self.snd_nxt, TcpFlags::FIN.union(TcpFlags::ACK), None);
        self.fin_seq = Some(self.snd_nxt);
        self.snd_nxt = self.snd_nxt.add(1);
        Ok(Outcome { emit: Some(Emit::Segment(fin)), ..Outcome::default() })
    }

    // ---- arriving segments ----

    /// Process one arriving segment already matched to this connection.
    pub fn on_segment(&mut self, seg: &TcpSegment<'_>) -> Outcome {
        match self.state {
            TcpState::Closed | TcpState::Listen => Outcome {
                emit: reset_for_unmatched(seg).map(Emit::Segment),
                drop: Some(DropReason::BlockClosed),
                ..Outcome::default()
            },
            TcpState::SynSent => self.on_segment_syn_sent(seg),
            TcpState::SynReceived
            | TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => self.on_segment_synchronized(seg),
        }
    }

    /// RFC 9293 § 3.10.7.3.
    fn on_segment_syn_sent(&mut self, seg: &TcpSegment<'_>) -> Outcome {
        let mut ack_ok = false;
        if seg.flags.ack() {
            // Acceptable iff ISS < SEG.ACK =< SND.NXT.
            if !seg.ack.in_range_open_closed(self.iss, self.snd_nxt) {
                if seg.flags.rst() {
                    return Outcome::dropped(DropReason::RstWithoutAcceptableAck);
                }
                let rst = TcpRepr {
                    source_port: self.local.port,
                    destination_port: self.remote.port,
                    seq: seg.ack,
                    ack: SeqNum(0),
                    flags: TcpFlags::RST,
                    window: 0,
                    mss: None,
                };
                return Outcome::dropped_with(DropReason::AckUnacceptable, Emit::Segment(rst));
            }
            ack_ok = true;
        }
        if seg.flags.rst() {
            if !ack_ok {
                return Outcome::dropped(DropReason::RstWithoutAcceptableAck);
            }
            return self.terminate(TcbEvent::Refused);
        }
        if !seg.flags.syn() {
            return Outcome::dropped(DropReason::NoAck);
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.add(1);
        self.peer_mss = seg.options.mss.unwrap_or(DEFAULT_IPV4_MSS);
        if ack_ok {
            self.snd_una = seg.ack;
            if let Err(reason) = self.enter(TcpState::Established) {
                return Outcome::dropped(reason);
            }
            self.update_send_window(seg, true);
            let mut out = Outcome::default();
            out.events.insert(TcbEvent::Connected);
            // Text on a SYN,ACK begins after the SYN's sequence number.
            self.process_text_and_fin(seg, seg.seq.add(1), &mut out);
            // The handshake's third segment is always sent.
            if out.emit.is_none() {
                out.emit = Some(Emit::Segment(self.ack_now()));
            }
            out
        } else {
            // Simultaneous open: SYN-RECEIVED, answer SYN,ACK.
            if let Err(reason) = self.enter(TcpState::SynReceived) {
                return Outcome::dropped(reason);
            }
            let syn_ack = self.control(self.iss, TcpFlags::SYN.union(TcpFlags::ACK), Some(self.config.local_mss));
            Outcome { emit: Some(Emit::Segment(syn_ack)), ..Outcome::default() }
        }
    }

    /// Enter CLOSED and report `event`.
    fn terminate(&mut self, event: TcbEvent) -> Outcome {
        match self.enter(TcpState::Closed) {
            Ok(()) => {
                let mut out = Outcome::default();
                out.events.insert(event);
                out
            }
            Err(reason) => Outcome::dropped(reason),
        }
    }

    /// RFC 9293 § 3.10.7.4 for SYN-RECEIVED and the synchronized states.
    fn on_segment_synchronized(&mut self, seg: &TcpSegment<'_>) -> Outcome {
        // RST (RFC 5961 § 3.2), checked against the window directly.
        if seg.flags.rst() {
            return match rst_check(seg.seq, self.rcv_nxt, self.rcv_wnd) {
                RstCheck::OutOfWindow => Outcome::dropped(DropReason::RstOutOfWindow),
                RstCheck::InWindow => {
                    Outcome::dropped_with(DropReason::RstInWindow, Emit::ChallengeAck(self.ack_now()))
                }
                RstCheck::Exact => {
                    let event = match (self.state, self.origin) {
                        (TcpState::SynReceived, Origin::Passive) => TcbEvent::ReturnedToListen,
                        (TcpState::SynReceived, Origin::Active) => TcbEvent::Refused,
                        (TcpState::Closing | TcpState::LastAck | TcpState::TimeWait, _) => TcbEvent::Closed,
                        _ => TcbEvent::Reset,
                    };
                    self.terminate(event)
                }
            };
        }

        // SYN in a synchronized state: challenged irrespective of its
        // sequence number (RFC 5961 § 4.2). SYN-RECEIVED keeps RFC 9293's
        // order (sequence check first, below), so a retransmitted SYN is
        // answered with an ACK and cannot abandon a half-open block.
        if seg.flags.syn() && self.state.is_synchronized() {
            return Outcome::dropped_with(DropReason::SynInSynchronized, Emit::ChallengeAck(self.ack_now()));
        }

        // First check: sequence acceptability.
        if !acceptable(seg.seq, seg.seg_len(), self.rcv_nxt, self.rcv_wnd) {
            // With RCV.WND = 0 nothing with text or FIN is acceptable, but
            // a valid ACK must still be processed (RFC 9293 § 3.10.7.4):
            // otherwise the ACK of our FIN on a zero-window probe is lost.
            // "Valid" here: it sits exactly at RCV.NXT.
            if self.rcv_wnd == 0 && seg.flags.ack() && seg.seq == self.rcv_nxt {
                return match self.process_ack(seg) {
                    Ok(mut out) => {
                        out.drop = Some(DropReason::ZeroWindow);
                        out.emit = Some(Emit::Segment(self.ack_now()));
                        out
                    }
                    Err(out) => out,
                };
            }
            return Outcome::dropped_with(DropReason::Unacceptable, Emit::Segment(self.ack_now()));
        }

        // Fourth check: SYN, reached only in SYN-RECEIVED.
        if seg.flags.syn() {
            if self.origin == Origin::Passive {
                return self.terminate(TcbEvent::ReturnedToListen);
            }
            return Outcome::dropped_with(DropReason::SynInSynchronized, Emit::ChallengeAck(self.ack_now()));
        }

        // Fifth check: ACK.
        if !seg.flags.ack() {
            return Outcome::dropped(DropReason::NoAck);
        }
        let mut out = match self.process_ack(seg) {
            Ok(out) => out,
            Err(out) => return out,
        };

        // Seventh and eighth steps: text, then FIN.
        self.process_text_and_fin(seg, seg.seq, &mut out);
        out
    }

    /// The fifth step of RFC 9293 § 3.10.7.4 with RFC 5961 § 5, for a
    /// segment whose ACK bit is set. `Ok` carries the outcome so far on to
    /// the text and FIN steps; `Err` is this segment's final outcome.
    fn process_ack(&mut self, seg: &TcpSegment<'_>) -> Result<Outcome, Outcome> {
        let mut out = Outcome::default();
        if self.state == TcpState::SynReceived {
            if !seg.ack.in_range_open_closed(self.snd_una, self.snd_nxt) {
                let rst = TcpRepr {
                    source_port: self.local.port,
                    destination_port: self.remote.port,
                    seq: seg.ack,
                    ack: SeqNum(0),
                    flags: TcpFlags::RST,
                    window: 0,
                    mss: None,
                };
                return Err(Outcome::dropped_with(DropReason::AckUnacceptable, Emit::Segment(rst)));
            }
            if let Err(reason) = self.enter(TcpState::Established) {
                return Err(Outcome::dropped(reason));
            }
            self.update_send_window(seg, true);
            out.events.insert(TcbEvent::Connected);
        }
        match ack_check(seg.ack, self.snd_una, self.snd_nxt, self.max_snd_wnd) {
            // Both sides of the RFC 5961 § 5.2 acceptable range are answered
            // with the same ACK and both are subject to the § 7 rate limit,
            // so both are marked as challenges.
            AckCheck::Unsent => {
                return Err(Outcome::dropped_with(DropReason::AckUnsent, Emit::ChallengeAck(self.ack_now())));
            }
            AckCheck::TooOld => {
                return Err(Outcome::dropped_with(DropReason::AckTooOld, Emit::ChallengeAck(self.ack_now())));
            }
            AckCheck::New => {
                self.snd_una = seg.ack;
                self.update_send_window(seg, false);
            }
            // The window may be updated only when SND.UNA =< SEG.ACK
            // (RFC 9293 § 3.10.7.4); an older duplicate leaves it alone.
            AckCheck::Duplicate => {
                if seg.ack == self.snd_una {
                    self.update_send_window(seg, false);
                }
            }
        }
        if self.our_fin_acked() {
            let next = match self.state {
                TcpState::FinWait1 => Some(TcpState::FinWait2),
                TcpState::Closing => Some(TcpState::TimeWait),
                TcpState::LastAck => Some(TcpState::Closed),
                _ => None,
            };
            if let Some(to) = next {
                if let Err(reason) = self.enter(to) {
                    out.drop = Some(reason);
                    return Err(out);
                }
                if to == TcpState::Closed {
                    out.events.insert(TcbEvent::Closed);
                    return Err(out);
                }
            }
        }
        Ok(out)
    }

    /// Accept in-order segment text and an in-order FIN. `text_seq` is
    /// the sequence number of the first payload octet.
    fn process_text_and_fin(&mut self, seg: &TcpSegment<'_>, text_seq: SeqNum, out: &mut Outcome) {
        // The parser bounds payloads to the IPv4 pseudo-header's 16 bits.
        let payload_len = u32::try_from(seg.payload.len()).unwrap_or(u32::MAX);
        let mut need_ack = false;
        let mut in_order = true;

        if payload_len > 0 {
            if self.state.accepts_text() {
                need_ack = true;
                // RCV.NXT within [text_seq, text_seq + len] means the
                // segment starts at or before what we expect next.
                if self.rcv_nxt.in_window(text_seq, payload_len.saturating_add(1)) {
                    let skip = self.rcv_nxt.distance_from(text_seq);
                    let fresh = payload_len.saturating_sub(skip).min(self.rcv_wnd);
                    if fresh > 0 {
                        out.deliver = Some(Delivery {
                            offset: usize::try_from(skip).unwrap_or(usize::MAX),
                            len: usize::try_from(fresh).unwrap_or(0),
                        });
                        self.rcv_nxt = self.rcv_nxt.add(fresh);
                        self.rcv_wnd = self.rcv_wnd.saturating_sub(fresh);
                    }
                } else {
                    in_order = false;
                    out.drop = Some(DropReason::OutOfOrder);
                }
            } else {
                out.drop = Some(DropReason::TextIgnored);
            }
        }

        if seg.flags.fin() && in_order {
            need_ack = true;
            let fin_seq = text_seq.add(payload_len);
            if fin_seq == self.rcv_nxt {
                let next = match self.state {
                    TcpState::SynReceived | TcpState::Established => Some(TcpState::CloseWait),
                    TcpState::FinWait1 => Some(TcpState::Closing),
                    TcpState::FinWait2 => Some(TcpState::TimeWait),
                    // A FIN already counted: acknowledge, stay.
                    _ => None,
                };
                if let Some(to) = next {
                    match self.enter(to) {
                        Ok(()) => {
                            self.rcv_nxt = self.rcv_nxt.add(1);
                            out.events.insert(TcbEvent::PeerClosed);
                        }
                        Err(reason) => out.drop = Some(reason),
                    }
                }
            }
        }

        if need_ack && out.emit.is_none() {
            out.emit = Some(Emit::Segment(self.ack_now()));
        }
    }
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// Every harness starts from a fully symbolic block: any state, any
/// origin, and every sequence, window and option field unconstrained, so
/// the properties hold for internally inconsistent blocks too, not only
/// for the ones a real connection reaches. Segment payloads are symbolic
/// with length 0..=`PAYLOAD_MAX`; segment flags are any octet.
#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::addr::{IpAddress, Ipv4Address};
    use crate::wire::tcp::TcpOptions;

    /// SCAFFOLDING: symbolic payload length bound for the harnesses.
    /// Why: no step in the block loops over payload octets (delivery is
    /// offset arithmetic), so 2 octets exercise empty, partial and whole
    /// delivery while keeping the solver fast.
    /// Replace when: segment text is copied or reassembled inside the core
    /// (the out-of-order buffer lands), which makes length matter.
    const PAYLOAD_MAX: usize = 2;

    fn any_state() -> TcpState {
        match TcpState::from_rfc4022(kani::any()) {
            Some(s) => s,
            None => {
                kani::assume(false);
                TcpState::Closed
            }
        }
    }

    fn any_socket() -> SocketAddress {
        SocketAddress { address: IpAddress::V4(Ipv4Address(kani::any())), port: kani::any() }
    }

    fn any_tcb(state: TcpState) -> Tcb {
        Tcb {
            state,
            origin: if kani::any() { Origin::Passive } else { Origin::Active },
            local: any_socket(),
            remote: any_socket(),
            config: TcbConfig { local_mss: kani::any(), receive_window: kani::any() },
            iss: SeqNum(kani::any()),
            snd_una: SeqNum(kani::any()),
            snd_nxt: SeqNum(kani::any()),
            snd_wnd: kani::any(),
            snd_wl1: SeqNum(kani::any()),
            snd_wl2: SeqNum(kani::any()),
            max_snd_wnd: kani::any(),
            fin_seq: if kani::any() { Some(SeqNum(kani::any())) } else { None },
            irs: SeqNum(kani::any()),
            rcv_nxt: SeqNum(kani::any()),
            rcv_wnd: kani::any(),
            peer_mss: kani::any(),
        }
    }

    fn any_segment(payload: &[u8]) -> TcpSegment<'_> {
        TcpSegment {
            source_port: kani::any(),
            destination_port: kani::any(),
            seq: SeqNum(kani::any()),
            ack: SeqNum(kani::any()),
            flags: TcpFlags(kani::any()),
            window: kani::any(),
            urgent: kani::any(),
            options: TcpOptions {
                mss: if kani::any() { Some(kani::any()) } else { None },
                window_scale: None,
                sack_permitted: false,
                timestamps: None,
            },
            payload,
        }
    }

    fn within_two_edges(from: TcpState, to: TcpState) -> bool {
        is_allowed(from, to) || TcpState::ALL.iter().any(|&mid| is_allowed(from, mid) && is_allowed(mid, to))
    }

    /// The RFC 5961 challenge ACK for `tcb`: `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`.
    fn is_challenge_for(emit: Option<Emit>, tcb: &Tcb) -> bool {
        match emit {
            Some(Emit::ChallengeAck(r)) => r.seq == tcb.snd_nxt && r.ack == tcb.rcv_nxt && r.flags == TcpFlags::ACK,
            _ => false,
        }
    }

    // ---- P2: the two-edge reachability relation, computed by the compiler ----
    //
    // `REACH2[a][b]` is "b is reachable from a in one or two edges of
    // TRANSITIONS". It is the square of `state::EDGES` (itself the
    // compile-time form of TRANSITIONS), evaluated by the compiler, so
    // CBMC sees a constant lookup instead of a nested symbolic scan and
    // nothing in it is written by hand.
    // `p2_reach2_is_the_two_edge_closure` proves it equals the definition
    // `within_two_edges` for every pair of states;
    // `state::proofs::edges_equal_transitions_membership` proves `EDGES`
    // equals TRANSITIONS membership.

    use crate::tcp::state::{index as idx, EDGES, STATE_COUNT as STATES};

    const fn reach2_table() -> [[bool; STATES]; STATES] {
        let mut r = [[false; STATES]; STATES];
        let mut a = 0;
        while a < STATES {
            let mut b = 0;
            while b < STATES {
                let mut ok = EDGES[a][b];
                let mut m = 0;
                while m < STATES {
                    if EDGES[a][m] && EDGES[m][b] {
                        ok = true;
                    }
                    m += 1;
                }
                r[a][b] = ok;
                b += 1;
            }
            a += 1;
        }
        r
    }

    const REACH2: [[bool; STATES]; STATES] = reach2_table();

    /// The constant table equals the definition (one edge, or two edges
    /// through some intermediate state) for all 121 state pairs.
    ///
    /// The domain is finite and small, so the harness enumerates every
    /// pair concretely instead of drawing two symbolic states: that is a
    /// complete check of the whole domain with a single path for CBMC
    /// (a symbolic-pair version did not finish within 180 s).
    /// Unwind 12: each of the three nested scans covers the 11 states.
    #[kani::proof]
    #[kani::unwind(12)]
    fn p2_reach2_is_the_two_edge_closure() {
        for a in TcpState::ALL {
            for b in TcpState::ALL {
                assert_eq!(REACH2[idx(a)][idx(b)], within_two_edges(a, b));
            }
        }
    }

    /// P2 (ADR-039 § 6.1; INV-net-007), for one starting state: any
    /// arriving segment moves the block along at most two edges of
    /// `TRANSITIONS` (one segment can complete a handshake or acknowledge
    /// our FIN and carry a FIN), never reports an illegal transition, and
    /// any delivery lies inside the segment's payload.
    ///
    /// The claim for all states is the conjunction of the eleven
    /// per-state harnesses below (compositional: the starting state is a
    /// case split, not a narrowing). Every other input is as symbolic as
    /// before: all block fields, both origins, any segment, payload
    /// 0..=`PAYLOAD_MAX` octets.
    fn p2_segment_from(before: TcpState) {
        let mut tcb = any_tcb(before);
        let buf: [u8; PAYLOAD_MAX] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= PAYLOAD_MAX);
        let seg = any_segment(&buf[..n]);
        let out = tcb.on_segment(&seg);
        let after = tcb.state();
        assert!(after == before || REACH2[idx(before)][idx(after)]);
        assert!(out.drop != Some(DropReason::IllegalTransition));
        if let Some(d) = out.deliver {
            assert!(d.len > 0 && d.offset <= n && d.len <= n - d.offset);
        }
    }

    macro_rules! p2_per_state {
        ($($name:ident => $state:ident),* $(,)?) => {
            $(
                /// P2 starting from one state; see `p2_segment_from`.
                /// Unwind 28: a safety margin; `enter` is a constant-time lookup
                /// and no loop remains on this path.
                #[kani::proof]
                #[kani::unwind(28)]
                fn $name() {
                    p2_segment_from(TcpState::$state);
                }
            )*
        };
    }

    p2_per_state! {
        p2_segment_from_closed => Closed,
        p2_segment_from_listen => Listen,
        p2_segment_from_syn_sent => SynSent,
        p2_segment_from_syn_received => SynReceived,
        p2_segment_from_established => Established,
        p2_segment_from_fin_wait1 => FinWait1,
        p2_segment_from_fin_wait2 => FinWait2,
        p2_segment_from_close_wait => CloseWait,
        p2_segment_from_closing => Closing,
        p2_segment_from_last_ack => LastAck,
        p2_segment_from_time_wait => TimeWait,
    }

    /// P2 for the local CLOSE call: at most one table edge, never illegal.
    /// Unwind 28: a safety margin; `is_allowed` is a constant-time lookup.
    #[kani::proof]
    #[kani::unwind(28)]
    fn p2_close_takes_one_table_edge() {
        let before = any_state();
        let mut tcb = any_tcb(before);
        let result = tcb.close();
        let after = tcb.state();
        assert!(after == before || is_allowed(before, after));
        if result.is_err() {
            assert!(after == before);
        }
    }

    /// P3 (ADR-039 § 6.1; INV-net-009, RFC 5961 § 3.2): in SYN-RECEIVED
    /// or any synchronized state, an RST whose SEG.SEQ is not RCV.NXT
    /// leaves the whole block unchanged, delivers nothing, raises no
    /// event, and yields exactly one challenge ACK when in the window and
    /// nothing when outside it.
    /// Unwind 28: a safety margin; `enter` is a constant-time lookup.
    #[kani::proof]
    #[kani::unwind(28)]
    fn p3_non_exact_rst_changes_nothing() {
        let state = any_state();
        kani::assume(state == TcpState::SynReceived || state.is_synchronized());
        let mut tcb = any_tcb(state);
        let before = tcb;
        let buf: [u8; PAYLOAD_MAX] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= PAYLOAD_MAX);
        let mut seg = any_segment(&buf[..n]);
        seg.flags = seg.flags.union(TcpFlags::RST);
        kani::assume(seg.seq != before.rcv_nxt);
        let out = tcb.on_segment(&seg);
        assert!(tcb == before);
        assert!(out.events.is_empty() && out.deliver.is_none());
        if seg.seq.in_window(before.rcv_nxt, before.rcv_wnd) {
            assert!(is_challenge_for(out.emit, &before));
            assert!(out.drop == Some(DropReason::RstInWindow));
        } else {
            assert!(out.emit.is_none());
            assert!(out.drop == Some(DropReason::RstOutOfWindow));
        }
    }

    /// P3 complement: an RST exactly at RCV.NXT always ends the block.
    /// Unwind 28: a safety margin; `enter` is a constant-time lookup.
    #[kani::proof]
    #[kani::unwind(28)]
    fn p3_exact_rst_closes() {
        let state = any_state();
        kani::assume(state == TcpState::SynReceived || state.is_synchronized());
        let mut tcb = any_tcb(state);
        let mut seg = any_segment(&[]);
        seg.flags = seg.flags.union(TcpFlags::RST);
        seg.seq = tcb.rcv_nxt;
        let out = tcb.on_segment(&seg);
        assert!(tcb.state() == TcpState::Closed);
        assert!(out.emit.is_none() && !out.events.is_empty());
    }

    /// P4 (ADR-039 § 6.1; INV-net-009, RFC 5961 § 4.2): in any
    /// synchronized state, a SYN (without RST), whatever its sequence
    /// number, leaves the whole block unchanged and yields exactly one
    /// challenge ACK. It never resets the connection.
    /// Unwind 28: a safety margin; no loop remains on this path.
    #[kani::proof]
    #[kani::unwind(28)]
    fn p4_syn_in_synchronized_state_is_challenged() {
        let state = any_state();
        kani::assume(state.is_synchronized());
        let mut tcb = any_tcb(state);
        let before = tcb;
        let buf: [u8; PAYLOAD_MAX] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= PAYLOAD_MAX);
        let mut seg = any_segment(&buf[..n]);
        seg.flags = seg.flags.union(TcpFlags::SYN);
        kani::assume(!seg.flags.rst());
        let out = tcb.on_segment(&seg);
        assert!(tcb == before);
        assert!(out.events.is_empty() && out.deliver.is_none());
        assert!(is_challenge_for(out.emit, &before));
        assert!(out.drop == Some(DropReason::SynInSynchronized));
    }
}
