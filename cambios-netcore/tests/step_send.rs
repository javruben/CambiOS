// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Sending stream data through the engine, written before SEND existed:
//! a bounded per-socket transmit buffer (`TX` octets), segments limited by
//! min(peer window, congestion window) and the MSS, release on ACK, data
//! retransmission at the RTO with the congestion window collapsed, zero
//! window probing that does not time out while the peer answers, and the
//! FIN held back until the buffer drains. One segment per step; when more
//! may go, the step arms `now`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{
    Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Op, Principal, SocketId, SocketState,
};
use cambios_netcore::tcp::{SeqNum, TcpState};
use cambios_netcore::wire::arp::{self, ArpOperation, ArpPacket};
use cambios_netcore::wire::ethernet::{self, EtherType};
use cambios_netcore::wire::tcp::{TcpFlags, TcpSegment};
use cambios_netcore::NetError;
use common::*;

const TX: usize = 16_384;
type Eng = Engine<'static, 2, 1, 4, 0>;
/// Zeroed transmit storage for a test engine, leaked to live as long as
/// the test (`'static`).
fn tx_store(octets: usize) -> &'static mut [u8] {
    Box::leak(vec![0u8; octets].into_boxed_slice())
}

const ALICE: Principal = Principal([0xA1; 32]);
const BOB: Principal = Principal([0xB0; 32]);
const DATA_FLAGS: TcpFlags = TcpFlags::ACK.union(TcpFlags::PSH);

fn engine() -> Eng {
    Engine::new(EngineConfig {
        mac: LOCAL_MAC,
        ipv4: LOCAL_IP,
        prefix_len: 24,
        gateway: None,
        ttl: TTL,
        mtu: MTU,
        tcb: config(4096),
        iss_key: Some(IssKey([7; 16])),
        half_open_per_listener: 4,
        neighbor_ttl_ms: 600_000,
        arp_timeout_ms: 1_000,
        arp_attempts: 3,
        challenge_ack_interval_ms: 1_000,
        max_retransmits: 2,
        hold_per_socket: 0,
    }, tx_store(2 * TX))
    .expect("config")
}

struct Out {
    actions: Vec<Action>,
    frame: Option<Vec<u8>>,
}

impl Out {
    fn arm(&self) -> Option<Instant> {
        self.actions.iter().find_map(|a| if let Action::Arm(t) = a { Some(*t) } else { None })
    }
    fn seg(&self) -> TcpSegment<'_> {
        tcp_of(self.frame.as_ref().expect("a frame"))
    }
    fn reply(&self) -> ControlReply {
        self.actions.iter().find_map(|a| if let Action::Reply { msg, .. } = a { Some(*msg) } else { None }).expect("reply")
    }
}

fn step(e: &mut Eng, now: u64, ev: Event<'_>) -> Out {
    let a = e.step(Instant(now), ev).expect("step");
    let actions: Vec<Action> = a.iter().copied().collect();
    let frame = actions.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    Out { actions, frame }
}

fn ctl(e: &mut Eng, now: u64, from: Principal, op: Op<'_>) -> Out {
    step(e, now, Event::Control(Control { from, op }))
}

fn tick(e: &mut Eng, now: u64) -> Out {
    step(e, now, Event::Tick(Instant(now)))
}

/// Pinned peer, active open at 0, SYN,ACK (peer ISS 500, `window`) at 1.
/// Returns (socket, first data sequence number = ISS + 1).
fn established(e: &mut Eng, window: u16) -> (SocketId, u32) {
    ctl(e, 0, ALICE, Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC });
    let o = ctl(e, 0, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    let ControlReply::Socket(id) = o.reply() else { panic!() };
    let iss = o.seg().seq.0;
    step(e, 1, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), window, &[])));
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    (id, iss.wrapping_add(1))
}

fn ack(e: &mut Eng, now: u64, ack: u32, window: u16) -> Out {
    step(e, now, Event::Frame(&peer_frame(TcpFlags::ACK, 501, ack, window, &[])))
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

#[test]
fn a_small_send_goes_out_at_once() {
    let mut e = engine();
    let (id, first) = established(&mut e, 65_535);
    let o = ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"hello" });
    assert_eq!(o.reply(), ControlReply::Sent(5));
    let s = o.seg();
    assert_eq!((s.seq, s.ack, s.flags, s.payload), (SeqNum(first), SeqNum(501), DATA_FLAGS, &b"hello"[..]));
    assert_eq!(o.arm(), Some(Instant(210)), "RTO 200 ms after a 1 ms handshake sample");
    assert!(ack(&mut e, 20, first + 5, 65_535).arm().is_none(), "acknowledged: nothing outstanding");
}

#[test]
fn only_the_owner_may_send() {
    let mut e = engine();
    let (id, _) = established(&mut e, 65_535);
    assert_eq!(ctl(&mut e, 10, BOB, Op::Send { socket: id, data: b"x" }).reply(), ControlReply::Refused(NetError::Denied));
}

#[test]
fn the_peer_window_limits_each_flight() {
    let mut e = engine();
    let (id, first) = established(&mut e, 3);
    let o = ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"abcdefghij" });
    assert_eq!(o.reply(), ControlReply::Sent(10));
    assert_eq!(o.seg().payload, b"abc");
    assert!(tick(&mut e, 10).frame.is_none(), "the window is full");
    let o = ack(&mut e, 20, first + 3, 3);
    assert_eq!((o.seg().seq, o.seg().payload), (SeqNum(first + 3), &b"def"[..]));
}

#[test]
fn the_congestion_window_limits_the_first_flight() {
    let mut e = engine();
    let (id, first) = established(&mut e, 65_535);
    let data = bytes(10_000, 1);
    let o = ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: &data });
    assert_eq!(o.reply(), ControlReply::Sent(10_000));
    assert_eq!(o.seg().payload.len(), 1460);
    assert_eq!(o.arm(), Some(Instant(10)), "more may go: step again now");
    // IW = 3 × 1460 (RFC 5681 § 3.1): two more segments, then stop.
    for k in 1..3u32 {
        let o = tick(&mut e, 10);
        assert_eq!(o.seg().seq, SeqNum(first + 1460 * k));
    }
    assert!(tick(&mut e, 10).frame.is_none(), "cwnd full");
    // One segment acknowledged: slow start grows cwnd by one SMSS, so two
    // more segments may go.
    let o = ack(&mut e, 20, first + 1460, 65_535);
    assert_eq!(o.seg().seq, SeqNum(first + 1460 * 3));
    assert_eq!(tick(&mut e, 20).seg().seq, SeqNum(first + 1460 * 4));
    assert!(tick(&mut e, 20).frame.is_none());
}

#[test]
fn the_buffer_is_bounded_and_released_by_acks_across_its_wrap() {
    let mut e = engine();
    let (id, first) = established(&mut e, 65_535);
    let big = bytes(20_000, 2);
    let first_out = ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: &big });
    assert_eq!(first_out.reply(), ControlReply::Sent(TX as u32));
    assert_eq!(ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"more" }).reply(), ControlReply::Refused(NetError::WouldBlock));

    // Drain everything by acknowledging each segment as it appears (from
    // a Send, a tick or an ACK step alike); the received stream must equal
    // what was accepted, in order.
    fn drain(e: &mut Eng, start: Out, next: &mut u32, now: &mut u64, total: usize) -> Vec<u8> {
        let mut received = Vec::new();
        let mut pending = Some(start);
        let mut guard = 0;
        while received.len() < total {
            guard += 1;
            assert!(guard < 1_000, "stalled at {}", received.len());
            let o = match pending.take() {
                Some(o) => o,
                None => tick(e, *now),
            };
            if let Some(f) = o.frame.as_ref() {
                let s = tcp_of(f);
                assert_eq!(s.seq, SeqNum(*next));
                received.extend_from_slice(s.payload);
                *next = next.wrapping_add(s.payload.len() as u32);
                *now += 1;
                pending = Some(ack(e, *now, *next, 65_535));
            }
        }
        received
    }
    let mut next = first;
    let mut now = 20;
    let received = drain(&mut e, first_out, &mut next, &mut now, TX);
    assert_eq!(&received[..], &big[..TX]);

    // A full fill leaves the ring's start where it began; offset it by a
    // smaller fill so the next full fill wraps the ring's end.
    let small = bytes(1_000, 5);
    let o = ctl(&mut e, now, ALICE, Op::Send { socket: id, data: &small });
    assert_eq!(o.reply(), ControlReply::Sent(1_000));
    assert_eq!(drain(&mut e, o, &mut next, &mut now, 1_000), small);
    let second = bytes(TX, 3);
    let o = ctl(&mut e, now, ALICE, Op::Send { socket: id, data: &second });
    assert_eq!(o.reply(), ControlReply::Sent(TX as u32));
    let received = drain(&mut e, o, &mut next, &mut now, TX);
    assert_eq!(received, second);
}

#[test]
fn a_lost_segment_is_resent_and_the_congestion_window_collapses() {
    let mut e = engine();
    let (id, first) = established(&mut e, 65_535);
    ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"hello" });
    let o = tick(&mut e, 210);
    assert_eq!((o.seg().seq, o.seg().payload), (SeqNum(first), &b"hello"[..]), "the same octets");
    assert_eq!(o.arm(), Some(Instant(610)), "RTO backed off to 400 ms");
    ack(&mut e, 300, first + 5, 65_535);
    // After the loss, cwnd restarted from one SMSS: the next flight is
    // limited to (about) one segment, not the initial window.
    let mut flight = 0usize;
    let mut o = ctl(&mut e, 400, ALICE, Op::Send { socket: id, data: &bytes(6_000, 4) });
    while let Some(f) = o.frame.as_ref() {
        flight += tcp_of(f).payload.len();
        o = tick(&mut e, 400);
    }
    assert!((1460..=1465).contains(&flight), "flight {flight}");
}

#[test]
fn a_zero_window_is_probed_without_timing_out() {
    let mut e = engine();
    let (id, first) = established(&mut e, 0);
    let o = ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"hello" });
    assert_eq!(o.reply(), ControlReply::Sent(5));
    assert!(o.frame.is_none(), "the window is closed");
    let mut now = o.arm().expect("persist timer").0;
    // More probes than max_retransmits (2): the peer keeps answering, so
    // the connection stays up (RFC 9293 § 3.8.6.1).
    for _ in 0..5 {
        let o = tick(&mut e, now);
        assert_eq!((o.seg().seq, o.seg().payload), (SeqNum(first), &b"h"[..]), "a one-octet probe");
        ack(&mut e, now + 1, first, 0);
        assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
        now = e.step(Instant(now + 1), Event::Tick(Instant(now + 1))).unwrap().iter().find_map(|a| if let Action::Arm(t) = a { Some(t.0) } else { None }).expect("still armed");
    }
    // The window opens: the probe octet is acknowledged and the rest goes.
    let o = ack(&mut e, now, first + 1, 100);
    assert_eq!((o.seg().seq, o.seg().payload), (SeqNum(first + 1), &b"ello"[..]));
}

#[test]
fn close_waits_for_the_buffer_to_drain() {
    let mut e = engine();
    let (id, first) = established(&mut e, 3);
    ctl(&mut e, 10, ALICE, Op::Send { socket: id, data: b"abcdef" });
    let o = ctl(&mut e, 11, ALICE, Op::Close { socket: id });
    assert_eq!(o.reply(), ControlReply::Done);
    assert!(o.frame.is_none(), "no FIN while data is unsent");
    assert_eq!(ctl(&mut e, 12, ALICE, Op::Send { socket: id, data: b"x" }).reply(), ControlReply::Refused(NetError::Closed));
    let o = ack(&mut e, 20, first + 3, 3);
    assert_eq!(o.seg().payload, b"def");
    let o = tick(&mut e, 20);
    let fin = o.seg();
    assert!(fin.flags.fin());
    assert_eq!(fin.seq, SeqNum(first + 6), "the FIN follows the data");
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::FinWait1)));
}

#[test]
fn data_queued_before_the_handshake_follows_it() {
    let mut e = engine();
    let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    let ControlReply::Socket(id) = o.reply() else { panic!() };
    assert_eq!(ctl(&mut e, 1, ALICE, Op::Send { socket: id, data: b"hi" }).reply(), ControlReply::Sent(2));
    let mut f = vec![0u8; 14 + arp::PACKET_LEN];
    let p = ArpPacket { operation: ArpOperation::Reply, sender_mac: REMOTE_MAC, sender_ip: REMOTE_IP, target_mac: LOCAL_MAC, target_ip: LOCAL_IP };
    ethernet::emit_header(&mut f, LOCAL_MAC, REMOTE_MAC, EtherType::Arp).unwrap();
    arp::emit(&p, &mut f[14..]).unwrap();
    let iss = step(&mut e, 2, Event::Frame(&f)).seg().seq.0;
    let o = step(&mut e, 3, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 8192, &[])));
    assert_eq!(o.seg().flags, TcpFlags::ACK, "the handshake ACK first");
    assert_eq!(o.arm(), Some(Instant(3)));
    let o = tick(&mut e, 3);
    assert_eq!((o.seg().seq, o.seg().payload), (SeqNum(iss.wrapping_add(1)), &b"hi"[..]));
}
