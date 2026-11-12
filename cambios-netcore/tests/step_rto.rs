// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Retransmission of control segments (SYN, SYN-ACK, FIN) through the
//! engine: RFC 6298 with the ADR-039 § 5.2 values (RTO floor 200 ms,
//! ceiling 60 s, backoff ×2), written before retransmission existed.
//! Data retransmission is not covered: there is no SEND yet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{
    Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Notify, Op, Principal, SocketId, SocketState,
};
use cambios_netcore::tcp::{SeqNum, TcpState};
use cambios_netcore::wire::tcp::{TcpFlags, TcpSegment};
use cambios_netcore::NetError;
use common::*;

type Eng = Engine<'static, 2, 1, 4, 0>;
/// Zeroed transmit storage for a test engine, leaked to live as long as
/// the test (`'static`).
fn tx_store(octets: usize) -> &'static mut [u8] {
    Box::leak(vec![0u8; octets].into_boxed_slice())
}

const ALICE: Principal = Principal([0xA1; 32]);

fn engine(max_retransmits: u8) -> Eng {
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
        max_retransmits,
        hold_per_socket: 0,
    }, tx_store(2 * 256))
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
    fn notified(&self, s: SocketId, n: Notify) -> bool {
        self.actions.contains(&Action::Notify { socket: s, what: n })
    }
}

fn step(e: &mut Eng, now: u64, ev: Event<'_>) -> Out {
    let a = e.step(Instant(now), ev).expect("step");
    let actions: Vec<Action> = a.iter().copied().collect();
    let frame = actions.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    Out { actions, frame }
}

fn tick(e: &mut Eng, now: u64) -> Out {
    step(e, now, Event::Tick(Instant(now)))
}

/// Pin the peer and open actively at t = 0. Returns (socket, ISS).
fn open(e: &mut Eng) -> (SocketId, u32) {
    step(e, 0, Event::Control(Control { from: ALICE, op: Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC } }));
    let o = step(e, 0, Event::Control(Control { from: ALICE, op: Op::Connect { remote: remote(), local_port: LOCAL_PORT } }));
    let id = o.actions.iter().find_map(|a| if let Action::Reply { msg: ControlReply::Socket(s), .. } = a { Some(*s) } else { None }).expect("socket");
    assert!(o.seg().flags.syn());
    assert_eq!(o.arm(), Some(Instant(1_000)), "RFC 6298 § 2.1: initial RTO 1 s");
    (id, o.seg().seq.0)
}

#[test]
fn a_lost_syn_is_resent_with_backoff_then_times_out() {
    let mut e = engine(2);
    let (id, iss) = open(&mut e);
    assert!(tick(&mut e, 999).frame.is_none());
    let o = tick(&mut e, 1_000);
    assert_eq!((o.seg().seq, o.seg().flags), (SeqNum(iss), TcpFlags::SYN), "the same SYN");
    assert_eq!(o.arm(), Some(Instant(3_000)), "backed off to 2 s");
    let o = tick(&mut e, 3_000);
    assert!(o.seg().flags.syn());
    assert_eq!(o.arm(), Some(Instant(7_000)), "backed off to 4 s");
    let o = tick(&mut e, 7_000);
    assert!(o.frame.is_none(), "retries exhausted");
    assert!(o.notified(id, Notify::Error(NetError::TimedOut)));
    assert_eq!(e.state(id), None);
}

#[test]
fn the_rto_is_capped_at_sixty_seconds() {
    let mut e = engine(10);
    open(&mut e);
    let mut now = 1_000u64;
    let mut expected_rto = 2_000u64;
    for _ in 0..8 {
        let o = tick(&mut e, now);
        assert!(o.seg().flags.syn());
        assert_eq!(o.arm(), Some(Instant(now + expected_rto)), "at {now}");
        now += expected_rto;
        expected_rto = (expected_rto * 2).min(60_000);
    }
}

#[test]
fn a_lost_syn_ack_is_resent_and_the_ack_stops_the_timer() {
    let mut e = engine(3);
    step(&mut e, 0, Event::Control(Control { from: ALICE, op: Op::Listen { port: LOCAL_PORT } }));
    let o = step(&mut e, 0, Event::Frame(&peer_frame(TcpFlags::SYN, 100, 0, 8192, &[])));
    let first = (o.seg().seq, o.seg().ack);
    assert_eq!(o.arm(), Some(Instant(1_000)));
    let o = tick(&mut e, 1_000);
    assert!(o.seg().flags.syn() && o.seg().flags.ack());
    assert_eq!((o.seg().seq, o.seg().ack), first, "the same SYN-ACK");
    let o = step(&mut e, 1_100, Event::Frame(&peer_frame(TcpFlags::ACK, 101, first.0 .0.wrapping_add(1), 8192, &[])));
    assert_eq!(o.arm(), None, "nothing outstanding");
    assert!(tick(&mut e, 10_000).frame.is_none());
}

#[test]
fn a_measured_rtt_sets_the_rto_for_the_fin() {
    let mut e = engine(3);
    let (id, iss) = open(&mut e);
    // SYN-ACK after 300 ms, first transmission: R = 300, SRTT = 300,
    // RTTVAR = 150, RTO = 300 + max(1, 4 × 150) = 900 (RFC 6298 § 2.2).
    step(&mut e, 300, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 8192, &[])));
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    let o = step(&mut e, 1_000, Event::Control(Control { from: ALICE, op: Op::Close { socket: id } }));
    assert!(o.seg().flags.fin());
    assert_eq!(o.arm(), Some(Instant(1_900)));
    let o = tick(&mut e, 1_900);
    assert_eq!((o.seg().seq, o.seg().flags), (SeqNum(iss.wrapping_add(1)), TcpFlags::FIN.union(TcpFlags::ACK)), "the same FIN");
    let o = step(&mut e, 2_000, Event::Frame(&peer_frame(TcpFlags::ACK, 501, iss.wrapping_add(2), 8192, &[])));
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::FinWait2)));
    assert_eq!(o.arm(), None);
}

#[test]
fn karn_and_the_three_second_rule_after_a_lost_syn() {
    let mut e = engine(3);
    let (id, iss) = open(&mut e);
    tick(&mut e, 1_000); // SYN resent: no RTT sample may come from it (Karn)
    step(&mut e, 1_300, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 8192, &[])));
    // RFC 6298 § 5.7: the RTO is re-initialised to 3 s.
    let o = step(&mut e, 2_000, Event::Control(Control { from: ALICE, op: Op::Close { socket: id } }));
    assert_eq!(o.arm(), Some(Instant(5_000)));
}

#[test]
fn the_rto_never_drops_below_two_hundred_ms() {
    let mut e = engine(3);
    let (id, iss) = open(&mut e);
    // R = 10: RTO = 10 + max(1, 20) = 30, raised to the 200 ms floor.
    step(&mut e, 10, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 8192, &[])));
    let o = step(&mut e, 100, Event::Control(Control { from: ALICE, op: Op::Close { socket: id } }));
    assert_eq!(o.arm(), Some(Instant(300)));
}
