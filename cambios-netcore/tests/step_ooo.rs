// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Bounded out-of-order reassembly in the engine (ADR-039 § 5.2: at most
//! `MAX_OOO_SEGMENTS` held per socket), written before it existed. The
//! connection block is unchanged: it still reports a segment past
//! RCV.NXT as out of order; the engine holds its octets and, once the gap
//! is filled, replays it into the block as an ordinary in-order segment.
//! Held octets reach the shell through `Action::DeliverHeld` and
//! `Actions::held_data()`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{
    Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Notify, Op, Principal, SocketId, SocketState,
};
use cambios_netcore::tcp::{SeqNum, TcpState};
use cambios_netcore::wire::tcp::TcpFlags;
use common::*;

/// Four held segments per socket (the ADR-039 § 8 value, the default).
type Eng = Engine<'static, 2, 1, 4, 0>;
const ALICE: Principal = Principal([0xA1; 32]);
/// Per-socket hold area: four chunks of 100 octets.
const HOLD: usize = 400;

fn engine(hold: usize) -> Eng {
    let store = Box::leak(vec![0u8; 2 * (1_024 + hold)].into_boxed_slice());
    Engine::new(
        EngineConfig {
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
            max_retransmits: 3,
            hold_per_socket: hold,
        },
        store,
    )
    .expect("config")
}

/// What one step delivered, in action order: frame ranges and held data.
struct Out {
    actions: Vec<Action>,
    frame: Option<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    held_deliveries: usize,
}

fn step(e: &mut Eng, now: u64, ev: Event<'_>, input: &[u8]) -> Out {
    let a = e.step(Instant(now), ev).expect("step");
    let actions: Vec<Action> = a.iter().copied().collect();
    let frame = actions.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    let mut delivered = Vec::new();
    let mut held_deliveries = 0;
    for x in &actions {
        match *x {
            Action::Deliver { offset, len, .. } => delivered.push(input[offset..offset + len].to_vec()),
            Action::DeliverHeld { offset, len, .. } => {
                delivered.push(a.held_data()[offset..offset + len].to_vec());
                held_deliveries += 1;
            }
            _ => {}
        }
    }
    Out { actions, frame, delivered, held_deliveries }
}

fn data(e: &mut Eng, now: u64, seq: u32, payload: &[u8]) -> Out {
    let f = peer_frame(TcpFlags::ACK.union(TcpFlags::PSH), seq, 0, 8192, payload);
    // The ACK field is not checked against SND.UNA here; build frames
    // with the right ACK through `data_acking`.
    step(e, now, Event::Frame(&f), &f)
}

/// Active open with a pinned peer whose ISS is `irs`. Returns (socket,
/// our first sequence number, so ACK fields can be right).
fn open(e: &mut Eng, irs: u32) -> (SocketId, u32) {
    step(e, 0, Event::Control(Control { from: ALICE, op: Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC } }), &[]);
    let o = step(e, 0, Event::Control(Control { from: ALICE, op: Op::Connect { remote: remote(), local_port: LOCAL_PORT } }), &[]);
    let id = o.actions.iter().find_map(|a| if let Action::Reply { msg: ControlReply::Socket(s), .. } = a { Some(*s) } else { None }).unwrap();
    let iss = tcp_of(o.frame.as_ref().unwrap()).seq.0;
    let sa = peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), irs, iss.wrapping_add(1), 8192, &[]);
    step(e, 1, Event::Frame(&sa), &sa);
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    (id, iss.wrapping_add(1))
}

fn seg(e: &mut Eng, now: u64, una: u32, seq: u32, flags: TcpFlags, payload: &[u8]) -> Out {
    let f = peer_frame(flags, seq, una, 8192, payload);
    step(e, now, Event::Frame(&f), &f)
}

const PSH_ACK: TcpFlags = TcpFlags::ACK.union(TcpFlags::PSH);

#[test]
fn a_filled_gap_delivers_both_parts_with_one_cumulative_ack() {
    let mut e = engine(HOLD);
    let (_, una) = open(&mut e, 500);
    let o = seg(&mut e, 10, una, 506, PSH_ACK, b"world");
    assert!(o.delivered.is_empty());
    assert_eq!(tcp_of(o.frame.as_ref().unwrap()).ack, SeqNum(501), "duplicate ACK for the gap");
    let o = seg(&mut e, 11, una, 501, PSH_ACK, b"hello");
    assert_eq!(o.delivered, vec![b"hello".to_vec(), b"world".to_vec()], "in order");
    assert_eq!(o.held_deliveries, 1);
    assert_eq!(tcp_of(o.frame.as_ref().unwrap()).ack, SeqNum(511), "one cumulative ACK");
}

#[test]
fn at_most_four_segments_are_held() {
    let mut e = engine(HOLD);
    let (id, una) = open(&mut e, 500);
    for k in 0..5u32 {
        seg(&mut e, 10, una, 601 + 100 * k, PSH_ACK, &[k as u8; 10]);
    }
    let mut o = seg(&mut e, 20, una, 501, PSH_ACK, &[9u8; 100]);
    let mut held = o.held_deliveries;
    let mut guard = 0;
    while o.actions.contains(&Action::Arm(Instant(20))) {
        guard += 1;
        assert!(guard < 10);
        o = step(&mut e, 20, Event::Tick(Instant(20)), &[]);
        held += o.held_deliveries;
    }
    // 601..611 joins at once; 701, 801, 901 are separated by gaps and
    // stay held; the fifth (1001) was never held.
    assert_eq!(held, 1);
    assert_eq!(e.tcb(id).unwrap().rcv_nxt(), SeqNum(611));
}

#[test]
fn contiguous_held_segments_replay_one_per_step() {
    let mut e = engine(HOLD);
    let (id, una) = open(&mut e, 500);
    for k in 0..3u32 {
        seg(&mut e, 10, una, 511 + 10 * k, PSH_ACK, &[b'a' + k as u8; 10]);
    }
    let o = seg(&mut e, 20, una, 501, PSH_ACK, &[b'0'; 10]);
    assert_eq!(o.held_deliveries, 1);
    assert!(o.actions.contains(&Action::Arm(Instant(20))), "more is ready: step again now");
    let o2 = step(&mut e, 20, Event::Tick(Instant(20)), &[]);
    let o3 = step(&mut e, 20, Event::Tick(Instant(20)), &[]);
    assert_eq!((o2.delivered.clone(), o3.delivered.clone()), (vec![vec![b'b'; 10]], vec![vec![b'c'; 10]]));
    assert_eq!(e.tcb(id).unwrap().rcv_nxt(), SeqNum(541));
    assert_eq!(tcp_of(o3.frame.as_ref().unwrap()).ack, SeqNum(541));
}

#[test]
fn duplicates_and_overlaps_are_not_delivered_twice() {
    let mut e = engine(HOLD);
    let (_, una) = open(&mut e, 500);
    seg(&mut e, 10, una, 503, PSH_ACK, b"llo-world"); // overlaps what comes next
    seg(&mut e, 11, una, 503, PSH_ACK, b"llo-world"); // the same again: held once
    let o = seg(&mut e, 12, una, 501, PSH_ACK, b"hello");
    assert_eq!(o.delivered, vec![b"hello".to_vec(), b"-world".to_vec()], "the overlap is trimmed by the block");
    assert_eq!(o.held_deliveries, 1);
    assert!(!o.actions.contains(&Action::Arm(Instant(12))), "nothing else held");
}

#[test]
fn a_held_fin_closes_after_the_gap() {
    let mut e = engine(HOLD);
    let (id, una) = open(&mut e, 500);
    seg(&mut e, 10, una, 506, TcpFlags::FIN.union(PSH_ACK), b"end");
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    let o = seg(&mut e, 11, una, 501, PSH_ACK, b"start");
    assert_eq!(o.delivered, vec![b"start".to_vec(), b"end".to_vec()]);
    assert!(o.actions.contains(&Action::Notify { socket: id, what: Notify::PeerClosed }));
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::CloseWait)));
    assert_eq!(tcp_of(o.frame.as_ref().unwrap()).ack, SeqNum(510), "the FIN is acknowledged");
}

#[test]
fn reassembly_across_the_sequence_wrap() {
    let mut e = engine(HOLD);
    let (id, una) = open(&mut e, u32::MAX - 3); // RCV.NXT = 2^32 - 3
    seg(&mut e, 10, una, 2, PSH_ACK, b"tail");
    let o = seg(&mut e, 11, una, u32::MAX - 2, PSH_ACK, b"abcde"); // 2^32-3 ..= 1: next is 2 after the wrap
    assert_eq!(o.delivered, vec![b"abcde".to_vec(), b"tail".to_vec()]);
    assert_eq!(e.tcb(id).unwrap().rcv_nxt(), SeqNum(6));
}

#[test]
fn nothing_beyond_the_window_or_too_large_is_held() {
    let mut e = engine(HOLD);
    let (id, una) = open(&mut e, 500);
    seg(&mut e, 10, una, 501 + 5_000, PSH_ACK, b"far"); // past RCV.WND (4096)
    seg(&mut e, 10, una, 601, PSH_ACK, &[1u8; 101]); // larger than a 100-octet chunk
    let o = seg(&mut e, 11, una, 501, PSH_ACK, &[0u8; 100]);
    assert_eq!(o.held_deliveries, 0);
    assert_eq!(e.tcb(id).unwrap().rcv_nxt(), SeqNum(601));
}

#[test]
fn with_no_hold_area_out_of_order_data_is_dropped_as_before() {
    let mut e = engine(0);
    let (id, una) = open(&mut e, 500);
    seg(&mut e, 10, una, 506, PSH_ACK, b"world");
    let o = seg(&mut e, 11, una, 501, PSH_ACK, b"hello");
    assert_eq!(o.delivered, vec![b"hello".to_vec()]);
    assert_eq!(o.held_deliveries, 0);
    assert_eq!(e.tcb(id).unwrap().rcv_nxt(), SeqNum(506));
    let _ = data; // keep the helper for frames without a meaningful ACK
}
