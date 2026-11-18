// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fast retransmit and fast recovery (RFC 5681 § 3.2) through the
//! engine, written before they existed: on the third duplicate ACK the
//! first unacknowledged segment is resent at once (no RTO wait), ssthresh
//! = max(flight / 2, 2 × SMSS), cwnd = ssthresh + 3 × SMSS; each further
//! duplicate inflates cwnd by one SMSS; the next ACK of new data deflates
//! cwnd to ssthresh. What counts as a duplicate is RFC 5681 § 2's
//! definition.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Op, Principal, SocketId};
use cambios_netcore::tcp::SeqNum;
use cambios_netcore::wire::tcp::TcpFlags;
use common::*;

type Eng = Engine<'static, 1, 1, 4, 0>;
const ALICE: Principal = Principal([0xA1; 32]);
const SMSS: u32 = 1460;

fn engine() -> Eng {
    let store = Box::leak(vec![0u8; 16_384].into_boxed_slice());
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
            hold_per_socket: 0,
        },
        store,
    )
    .expect("config")
}

fn step(e: &mut Eng, now: u64, ev: Event<'_>) -> (Vec<Action>, Option<Vec<u8>>) {
    let a = e.step(Instant(now), ev).expect("step");
    let actions: Vec<Action> = a.iter().copied().collect();
    let frame = actions.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    (actions, frame)
}

/// Send whatever the windows allow now; returns the sequence numbers of
/// the segments that went out.
fn flush(e: &mut Eng, now: u64, first: Option<Vec<u8>>) -> Vec<u32> {
    let mut seqs = Vec::new();
    let mut f = first;
    while let Some(frame) = f {
        seqs.push(tcp_of(&frame).seq.0);
        f = step(e, now, Event::Tick(Instant(now))).1;
    }
    seqs
}

fn ack(e: &mut Eng, now: u64, ack: u32, window: u16, payload: &[u8]) -> Option<Vec<u8>> {
    step(e, now, Event::Frame(&peer_frame(TcpFlags::ACK, 501, ack, window, payload))).1
}

/// Established, then five full segments in flight (the first ACK grows
/// cwnd from 3 to 4 SMSS). Returns (socket, first data sequence number).
fn five_in_flight(e: &mut Eng) -> (SocketId, u32) {
    step(e, 0, Event::Control(Control { from: ALICE, op: Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC } }));
    let (a, f) = step(e, 0, Event::Control(Control { from: ALICE, op: Op::Connect { remote: remote(), local_port: LOCAL_PORT } }));
    let id = a.iter().find_map(|x| if let Action::Reply { msg: ControlReply::Socket(s), .. } = x { Some(*s) } else { None }).unwrap();
    let iss = tcp_of(&f.unwrap()).seq.0;
    step(e, 1, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 65_535, &[])));
    let first = iss.wrapping_add(1);
    let data = vec![7u8; 10 * SMSS as usize];
    let (_, f) = step(e, 10, Event::Control(Control { from: ALICE, op: Op::Send { socket: id, data: &data } }));
    assert_eq!(flush(e, 10, f).len(), 3, "IW = 3 segments");
    let f = ack(e, 20, first + SMSS, 65_535, &[]);
    let more = flush(e, 20, f);
    assert_eq!(more, vec![first + 3 * SMSS, first + 4 * SMSS], "cwnd 4 SMSS after one ACK");
    (id, first)
}

#[test]
fn the_third_duplicate_ack_resends_at_once() {
    let mut e = engine();
    let (_, first) = five_in_flight(&mut e);
    // Segment 2 (first + SMSS) was lost; 3, 4, 5 each draw a duplicate.
    assert!(ack(&mut e, 30, first + SMSS, 65_535, &[]).is_none(), "first duplicate");
    assert!(ack(&mut e, 31, first + SMSS, 65_535, &[]).is_none(), "second duplicate");
    let f = ack(&mut e, 32, first + SMSS, 65_535, &[]).expect("fast retransmit");
    let s = tcp_of(&f);
    assert_eq!((s.seq, s.payload.len()), (SeqNum(first + SMSS), SMSS as usize), "the first unacknowledged segment");
}

#[test]
fn recovery_inflates_then_deflates_the_window() {
    let mut e = engine();
    let (_, first) = five_in_flight(&mut e);
    for t in 30..33 {
        ack(&mut e, t, first + SMSS, 65_535, &[]);
    }
    // flight was 4 SMSS: ssthresh = 2 SMSS, cwnd = 5 SMSS, 4 in flight:
    // one new segment may go after the next duplicate inflates cwnd to 6.
    let f = ack(&mut e, 33, first + SMSS, 65_535, &[]);
    assert_eq!(flush(&mut e, 33, f), vec![first + 5 * SMSS, first + 6 * SMSS], "inflated by the 4th duplicate");
    // The retransmission repaired the hole: everything sent is ACKed.
    // cwnd deflates to ssthresh = 2 SMSS: two new segments, not more.
    let f = ack(&mut e, 40, first + 7 * SMSS, 65_535, &[]);
    assert_eq!(flush(&mut e, 40, f), vec![first + 7 * SMSS, first + 8 * SMSS]);
}

#[test]
fn only_true_duplicates_count() {
    let mut e = engine();
    let (_, first) = five_in_flight(&mut e);
    // A segment carrying data is not a duplicate ACK (RFC 5681 § 2). The
    // peer's sequence number advances with each octet it sends, so its
    // later segments stay acceptable (RFC 9293 § 3.10.7.4).
    let seg = |e: &mut Eng, t: u64, seq: u32, window: u16, payload: &[u8]| step(e, t, Event::Frame(&peer_frame(TcpFlags::ACK, seq, first + SMSS, window, payload))).1;
    for (i, t) in (30..34).enumerate() {
        let f = seg(&mut e, t, 501 + i as u32, 65_535, b"x");
        assert!(f.is_none_or(|f| tcp_of(&f).payload.is_empty() || tcp_of(&f).seq != SeqNum(first + SMSS)));
    }
    // Nor is one that changes the window.
    assert!(seg(&mut e, 40, 505, 60_000, &[]).is_none());
    assert!(seg(&mut e, 41, 505, 50_000, &[]).is_none());
    let f = seg(&mut e, 42, 505, 40_000, &[]);
    assert!(f.is_none_or(|f| tcp_of(&f).seq != SeqNum(first + SMSS)), "window updates are not duplicates");
}
