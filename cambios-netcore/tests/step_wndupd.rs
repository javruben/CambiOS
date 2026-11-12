// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Window updates when receive space reopens (RFC 9293 § 3.8.6.2.2,
//! receiver silly-window avoidance), written before they existed: when
//! the shell reports consumed octets (`Op::Consumed`) and RCV.WND rises
//! from below min(buffer / 2, SMSS) to at least it, the engine sends an
//! ACK announcing the reopened window; smaller increases wait.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Op, Principal, SocketId};
use cambios_netcore::tcp::SeqNum;
use cambios_netcore::wire::tcp::TcpFlags;
use common::*;

type Eng = Engine<'static, 1, 1, 4, 0>;
const ALICE: Principal = Principal([0xA1; 32]);

fn engine() -> Eng {
    let store = Box::leak(vec![0u8; 4_096].into_boxed_slice());
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

fn step(e: &mut Eng, now: u64, ev: Event<'_>) -> Option<Vec<u8>> {
    let a = e.step(Instant(now), ev).expect("step");
    let actions: Vec<Action> = a.iter().copied().collect();
    actions.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None })
}

/// Established, then the peer fills our 4096-octet window.
fn full_window(e: &mut Eng) -> (SocketId, u32) {
    step(e, 0, Event::Control(Control { from: ALICE, op: Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC } }));
    let a = e.step(Instant(0), Event::Control(Control { from: ALICE, op: Op::Connect { remote: remote(), local_port: LOCAL_PORT } })).unwrap();
    let id = a.iter().find_map(|x| if let Action::Reply { msg: ControlReply::Socket(s), .. } = x { Some(*s) } else { None }).unwrap();
    let iss = a.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(tcp_of(&a.tx_frame()[..usize::from(*frame_len)]).seq.0) } else { None }).unwrap();
    let una = iss.wrapping_add(1);
    step(e, 1, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, una, 8192, &[])));
    let mut seq = 501u32;
    let mut last = None;
    for len in [1460usize, 1460, 1176] {
        last = step(e, 2, Event::Frame(&peer_frame(TcpFlags::ACK.union(TcpFlags::PSH), seq, una, 8192, &vec![1u8; len])));
        seq += len as u32;
    }
    let ack = tcp_of(last.as_ref().unwrap());
    assert_eq!((ack.ack, ack.window), (SeqNum(501 + 4096), 0), "window full");
    (id, una)
}

#[test]
fn a_small_reopening_waits_and_a_large_one_is_announced() {
    let mut e = engine();
    let (id, _) = full_window(&mut e);
    let consumed = |e: &mut Eng, n: u32| step(e, 10, Event::Control(Control { from: ALICE, op: Op::Consumed { socket: id, octets: n } }));
    // 100 octets: below min(4096 / 2, 1460) = 1460, so no update yet.
    assert!(consumed(&mut e, 100).is_none());
    // 1400 more: the window is 1500, past the threshold: announce it.
    let f = consumed(&mut e, 1_400).expect("window update");
    let s = tcp_of(&f);
    assert_eq!((s.flags, s.ack, s.window), (TcpFlags::ACK, SeqNum(501 + 4096), 1_500));
    assert!(s.payload.is_empty());
    // Further reopening from an already-open window needs no extra ACK.
    assert!(consumed(&mut e, 2_596).is_none());
}
