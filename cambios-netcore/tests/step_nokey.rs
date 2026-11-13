// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! An engine without an RFC 6528 key fails closed for TCP, written
//! before the behaviour existed. CambiOS has no entropy source yet
//! (owner ruling 2026-11-10: a kernel hardware-RNG call will provide
//! one; until then the stack refuses TCP rather than use a weak key).
//! With `iss_key: None`: an active or passive open is refused
//! `Unsupported` and sends nothing; a SYN from a peer finds no listener
//! and is answered with a reset; UDP still works.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{Action, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Op, Principal};
use cambios_netcore::NetError;
use cambios_netcore::wire::tcp::TcpFlags;
use common::*;

type Eng = Engine<'static, 2, 1, 4, 1>;
const ALICE: Principal = Principal([0xA1; 32]);

fn engine(iss_key: Option<IssKey>) -> Eng {
    let store = Box::leak(vec![0u8; 8_192].into_boxed_slice());
    Engine::new(
        EngineConfig {
            mac: LOCAL_MAC,
            ipv4: LOCAL_IP,
            prefix_len: 24,
            gateway: None,
            ttl: TTL,
            mtu: MTU,
            tcb: config(4096),
            iss_key,
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

/// (reply, emitted frame) of one step.
fn ctl(e: &mut Eng, now: u64, op: Op<'_>) -> (Option<ControlReply>, Option<Vec<u8>>) {
    let a = e.step(Instant(now), Event::Control(Control { from: ALICE, op })).expect("step");
    let reply = a.iter().find_map(|x| if let Action::Reply { msg, .. } = x { Some(*msg) } else { None });
    let frame = a.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    (reply, frame)
}

#[test]
fn opens_are_refused_and_send_nothing() {
    let mut e = engine(None);
    ctl(&mut e, 0, Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC });
    let (reply, frame) = ctl(&mut e, 1, Op::Listen { port: LOCAL_PORT });
    assert_eq!(reply, Some(ControlReply::Refused(NetError::Unsupported)));
    assert!(frame.is_none());
    let (reply, frame) = ctl(&mut e, 2, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    assert_eq!(reply, Some(ControlReply::Refused(NetError::Unsupported)));
    assert!(frame.is_none(), "no SYN without a key");
}

#[test]
fn a_peer_syn_is_reset() {
    let mut e = engine(None);
    let a = e.step(Instant(0), Event::Frame(&peer_frame(TcpFlags::SYN, 500, 0, 8192, &[]))).expect("step");
    let rst = a.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(a.tx_frame()[..usize::from(*frame_len)].to_vec()) } else { None });
    let rst = rst.expect("a reset");
    let s = tcp_of(&rst);
    assert!(s.flags.contains(TcpFlags::RST));
}

#[test]
fn udp_still_works() {
    let mut e = engine(None);
    let (reply, _) = ctl(&mut e, 0, Op::UdpBind { port: 53 });
    assert!(matches!(reply, Some(ControlReply::Endpoint(_))), "{reply:?}");
}

#[test]
fn with_a_key_opens_proceed() {
    let mut e = engine(Some(IssKey([7; 16])));
    ctl(&mut e, 0, Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC });
    let (reply, _) = ctl(&mut e, 1, Op::Listen { port: LOCAL_PORT });
    assert!(matches!(reply, Some(ControlReply::Listener(_))), "{reply:?}");
    let (reply, frame) = ctl(&mut e, 2, Op::Connect { remote: remote(), local_port: 9 });
    assert!(matches!(reply, Some(ControlReply::Socket(_))), "{reply:?}");
    assert!(tcp_of(&frame.expect("SYN")).flags.contains(TcpFlags::SYN));
}
