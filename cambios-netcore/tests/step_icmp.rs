// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ICMPv4 echo through the engine (ADR-039 § 5.2 "ICMPv4 echo"; RFC 792,
//! RFC 1122 § 3.2.2.6), written before the engine handled ICMP. An echo
//! request addressed to this interface is answered with an echo reply of
//! the same identifier, sequence and data; nothing else in ICMP is acted
//! on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{Action, Engine, EngineConfig, EngineError, Event, Instant, IssKey, Refusal};
use cambios_netcore::wire::frame::{self, Classified, Ipv4Route};
use cambios_netcore::wire::icmpv4::{self, Echo, EchoKind, Icmpv4Message};
use cambios_netcore::{Ipv4Address, ParseError};
use common::*;

type Eng = Engine<'static, 2, 1, 4, 1>;
/// Zeroed transmit storage for a test engine, leaked to live as long as
/// the test (`'static`).
fn tx_store(octets: usize) -> &'static mut [u8] {
    Box::leak(vec![0u8; octets].into_boxed_slice())
}


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
        neighbor_ttl_ms: 60_000,
        arp_timeout_ms: 1_000,
        arp_attempts: 3,
        challenge_ack_interval_ms: 1_000,
        max_retransmits: 5,
        hold_per_socket: 0,
    }, tx_store(2 * 256))
    .expect("config")
}

fn icmp_frame(dst: Ipv4Address, message: &[u8]) -> Vec<u8> {
    let route = Ipv4Route { source_mac: REMOTE_MAC, destination_mac: LOCAL_MAC, source: REMOTE_IP, destination: dst, ttl: TTL };
    let mut out = vec![0u8; 1514];
    let n = frame::emit_ipv4_icmp(&route, message, &mut out).expect("emit");
    out.truncate(n);
    out
}

fn echo(kind: EchoKind, data: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; icmpv4::HEADER_LEN + data.len()];
    let n = icmpv4::emit_echo(&Echo { kind, identifier: 0x1234, sequence: 7 }, data, &mut m).expect("echo");
    m.truncate(n);
    m
}

fn run(e: &mut Eng, f: &[u8]) -> Result<Option<Vec<u8>>, EngineError> {
    let a = e.step(Instant(0), Event::Frame(f))?;
    let emitted = a.iter().find_map(|x| if let Action::Emit { frame_len } = x { Some(usize::from(*frame_len)) } else { None });
    Ok(emitted.map(|n| a.tx_frame()[..n].to_vec()))
}

#[test]
fn an_echo_request_for_us_is_answered_in_kind() {
    let mut e = engine();
    let data = b"0123456789abcdefghij";
    let reply = run(&mut e, &icmp_frame(LOCAL_IP, &echo(EchoKind::Request, data))).expect("ok").expect("a reply");
    match frame::classify(&reply, MTU).expect("parses") {
        Classified::Ipv4Icmp { link, ip, message } => {
            assert_eq!(link.destination, REMOTE_MAC);
            assert_eq!((ip.source, ip.destination), (LOCAL_IP, REMOTE_IP));
            assert_eq!(
                message,
                Icmpv4Message::Echo { echo: Echo { kind: EchoKind::Reply, identifier: 0x1234, sequence: 7 }, data: &data[..] }
            );
        }
        other => panic!("not ICMP: {other:?}"),
    }
}

#[test]
fn echo_requests_not_for_us_are_refused() {
    let mut e = engine();
    let req = echo(EchoKind::Request, b"x");
    assert_eq!(run(&mut e, &icmp_frame(Ipv4Address([192, 0, 2, 99]), &req)).err(), Some(EngineError::Refused(Refusal::NotForUs)));
    // A broadcast echo request is not answered (RFC 1122 § 3.2.2.6 allows
    // silence; answering would make this host an amplifier).
    assert_eq!(run(&mut e, &icmp_frame(Ipv4Address::BROADCAST, &req)).err(), Some(EngineError::Refused(Refusal::NotForUs)));
}

#[test]
fn other_icmp_is_not_acted_on() {
    let mut e = engine();
    let reply = echo(EchoKind::Reply, b"x");
    assert_eq!(run(&mut e, &icmp_frame(LOCAL_IP, &reply)).err(), Some(EngineError::Refused(Refusal::IcmpIgnored)));
    // Destination unreachable: carried by type, not interpreted.
    let mut unreach = vec![3u8, 3, 0, 0, 0, 0, 0, 0, 0x45, 0, 0, 28];
    let c = !fold(&unreach);
    unreach[2..4].copy_from_slice(&c.to_be_bytes());
    assert_eq!(run(&mut e, &icmp_frame(LOCAL_IP, &unreach)).err(), Some(EngineError::Refused(Refusal::IcmpIgnored)));
}

#[test]
fn a_corrupt_icmp_message_is_malformed() {
    let mut e = engine();
    let mut req = echo(EchoKind::Request, b"ping");
    let last = req.len() - 1;
    req[last] ^= 1;
    assert_eq!(
        run(&mut e, &icmp_frame(LOCAL_IP, &req)).err(),
        Some(EngineError::Refused(Refusal::Malformed(ParseError::IcmpChecksum)))
    );
}

fn fold(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}
