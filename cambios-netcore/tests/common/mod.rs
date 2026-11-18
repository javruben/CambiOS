// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Shared builders for the integration tests. Segments are produced by
//! the crate's own emitter and read back by its own parser, so every test
//! that uses them also exercises the wire path.

#![allow(dead_code)]

use cambios_netcore::tcp::tcb::{Emit, Outcome};
use cambios_netcore::tcp::{SeqNum, Tcb, TcbConfig};
use cambios_netcore::wire::frame::{self, Classified, Ipv4Route};
use cambios_netcore::wire::tcp::{self, TcpFlags, TcpRepr, TcpSegment};
use cambios_netcore::{IpAddress, Ipv4Address, MacAddress, SocketAddress};

pub const LOCAL_IP: Ipv4Address = Ipv4Address([192, 0, 2, 2]);
pub const REMOTE_IP: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
pub const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);
pub const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x01]);
pub const LOCAL_PORT: u16 = 7;
pub const REMOTE_PORT: u16 = 40000;
pub const MTU: u16 = 1500;
pub const TTL: u8 = 64;

pub fn local() -> SocketAddress {
    SocketAddress { address: IpAddress::V4(LOCAL_IP), port: LOCAL_PORT }
}

pub fn remote() -> SocketAddress {
    SocketAddress { address: IpAddress::V4(REMOTE_IP), port: REMOTE_PORT }
}

pub fn config(receive_window: u16) -> TcbConfig {
    TcbConfig { local_mss: 1460, receive_window }
}

pub fn flags_from(names: &[&str]) -> TcpFlags {
    names.iter().fold(TcpFlags::empty(), |acc, n| {
        acc.union(match *n {
            "SYN" => TcpFlags::SYN,
            "ACK" => TcpFlags::ACK,
            "FIN" => TcpFlags::FIN,
            "RST" => TcpFlags::RST,
            "PSH" => TcpFlags::PSH,
            other => panic!("unknown flag {other}"),
        })
    })
}

/// Bytes of a TCP segment from the remote peer to us (IPv4 checksum).
pub fn peer_segment_bytes(flags: TcpFlags, seq: u32, ack: u32, window: u16, payload: &[u8]) -> Vec<u8> {
    let repr = TcpRepr {
        source_port: REMOTE_PORT,
        destination_port: LOCAL_PORT,
        seq: SeqNum(seq),
        ack: SeqNum(ack),
        flags,
        window,
        mss: if flags.syn() { Some(1460) } else { None },
    };
    let mut buf = vec![0u8; 24 + payload.len()];
    let n = tcp::emit_ipv4(&repr, payload, REMOTE_IP, LOCAL_IP, &mut buf).expect("emit");
    buf.truncate(n);
    buf
}

/// Parse bytes produced by [`peer_segment_bytes`].
pub fn parse_peer(bytes: &[u8]) -> TcpSegment<'_> {
    tcp::parse_ipv4(bytes, REMOTE_IP, LOCAL_IP).expect("parse")
}

/// A whole Ethernet frame from the remote peer.
pub fn peer_frame(flags: TcpFlags, seq: u32, ack: u32, window: u16, payload: &[u8]) -> Vec<u8> {
    let repr = TcpRepr {
        source_port: REMOTE_PORT,
        destination_port: LOCAL_PORT,
        seq: SeqNum(seq),
        ack: SeqNum(ack),
        flags,
        window,
        mss: if flags.syn() { Some(1460) } else { None },
    };
    let route = Ipv4Route {
        source_mac: REMOTE_MAC,
        destination_mac: LOCAL_MAC,
        source: REMOTE_IP,
        destination: LOCAL_IP,
        ttl: TTL,
    };
    let mut buf = vec![0u8; 1514];
    let n = frame::emit_ipv4_tcp(&route, &repr, payload, &mut buf).expect("emit frame");
    buf.truncate(n);
    buf
}

/// The frame we would transmit for `emit`.
pub fn our_frame(emit: &Emit) -> Vec<u8> {
    let route = Ipv4Route {
        source_mac: LOCAL_MAC,
        destination_mac: REMOTE_MAC,
        source: LOCAL_IP,
        destination: REMOTE_IP,
        ttl: TTL,
    };
    let mut buf = vec![0u8; 1514];
    let n = frame::emit_ipv4_tcp(&route, emit.repr(), &[], &mut buf).expect("emit frame");
    buf.truncate(n);
    buf
}

/// Classify `bytes` and return the TCP segment, or panic.
pub fn tcp_of(bytes: &[u8]) -> TcpSegment<'_> {
    match frame::classify(bytes, MTU).expect("classify") {
        Classified::Ipv4Tcp { segment, .. } => segment,
        other => panic!("not TCP: {other:?}"),
    }
}

/// A passive connection driven through the handshake to ESTABLISHED with
/// `rcv_nxt = irs + 1` and `snd_nxt = iss + 1`.
pub fn established(irs: u32, iss: u32, receive_window: u16) -> Tcb {
    let syn = peer_segment_bytes(TcpFlags::SYN, irs, 0, 65535, &[]);
    let (mut tcb, _) = Tcb::accept_syn(config(receive_window), local(), remote(), &parse_peer(&syn), SeqNum(iss))
        .expect("accept_syn");
    let ack = peer_segment_bytes(TcpFlags::ACK, irs.wrapping_add(1), iss.wrapping_add(1), 65535, &[]);
    let out: Outcome = tcb.on_segment(&parse_peer(&ack));
    assert!(out.drop.is_none(), "{out:?}");
    tcb
}
