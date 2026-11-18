// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! NET-V-090 (AT-net-011): every length field at 0, 1, header − 1,
//! header, packet, packet + 1, and the input truncated to each of those
//! lengths, yields a packet or a closed error, never a panic.
//!
//! In scope here: Ethernet, IPv4, TCP. The vector also lists ARP, IPv6,
//! UDP, DNS and DHCP, which this crate does not parse yet; their part of
//! NET-V-090 is not covered.
//!
//! A deterministic pseudo-random sweep then feeds mutated frames through
//! the whole receive path into connection blocks in every reachable
//! state. It asserts no panic, that every state change is an edge of
//! `TRANSITIONS`, and that the sweep is not vacuous (both accepted and
//! refused inputs occur). This is testing, not proof: it samples inputs,
//! it does not cover them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::tcp::state::is_allowed;
use cambios_netcore::tcp::{SeqNum, Tcb, TcpState};
use cambios_netcore::wire::frame::{self, Classified};
use cambios_netcore::wire::tcp::TcpFlags;
use cambios_netcore::wire::{ethernet, ipv4, tcp};
use cambios_netcore::ParseError;
use common::*;

fn partition(header: usize, packet: usize) -> Vec<usize> {
    let mut v = vec![0, 1, header.saturating_sub(1), header, packet, packet + 1];
    v.sort_unstable();
    v.dedup();
    v
}

#[test]
fn ethernet_input_length_partition() {
    let f = peer_frame(TcpFlags::SYN, 1, 0, 100, b"x");
    for len in partition(ethernet::HEADER_LEN, f.len()) {
        let mut input = f.clone();
        input.resize(len, 0);
        let r = ethernet::parse(&input, MTU);
        if len < ethernet::HEADER_LEN {
            assert_eq!(r, Err(ParseError::EthernetTooShort), "len {len}");
        } else {
            assert_eq!(r.expect("header present").payload.len(), len - ethernet::HEADER_LEN);
        }
    }
}

#[test]
fn ipv4_total_length_and_ihl_partition() {
    let f = peer_frame(TcpFlags::SYN, 1, 0, 100, b"xyz");
    let ip = f[ethernet::HEADER_LEN..].to_vec();
    let packet = ip.len();
    let header = ipv4::MIN_HEADER_LEN;

    // Total-length field at each boundary, checksum fixed up so the length
    // rule (not the checksum) is what decides.
    for total in partition(header, packet) {
        let mut p = ip.clone();
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        fix_ipv4_checksum(&mut p);
        let r = ipv4::parse(&p);
        match total {
            t if t < header => assert_eq!(r, Err(ParseError::Ipv4TotalLengthLessThanHeader), "total {t}"),
            t if t > packet => assert_eq!(r, Err(ParseError::Ipv4TotalLengthExceedsAvailable), "total {t}"),
            t => assert_eq!(r.expect("valid").payload.len(), t - header, "total {t}"),
        }
    }
    // IHL at each value (0..=15 is the whole field).
    for ihl in 0u8..=15 {
        let mut p = ip.clone();
        p[0] = 0x40 | ihl;
        fix_ipv4_checksum(&mut p);
        let r = ipv4::parse(&p);
        let hlen = usize::from(ihl) * 4;
        if hlen < header || hlen > packet {
            assert_eq!(r, Err(ParseError::Ipv4HeaderLength), "ihl {ihl}");
        } else {
            // Either accepted, or refused by a later rule; never a panic.
            let _ = r;
        }
    }
    // Input truncated at each boundary.
    for len in partition(header, packet) {
        let mut p = ip.clone();
        p.resize(len, 0);
        let r = ipv4::parse(&p);
        if len < header {
            assert_eq!(r, Err(ParseError::Ipv4TooShort), "len {len}");
        } else if len < packet {
            assert_eq!(r, Err(ParseError::Ipv4TotalLengthExceedsAvailable), "len {len}");
        } else {
            // Trailing link padding beyond total length is not IP data.
            assert_eq!(r.expect("valid").payload.len(), packet - header, "len {len}");
        }
    }
}

fn fix_ipv4_checksum(p: &mut [u8]) {
    let hlen = (usize::from(p[0] & 0x0F) * 4).clamp(20, p.len());
    p[10] = 0;
    p[11] = 0;
    let ck = cambios_netcore::checksum::of(&p[..hlen]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
}

#[test]
fn tcp_data_offset_and_length_partition() {
    let seg = peer_segment_bytes(TcpFlags::SYN, 1, 0, 100, b"abc"); // 24-octet header (MSS)
    let packet = seg.len();
    // Data offset at each value; checksum recomputed so the offset decides.
    for off in 0u8..=15 {
        let mut s = seg.clone();
        s[12] = off << 4;
        fix_tcp_checksum(&mut s);
        let r = tcp::parse_ipv4(&s, REMOTE_IP, LOCAL_IP);
        let hlen = usize::from(off) * 4;
        if hlen < tcp::MIN_HEADER_LEN || hlen > packet {
            assert_eq!(r, Err(ParseError::TcpDataOffset), "offset {off}");
        } else {
            let _ = r; // packet or a closed option error
        }
    }
    // Segment truncated at each boundary (checksum then decides above 20).
    for len in partition(tcp::MIN_HEADER_LEN, packet) {
        let mut s = seg.clone();
        s.resize(len, 0);
        let r = tcp::parse_ipv4(&s, REMOTE_IP, LOCAL_IP);
        if len < tcp::MIN_HEADER_LEN {
            assert_eq!(r, Err(ParseError::TcpTooShort), "len {len}");
        } else if len == packet {
            assert!(r.is_ok(), "len {len}");
        } else {
            assert!(r.is_err(), "len {len}: a resized segment must not verify");
        }
    }
    // Option length octet at 0, 1, and running one past the header.
    for bad_len in [0u8, 1, 5] {
        let mut s = seg.clone();
        s[21] = bad_len; // MSS option's length octet
        fix_tcp_checksum(&mut s);
        let r = tcp::parse_ipv4(&s, REMOTE_IP, LOCAL_IP);
        assert_eq!(r, Err(ParseError::TcpOptionLength), "option len {bad_len}");
    }
    // A well-formed option of the wrong length for its kind.
    let mut s = seg.clone();
    s[20..24].copy_from_slice(&[3, 4, 7, 0]); // window scale must be length 3
    fix_tcp_checksum(&mut s);
    assert_eq!(tcp::parse_ipv4(&s, REMOTE_IP, LOCAL_IP), Err(ParseError::TcpOptionValue));
}

fn fix_tcp_checksum(s: &mut [u8]) {
    s[16] = 0;
    s[17] = 0;
    let mut c = cambios_netcore::checksum::Checksum::new();
    c.add_bytes(&REMOTE_IP.0);
    c.add_bytes(&LOCAL_IP.0);
    c.add_bytes(&[0, 6]);
    c.add_u16(s.len() as u16);
    c.add_bytes(s);
    s[16..18].copy_from_slice(&c.finish().to_be_bytes());
}

/// xorshift64*: deterministic, seedable, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Connection blocks in each state the transition function can reach.
fn blocks_in_every_state() -> Vec<Tcb> {
    let mut v = Vec::new();
    let (syn_sent, _) = Tcb::connect(config(2048), local(), remote(), SeqNum(300));
    v.push(syn_sent);
    let syn = peer_segment_bytes(TcpFlags::SYN, 100, 0, 1000, &[]);
    let (syn_rcvd, _) = Tcb::accept_syn(config(2048), local(), remote(), &parse_peer(&syn), SeqNum(200)).unwrap();
    v.push(syn_rcvd);
    let est = established(100, 200, 2048);
    v.push(est);
    let mut fw1 = est;
    fw1.close().unwrap();
    v.push(fw1);
    let mut fw2 = fw1;
    fw2.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 101, 202, 1000, &[])));
    v.push(fw2);
    let mut cw = est;
    cw.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 101, 201, 1000, &[])));
    v.push(cw);
    let mut la = cw;
    la.close().unwrap();
    v.push(la);
    let mut closing = fw1;
    closing.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 101, 201, 1000, &[])));
    v.push(closing);
    let mut tw = fw2;
    tw.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 101, 202, 1000, &[])));
    v.push(tw);
    let states: Vec<TcpState> = v.iter().map(|t| t.state()).collect();
    for want in [
        TcpState::SynSent,
        TcpState::SynReceived,
        TcpState::Established,
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::CloseWait,
        TcpState::LastAck,
        TcpState::Closing,
        TcpState::TimeWait,
    ] {
        assert!(states.contains(&want), "fixture missing {want:?}: {states:?}");
    }
    v
}

fn within_two_edges(from: TcpState, to: TcpState) -> bool {
    is_allowed(from, to) || TcpState::ALL.iter().any(|&mid| is_allowed(from, mid) && is_allowed(mid, to))
}

#[test]
fn composite_steps_are_two_table_edges() {
    // SYN,ACK carrying a FIN: SYN-SENT → ESTABLISHED → CLOSE-WAIT.
    let (mut tcb, _) = Tcb::connect(config(2048), local(), remote(), SeqNum(300));
    let seg = peer_segment_bytes(TcpFlags::SYN.union(TcpFlags::ACK).union(TcpFlags::FIN), 900, 301, 1000, &[]);
    tcb.on_segment(&parse_peer(&seg));
    assert_eq!(tcb.state(), TcpState::CloseWait);
    assert!(!is_allowed(TcpState::SynSent, TcpState::CloseWait));
    assert!(within_two_edges(TcpState::SynSent, TcpState::CloseWait));
}

#[test]
fn seeded_sweep_never_panics_and_only_takes_table_edges() {
    let blocks = blocks_in_every_state();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted_tcp = 0u32;
    let mut refused = 0u32;
    let mut state_changes = 0u32;

    for i in 0..20_000u32 {
        // Start from a valid frame with random fields, then damage it.
        let flags = TcpFlags((rng.next() & 0x3F) as u8);
        let payload_len = rng.below(64);
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.next() as u8).collect();
        // Half the time near the fixtures' RCV.NXT (101) and SND.NXT values
        // (201, 202, 301), so the sweep reaches the real transitions.
        let seq = if rng.below(2) == 0 { 100u32.wrapping_add(rng.below(8) as u32) } else { rng.next() as u32 };
        let ack = if rng.below(2) == 0 {
            [201u32, 202, 301][rng.below(3)].wrapping_add(rng.below(3) as u32).wrapping_sub(1)
        } else {
            rng.next() as u32
        };
        let mut f = peer_frame(flags, seq, ack, rng.next() as u16, &payload);
        match rng.below(4) {
            0 => {} // leave valid
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let at = rng.below(f.len());
                    f[at] ^= 1 << rng.below(8);
                }
            }
            2 => {
                let len = rng.below(f.len() + 8);
                f.resize(len, rng.next() as u8);
            }
            _ => {
                let len = rng.below(128);
                f = (0..len).map(|_| rng.next() as u8).collect();
            }
        }
        match frame::classify(&f, MTU) {
            Err(_) => refused += 1,
            Ok(Classified::Ipv4Tcp { segment, .. }) => {
                accepted_tcp += 1;
                for b in &blocks {
                    let mut t = *b;
                    let before = t.state();
                    let out = t.on_segment(&segment);
                    let after = t.state();
                    if before != after {
                        state_changes += 1;
                        // One segment may take up to two edges (an ACK that
                        // completes a handshake or acks our FIN, plus a FIN);
                        // each edge is checked by `enter` as it is taken.
                        assert!(within_two_edges(before, after), "iter {i}: {before:?} -> {after:?}");
                    }
                    if let Some(d) = out.deliver {
                        assert!(d.offset + d.len <= segment.payload.len(), "iter {i}: delivery in bounds");
                        assert!(d.len > 0);
                    }
                }
                let _ = cambios_netcore::tcp::tcb::reset_for_unmatched(&segment);
                let _ = Tcb::accept_syn(config(2048), local(), remote(), &segment, SeqNum(1));
            }
            Ok(_) => {}
        }
    }
    // The sweep is not vacuous.
    assert!(accepted_tcp > 1000, "accepted {accepted_tcp}");
    assert!(refused > 1000, "refused {refused}");
    assert!(state_changes > 100, "state changes {state_changes}");
}
