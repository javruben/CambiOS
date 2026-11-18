// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Sending data at the connection-block level (RFC 9293 § 3.10.2 SEND,
//! § 3.10.7.4 ACK processing) and the RFC 5681 congestion window, written
//! before `Tcb::send_data` and `tcp::congestion` existed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::tcp::congestion::Reno;
use cambios_netcore::tcp::tcb::Emit;
use cambios_netcore::tcp::{SeqNum, Tcb, TcpState};
use cambios_netcore::wire::tcp::TcpFlags;
use cambios_netcore::NetError;
use common::*;

/// An active connection with ISS `iss`, ESTABLISHED by a SYN,ACK from a
/// peer whose ISS is 500 and window `window`.
fn active(iss: u32, window: u16) -> Tcb {
    let (mut tcb, _) = Tcb::connect(config(4096), local(), remote(), SeqNum(iss));
    let sa = peer_segment_bytes(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), window, &[]);
    tcb.on_segment(&parse_peer(&sa));
    assert_eq!(tcb.state(), TcpState::Established);
    tcb
}

#[test]
fn send_data_writes_a_header_at_snd_nxt_and_advances_it() {
    let mut tcb = active(1000, 8192);
    let h = tcb.send_data(5).expect("established");
    assert_eq!((h.seq, h.ack, h.flags), (SeqNum(1001), SeqNum(501), TcpFlags::ACK.union(TcpFlags::PSH)));
    assert_eq!(h.mss, None);
    assert_eq!((tcb.snd_una(), tcb.snd_nxt()), (SeqNum(1001), SeqNum(1006)));
    // A header for resending the same octets changes nothing.
    let before = tcb;
    let again = tcb.data_header(SeqNum(1001));
    assert_eq!((again.seq, again.flags), (SeqNum(1001), TcpFlags::ACK.union(TcpFlags::PSH)));
    assert_eq!(tcb, before);
    // The peer's ACK of all five releases them.
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 501, 1006, 8192, &[])));
    assert_eq!(tcb.snd_una(), SeqNum(1006));
    assert!(tcb.retransmit().is_none(), "data is resent from the engine's buffer, not here");
}

#[test]
fn send_data_is_refused_outside_established_and_close_wait() {
    let (mut syn_sent, _) = Tcb::connect(config(4096), local(), remote(), SeqNum(1));
    assert_eq!(syn_sent.send_data(1), Err(NetError::WouldBlock), "queue in the engine until established");
    let mut closing = active(1000, 8192);
    closing.close().expect("close");
    assert_eq!(closing.send_data(1), Err(NetError::Closed));
    // CLOSE-WAIT may still send.
    let mut cw = active(1000, 8192);
    cw.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 501, 1001, 8192, &[])));
    assert_eq!(cw.state(), TcpState::CloseWait);
    assert!(cw.send_data(3).is_ok());
}

#[test]
fn sequence_numbers_wrap_through_send_and_ack() {
    let mut tcb = active(u32::MAX - 2, 8192); // first data octet at 2^32 - 2
    let h = tcb.send_data(5).expect("send");
    assert_eq!(h.seq, SeqNum(u32::MAX - 1));
    assert_eq!(tcb.snd_nxt(), SeqNum(3), "wrapped");
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 501, 1, 8192, &[])));
    assert_eq!(tcb.snd_una(), SeqNum(1), "a partial ACK across the wrap");
    let out = tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 501, 3, 8192, &[])));
    assert_eq!(tcb.snd_una(), SeqNum(3));
    assert!(out.drop.is_none());
    // An ACK beyond what was sent is still a challenge.
    let out = tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 501, 10, 8192, &[])));
    assert!(matches!(out.emit, Some(Emit::ChallengeAck(_))));
}

#[test]
fn the_fin_follows_the_data() {
    let mut tcb = active(1000, 8192);
    tcb.send_data(4).expect("send");
    let out = tcb.close().expect("close");
    assert_eq!(out.emit.expect("FIN").repr().seq, SeqNum(1005), "FIN after four data octets");
    // Data still unacknowledged: retransmit() is about the FIN only.
    assert_eq!(tcb.retransmit().expect("FIN outstanding").seq, SeqNum(1005));
}

#[test]
fn reno_initial_window_by_mss() {
    // RFC 5681 § 3.1: IW = 2 / 3 / 4 segments by SMSS.
    assert_eq!(Reno::new(2_500).cwnd(), 5_000);
    assert_eq!(Reno::new(1_460).cwnd(), 4_380);
    assert_eq!(Reno::new(536).cwnd(), 2_144);
}

#[test]
fn reno_slow_start_congestion_avoidance_and_timeout() {
    let mut r = Reno::new(1_000);
    assert_eq!(r.cwnd(), 4_000);
    r.on_ack(1_000, 1_000);
    assert_eq!(r.cwnd(), 5_000, "slow start: + min(acked, SMSS)");
    r.on_ack(3_000, 1_000);
    assert_eq!(r.cwnd(), 6_000, "at most one SMSS per ACK");
    // Timeout with 6000 in flight: ssthresh = max(flight / 2, 2 SMSS), cwnd = 1 SMSS.
    r.on_timeout(6_000, 1_000);
    assert_eq!((r.cwnd(), r.ssthresh()), (1_000, 3_000));
    r.on_ack(1_000, 1_000);
    r.on_ack(1_000, 1_000);
    assert_eq!(r.cwnd(), 3_000);
    // Congestion avoidance: + SMSS * SMSS / cwnd per ACK.
    r.on_ack(1_000, 1_000);
    assert_eq!(r.cwnd(), 3_333);
    // A small flight still leaves ssthresh at 2 SMSS.
    r.on_timeout(500, 1_000);
    assert_eq!(r.ssthresh(), 2_000);
    // Nothing overflows.
    let mut big = Reno::new(u16::MAX);
    for _ in 0..100_000 {
        big.on_ack(u32::MAX, u16::MAX);
    }
    assert!(big.cwnd() > 0);
}
