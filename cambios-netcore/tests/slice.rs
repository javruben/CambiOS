// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The vertical slice end to end: Ethernet frames in, Ethernet frames
//! out, through every layer this crate implements. A peer opens a
//! connection, sends data, and closes; then an unmatched segment gets
//! the no-listener reset (spec B-17 response class).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::tcp::tcb::{reset_for_unmatched, DropReason, Emit, TcbEvent};
use cambios_netcore::tcp::{SeqNum, Tcb, TcpState};
use cambios_netcore::wire::frame::{self, Classified};
use cambios_netcore::wire::tcp::TcpFlags;
use cambios_netcore::ParseError;
use common::*;

const ISS: u32 = 0x1000_0000;
const IRS: u32 = 0xFFFF_FFF0; // the stream crosses the 2^32 wrap

#[test]
fn frames_in_frames_out_open_transfer_close() {
    // 1. SYN frame from the peer reaches a listener.
    let syn = peer_frame(TcpFlags::SYN, IRS, 0, 8192, &[]);
    let Classified::Ipv4Tcp { ip, segment, .. } = frame::classify(&syn, MTU).expect("classify SYN") else {
        panic!("SYN is TCP");
    };
    assert_eq!((ip.source, ip.destination), (REMOTE_IP, LOCAL_IP));
    assert_eq!(segment.options.mss, Some(1460));
    let (mut tcb, out) =
        Tcb::accept_syn(config(4096), local(), remote(), &segment, SeqNum(ISS)).expect("accept");
    assert_eq!(tcb.state(), TcpState::SynReceived);

    // 2. Our SYN,ACK leaves as a frame that parses back with valid checksums.
    let syn_ack_frame = our_frame(&out.emit.expect("SYN,ACK"));
    let sa = tcp_of(&syn_ack_frame);
    assert!(sa.flags.syn() && sa.flags.ack());
    assert_eq!((sa.seq, sa.ack), (SeqNum(ISS), SeqNum(IRS.wrapping_add(1))));
    assert_eq!(sa.options.mss, Some(1460));
    assert_eq!(sa.window, 4096);

    // 3. Final ACK: ESTABLISHED, Connected, nothing emitted.
    let ack = peer_frame(TcpFlags::ACK, IRS.wrapping_add(1), ISS + 1, 8192, &[]);
    let out = tcb.on_segment(&tcp_of(&ack));
    assert_eq!(tcb.state(), TcpState::Established);
    assert!(out.events.contains(TcbEvent::Connected));
    assert!(out.emit.is_none() && out.deliver.is_none() && out.drop.is_none());
    assert_eq!(tcb.snd_wnd(), 8192);

    // 4. Data crossing the sequence wrap is delivered in order and ACKed.
    let data = b"0123456789abcdefXYZ"; // 19 octets: IRS+1 .. wraps past 0
    let seg_frame = peer_frame(TcpFlags::ACK.union(TcpFlags::PSH), IRS.wrapping_add(1), ISS + 1, 8192, data);
    let seg = tcp_of(&seg_frame);
    let out = tcb.on_segment(&seg);
    let d = out.deliver.expect("delivered");
    assert_eq!(&seg.payload[d.offset..d.offset + d.len], data);
    let ack_out = tcp_of(&our_frame(&out.emit.expect("ACK"))).ack;
    assert_eq!(ack_out, SeqNum(IRS.wrapping_add(1).wrapping_add(19)));
    assert_eq!(tcb.rcv_wnd(), 4096 - 19);

    // 5. A retransmission overlapping old and new octets delivers only the new.
    let more = b"XYZ+more";
    let overlap = peer_frame(TcpFlags::ACK, IRS.wrapping_add(17), ISS + 1, 8192, more);
    let seg = tcp_of(&overlap);
    let out = tcb.on_segment(&seg);
    let d = out.deliver.expect("delivered");
    assert_eq!(&seg.payload[d.offset..d.offset + d.len], b"+more");

    // 6. A segment past RCV.NXT is out of order: dropped and ACKed, not held.
    let gap = peer_frame(TcpFlags::ACK, IRS.wrapping_add(100), ISS + 1, 8192, b"later");
    let rcv_before = tcb.rcv_nxt();
    let out = tcb.on_segment(&tcp_of(&gap));
    assert!(out.deliver.is_none());
    assert_eq!(tcb.rcv_nxt(), rcv_before);
    assert!(matches!(out.emit, Some(Emit::Segment(r)) if r.ack == rcv_before));

    // 7. The application consumed everything: window reopens to capacity.
    tcb.release_receive_space(1_000_000);
    assert_eq!(tcb.rcv_wnd(), 4096);

    // 8. Peer FIN → CLOSE-WAIT; our close → LAST-ACK with a FIN; ACK → CLOSED.
    let fin = peer_frame(TcpFlags::FIN.union(TcpFlags::ACK), rcv_before.0, ISS + 1, 8192, &[]);
    let out = tcb.on_segment(&tcp_of(&fin));
    assert_eq!(tcb.state(), TcpState::CloseWait);
    assert!(out.events.contains(TcbEvent::PeerClosed));
    let out = tcb.close().expect("close");
    assert_eq!(tcb.state(), TcpState::LastAck);
    let fin_frame = our_frame(&out.emit.expect("FIN"));
    let our_fin = tcp_of(&fin_frame);
    assert!(our_fin.flags.fin());
    assert_eq!(our_fin.seq, SeqNum(ISS + 1));
    let last = peer_frame(TcpFlags::ACK, rcv_before.0.wrapping_add(1), ISS + 2, 8192, &[]);
    let out = tcb.on_segment(&tcp_of(&last));
    assert_eq!(tcb.state(), TcpState::Closed);
    assert!(out.events.contains(TcbEvent::Closed));
    assert!(tcb.close().is_err());
}

#[test]
fn active_open_and_simultaneous_close() {
    let (mut tcb, syn) = Tcb::connect(config(2048), local(), remote(), SeqNum(500));
    assert_eq!(tcb.state(), TcpState::SynSent);
    assert!(syn.flags.syn() && !syn.flags.ack());
    assert_eq!(syn.mss, Some(1460));

    // A SYN,ACK that does not cover our SYN gets a reset; state unchanged.
    let wrong = peer_segment_bytes(TcpFlags::SYN.union(TcpFlags::ACK), 9000, 400, 1000, &[]);
    let out = tcb.on_segment(&parse_peer(&wrong));
    assert_eq!(tcb.state(), TcpState::SynSent);
    let rst = *out.emit.expect("RST").repr();
    assert!(rst.flags.rst());
    assert_eq!(rst.seq, SeqNum(400));

    // The right SYN,ACK establishes and is answered with an ACK.
    let ok = peer_segment_bytes(TcpFlags::SYN.union(TcpFlags::ACK), 9000, 501, 1000, &[]);
    let out = tcb.on_segment(&parse_peer(&ok));
    assert_eq!(tcb.state(), TcpState::Established);
    assert!(out.events.contains(TcbEvent::Connected));
    let ack = *out.emit.expect("ACK").repr();
    assert_eq!((ack.seq, ack.ack, ack.flags), (SeqNum(501), SeqNum(9001), TcpFlags::ACK));
    assert_eq!(tcb.peer_mss(), 1460);

    // Simultaneous close: our FIN, then the peer's FIN before it ACKs ours.
    let out = tcb.close().expect("close");
    assert_eq!(tcb.state(), TcpState::FinWait1);
    assert_eq!(out.emit.expect("FIN").repr().seq, SeqNum(501));
    let their_fin = peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 9001, 501, 1000, &[]);
    tcb.on_segment(&parse_peer(&their_fin));
    assert_eq!(tcb.state(), TcpState::Closing);
    let ack_of_ours = peer_segment_bytes(TcpFlags::ACK, 9002, 502, 1000, &[]);
    tcb.on_segment(&parse_peer(&ack_of_ours));
    assert_eq!(tcb.state(), TcpState::TimeWait);
}

#[test]
fn fin_wait_paths() {
    // FIN,ACK covering our FIN: FIN-WAIT-1 → TIME-WAIT in one segment.
    let mut tcb = established(100, 200, 1000);
    tcb.close().expect("close");
    let both = peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 101, 202, 1000, &[]);
    let out = tcb.on_segment(&parse_peer(&both));
    assert_eq!(tcb.state(), TcpState::TimeWait);
    assert!(out.events.contains(TcbEvent::PeerClosed));

    // ACK first (FIN-WAIT-2), FIN later (TIME-WAIT).
    let mut tcb = established(100, 200, 1000);
    tcb.close().expect("close");
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 101, 202, 1000, &[])));
    assert_eq!(tcb.state(), TcpState::FinWait2);
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::FIN.union(TcpFlags::ACK), 101, 202, 1000, &[])));
    assert_eq!(tcb.state(), TcpState::TimeWait);
}

#[test]
fn exact_rst_resets_and_passive_half_open_returns_to_listen() {
    let mut tcb = established(100, 200, 1000);
    let rst = peer_segment_bytes(TcpFlags::RST, 101, 0, 0, &[]);
    let out = tcb.on_segment(&parse_peer(&rst));
    assert_eq!(tcb.state(), TcpState::Closed);
    assert!(out.events.contains(TcbEvent::Reset));
    assert!(out.emit.is_none());

    // Out-of-window RST: silently dropped.
    let mut tcb = established(100, 200, 1000);
    let far = peer_segment_bytes(TcpFlags::RST, 5000, 0, 0, &[]);
    let out = tcb.on_segment(&parse_peer(&far));
    assert_eq!(tcb.state(), TcpState::Established);
    assert!(out.emit.is_none());

    // Passive SYN-RECEIVED + exact RST: the half-open block is abandoned.
    let syn = peer_segment_bytes(TcpFlags::SYN, 100, 0, 1000, &[]);
    let (mut half, _) = Tcb::accept_syn(config(1000), local(), remote(), &parse_peer(&syn), SeqNum(200)).expect("accept");
    let out = half.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::RST, 101, 0, 0, &[])));
    assert_eq!(half.state(), TcpState::Closed);
    assert!(out.events.contains(TcbEvent::ReturnedToListen));
}

#[test]
fn ack_checks_rfc5961_section_5() {
    let mut tcb = established(100, 200, 1000);
    // ACK of data never sent: challenge ACK (RFC 5961 § 5.2), nothing changes.
    let before = tcb;
    let out = tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 101, 999, 1000, &[])));
    assert_eq!(tcb, before);
    assert!(matches!(out.emit, Some(Emit::ChallengeAck(_))));
    assert_eq!(out.drop, Some(DropReason::AckUnsent));
    // ACK far older than SND.UNA - MAX.SND.WND: challenge ACK, nothing changes.
    let out = tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 101, 200u32.wrapping_sub(100_000), 1000, &[])));
    assert_eq!(tcb, before);
    assert!(matches!(out.emit, Some(Emit::ChallengeAck(_))));
}

#[test]
fn old_duplicate_ack_does_not_move_the_send_window() {
    // ESTABLISHED: SND.UNA = 201, SND.WND = MAX.SND.WND = 65535 (the
    // handshake ACK in `established`), WL1 = 101.
    let mut tcb = established(100, 200, 1000);
    assert_eq!(tcb.snd_wnd(), 65535);
    // Newer SEG.SEQ (102 > WL1) but SEG.ACK = 150 < SND.UNA: no update.
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 102, 150, 5, &[])));
    assert_eq!(tcb.snd_wnd(), 65535);
    // The same segment acknowledging SND.UNA exactly does update it.
    tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::ACK, 102, 201, 5, &[])));
    assert_eq!(tcb.snd_wnd(), 5);
}

#[test]
fn syn_challenge_ignores_sequence_but_syn_received_keeps_rfc9293_order() {
    // Out-of-window SYN in ESTABLISHED: still a challenge (RFC 5961 § 4.2).
    let mut tcb = established(100, 200, 1000);
    let before = tcb;
    let out = tcb.on_segment(&parse_peer(&peer_segment_bytes(TcpFlags::SYN, 900_000, 0, 1000, &[])));
    assert_eq!(tcb, before);
    assert!(matches!(out.emit, Some(Emit::ChallengeAck(_))));
    assert_eq!(out.drop, Some(DropReason::SynInSynchronized));

    // Retransmitted SYN in passive SYN-RECEIVED: an ACK, and the half-open
    // block survives (the SYN is below RCV.NXT, so the sequence check fires).
    let syn = peer_segment_bytes(TcpFlags::SYN, 100, 0, 1000, &[]);
    let (mut half, _) = Tcb::accept_syn(config(1000), local(), remote(), &parse_peer(&syn), SeqNum(200)).expect("accept");
    let out = half.on_segment(&parse_peer(&syn));
    assert_eq!(half.state(), TcpState::SynReceived);
    assert!(matches!(out.emit, Some(Emit::Segment(_))));
    assert_eq!(out.drop, Some(DropReason::Unacceptable));
}

#[test]
fn zero_window_still_processes_a_valid_ack() {
    // RCV.WND = 0. We close (FIN at 201); the peer's next segment carries
    // data we cannot take, plus the ACK of our FIN.
    let mut tcb = established(100, 200, 0);
    tcb.close().expect("close");
    assert_eq!(tcb.state(), TcpState::FinWait1);
    let probe = peer_segment_bytes(TcpFlags::ACK, 101, 202, 1000, b"x");
    let out = tcb.on_segment(&parse_peer(&probe));
    assert_eq!(tcb.state(), TcpState::FinWait2, "the ACK of our FIN was processed");
    assert_eq!(out.drop, Some(DropReason::ZeroWindow));
    assert!(out.deliver.is_none());
    assert_eq!(tcb.rcv_nxt(), SeqNum(101), "no text accepted");
    assert!(matches!(out.emit, Some(Emit::Segment(r)) if r.ack == SeqNum(101) && r.window == 0));
}

#[test]
fn no_listener_reset_class() {
    // A SYN to a port with no listener: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
    let syn = peer_frame(TcpFlags::SYN, 777, 0, 1000, &[]);
    let seg = tcp_of(&syn);
    let rst = reset_for_unmatched(&seg).expect("reset");
    assert_eq!((rst.seq, rst.ack), (SeqNum(0), SeqNum(778)));
    assert!(rst.flags.rst() && rst.flags.ack());
    assert_eq!((rst.source_port, rst.destination_port), (LOCAL_PORT, REMOTE_PORT));
    let wire = our_frame(&Emit::Segment(rst));
    assert!(tcp_of(&wire).flags.rst());

    // An ACK to no connection: <SEQ=SEG.ACK><CTL=RST>.
    let stray = peer_segment_bytes(TcpFlags::ACK, 5, 4242, 1000, &[]);
    let rst = reset_for_unmatched(&parse_peer(&stray)).expect("reset");
    assert_eq!((rst.seq, rst.flags), (SeqNum(4242), TcpFlags::RST));

    // An RST is never answered.
    let r = peer_segment_bytes(TcpFlags::RST, 5, 0, 0, &[]);
    assert!(reset_for_unmatched(&parse_peer(&r)).is_none());

    // A listener answers a stray ACK the same way.
    let refused = Tcb::accept_syn(config(1000), local(), remote(), &parse_peer(&stray), SeqNum(1)).expect_err("not a SYN");
    assert_eq!(refused.emit.expect("reset").repr().seq, SeqNum(4242));
}

#[test]
fn corrupted_frames_are_refused_by_the_layer_that_owns_the_rule() {
    let good = peer_frame(TcpFlags::SYN, 1, 0, 1000, &[]);
    // Flip one TCP payload-region bit (inside the TCP header, past IP).
    let mut bad_tcp = good.clone();
    bad_tcp[14 + 20 + 4] ^= 0x01;
    assert_eq!(frame::classify(&bad_tcp, MTU), Err(ParseError::TcpChecksum));
    // Flip one IP header bit.
    let mut bad_ip = good.clone();
    bad_ip[14 + 8] ^= 0x01;
    assert_eq!(frame::classify(&bad_ip, MTU), Err(ParseError::Ipv4HeaderChecksum));
    // A frame whose payload exceeds the MTU.
    assert_eq!(frame::classify(&good, 20), Err(ParseError::EthernetExceedsMtu));
    // Broadcast source MAC.
    let mut bad_mac = good.clone();
    bad_mac[6] = 0xFF;
    assert_eq!(frame::classify(&bad_mac, MTU), Err(ParseError::EthernetGroupSource));
}
