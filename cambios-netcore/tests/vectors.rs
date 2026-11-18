// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Replays the language-neutral conformance vectors in
//! `spec/vectors/net/` that fall inside this crate's implemented scope.
//! Each test names its vector id and the acceptance test it serves.
//!
//! These are ordinary tests. They show the implementation produces the
//! vector's expected values; they are not formal verification.
//!
//! Engine-level expectations in the vectors (`socket_events`,
//! `tx_frames`, counters) are not replayed through `engine::Engine`
//! here; where a vector states one, the test asserts the strongest thing
//! the parser or connection block can show and says so.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::tcp::accept::acceptable;
use cambios_netcore::tcp::send::sendable;
use cambios_netcore::tcp::tcb::{DropReason, Emit};
use cambios_netcore::tcp::{SeqNum, Tcb, TcpState};
use cambios_netcore::wire::{frame, ipv4};
use cambios_netcore::{NetError, ParseError};
use common::*;
use serde_json::Value;

fn vector(file: &str, id: &str) -> Value {
    let path = format!("{}/../spec/vectors/net/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let doc: Value = serde_json::from_str(&text).expect("json");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("{id} not in {file}"))
        .clone()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn state_name(s: TcpState) -> &'static str {
    match s {
        TcpState::Closed => "Closed",
        TcpState::Listen => "Listen",
        TcpState::SynSent => "SynSent",
        TcpState::SynReceived => "SynReceived",
        TcpState::Established => "Established",
        TcpState::FinWait1 => "FinWait1",
        TcpState::FinWait2 => "FinWait2",
        TcpState::CloseWait => "CloseWait",
        TcpState::Closing => "Closing",
        TcpState::LastAck => "LastAck",
        TcpState::TimeWait => "TimeWait",
    }
}

fn flag_names(v: &Value) -> Vec<&str> {
    v.as_array().expect("flags").iter().map(|f| f.as_str().expect("flag")).collect()
}

/// NET-V-001 (AT-net-001): a frame shorter than the Ethernet header is
/// refused as Malformed before any protocol parser sees it.
#[test]
fn net_v_001_short_frame_is_malformed() {
    let case = vector("frames.json", "NET-V-001");
    let bytes = hex(case["input"]["frame_hex"].as_str().expect("hex"));
    let mtu = u16::try_from(case["input"]["interface_mtu"].as_u64().expect("mtu")).expect("u16");
    let err = frame::classify(&bytes, mtu).expect_err("must refuse");
    assert_eq!(err, ParseError::EthernetTooShort);
    assert_eq!(format!("{:?}", err.net_error()), case["expect"]["result"].as_str().expect("result"));
    // socket_events / tx_frames: a parse error yields no value from which
    // an event or a frame could be produced; the engine-level count is
    // not replayed through engine::Engine in this file.
}

fn ipv4_reason(reason: &str) -> ParseError {
    match reason {
        "header_checksum" => ParseError::Ipv4HeaderChecksum,
        "total_length_less_than_header" => ParseError::Ipv4TotalLengthLessThanHeader,
        other => panic!("unmapped reason {other}"),
    }
}

/// NET-V-010 / NET-V-011 (AT-net-002): IPv4 headers refused before
/// transport delivery, each for the reason the vector names.
#[test]
fn net_v_010_011_ipv4_refusals() {
    for id in ["NET-V-010", "NET-V-011"] {
        let case = vector("ipv4.json", id);
        let bytes = hex(case["input"]["ipv4_header_hex"].as_str().expect("hex"));
        if let Some(avail) = case["input"]["available_bytes"].as_u64() {
            assert_eq!(bytes.len() as u64, avail, "{id}: available_bytes");
        }
        let err = ipv4::parse(&bytes).expect_err(id);
        assert_eq!(err, ipv4_reason(case["expect"]["reason"].as_str().expect("reason")), "{id}");
        assert_eq!(err.net_error(), NetError::Malformed, "{id}");
    }
}

/// NET-V-050 (AT-net-006): the passive three-way handshake moves the
/// connection Listen → SynReceived → Established and delivers no bytes.
/// The ISS is the vector's own SYN,ACK sequence number (an input to the
/// pure core).
#[test]
fn net_v_050_three_way_handshake() {
    let case = vector("tcp-open-close.json", "NET-V-050");
    let tcb = run_handshake(&case);
    assert_eq!(tcb.state(), TcpState::Established);
}

/// Drive NET-V-050's trace and check every expectation; returns the
/// block for NET-V-051 to continue.
fn run_handshake(case: &Value) -> Tcb {
    let trace = case["input"]["trace"].as_array().expect("trace");
    let expected = case["expect"]["state_after_event"].as_array().expect("states");
    assert_eq!(case["expect"]["delivered_stream_hex"], "");
    let iss = trace
        .iter()
        .find(|e| e["direction"] == "out")
        .and_then(|e| e["seq"].as_u64())
        .expect("out seq") as u32;

    let mut tcb: Option<Tcb> = None;
    let mut last_emit: Option<Emit> = None;
    let mut delivered = 0usize;
    for (event, want) in trace.iter().zip(expected) {
        let flags = flags_from(&flag_names(&event["flags"]));
        let seq = event["seq"].as_u64().expect("seq") as u32;
        let ack = event["ack"].as_u64().expect("ack") as u32;
        match event["direction"].as_str().expect("direction") {
            "in" => {
                let bytes = peer_segment_bytes(flags, seq, ack, 65535, &[]);
                let seg = parse_peer(&bytes);
                let out = match tcb.as_mut() {
                    None => {
                        let (t, out) = Tcb::accept_syn(config(65535), local(), remote(), &seg, SeqNum(iss))
                            .expect("listener accepts SYN");
                        tcb = Some(t);
                        out
                    }
                    Some(t) => t.on_segment(&seg),
                };
                assert!(out.drop.is_none(), "{out:?}");
                delivered += out.deliver.map_or(0, |d| d.len);
                last_emit = out.emit;
            }
            "out" => {
                let emit = last_emit.take().expect("an emitted segment");
                let repr = emit.repr();
                assert!(matches!(emit, Emit::Segment(_)));
                assert_eq!(repr.flags, flags);
                assert_eq!(repr.seq, SeqNum(seq));
                assert_eq!(repr.ack, SeqNum(ack));
                // The emitted segment survives a full frame round trip.
                let wire = our_frame(&emit);
                let seg = tcp_of(&wire);
                assert_eq!((seg.seq, seg.ack, seg.flags), (repr.seq, repr.ack, repr.flags));
            }
            other => panic!("direction {other}"),
        }
        let state = tcb.as_ref().expect("tcb").state();
        assert_eq!(state_name(state), want.as_str().expect("state"));
    }
    assert_eq!(delivered, 0, "no stream bytes in a handshake");
    assert_eq!(case["expect"]["duplicate_bytes"], 0);
    tcb.expect("tcb")
}

/// NET-V-051 (AT-net-006): passive close. The vector's sequence numbers
/// continue NET-V-050 (RCV.NXT = 101, SND.NXT = 501), so the block is
/// the one NET-V-050 leaves ESTABLISHED.
#[test]
fn net_v_051_passive_close() {
    let mut tcb = run_handshake(&vector("tcp-open-close.json", "NET-V-050"));
    let case = vector("tcp-open-close.json", "NET-V-051");
    let trace = case["input"]["trace"].as_array().expect("trace");
    let expected = case["expect"]["state_after_event"].as_array().expect("states");
    for (event, want) in trace.iter().zip(expected) {
        match event["direction"].as_str().expect("direction") {
            "in" => {
                let flags = flags_from(&flag_names(&event["flags"]));
                let seq = event["seq"].as_u64().expect("seq") as u32;
                let ack = event["ack"].as_u64().expect("ack") as u32;
                let bytes = peer_segment_bytes(flags, seq, ack, 65535, &[]);
                let out = tcb.on_segment(&parse_peer(&bytes));
                assert!(out.drop.is_none(), "{out:?}");
            }
            "local" => {
                assert_eq!(event["event"], "close");
                let out = tcb.close().expect("close");
                // Our FIN occupies SND.NXT = 501; the peer's ACK of 502
                // in the next event covers it.
                let fin = *out.emit.expect("FIN").repr();
                assert!(fin.flags.fin() && fin.flags.ack());
                assert_eq!(fin.seq, SeqNum(501));
                assert_eq!(fin.ack, SeqNum(102));
            }
            other => panic!("direction {other}"),
        }
        assert_eq!(state_name(tcb.state()), want.as_str().expect("state"));
    }
}

/// NET-V-052 (AT-net-007): new data sent is min(peer window, cwnd).
#[test]
fn net_v_052_send_window_is_the_minimum() {
    let case = vector("tcp-open-close.json", "NET-V-052");
    let input = &case["input"];
    assert_eq!(input["state"], "Established");
    let wnd = input["peer_receive_window_bytes"].as_u64().expect("wnd") as u32;
    let cwnd = input["congestion_window_bytes"].as_u64().expect("cwnd") as u32;
    let unsent = input["unsent_data_bytes"].as_u64().expect("unsent") as u32;
    let una = SeqNum(5000);
    let sent = sendable(una, una, wnd, cwnd, unsent);
    assert_eq!(u64::from(sent), case["expect"]["new_data_bytes_sent"].as_u64().expect("sent"));
    let outside = sent.saturating_sub(wnd.min(cwnd));
    assert_eq!(u64::from(outside), case["expect"]["bytes_outside_minimum_window"].as_u64().expect("outside"));
}

/// NET-V-060 / NET-V-061 (AT-net-008): an in-window RST that is not at
/// RCV.NXT, and a SYN in ESTABLISHED, leave the connection ESTABLISHED
/// and yield one challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`.
///
/// The vectors give RCV.NXT and RCV.WND but not SND.NXT; their expected
/// `seq: 0` is SND.NXT. The block is built with ISS = 2^32 - 1 so that
/// SND.NXT is 0, and IRS = 999 so that RCV.NXT is 1000.
///
/// Rate limiting (RFC 5961 § 7) is not applied by the connection block:
/// its unit and value are open (crosswalk R-6). The test asserts the
/// ACK is marked as a challenge, which is what a limiter would act on.
#[test]
fn net_v_060_061_challenge_acks() {
    for (id, reason) in [("NET-V-060", DropReason::RstInWindow), ("NET-V-061", DropReason::SynInSynchronized)] {
        let case = vector("tcp-reset-defense.json", id);
        let input = &case["input"];
        assert_eq!(input["state"], "Established");
        let rcv_nxt = input["rcv_nxt"].as_u64().expect("rcv_nxt") as u32;
        let rcv_wnd = input["rcv_wnd"].as_u64().expect("rcv_wnd") as u16;
        let mut tcb = established(rcv_nxt.wrapping_sub(1), u32::MAX, rcv_wnd);
        assert_eq!(tcb.rcv_nxt(), SeqNum(rcv_nxt));
        assert_eq!(tcb.rcv_wnd(), u32::from(rcv_wnd));
        assert_eq!(tcb.snd_nxt(), SeqNum(0));

        let seg_in = &input["segment"];
        let flags = flags_from(&flag_names(&seg_in["flags"]));
        let seq = seg_in["seq"].as_u64().expect("seq") as u32;
        let bytes = peer_segment_bytes(flags, seq, 0, 65535, &[]);
        let before = tcb;
        let out = tcb.on_segment(&parse_peer(&bytes));

        assert_eq!(state_name(tcb.state()), case["expect"]["state"].as_str().expect("state"), "{id}");
        assert_eq!(tcb, before, "{id}: a challenged segment changes nothing");
        assert_eq!(out.drop, Some(reason), "{id}");
        assert!(out.events.is_empty(), "{id}");
        let Some(Emit::ChallengeAck(ack)) = out.emit else {
            panic!("{id}: expected a challenge ACK, got {:?}", out.emit)
        };
        let want = &case["expect"]["response"];
        assert_eq!(ack.flags, flags_from(&flag_names(&want["flags"])), "{id}");
        assert_eq!(u64::from(ack.seq.0), want["seq"].as_u64().expect("seq"), "{id}");
        assert_eq!(u64::from(ack.ack.0), want["ack"].as_u64().expect("ack"), "{id}");
    }
}

/// NET-V-091 (AT-net-011): a two-octet segment starting at 2^32 - 1
/// crosses the sequence wrap. Acceptability, delivery and the send
/// window all use modular arithmetic and do not trap.
#[test]
fn net_v_091_sequence_wrap() {
    let case = vector("parser-boundaries.json", "NET-V-091");
    let input = &case["input"];
    let seq = input["tcp_seq"].as_u64().expect("seq") as u32;
    let len = input["tcp_len"].as_u64().expect("len") as u32;
    let window = input["peer_window"].as_u64().expect("window") as u32;
    assert_eq!(input["crosses_u32_wrap"], true);
    assert!(seq.checked_add(len).is_none(), "the vector does cross the wrap");

    // Receive side: window starting at the segment, and at its last octet.
    assert!(acceptable(SeqNum(seq), len, SeqNum(seq), window));
    assert!(acceptable(SeqNum(seq), len, SeqNum(seq.wrapping_add(1)), window));
    assert!(!acceptable(SeqNum(seq), len, SeqNum(seq.wrapping_add(len)), window));

    // Through a connection block: RCV.NXT = 2^32 - 1, two octets arrive,
    // both are delivered and RCV.NXT wraps to 1.
    let mut tcb = established(seq.wrapping_sub(1), 7000, window as u16);
    assert_eq!(tcb.rcv_nxt(), SeqNum(seq));
    let bytes = peer_segment_bytes(flags_from(&["ACK"]), seq, 7001, 65535, b"ab");
    let out = tcb.on_segment(&parse_peer(&bytes));
    let d = out.deliver.expect("delivered");
    assert_eq!((d.offset, d.len), (0, len as usize));
    assert_eq!(tcb.rcv_nxt(), SeqNum(seq.wrapping_add(len)));
    assert_eq!(tcb.rcv_wnd(), window - len);
    // Re-sending the same two octets delivers nothing (no duplicate bytes).
    let again = tcb.on_segment(&parse_peer(&bytes));
    assert!(again.deliver.is_none());

    // Send side: 2 octets in flight across the wrap, window 16 → 14 more.
    assert_eq!(sendable(SeqNum(seq), SeqNum(seq).add(len), window, u32::MAX, u32::MAX), window - len);
}
