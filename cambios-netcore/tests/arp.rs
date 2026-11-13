// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ARP for Ethernet/IPv4 (RFC 826) and the neighbor table (spec B-5,
//! INV-net-005, AT-net-004 / NET-V-030; ADR-039 § 5.2: "a reply updates
//! an entry only if we asked"), written before `wire::arp` and `neighbor`
//! existed. The learning tests were rewritten (red against the first
//! implementation, which used the RFC 826 merge rule) to follow ADR-039.
//!
//! The table is one interface's (one table per engine), so an entry can
//! only ever affect that interface. Capacity is a const generic; time and
//! each entry's expiry instant are inputs, so no lifetime value is chosen
//! here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::neighbor::{Ignored, Learn, NeighborError, NeighborTable};
use cambios_netcore::wire::arp::{self, ArpOperation, ArpPacket, PACKET_LEN};
use cambios_netcore::wire::ethernet::{self, EtherType};
use cambios_netcore::wire::frame::{self, Classified};
use cambios_netcore::{Ipv4Address, MacAddress, NetError, ParseError};
use common::*;
use serde_json::Value;

const OTHER_IP: Ipv4Address = Ipv4Address([192, 0, 2, 3]);
const OTHER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x03]);

fn request(sender_mac: MacAddress, sender_ip: Ipv4Address, target_ip: Ipv4Address) -> ArpPacket {
    ArpPacket { operation: ArpOperation::Request, sender_mac, sender_ip, target_mac: MacAddress([0; 6]), target_ip }
}

fn reply(sender_mac: MacAddress, sender_ip: Ipv4Address, target_mac: MacAddress, target_ip: Ipv4Address) -> ArpPacket {
    ArpPacket { operation: ArpOperation::Reply, sender_mac, sender_ip, target_mac, target_ip }
}

#[test]
fn known_answer_request_bytes_and_round_trip() {
    let p = request(REMOTE_MAC, REMOTE_IP, LOCAL_IP);
    let mut out = [0xAAu8; 40];
    assert_eq!(arp::emit(&p, &mut out), Ok(PACKET_LEN));
    #[rustfmt::skip]
    let expected: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01,     // Ethernet, IPv4, 6/4, request
        0x02, 0, 0, 0, 0, 0x01, 192, 0, 2, 1,         // sender
        0, 0, 0, 0, 0, 0, 192, 0, 2, 2,               // target
    ];
    assert_eq!(&out[..28], &expected);
    assert_eq!(out[28], 0xAA, "nothing written past the packet");
    assert_eq!(arp::parse(&out[..28]), Ok(p));
    assert_eq!(PACKET_LEN, 28);
}

#[test]
fn parse_refusals_and_padding() {
    let mut good = [0u8; 28];
    arp::emit(&reply(REMOTE_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP), &mut good).expect("emit");

    assert_eq!(arp::parse(&good[..27]), Err(ParseError::ArpTooShort));

    // Ethernet minimum payload is 46 octets: trailing padding is ignored.
    let mut padded = good.to_vec();
    padded.resize(46, 0);
    assert_eq!(arp::parse(&padded).expect("padded").operation, ArpOperation::Reply);

    for (at, value) in [(1usize, 6u8), (3, 0xDD), (4, 8), (5, 16)] {
        let mut bad = good;
        bad[at] = value;
        let err = arp::parse(&bad).expect_err("other hardware/protocol");
        assert_eq!(err, ParseError::ArpUnsupported, "byte {at}");
        assert_eq!(err.net_error(), NetError::Unsupported);
    }

    let mut bad = good;
    bad[7] = 3;
    let err = arp::parse(&bad).expect_err("opcode 3");
    assert_eq!(err, ParseError::ArpOperation);
    assert_eq!(err.net_error(), NetError::Malformed);

    let mut small = [0u8; 27];
    assert!(arp::emit(&reply(REMOTE_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP), &mut small).is_err());
}

#[test]
fn arp_frames_classify_as_arp() {
    let mut f = vec![0u8; 14 + 28];
    ethernet::emit_header(&mut f, MacAddress::BROADCAST, REMOTE_MAC, EtherType::Arp).expect("header");
    arp::emit(&request(REMOTE_MAC, REMOTE_IP, LOCAL_IP), &mut f[14..]).expect("arp");
    match frame::classify(&f, MTU).expect("classify") {
        Classified::Arp { link, arp } => {
            assert_eq!(link.source, REMOTE_MAC);
            assert_eq!(arp.target_ip, LOCAL_IP);
        }
        other => panic!("not ARP: {other:?}"),
    }
    f[14 + 7] = 9;
    assert_eq!(frame::classify(&f, MTU), Err(ParseError::ArpOperation));
}

fn mac(s: &str) -> MacAddress {
    let b: Vec<u8> = s.split(':').map(|h| u8::from_str_radix(h, 16).expect("hex")).collect();
    MacAddress(b.try_into().expect("6 octets"))
}

fn ip(s: &str) -> Ipv4Address {
    let b: Vec<u8> = s.split('.').map(|d| d.parse().expect("octet")).collect();
    Ipv4Address(b.try_into().expect("4 octets"))
}

#[test]
fn net_v_030_a_reply_cannot_move_a_pinned_mapping() {
    let path = format!("{}/../spec/vectors/net/neighbors.json", env!("CARGO_MANIFEST_DIR"));
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("json");
    let case = doc["cases"].as_array().expect("cases").iter().find(|c| c["id"] == "NET-V-030").expect("case").clone();
    let pinned = &case["input"]["operator_pinned"];
    let lie = &case["input"]["arp_reply"];
    assert_eq!(pinned["interface"], lie["interface"], "same interface: the table is that interface's");

    let mut t: NeighborTable<4> = NeighborTable::new();
    let pinned_ip = ip(pinned["ip"].as_str().unwrap());
    t.pin(pinned_ip, mac(pinned["mac"].as_str().unwrap())).expect("pin");
    // Even a request we make for the pinned address does not open it.
    t.request(pinned_ip, 0, 1000).expect("asking is harmless");
    let p = reply(mac(lie["sender_mac"].as_str().unwrap()), ip(lie["sender_ip"].as_str().unwrap()), LOCAL_MAC, LOCAL_IP);
    assert_eq!(t.on_arp(&p, LOCAL_IP, 0, 1000), Learn::Ignored(Ignored::Pinned));

    let want = &case["expect"]["pinned_mapping"];
    assert_eq!(t.lookup(ip(want["ip"].as_str().unwrap()), 999_999), Some(mac(want["mac"].as_str().unwrap())), "pinned never expires");
    assert_eq!(case["expect"]["principal_policy_changed"], false); // the table holds no policy to change
}

#[test]
fn a_reply_resolves_only_what_we_asked() {
    let mut t: NeighborTable<4> = NeighborTable::new();
    // Unsolicited reply: nothing learned.
    let r = reply(REMOTE_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP);
    assert_eq!(t.on_arp(&r, LOCAL_IP, 0, 100), Learn::Ignored(Ignored::Unsolicited));
    assert_eq!(t.lookup(REMOTE_IP, 0), None);
    // A request addressed to us teaches nothing either.
    assert_eq!(t.on_arp(&request(REMOTE_MAC, REMOTE_IP, LOCAL_IP), LOCAL_IP, 0, 100), Learn::Ignored(Ignored::Unsolicited));
    assert!(t.is_empty());

    // We ask; the pending entry resolves nothing by itself.
    t.request(REMOTE_IP, 0, 50).expect("ask");
    assert_eq!(t.lookup(REMOTE_IP, 0), None, "pending is not resolved");
    // A request (not a reply) from the asked host does not resolve it.
    assert_eq!(t.on_arp(&request(REMOTE_MAC, REMOTE_IP, LOCAL_IP), LOCAL_IP, 1, 100), Learn::Ignored(Ignored::Unsolicited));
    // The reply does, valid until its expiry instant.
    assert_eq!(t.on_arp(&r, LOCAL_IP, 10, 100), Learn::Resolved);
    assert_eq!(t.lookup(REMOTE_IP, 99), Some(REMOTE_MAC));
    assert_eq!(t.lookup(REMOTE_IP, 100), None, "expired at its instant");
    // A second reply, now that the question is answered, is unsolicited.
    let moved = reply(MacAddress([0x02, 0, 0, 0, 0, 0x42]), REMOTE_IP, LOCAL_MAC, LOCAL_IP);
    assert_eq!(t.on_arp(&moved, LOCAL_IP, 20, 500), Learn::Ignored(Ignored::Unsolicited));
    assert_eq!(t.lookup(REMOTE_IP, 20), Some(REMOTE_MAC));
}

#[test]
fn a_question_left_unanswered_expires() {
    let mut t: NeighborTable<4> = NeighborTable::new();
    t.request(REMOTE_IP, 0, 50).expect("ask");
    let r = reply(REMOTE_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP);
    assert_eq!(t.on_arp(&r, LOCAL_IP, 50, 500), Learn::Ignored(Ignored::Unsolicited), "asked until 50, answered at 50");
    assert_eq!(t.lookup(REMOTE_IP, 50), None);
}

#[test]
fn senders_that_must_not_be_learned() {
    let mut t: NeighborTable<8> = NeighborTable::new();
    // Someone claims our own address (RFC 5227 conflict): never learned.
    assert_eq!(t.on_arp(&reply(OTHER_MAC, LOCAL_IP, LOCAL_MAC, LOCAL_IP), LOCAL_IP, 0, 100), Learn::Ignored(Ignored::OwnAddress));
    // Group or zero sender MAC, unspecified/broadcast/multicast sender IP,
    // even for an address we asked about.
    t.request(REMOTE_IP, 0, 100).expect("ask");
    for p in [
        reply(MacAddress::BROADCAST, REMOTE_IP, LOCAL_MAC, LOCAL_IP),
        reply(MacAddress([0; 6]), REMOTE_IP, LOCAL_MAC, LOCAL_IP),
        reply(REMOTE_MAC, Ipv4Address([0, 0, 0, 0]), LOCAL_MAC, LOCAL_IP), // an RFC 5227 probe shape
        reply(REMOTE_MAC, Ipv4Address::BROADCAST, LOCAL_MAC, LOCAL_IP),
        reply(REMOTE_MAC, Ipv4Address([224, 0, 0, 1]), LOCAL_MAC, LOCAL_IP),
    ] {
        assert_eq!(t.on_arp(&p, LOCAL_IP, 0, 100), Learn::Ignored(Ignored::InvalidSender), "{p:?}");
    }
    assert_eq!(t.lookup(REMOTE_IP, 0), None);
    // Nor may we ask about such addresses.
    for bad in [Ipv4Address([0, 0, 0, 0]), Ipv4Address::BROADCAST, Ipv4Address([224, 0, 0, 1])] {
        assert_eq!(t.request(bad, 0, 100), Err(NeighborError::InvalidAddress));
    }
}

#[test]
fn a_full_table_reuses_only_dead_slots() {
    let mut t: NeighborTable<1> = NeighborTable::new();
    t.request(REMOTE_IP, 0, 10).expect("ask");
    assert_eq!(t.on_arp(&reply(REMOTE_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP), LOCAL_IP, 5, 100), Learn::Resolved);
    // The resolved entry is live: no room for another question.
    assert_eq!(t.request(OTHER_IP, 10, 20), Err(NeighborError::TableFull));
    assert_eq!(t.lookup(REMOTE_IP, 10), Some(REMOTE_MAC));
    // Once it expires its slot is reused.
    t.request(OTHER_IP, 100, 120).expect("slot reused");
    assert_eq!(t.lookup(REMOTE_IP, 100), None);
    // An unanswered question also holds the slot only until it lapses.
    assert_eq!(t.request(REMOTE_IP, 110, 130), Err(NeighborError::TableFull));
    t.request(REMOTE_IP, 120, 140).expect("lapsed question freed");
}

#[test]
fn pinning_rules() {
    let mut t: NeighborTable<1> = NeighborTable::new();
    assert_eq!(t.pin(REMOTE_IP, MacAddress::BROADCAST), Err(NeighborError::InvalidAddress));
    assert_eq!(t.pin(Ipv4Address([0, 0, 0, 0]), REMOTE_MAC), Err(NeighborError::InvalidAddress));

    // A pin replaces a resolved entry for the same address.
    t.request(REMOTE_IP, 0, 10).expect("ask");
    t.on_arp(&reply(OTHER_MAC, REMOTE_IP, LOCAL_MAC, LOCAL_IP), LOCAL_IP, 0, 100);
    t.pin(REMOTE_IP, REMOTE_MAC).expect("pin over resolved");
    assert_eq!(t.lookup(REMOTE_IP, 0), Some(REMOTE_MAC));
    assert_eq!(t.len(), 1);

    // A pinned entry is never evicted; another pin or a question into a
    // full table fails.
    assert_eq!(t.pin(OTHER_IP, OTHER_MAC), Err(NeighborError::TableFull));
    assert_eq!(t.request(OTHER_IP, 1_000_000, 2_000_000), Err(NeighborError::TableFull));
    // Re-pinning the same address to a new MAC is the operator's right.
    t.pin(REMOTE_IP, OTHER_MAC).expect("re-pin");
    assert_eq!(t.lookup(REMOTE_IP, 0), Some(OTHER_MAC));
}
