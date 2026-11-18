// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! UDP over IPv4 (RFC 768; spec INV-net-006, B-11), written before
//! `wire::udp` existed. Replays NET-V-040, 041, 043 and 044 from
//! `spec/vectors/net/udp.json`. NET-V-042 (IPv6 zero checksum) is not
//! replayed: no IPv6 behaviour exists.
//!
//! The vectors' `endpoint_permitted` and `socket_events` are engine
//! expectations, covered through the engine in `tests/step.rs`;
//! these tests show the parser's part.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::wire::frame::{self, Classified, Ipv4Route};
use cambios_netcore::wire::udp::{self, UdpRepr, HEADER_LEN};
use cambios_netcore::{NetError, ParseError};
use common::*;
use serde_json::Value;

fn vector(id: &str) -> Value {
    let path = format!("{}/../spec/vectors/net/udp.json", env!("CARGO_MANIFEST_DIR"));
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
    doc["cases"].as_array().expect("cases").iter().find(|c| c["id"] == id).expect("case").clone()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn n(v: &Value) -> u16 {
    u16::try_from(v.as_u64().expect("number")).expect("u16")
}

/// A UDP datagram 40000 → 7 with the given length field and checksum
/// field, padded or cut to `available` octets.
fn raw(udp_length: u16, checksum: u16, payload: &[u8], available: usize) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&40000u16.to_be_bytes());
    b.extend_from_slice(&7u16.to_be_bytes());
    b.extend_from_slice(&udp_length.to_be_bytes());
    b.extend_from_slice(&checksum.to_be_bytes());
    b.extend_from_slice(payload);
    b.resize(available, 0);
    b
}

#[test]
fn net_v_040_ipv4_zero_checksum_is_accepted() {
    let case = vector("NET-V-040");
    let i = &case["input"];
    assert_eq!(i["family"], "ipv4");
    assert_eq!(n(&i["checksum"]), 0);
    let payload = hex(case["expect"]["payload_hex"].as_str().expect("hex"));
    let bytes = raw(n(&i["udp_length"]), 0, &payload, usize::from(n(&i["available_transport_bytes"])));
    let d = udp::parse_ipv4(&bytes, REMOTE_IP, LOCAL_IP).expect("delivered");
    assert_eq!(d.payload, &payload[..]);
    assert!(!d.checksum_present, "RFC 768: zero means no checksum was computed");
    assert_eq!((d.source_port, d.destination_port), (40000, 7));
}

#[test]
fn net_v_041_length_beyond_the_packet_is_malformed() {
    let case = vector("NET-V-041");
    let i = &case["input"];
    let bytes = raw(n(&i["udp_length"]), 0, b"test", usize::from(n(&i["available_transport_bytes"])));
    let err = udp::parse_ipv4(&bytes, REMOTE_IP, LOCAL_IP).expect_err("refused");
    assert_eq!(err, ParseError::UdpLengthExceedsPacket);
    assert_eq!(case["expect"]["reason"], "udp_length_exceeds_packet");
    assert_eq!(format!("{:?}", err.net_error()), case["expect"]["result"].as_str().expect("result"));
}

#[test]
fn net_v_043_invalid_checksum_is_malformed() {
    let case = vector("NET-V-043");
    assert_eq!(case["input"]["checksum"], "nonzero-invalid");
    let mut out = [0u8; 64];
    let len = udp::emit_ipv4(&UdpRepr { source_port: 40000, destination_port: 7 }, b"test", REMOTE_IP, LOCAL_IP, &mut out)
        .expect("emit");
    assert_eq!(len, 12);
    let mut bytes = out[..len].to_vec();
    bytes[6] ^= 0x01; // still nonzero, no longer valid
    assert_ne!(u16::from_be_bytes([bytes[6], bytes[7]]), 0);
    let err = udp::parse_ipv4(&bytes, REMOTE_IP, LOCAL_IP).expect_err("refused");
    assert_eq!(err, ParseError::UdpChecksum);
    assert_eq!(case["expect"]["reason"], "udp_checksum");
    assert_eq!(err.net_error(), NetError::Malformed);
    assert!(err.is_checksum(), "counted with the other checksum failures");
}

#[test]
fn net_v_044_known_answer_checksum() {
    let case = vector("NET-V-044");
    let i = &case["input"];
    assert_eq!((i["source"].as_str(), i["destination"].as_str()), (Some("192.0.2.1"), Some("192.0.2.2")));
    assert_eq!((n(&i["source_port"]), n(&i["destination_port"])), (40000, 7));
    let payload = hex(i["payload_hex"].as_str().expect("hex"));
    let mut out = [0u8; 64];
    let len = udp::emit_ipv4(&UdpRepr { source_port: 40000, destination_port: 7 }, &payload, REMOTE_IP, LOCAL_IP, &mut out)
        .expect("emit");
    assert_eq!(len, usize::from(n(&i["udp_length"])));
    // Worked by hand, independently of the crate (RFC 1071 sum):
    // c000+0201+c000+0202 (addresses) + 0011 (protocol) + 000c (length)
    // + 9c40+0007+000c+0000 (header) + 7465+7374 (payload) = 0x3084c;
    // fold 0x084c + 0x3 = 0x084f; complement 0xf7b0.
    assert_eq!(&out[..8], &[0x9c, 0x40, 0x00, 0x07, 0x00, 0x0c, 0xf7, 0xb0]);
    let d = udp::parse_ipv4(&out[..len], REMOTE_IP, LOCAL_IP).expect("delivered");
    assert_eq!(d.payload, &hex(case["expect"]["payload_hex"].as_str().expect("hex"))[..]);
    assert!(d.checksum_present);
}

#[test]
fn a_computed_zero_checksum_is_sent_as_all_ones() {
    // Payload chosen so the one's-complement sum is 0xffff: the computed
    // checksum is 0, which RFC 768 transmits as 0xffff (0 means "none").
    // Sum without payload, by hand: c000+0201+c000+0202+0011+000a
    // + 9c40+0007+000a+0000 = 0x2206f, folded 0x2071; 0x2071 + 0xdf8e = 0xffff.
    let mut out = [0u8; 64];
    let len = udp::emit_ipv4(&UdpRepr { source_port: 40000, destination_port: 7 }, &[0xdf, 0x8e], REMOTE_IP, LOCAL_IP, &mut out)
        .expect("emit");
    assert_eq!(len, 10);
    assert_eq!(&out[6..8], &[0xff, 0xff]);
    let d = udp::parse_ipv4(&out[..len], REMOTE_IP, LOCAL_IP).expect("all-ones verifies");
    assert!(d.checksum_present);
}

#[test]
fn length_field_partitions() {
    assert_eq!(udp::parse_ipv4(&[0u8; 7], REMOTE_IP, LOCAL_IP), Err(ParseError::UdpTooShort));
    for bad in [0u16, 1, 7] {
        let bytes = raw(bad, 0, &[], 8);
        assert_eq!(udp::parse_ipv4(&bytes, REMOTE_IP, LOCAL_IP), Err(ParseError::UdpLength), "length {bad}");
    }
    // Header only: an empty datagram is valid.
    let empty = raw(8, 0, &[], 8);
    let d = udp::parse_ipv4(&empty, REMOTE_IP, LOCAL_IP).expect("empty");
    assert!(d.payload.is_empty());
    // Octets past the length field are not payload (RFC 768: the length
    // field governs; IPv4 already cut link padding).
    let short = raw(10, 0, b"abcd", 12);
    let d = udp::parse_ipv4(&short, REMOTE_IP, LOCAL_IP).expect("short length");
    assert_eq!(d.payload, b"ab");
    assert_eq!(HEADER_LEN, 8);
}

#[test]
fn emit_refuses_what_does_not_fit() {
    let repr = UdpRepr { source_port: 1, destination_port: 2 };
    let mut small = [0u8; 9];
    assert!(udp::emit_ipv4(&repr, b"ab", REMOTE_IP, LOCAL_IP, &mut small).is_err());
    let big = vec![0u8; 65536 - 8]; // length field would be 65536
    let mut out = vec![0u8; 70000];
    assert!(udp::emit_ipv4(&repr, &big, REMOTE_IP, LOCAL_IP, &mut out).is_err());
}

fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let route = Ipv4Route { source_mac: REMOTE_MAC, destination_mac: LOCAL_MAC, source: REMOTE_IP, destination: LOCAL_IP, ttl: TTL };
    let mut out = vec![0u8; 1514];
    let len = frame::emit_ipv4_udp(&route, &UdpRepr { source_port: 40000, destination_port: 7 }, payload, &mut out).expect("emit");
    out.truncate(len);
    out
}

#[test]
fn whole_frames_classify_as_ipv4_udp() {
    let f = udp_frame(b"hello");
    assert_eq!(f.len(), 14 + 20 + 8 + 5);
    match frame::classify(&f, MTU).expect("classify") {
        Classified::Ipv4Udp { ip, datagram, .. } => {
            assert_eq!((ip.source, ip.destination), (REMOTE_IP, LOCAL_IP));
            assert_eq!(datagram.payload, b"hello");
            assert_eq!(datagram.destination_port, 7);
        }
        other => panic!("not UDP: {other:?}"),
    }
    let mut bad = f.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(frame::classify(&bad, MTU), Err(ParseError::UdpChecksum));
}
