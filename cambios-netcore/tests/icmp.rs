// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ICMPv4 message parse and echo emit (RFC 792; spec § 4 ICMP rows),
//! written before `wire::icmpv4` existed. Wire format only: no engine
//! behaviour (echo replies, error handling) is implied or tested here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use cambios_netcore::wire::icmpv4::{self, Echo, EchoKind, Icmpv4Message, HEADER_LEN};
use cambios_netcore::{NetError, ParseError};

#[test]
fn known_answer_echo_request() {
    let mut out = [0xAAu8; 32];
    let echo = Echo { kind: EchoKind::Request, identifier: 0x1234, sequence: 1 };
    let n = icmpv4::emit_echo(&echo, b"abcd", &mut out).expect("emit");
    assert_eq!(n, 12);
    // By hand: 0800 + 1234 + 0001 + 6162 + 6364 = 0xdefb; complement 0x2104.
    assert_eq!(&out[..12], &[0x08, 0x00, 0x21, 0x04, 0x12, 0x34, 0x00, 0x01, b'a', b'b', b'c', b'd']);
    assert_eq!(out[12], 0xAA, "nothing written past the message");
    match icmpv4::parse(&out[..n]).expect("parses") {
        Icmpv4Message::Echo { echo: e, data } => {
            assert_eq!(e, echo);
            assert_eq!(data, b"abcd");
        }
        other => panic!("not echo: {other:?}"),
    }
}

#[test]
fn odd_length_data_and_reply_kind() {
    let mut out = [0u8; 32];
    let echo = Echo { kind: EchoKind::Reply, identifier: 0x1234, sequence: 1 };
    let n = icmpv4::emit_echo(&echo, b"abc", &mut out).expect("emit");
    // By hand: 0000 + 1234 + 0001 + 6162 + 6300 (padded) = 0xd697; complement 0x2968.
    assert_eq!(&out[..4], &[0x00, 0x00, 0x29, 0x68]);
    assert!(matches!(icmpv4::parse(&out[..n]), Ok(Icmpv4Message::Echo { echo: Echo { kind: EchoKind::Reply, .. }, data: b"abc" })));
}

#[test]
fn refusals() {
    assert_eq!(HEADER_LEN, 8);
    assert_eq!(icmpv4::parse(&[0u8; 7]), Err(ParseError::IcmpTooShort));

    let mut good = [0u8; 12];
    icmpv4::emit_echo(&Echo { kind: EchoKind::Request, identifier: 7, sequence: 9 }, b"ping", &mut good).expect("emit");

    let mut bad = good;
    bad[11] ^= 0x01;
    let err = icmpv4::parse(&bad).expect_err("checksum");
    assert_eq!(err, ParseError::IcmpChecksum);
    assert!(err.is_checksum());
    assert_eq!(err.net_error(), NetError::Malformed);

    // Echo with a nonzero code: checksum valid, code invalid for the type.
    let mut code = good;
    code[1] = 1;
    code[2..4].copy_from_slice(&[0, 0]);
    let fixed = !fold(&code);
    code[2..4].copy_from_slice(&fixed.to_be_bytes());
    assert_eq!(icmpv4::parse(&code), Err(ParseError::IcmpCode));

    let mut tiny = [0u8; 11];
    assert!(icmpv4::emit_echo(&Echo { kind: EchoKind::Request, identifier: 1, sequence: 1 }, b"ping", &mut tiny).is_err());
}

#[test]
fn other_types_are_carried_not_interpreted() {
    // Destination unreachable (3), code 3 (port), 4 unused octets, then a
    // quoted prefix: well-formed, reported by type and code only.
    let mut m = vec![3u8, 3, 0, 0, 0, 0, 0, 0, 0x45, 0, 0, 28];
    let c = !fold(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    assert_eq!(icmpv4::parse(&m), Ok(Icmpv4Message::Other { message_type: 3, code: 3 }));
}

/// RFC 1071 one's-complement sum, written independently for the tests.
fn fold(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        let w = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(w);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}
