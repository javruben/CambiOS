// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! DHCPv4 message parse and emit (RFC 2131 § 2 fixed header, RFC 2132
//! options; spec § 4 "DHCPv4 fixed header / options"), written before
//! `wire::dhcpv4` existed. Wire format only: no client state machine.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use cambios_netcore::wire::dhcpv4::{self, BootOp, DhcpRepr, MessageType, FIXED_LEN, MAGIC_COOKIE};
use cambios_netcore::{Ipv4Address, MacAddress, NetError, ParseError};

const MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);
const SERVER: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
const OFFERED: Ipv4Address = Ipv4Address([192, 0, 2, 10]);

fn discover() -> DhcpRepr {
    DhcpRepr {
        op: BootOp::Request,
        message_type: MessageType::Discover,
        xid: 0xA1B2_C3D4,
        secs: 0,
        broadcast: true,
        ciaddr: Ipv4Address([0; 4]),
        yiaddr: Ipv4Address([0; 4]),
        chaddr: MAC,
        requested_ip: None,
        server_id: None,
        subnet_mask: None,
        router: None,
        lease_secs: None,
    }
}

/// A server reply built by hand from RFC 2131 Figure 1, independently of
/// the emitter: op 2, Ethernet, xid, yiaddr, chaddr, cookie, options.
fn hand_offer(options: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; FIXED_LEN];
    m[0] = 2; // BOOTREPLY
    m[1] = 1; // htype Ethernet
    m[2] = 6; // hlen
    m[4..8].copy_from_slice(&0xA1B2_C3D4u32.to_be_bytes());
    m[16..20].copy_from_slice(&OFFERED.0); // yiaddr
    m[28..34].copy_from_slice(&MAC.0); // chaddr
    m.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    m.extend_from_slice(options);
    m
}

#[test]
fn layout_constants() {
    assert_eq!(FIXED_LEN, 236);
    assert_eq!(MAGIC_COOKIE, [99, 130, 83, 99]);
}

#[test]
fn a_hand_built_offer_parses() {
    #[rustfmt::skip]
    let opts = [
        53, 1, 2,                    // DHCPOFFER
        54, 4, 192, 0, 2, 1,         // server identifier
        1, 4, 255, 255, 255, 0,      // subnet mask
        3, 8, 192, 0, 2, 1, 192, 0, 2, 2, // routers: the first is used
        51, 4, 0, 0, 0x0E, 0x10,     // lease 3600 s
        0, 0,                        // pads
        255,                         // end
    ];
    let m = dhcpv4::parse(&hand_offer(&opts)).expect("offer");
    assert_eq!((m.op, m.message_type, m.xid), (BootOp::Reply, MessageType::Offer, 0xA1B2_C3D4));
    assert_eq!((m.yiaddr, m.chaddr), (OFFERED, MAC));
    assert_eq!(m.server_id, Some(SERVER));
    assert_eq!(m.subnet_mask, Some(Ipv4Address([255, 255, 255, 0])));
    assert_eq!(m.router, Some(SERVER));
    assert_eq!(m.lease_secs, Some(3600));
}

#[test]
fn emitted_messages_round_trip() {
    let mut out = [0u8; 400];
    let n = dhcpv4::emit(&discover(), &mut out).expect("emit");
    assert!(n >= FIXED_LEN + 4);
    assert_eq!(out[0], 1, "BOOTREQUEST");
    assert_eq!(&out[10..12], &[0x80, 0], "broadcast flag");
    assert_eq!(&out[FIXED_LEN..FIXED_LEN + 4], &MAGIC_COOKIE);
    let m = dhcpv4::parse(&out[..n]).expect("parses");
    assert_eq!((m.op, m.message_type, m.xid, m.broadcast, m.chaddr), (BootOp::Request, MessageType::Discover, 0xA1B2_C3D4, true, MAC));

    let request = DhcpRepr { message_type: MessageType::Request, requested_ip: Some(OFFERED), server_id: Some(SERVER), ..discover() };
    let n = dhcpv4::emit(&request, &mut out).expect("emit");
    let m = dhcpv4::parse(&out[..n]).expect("parses");
    assert_eq!((m.message_type, m.requested_ip, m.server_id), (MessageType::Request, Some(OFFERED), Some(SERVER)));

    let mut small = [0u8; FIXED_LEN];
    assert!(dhcpv4::emit(&discover(), &mut small).is_err());
}

#[test]
fn refusals() {
    let good = hand_offer(&[53, 1, 2, 255]);
    assert!(dhcpv4::parse(&good).is_ok());

    assert_eq!(dhcpv4::parse(&good[..FIXED_LEN + 3]), Err(ParseError::DhcpTooShort));

    let mut op = good.clone();
    op[0] = 3;
    assert_eq!(dhcpv4::parse(&op), Err(ParseError::DhcpOp));

    for (at, v) in [(1usize, 6u8), (2, 8)] {
        let mut hw = good.clone();
        hw[at] = v;
        let err = dhcpv4::parse(&hw).expect_err("not Ethernet");
        assert_eq!(err, ParseError::DhcpUnsupported);
        assert_eq!(err.net_error(), NetError::Unsupported);
    }

    let mut cookie = good.clone();
    cookie[FIXED_LEN] = 0;
    assert_eq!(dhcpv4::parse(&cookie), Err(ParseError::DhcpCookie));

    // An option whose length runs past the message.
    assert_eq!(dhcpv4::parse(&hand_offer(&[53, 1, 2, 51, 4, 0, 0])), Err(ParseError::DhcpOptionLength));
    // Known options with the wrong length.
    for bad in [&[53u8, 2, 2, 0, 255][..], &[53, 1, 2, 54, 3, 1, 2, 3, 255], &[53, 1, 2, 3, 6, 1, 2, 3, 4, 5, 6, 255]] {
        assert_eq!(dhcpv4::parse(&hand_offer(bad)), Err(ParseError::DhcpOptionLength), "{bad:?}");
    }
    // No message type, or an unknown one.
    assert_eq!(dhcpv4::parse(&hand_offer(&[255])), Err(ParseError::DhcpMessageType));
    assert_eq!(dhcpv4::parse(&hand_offer(&[53, 1, 99, 255])), Err(ParseError::DhcpMessageType));
    // Option overload (52) moves options into sname/file: not parsed.
    assert_eq!(dhcpv4::parse(&hand_offer(&[53, 1, 2, 52, 1, 3, 255])), Err(ParseError::DhcpUnsupported));
    // Unknown options are skipped by length; a missing END at the end of
    // the message is accepted.
    assert!(dhcpv4::parse(&hand_offer(&[53, 1, 2, 200, 2, 9, 9])).is_ok());
    assert_eq!(ParseError::DhcpOptionLength.net_error(), NetError::Malformed);
}
