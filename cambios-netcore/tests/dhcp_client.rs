// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The DHCPv4 client state machine (RFC 2131; spec "DHCP client state"
//! table, B-16, INV-net-016, AT-net-014), written before `dhcp` existed.
//! Pure: time, transaction ids and retransmission jitter are inputs.
//! Replays NET-V-120, 121 and 123 (NET-V-122 is DHCPv6: not covered).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use cambios_netcore::dhcp::{ClientConfig, ClientState, DhcpClient, Ignored, Lease, Output};
use cambios_netcore::wire::dhcpv4::{BootOp, DhcpMessage, MessageType};
use cambios_netcore::{Ipv4Address, MacAddress};

const MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);
const SERVER: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
const ADDR: Ipv4Address = Ipv4Address([192, 0, 2, 10]);
const XID: u32 = 0xA1B2_C3D4;
const IFACE: u8 = 1;

fn cfg(pinned: Option<Ipv4Address>) -> ClientConfig {
    ClientConfig { interface: IFACE, mac: MAC, pinned, first_retry_ms: 4_000, max_attempts: 3 }
}

fn reply(t: MessageType, xid: u32) -> DhcpMessage {
    DhcpMessage {
        op: BootOp::Reply,
        xid,
        secs: 0,
        broadcast: false,
        ciaddr: Ipv4Address([0; 4]),
        yiaddr: ADDR,
        siaddr: Ipv4Address([0; 4]),
        chaddr: MAC,
        message_type: t,
        server_id: Some(SERVER),
        subnet_mask: Some(Ipv4Address([255, 255, 255, 0])),
        router: Some(SERVER),
        lease_secs: Some(3_600),
        requested_ip: None,
        renewal_secs: None,
        rebinding_secs: None,
    }
}

/// DISCOVER at 0, OFFER and ACK at 100: Bound.
fn bound(c: &mut DhcpClient) -> Lease {
    c.start(0, XID, 0);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 50);
    match c.on_message(IFACE, &reply(MessageType::Ack, XID), 100) {
        Output::LeaseAcquired(l) => l,
        other => panic!("{other:?}"),
    }
}

#[test]
fn discover_offer_request_ack() {
    let mut c = DhcpClient::new(cfg(None));
    assert_eq!(c.state(), ClientState::Stopped);
    let Output::Send(d) = c.start(0, XID, 0) else { panic!() };
    assert_eq!((d.message_type, d.xid, d.chaddr, d.broadcast), (MessageType::Discover, XID, MAC, true));
    assert_eq!(c.state(), ClientState::Selecting);
    assert_eq!(c.deadline(), Some(4_000));

    let Output::Send(r) = c.on_message(IFACE, &reply(MessageType::Offer, XID), 50) else { panic!() };
    assert_eq!((r.message_type, r.xid, r.requested_ip, r.server_id), (MessageType::Request, XID, Some(ADDR), Some(SERVER)));
    assert_eq!(c.state(), ClientState::Requesting);

    let Output::LeaseAcquired(l) = c.on_message(IFACE, &reply(MessageType::Ack, XID), 100) else { panic!() };
    assert_eq!((l.address, l.mask, l.router, l.server), (ADDR, Ipv4Address([255, 255, 255, 0]), Some(SERVER), SERVER));
    assert_eq!(l.expires_at_ms, 100 + 3_600_000);
    assert_eq!(c.state(), ClientState::Bound);
    assert_eq!(c.lease(), Some(l));
    assert_eq!(c.deadline(), Some(100 + 1_800_000), "T1 defaults to half the lease (RFC 2131 § 4.4.5)");
}

#[test]
fn net_v_120_a_reply_for_another_interface_changes_nothing() {
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 0);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 50);
    assert_eq!(c.on_message(2, &reply(MessageType::Ack, XID), 100), Output::Ignored(Ignored::WrongInterface));
    assert_eq!((c.state(), c.lease()), (ClientState::Requesting, None));
}

#[test]
fn net_v_121_an_operator_pin_is_never_overridden() {
    let pinned = Ipv4Address([192, 0, 2, 20]);
    let mut c = DhcpClient::new(cfg(Some(pinned)));
    c.start(0, XID, 0);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 50);
    assert_eq!(c.on_message(IFACE, &reply(MessageType::Ack, XID), 100), Output::Ignored(Ignored::OperatorPin));
    assert_eq!(c.lease(), None);
    assert_ne!(c.state(), ClientState::Bound);
}

#[test]
fn net_v_123_a_reply_for_another_transaction_changes_nothing() {
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 0);
    assert_eq!(c.on_message(IFACE, &reply(MessageType::Offer, 0x0102_0304), 50), Output::Ignored(Ignored::WrongTransaction));
    assert_eq!(c.state(), ClientState::Selecting);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 60);
    assert_eq!(c.on_message(IFACE, &reply(MessageType::Ack, 0x0102_0304), 100), Output::Ignored(Ignored::WrongTransaction));
    assert_eq!((c.state(), c.lease()), (ClientState::Requesting, None));
}

#[test]
fn replies_that_are_not_usable_are_ignored() {
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 0);
    // An ACK while selecting is not what was asked for.
    assert_eq!(c.on_message(IFACE, &reply(MessageType::Ack, XID), 10), Output::Ignored(Ignored::Unexpected));
    // An offer of no address, or without a server identifier.
    let mut zero = reply(MessageType::Offer, XID);
    zero.yiaddr = Ipv4Address([0; 4]);
    assert_eq!(c.on_message(IFACE, &zero, 20), Output::Ignored(Ignored::Invalid));
    let mut anon = reply(MessageType::Offer, XID);
    anon.server_id = None;
    assert_eq!(c.on_message(IFACE, &anon, 30), Output::Ignored(Ignored::Invalid));
    // A reply addressed to another hardware address.
    let mut other = reply(MessageType::Offer, XID);
    other.chaddr = MacAddress([2, 0, 0, 0, 0, 9]);
    assert_eq!(c.on_message(IFACE, &other, 40), Output::Ignored(Ignored::WrongTransaction));
    // A BOOTREQUEST is never a reply.
    let mut req = reply(MessageType::Offer, XID);
    req.op = BootOp::Request;
    assert_eq!(c.on_message(IFACE, &req, 50), Output::Ignored(Ignored::Unexpected));
    assert_eq!(c.state(), ClientState::Selecting);
}

#[test]
fn retransmission_backs_off_with_jitter_then_gives_up() {
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 250);
    assert_eq!(c.deadline(), Some(4_250), "4 s plus the caller's jitter");
    assert_eq!(c.tick(4_249, 7, 0), Output::Nothing);
    let Output::Send(d) = c.tick(4_250, 7, -300) else { panic!() };
    assert_eq!((d.message_type, d.xid), (MessageType::Discover, XID), "a retransmission keeps its xid");
    assert_eq!(c.deadline(), Some(4_250 + 8_000 - 300), "8 s, jittered");
    let t = c.deadline().unwrap();
    assert!(matches!(c.tick(t, 7, 0), Output::Send(_)));
    let t = c.deadline().unwrap();
    assert_eq!(c.tick(t, 7, 0), Output::Failed, "three attempts made");
    assert_eq!((c.state(), c.deadline()), (ClientState::Stopped, None));
}

#[test]
fn a_nak_restarts_selection_with_a_fresh_transaction() {
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 0);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 50);
    assert_eq!(c.on_message(IFACE, &reply(MessageType::Nak, XID), 60), Output::Nothing);
    assert_eq!((c.state(), c.deadline()), (ClientState::Selecting, Some(60)));
    let Output::Send(d) = c.tick(60, 0x5555, 0) else { panic!() };
    assert_eq!((d.message_type, d.xid), (MessageType::Discover, 0x5555));
}

#[test]
fn renewal_then_expiry() {
    let mut c = DhcpClient::new(cfg(None));
    let l = bound(&mut c);
    let t1 = c.deadline().unwrap();
    let Output::Send(r) = c.tick(t1, 0x7777, 0) else { panic!() };
    assert_eq!((r.message_type, r.xid, r.ciaddr, r.broadcast), (MessageType::Request, 0x7777, ADDR, false));
    assert_eq!(c.state(), ClientState::Renewing);
    let mut ack = reply(MessageType::Ack, 0x7777);
    ack.lease_secs = Some(7_200);
    let Output::LeaseAcquired(renewed) = c.on_message(IFACE, &ack, t1 + 10) else { panic!() };
    assert_eq!(renewed.expires_at_ms, t1 + 10 + 7_200_000);
    assert_eq!(c.state(), ClientState::Bound);

    // A renewal that is never answered: the lease runs out.
    let mut c = DhcpClient::new(cfg(None));
    let l2 = bound(&mut c);
    assert_eq!(l2, l);
    let mut now = c.deadline().unwrap();
    let mut out = c.tick(now, 0x8888, 0);
    while out != Output::LeaseLost {
        assert!(matches!(out, Output::Send(_) | Output::Nothing), "{out:?}");
        now = c.deadline().unwrap().min(l.expires_at_ms);
        out = c.tick(now, 0x8888, 0);
    }
    assert!(now >= l.expires_at_ms);
    assert_eq!((c.state(), c.lease()), (ClientState::Selecting, None));
}

#[test]
fn stop_drops_the_lease() {
    let mut c = DhcpClient::new(cfg(None));
    bound(&mut c);
    assert_eq!(c.stop(), Output::LeaseLost);
    assert_eq!((c.state(), c.lease(), c.deadline()), (ClientState::Stopped, None, None));
    assert_eq!(c.stop(), Output::Nothing);
}

/// codex 2026-11-12 (RFC 2131 § 4.3.1-4.3.2): only the selected server
/// commits the requested binding. Written before the check existed.
#[test]
fn an_ack_or_nak_from_another_server_or_for_another_address_changes_nothing() {
    const ROGUE: Ipv4Address = Ipv4Address([192, 0, 2, 66]);
    let mut c = DhcpClient::new(cfg(None));
    c.start(0, XID, 0);
    c.on_message(IFACE, &reply(MessageType::Offer, XID), 50);
    assert_eq!(c.state(), ClientState::Requesting);
    let mut rogue = reply(MessageType::Ack, XID);
    rogue.server_id = Some(ROGUE);
    assert_eq!(c.on_message(IFACE, &rogue, 60), Output::Ignored(Ignored::NotSelected));
    let mut other_addr = reply(MessageType::Ack, XID);
    other_addr.yiaddr = Ipv4Address([192, 0, 2, 99]);
    assert_eq!(c.on_message(IFACE, &other_addr, 61), Output::Ignored(Ignored::NotSelected));
    let mut rogue_nak = reply(MessageType::Nak, XID);
    rogue_nak.server_id = Some(ROGUE);
    assert_eq!(c.on_message(IFACE, &rogue_nak, 63), Output::Ignored(Ignored::NotSelected));
    assert_eq!((c.state(), c.lease()), (ClientState::Requesting, None), "still waiting for the selected server");
    // RFC 2131 Table 3: an ACK or NAK without a server identifier is not
    // the selected server's.
    let mut anon = reply(MessageType::Ack, XID);
    anon.server_id = None;
    assert_eq!(c.on_message(IFACE, &anon, 64), Output::Ignored(Ignored::NotSelected));
    let mut anon_nak = reply(MessageType::Nak, XID);
    anon_nak.server_id = None;
    assert_eq!(c.on_message(IFACE, &anon_nak, 65), Output::Ignored(Ignored::NotSelected));
    assert_eq!(c.state(), ClientState::Requesting);
    // The selected server's ACK binds.
    let Output::LeaseAcquired(l) = c.on_message(IFACE, &reply(MessageType::Ack, XID), 70) else { panic!() };
    assert_eq!((l.address, l.server), (ADDR, SERVER));

    // Renewing: the lease's server and address only.
    let t1 = c.deadline().unwrap();
    c.tick(t1, 0x7777, 0);
    assert_eq!(c.state(), ClientState::Renewing);
    let mut rogue = reply(MessageType::Ack, 0x7777);
    rogue.server_id = Some(ROGUE);
    assert_eq!(c.on_message(IFACE, &rogue, t1 + 1), Output::Ignored(Ignored::NotSelected));
    let mut moved = reply(MessageType::Ack, 0x7777);
    moved.yiaddr = Ipv4Address([192, 0, 2, 99]);
    assert_eq!(c.on_message(IFACE, &moved, t1 + 2), Output::Ignored(Ignored::NotSelected));
    let mut rogue_nak = reply(MessageType::Nak, 0x7777);
    rogue_nak.server_id = Some(ROGUE);
    assert_eq!(c.on_message(IFACE, &rogue_nak, t1 + 3), Output::Ignored(Ignored::NotSelected), "a forged NAK cannot drop the lease");
    assert_eq!((c.state(), c.lease()), (ClientState::Renewing, Some(l)));
    let Output::LeaseAcquired(_) = c.on_message(IFACE, &reply(MessageType::Ack, 0x7777), t1 + 4) else { panic!() };
    assert_eq!(c.state(), ClientState::Bound);
}
