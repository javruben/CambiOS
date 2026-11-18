// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! codex D1: an accepted DHCP lease reconfigures the interface through
//! `Event::Interface`. Written before the engine handled the event (red
//! run on a stub that ignored it, then green).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::dhcp::Lease;
use cambios_netcore::engine::{
    Action, Control, ControlReply, Engine, EngineConfig, EngineError, Event, Instant, InterfaceConfig, IssKey, Notify, Op, Principal,
    Refusal, SocketId, SocketState, MAX_ACTIONS_PER_STEP,
};
use cambios_netcore::tcp::TcpState;
use cambios_netcore::wire::arp::{ArpOperation, ArpPacket};
use cambios_netcore::wire::frame::{self, Classified};
use cambios_netcore::wire::tcp::TcpFlags;
use cambios_netcore::{IpAddress, Ipv4Address, NetError, SocketAddress};
use common::*;

type Eng = Engine<'static, 4, 2, 8, 2>;

const BOB: Principal = Principal([0xB0; 32]);
const ALICE: Principal = Principal([0xA1; 32]);
const NEW_IP: Ipv4Address = Ipv4Address([198, 51, 100, 7]);
const NEW_GW: Ipv4Address = Ipv4Address([198, 51, 100, 1]);

fn tx_store(octets: usize) -> &'static mut [u8] {
    Box::leak(vec![0u8; octets].into_boxed_slice())
}

fn cfg() -> EngineConfig {
    EngineConfig {
        mac: LOCAL_MAC,
        ipv4: LOCAL_IP,
        prefix_len: 24,
        gateway: None,
        ttl: TTL,
        mtu: MTU,
        tcb: config(4096),
        iss_key: Some(IssKey([7; 16])),
        half_open_per_listener: 4,
        neighbor_ttl_ms: 60_000,
        arp_timeout_ms: 1_000,
        arp_attempts: 3,
        challenge_ack_interval_ms: 1_000,
        max_retransmits: 5,
        hold_per_socket: 0,
    }
}

fn engine() -> Eng {
    Engine::new(cfg(), tx_store(4 * 256)).expect("config")
}

struct Out {
    actions: Vec<Action>,
    frame: Option<Vec<u8>>,
}

impl Out {
    fn reply(&self) -> ControlReply {
        let r: Vec<ControlReply> = self.actions.iter().filter_map(|a| if let Action::Reply { msg, .. } = a { Some(*msg) } else { None }).collect();
        assert_eq!(r.len(), 1, "{:?}", self.actions);
        r[0]
    }
    fn notifies(&self) -> Vec<(SocketId, Notify)> {
        self.actions.iter().filter_map(|a| if let Action::Notify { socket, what } = a { Some((*socket, *what)) } else { None }).collect()
    }
    fn arm(&self) -> Option<Instant> {
        self.actions.iter().find_map(|a| if let Action::Arm(t) = a { Some(*t) } else { None })
    }
    fn arp(&self) -> ArpPacket {
        match frame::classify(self.frame.as_ref().expect("a frame"), MTU).expect("parses") {
            Classified::Arp { arp, .. } => arp,
            other => panic!("not ARP: {other:?}"),
        }
    }
    /// (IPv4 source, IPv4 destination, TCP flags) of the emitted frame.
    fn tcp_ip(&self) -> (Ipv4Address, Ipv4Address, TcpFlags) {
        match frame::classify(self.frame.as_ref().expect("a frame"), MTU).expect("parses") {
            Classified::Ipv4Tcp { ip, segment, .. } => (ip.source, ip.destination, segment.flags),
            other => panic!("not TCP: {other:?}"),
        }
    }
}

fn step<const S: usize, const L: usize, const N: usize, const U: usize>(e: &mut Engine<'_, S, L, N, U>, now: u64, ev: Event<'_>) -> Result<Out, EngineError> {
    let a = e.step(Instant(now), ev)?;
    let actions: Vec<Action> = a.iter().copied().collect();
    assert!(actions.len() <= MAX_ACTIONS_PER_STEP);
    let emits: Vec<u16> = actions.iter().filter_map(|x| if let Action::Emit { frame_len } = x { Some(*frame_len) } else { None }).collect();
    assert!(emits.len() <= 1);
    let frame = emits.first().map(|&n| a.tx_frame()[..usize::from(n)].to_vec());
    Ok(Out { actions, frame })
}

fn ctl<const S: usize, const L: usize, const N: usize, const U: usize>(e: &mut Engine<'_, S, L, N, U>, now: u64, from: Principal, op: Op<'_>) -> Out {
    step(e, now, Event::Control(Control { from, op })).expect("control is always answered")
}

fn iface(ipv4: Ipv4Address, prefix_len: u8, gateway: Option<Ipv4Address>) -> InterfaceConfig {
    InterfaceConfig { ipv4, prefix_len, gateway }
}

/// A passive connection from REMOTE, ESTABLISHED and accepted by BOB.
fn accepted(e: &mut Eng) -> SocketId {
    let ControlReply::Listener(l) = ctl(e, 0, BOB, Op::Listen { port: LOCAL_PORT }).reply() else { panic!("listen") };
    let syn_ack = step(e, 0, Event::Frame(&peer_frame(TcpFlags::SYN, 100, 0, 8192, &[]))).expect("syn");
    let iss = tcp_of(syn_ack.frame.as_ref().unwrap()).seq.0;
    step(e, 0, Event::Frame(&peer_frame(TcpFlags::ACK, 101, iss.wrapping_add(1), 8192, &[]))).expect("ack");
    let ControlReply::Accepted { socket, .. } = ctl(e, 0, BOB, Op::Accept { listener: l }).reply() else { panic!("accept") };
    assert_eq!(e.state(socket), Some(SocketState::Tcp(TcpState::Established)));
    socket
}

#[test]
fn a_new_address_is_the_source_of_new_opens() {
    let mut e = engine();
    let o = step(&mut e, 0, Event::Interface(iface(NEW_IP, 24, Some(NEW_GW)))).expect("valid lease");
    assert!(o.notifies().is_empty(), "no sockets yet: {:?}", o.actions);
    // REMOTE (192.0.2.1) is now off-link: resolution goes to the new
    // gateway, asked from the new address.
    let o = ctl(&mut e, 1, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    assert!(matches!(o.reply(), ControlReply::Socket(_)), "{:?}", o.actions);
    let who = o.arp();
    assert_eq!((who.operation, who.target_ip, who.sender_ip), (ArpOperation::Request, NEW_GW, NEW_IP));
    // Pinned gateway: the SYN goes out at once, from the new address.
    let mut e = engine();
    step(&mut e, 0, Event::Interface(iface(NEW_IP, 24, Some(NEW_GW)))).expect("valid lease");
    assert_eq!(ctl(&mut e, 0, BOB, Op::PinNeighbor { ip: NEW_GW, mac: REMOTE_MAC }).reply(), ControlReply::Done);
    let o = ctl(&mut e, 1, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    let (src, dst, flags) = o.tcp_ip();
    assert_eq!((src, dst), (NEW_IP, REMOTE_IP));
    assert!(flags.syn() && !flags.ack());
}

#[test]
fn an_address_change_retires_live_sockets_and_never_emits_their_tuple() {
    let mut e = engine();
    let id = accepted(&mut e);
    let o = step(&mut e, 5, Event::Interface(iface(NEW_IP, 24, Some(NEW_GW)))).expect("valid lease");
    assert_eq!(o.notifies(), vec![(id, Notify::Error(NetError::NoAddress))]);
    assert!(o.frame.is_none(), "no frame for a retired socket: {:?}", o.actions);
    assert_eq!(e.state(id), None, "the handle is stale");
    // A segment to the old address is no longer ours.
    let late = peer_frame(TcpFlags::ACK, 101, 1, 8192, b"x");
    assert_eq!(step(&mut e, 6, Event::Frame(&late)).err(), Some(EngineError::Refused(Refusal::NotForUs)));
    // Nothing is due for it later either.
    for t in [1_000u64, 10_000, 200_000] {
        let o = step(&mut e, t, Event::Tick(Instant(t))).expect("tick");
        assert!(o.frame.is_none() && o.notifies().is_empty(), "t={t}: {:?}", o.actions);
    }
}

#[test]
fn a_renewal_or_a_new_gateway_keeps_sockets() {
    let mut e = engine();
    let id = accepted(&mut e);
    let o = step(&mut e, 5, Event::Interface(iface(LOCAL_IP, 24, None))).expect("same lease");
    assert!(o.notifies().is_empty(), "{:?}", o.actions);
    let o = step(&mut e, 6, Event::Interface(iface(LOCAL_IP, 24, Some(Ipv4Address([192, 0, 2, 254]))))).expect("new gateway");
    assert!(o.notifies().is_empty(), "{:?}", o.actions);
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    // A prefix change alone moves the subnet: sockets go.
    let o = step(&mut e, 7, Event::Interface(iface(LOCAL_IP, 25, None))).expect("new prefix");
    assert_eq!(o.notifies(), vec![(id, Notify::Error(NetError::NoAddress))]);
}

#[test]
fn an_unusable_configuration_changes_nothing() {
    let bad = [
        iface(Ipv4Address([0, 0, 0, 0]), 24, None),
        iface(Ipv4Address([255, 255, 255, 255]), 24, None),
        iface(Ipv4Address([224, 0, 0, 1]), 24, None),
        iface(NEW_IP, 0, None),
        iface(NEW_IP, 33, None),
        iface(Ipv4Address([198, 51, 100, 0]), 24, None),   // network address
        iface(Ipv4Address([198, 51, 100, 255]), 24, None), // broadcast address
        iface(NEW_IP, 24, Some(NEW_IP)),                    // gateway is us
        iface(NEW_IP, 24, Some(Ipv4Address([203, 0, 113, 1]))), // off-link gateway
        iface(NEW_IP, 24, Some(Ipv4Address([198, 51, 100, 255]))), // broadcast gateway
        iface(NEW_IP, 32, Some(NEW_GW)),                    // /32 has no on-link gateway
    ];
    let mut e = engine();
    let id = accepted(&mut e);
    for (n, c) in bad.iter().enumerate() {
        assert!(!c.is_valid(), "case {n}: {c:?}");
        assert_eq!(step(&mut e, 5, Event::Interface(*c)).err(), Some(EngineError::Config), "case {n}");
    }
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
    let o = ctl(&mut e, 6, ALICE, Op::Connect { remote: remote(), local_port: 9 });
    assert_eq!(o.arp().sender_ip, LOCAL_IP, "the old address still answers");
    // /31 and /32 have no network/broadcast pair.
    assert!(iface(Ipv4Address([198, 51, 100, 0]), 31, Some(Ipv4Address([198, 51, 100, 1]))).is_valid());
    assert!(iface(NEW_IP, 32, None).is_valid());
}

#[test]
fn more_retired_sockets_than_one_step_holds_are_all_notified_later() {
    let mut e: Engine<'static, 12, 2, 16, 2> = Engine::new(cfg(), tx_store(12 * 256)).expect("config");
    let mut ids = Vec::new();
    for p in 0..12u16 {
        let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: 1000 + p });
        let ControlReply::Socket(id) = o.reply() else { panic!("{:?}", o.actions) };
        ids.push(id);
    }
    let o = step(&mut e, 1, Event::Interface(iface(NEW_IP, 24, None))).expect("valid lease");
    let mut seen = o.notifies();
    assert!(seen.len() < 12, "one step cannot hold 12 notices");
    assert_eq!(o.arm(), Some(Instant(1)), "re-tick at once while notices are owed");
    // A slot whose notice is owed is not reused: no handle is recycled
    // before its owner heard the old one died. Notices also go out on
    // control steps, so check the invariant at every open: successful
    // re-opens never outnumber notices delivered so far.
    let near = |n: u16| SocketAddress { address: IpAddress::V4(Ipv4Address([198, 51, 100, 9])), port: 80 + n };
    let mut reopened = Vec::new();
    let mut refused = false;
    for n in 0..20u16 {
        let o = ctl(&mut e, 1, ALICE, Op::Connect { remote: near(n), local_port: 3000 + n });
        seen.extend(o.notifies().into_iter().filter(|(s, _)| ids.contains(s)));
        match o.reply() {
            ControlReply::Socket(id) => reopened.push(id),
            ControlReply::Refused(NetError::ResourceLimit) => {
                refused = true;
                break;
            }
            other => panic!("{other:?}"),
        }
        assert!(reopened.len() <= uniq(seen.clone()).len(), "open {n} reused a slot whose notice was still owed");
    }
    assert!(refused, "12 slots: some open must be refused");
    for _ in 0..4 {
        let o = step(&mut e, 1, Event::Tick(Instant(1))).expect("tick");
        seen.extend(o.notifies().into_iter().filter(|(s, _)| ids.contains(s)));
    }
    let seen = uniq(seen);
    assert_eq!(seen.len(), 12, "{seen:?}");
    assert!(seen.iter().all(|(s, w)| ids.contains(s) && *w == Notify::Error(NetError::NoAddress)));
    // A second move while the reopened sockets' notices are owed is
    // accepted and loses none.
    let mut again = step(&mut e, 3, Event::Interface(iface(LOCAL_IP, 24, None))).expect("move").notifies();
    again.extend(step(&mut e, 3, Event::Interface(iface(NEW_IP, 24, None))).expect("accepted mid-drain").notifies());
    for _ in 0..4 {
        again.extend(step(&mut e, 3, Event::Tick(Instant(3))).expect("tick").notifies());
    }
    let again = uniq(again);
    assert_eq!(again.len(), reopened.len(), "every reopened socket heard exactly once: {again:?}");
    assert!(again.iter().all(|(s, w)| reopened.contains(s) && *w == Notify::Error(NetError::NoAddress)));
}

#[test]
fn a_lost_lease_stops_every_use_of_the_old_address() {
    let mut e = engine();
    let id = accepted(&mut e);
    let ControlReply::Endpoint(u) = ctl(&mut e, 0, ALICE, Op::UdpBind { port: 5000 }).reply() else { panic!("bind") };
    let o = step(&mut e, 5, Event::AddressLost).expect("never refused");
    assert_eq!(o.notifies(), vec![(id, Notify::Error(NetError::NoAddress))]);
    assert!(o.frame.is_none());
    assert_eq!(e.state(id), None);
    // Inbound to the old address: not ours. ARP for it: not answered.
    let late = peer_frame(TcpFlags::ACK, 101, 1, 8192, b"x");
    assert_eq!(step(&mut e, 6, Event::Frame(&late)).err(), Some(EngineError::Refused(Refusal::NotForUs)));
    let syn = peer_frame(TcpFlags::SYN, 500, 0, 8192, &[]);
    assert_eq!(step(&mut e, 6, Event::Frame(&syn)).err(), Some(EngineError::Refused(Refusal::NotForUs)), "listener gets nothing");
    let who = ArpPacket { operation: ArpOperation::Request, sender_mac: REMOTE_MAC, sender_ip: REMOTE_IP, target_mac: cambios_netcore::MacAddress([0; 6]), target_ip: LOCAL_IP };
    let o = step(&mut e, 6, Event::Frame(&arp_frame(&who))).expect("arp is consumed");
    assert!(o.frame.is_none(), "no ARP reply for an address we no longer hold");
    // Outbound: refused, nothing emitted.
    let o = ctl(&mut e, 7, ALICE, Op::Connect { remote: remote(), local_port: 9 });
    assert_eq!(o.reply(), ControlReply::Refused(NetError::NoAddress));
    assert!(o.frame.is_none());
    let o = ctl(&mut e, 7, ALICE, Op::UdpSend { endpoint: u, remote: remote(), payload: b"hi" });
    assert_eq!(o.reply(), ControlReply::Refused(NetError::NoAddress));
    assert!(o.frame.is_none());
    for t in [1_000u64, 60_000] {
        let o = step(&mut e, t, Event::Tick(Instant(t))).expect("tick");
        assert!(o.frame.is_none(), "t={t}: {:?}", o.actions);
    }
    // A fresh lease ends it: the new address is used.
    step(&mut e, 8, Event::Interface(iface(NEW_IP, 24, Some(NEW_GW)))).expect("new lease");
    let o = ctl(&mut e, 9, ALICE, Op::Connect { remote: remote(), local_port: 10 });
    assert!(matches!(o.reply(), ControlReply::Socket(_)), "{:?}", o.actions);
    assert_eq!(o.arp().sender_ip, NEW_IP);
}

/// Distinct entries, first-seen order (`SocketId` is not ordered).
fn uniq(v: Vec<(SocketId, Notify)>) -> Vec<(SocketId, Notify)> {
    let mut out: Vec<(SocketId, Notify)> = Vec::new();
    for x in v {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn arp_frame(p: &ArpPacket) -> Vec<u8> {
    use cambios_netcore::wire::{arp, ethernet};
    let mut f = vec![0u8; 14 + arp::PACKET_LEN];
    ethernet::emit_header(&mut f, cambios_netcore::MacAddress::BROADCAST, p.sender_mac, ethernet::EtherType::Arp).expect("header");
    arp::emit(p, &mut f[14..]).expect("arp");
    f
}

#[test]
fn a_lease_maps_to_an_interface_only_with_a_prefix_mask() {
    let lease = |mask: [u8; 4], router: Option<Ipv4Address>| Lease {
        address: NEW_IP,
        mask: Ipv4Address(mask),
        router,
        server: NEW_GW,
        bound_at_ms: 0,
        renew_at_ms: 1,
        expires_at_ms: 2,
    };
    assert_eq!(lease([255, 255, 255, 0], Some(NEW_GW)).interface(), Some(iface(NEW_IP, 24, Some(NEW_GW))));
    assert_eq!(lease([255, 255, 255, 255], None).interface(), Some(iface(NEW_IP, 32, None)));
    assert_eq!(lease([255, 0, 255, 0], Some(NEW_GW)).interface(), None, "non-contiguous mask");
    assert_eq!(lease([255, 255, 255, 0], Some(Ipv4Address([203, 0, 113, 1]))).interface(), None, "off-link router");
    assert_eq!(lease([0, 0, 0, 0], None).interface(), None, "prefix 0");
}
