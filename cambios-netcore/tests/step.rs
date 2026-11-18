// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The engine through its one entry point, `Engine::step(now, Event)`
//! (ADR-039 § 5.1), written before the step-shaped engine existed. These
//! supersede the earlier per-method engine tests (`engine.rs`,
//! `engine_udp.rs`, `engine_arp.rs`, preserved in the red snapshots),
//! which targeted an API that no longer exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use cambios_netcore::engine::{
    Action, Control, ControlReply, Engine, EngineConfig, EngineError, Event, Instant, IssKey, Notify, Op, Principal, Refusal, SocketId,
    SocketState, MAX_ACTIONS_PER_STEP, MSL_MS,
};
use cambios_netcore::siphash::siphash24;
use cambios_netcore::tcp::{SeqNum, TcpState};
use cambios_netcore::wire::arp::{self, ArpOperation, ArpPacket};
use cambios_netcore::wire::ethernet::{self, EtherType};
use cambios_netcore::wire::frame::{self, Classified, Ipv4Route};
use cambios_netcore::wire::tcp::{TcpFlags, TcpRepr, TcpSegment};
use cambios_netcore::wire::udp::UdpRepr;
use cambios_netcore::{IpAddress, Ipv4Address, Ipv6Address, MacAddress, NetError, SocketAddress};
use common::*;

type Eng = Engine<'static, 4, 2, 8, 2>;
/// Zeroed transmit storage for a test engine, leaked to live as long as
/// the test (`'static`).
fn tx_store(octets: usize) -> &'static mut [u8] {
    Box::leak(vec![0u8; octets].into_boxed_slice())
}


const ALICE: Principal = Principal([0xA1; 32]);
const BOB: Principal = Principal([0xB0; 32]);
const GATEWAY: Ipv4Address = Ipv4Address([192, 0, 2, 254]);

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
        let replies: Vec<ControlReply> =
            self.actions.iter().filter_map(|a| if let Action::Reply { msg, .. } = a { Some(*msg) } else { None }).collect();
        assert_eq!(replies.len(), 1, "exactly one reply: {:?}", self.actions);
        replies[0]
    }
    fn notifies(&self) -> Vec<(SocketId, Notify)> {
        self.actions.iter().filter_map(|a| if let Action::Notify { socket, what } = a { Some((*socket, *what)) } else { None }).collect()
    }
    fn arm(&self) -> Option<Instant> {
        self.actions.iter().find_map(|a| if let Action::Arm(t) = a { Some(*t) } else { None })
    }
    fn tcp(&self) -> TcpSegment<'_> {
        tcp_of(self.frame.as_ref().expect("a frame"))
    }
    fn arp(&self) -> (MacAddress, ArpPacket) {
        match frame::classify(self.frame.as_ref().expect("a frame"), MTU).expect("parses") {
            Classified::Arp { link, arp } => (link.destination, arp),
            other => panic!("not ARP: {other:?}"),
        }
    }
}

fn step<const S: usize, const L: usize, const N: usize, const U: usize>(
    e: &mut Engine<'_, S, L, N, U>,
    now: u64,
    ev: Event<'_>,
) -> Result<Out, EngineError> {
    let a = e.step(Instant(now), ev)?;
    let actions: Vec<Action> = a.iter().copied().collect();
    assert!(actions.len() <= MAX_ACTIONS_PER_STEP);
    let emits: Vec<u16> = actions.iter().filter_map(|x| if let Action::Emit { frame_len } = x { Some(*frame_len) } else { None }).collect();
    assert!(emits.len() <= 1, "one emitted frame per step");
    let frame = emits.first().map(|&n| a.tx_frame()[..usize::from(n)].to_vec());
    Ok(Out { actions, frame })
}

fn ctl<const S: usize, const L: usize, const N: usize, const U: usize>(
    e: &mut Engine<'_, S, L, N, U>,
    now: u64,
    from: Principal,
    op: Op<'_>,
) -> Out {
    let out = step(e, now, Event::Control(Control { from, op })).expect("control is always answered");
    out
}

fn arp_frame(p: &ArpPacket, dst: MacAddress) -> Vec<u8> {
    let mut f = vec![0u8; 14 + arp::PACKET_LEN];
    ethernet::emit_header(&mut f, dst, p.sender_mac, EtherType::Arp).expect("header");
    arp::emit(p, &mut f[14..]).expect("arp");
    f
}

fn remote_is_at() -> Vec<u8> {
    let p = ArpPacket { operation: ArpOperation::Reply, sender_mac: REMOTE_MAC, sender_ip: REMOTE_IP, target_mac: LOCAL_MAC, target_ip: LOCAL_IP };
    arp_frame(&p, LOCAL_MAC)
}

fn frame_from_port(src_port: u16, flags: TcpFlags, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let repr = TcpRepr { source_port: src_port, destination_port: LOCAL_PORT, seq: SeqNum(seq), ack: SeqNum(ack), flags, window: 8192, mss: if flags.syn() { Some(1460) } else { None } };
    let route = Ipv4Route { source_mac: REMOTE_MAC, destination_mac: LOCAL_MAC, source: REMOTE_IP, destination: LOCAL_IP, ttl: TTL };
    let mut buf = vec![0u8; 1514];
    let n = frame::emit_ipv4_tcp(&route, &repr, payload, &mut buf).expect("emit");
    buf.truncate(n);
    buf
}

fn pin_remote<const S: usize, const L: usize, const N: usize, const U: usize>(e: &mut Engine<'_, S, L, N, U>) {
    assert_eq!(ctl(e, 0, BOB, Op::PinNeighbor { ip: REMOTE_IP, mac: REMOTE_MAC }).reply(), ControlReply::Done);
}

/// A passive connection from REMOTE:REMOTE_PORT, ESTABLISHED and accepted
/// by BOB. Returns (socket, our ISS, peer IRS).
fn accepted(e: &mut Eng) -> (SocketId, u32, u32) {
    let ControlReply::Listener(l) = ctl(e, 0, BOB, Op::Listen { port: LOCAL_PORT }).reply() else { panic!("listen") };
    let syn_ack = step(e, 0, Event::Frame(&peer_frame(TcpFlags::SYN, 100, 0, 8192, &[]))).expect("syn");
    let iss = syn_ack.tcp().seq.0;
    step(e, 0, Event::Frame(&peer_frame(TcpFlags::ACK, 101, iss.wrapping_add(1), 8192, &[]))).expect("ack");
    let ControlReply::Accepted { socket, .. } = ctl(e, 0, BOB, Op::Accept { listener: l }).reply() else { panic!("accept") };
    (socket, iss, 100)
}

#[test]
fn siphash24_matches_the_published_vector() {
    // Aumasson & Bernstein, "SipHash: a fast short-input PRF", Appendix A:
    // key 00..0f, message 00..0e (15 bytes) -> 0xa129ca6149be45e5.
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let msg: Vec<u8> = (0u8..15).collect();
    assert_eq!(siphash24(&key, &msg), 0xa129_ca61_49be_45e5);
}

#[test]
fn the_iss_key_never_prints() {
    let shown = format!("{:?}", cfg());
    assert!(shown.contains("IssKey(<redacted>)"), "{shown}");
    assert!(!shown.contains("7, 7"), "key bytes must not appear: {shown}");
    let e = engine();
    assert!(!format!("{e:?}").contains("7, 7, 7"));
}

#[test]
fn configuration_is_checked() {
    let mut c = cfg();
    c.mtu = 1501;
    assert_eq!(Eng::new(c, tx_store(1024)).err(), Some(EngineError::Config));
    let mut c = cfg();
    c.prefix_len = 33;
    assert_eq!(Eng::new(c, tx_store(1024)).err(), Some(EngineError::Config));
    let mut c = cfg();
    c.arp_attempts = 0;
    assert_eq!(Eng::new(c, tx_store(1024)).err(), Some(EngineError::Config));
}

#[test]
fn passive_open_accept_and_ownership() {
    let mut e = engine();
    let ControlReply::Listener(l) = ctl(&mut e, 0, BOB, Op::Listen { port: LOCAL_PORT }).reply() else { panic!() };
    let o = step(&mut e, 5, Event::Frame(&peer_frame(TcpFlags::SYN, 100, 0, 8192, &[]))).expect("syn");
    let sa = o.tcp();
    assert!(sa.flags.syn() && sa.flags.ack());
    assert_eq!(sa.ack, SeqNum(101));
    assert!(o.notifies().is_empty(), "nobody owns it until ACCEPT");
    let iss = sa.seq.0;

    // Not accepted before ESTABLISHED.
    assert_eq!(ctl(&mut e, 6, BOB, Op::Accept { listener: l }).reply(), ControlReply::NoData);
    let o = step(&mut e, 7, Event::Frame(&peer_frame(TcpFlags::ACK, 101, iss.wrapping_add(1), 8192, &[]))).expect("ack");
    assert!(o.frame.is_none());

    assert_eq!(ctl(&mut e, 8, ALICE, Op::Accept { listener: l }).reply(), ControlReply::Refused(NetError::Denied));
    let ControlReply::Accepted { socket, peer } = ctl(&mut e, 9, BOB, Op::Accept { listener: l }).reply() else { panic!() };
    assert_eq!(peer, remote());
    assert_eq!(ctl(&mut e, 10, BOB, Op::Accept { listener: l }).reply(), ControlReply::NoData);
    assert_eq!(ctl(&mut e, 11, BOB, Op::Status { socket }).reply(), ControlReply::State(SocketState::Tcp(TcpState::Established)));
    assert_eq!(e.owner(socket), Some(BOB));
    assert_eq!(ctl(&mut e, 12, ALICE, Op::Status { socket }).reply(), ControlReply::Refused(NetError::Denied));
    assert_eq!(ctl(&mut e, 13, ALICE, Op::Close { socket }).reply(), ControlReply::Refused(NetError::Denied));
}

#[test]
fn received_text_is_delivered_as_a_frame_range_and_acknowledged() {
    let mut e = engine();
    let (socket, iss, irs) = accepted(&mut e);
    let data = peer_frame(TcpFlags::ACK.union(TcpFlags::PSH), irs + 1, iss.wrapping_add(1), 8192, b"hello");
    let o = step(&mut e, 20, Event::Frame(&data)).expect("data");
    let d = o.actions.iter().find_map(|a| if let Action::Deliver { socket: s, offset, len } = a { Some((*s, *offset, *len)) } else { None });
    let (s, offset, len) = d.expect("delivered");
    assert_eq!(s, socket);
    assert_eq!(&data[offset..offset + len], b"hello");
    assert!(o.notifies().contains(&(socket, Notify::DataReady)));
    assert_eq!(o.tcp().ack, SeqNum(irs + 6));
    // The shell reports the client consumed it; the window reopens.
    assert_eq!(ctl(&mut e, 21, BOB, Op::Consumed { socket, octets: 5 }).reply(), ControlReply::Done);
    assert_eq!(e.tcb(socket).expect("tcb").rcv_wnd(), 4096);
}

#[test]
fn active_open_refuses_port_zero_on_either_end() {
    let mut e = engine();
    // build1-3626: a shell passing local_port 0 put port 0 on the wire.
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: 0 }).reply(), ControlReply::Refused(NetError::Malformed));
    let zero = SocketAddress { port: 0, ..remote() };
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Connect { remote: zero, local_port: LOCAL_PORT }).reply(), ControlReply::Refused(NetError::Malformed));
    // Neither refusal used up a slot: a proper open still succeeds.
    let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    assert!(matches!(o.reply(), ControlReply::Socket(_)), "{:?}", o.actions);
}

#[test]
fn active_open_resolves_by_solicited_arp_then_sends_syn() {
    let mut e = engine();
    let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    let ControlReply::Socket(id) = o.reply() else { panic!("{:?}", o.actions) };
    let (dst, who) = o.arp();
    assert_eq!(dst, MacAddress::BROADCAST);
    assert_eq!((who.operation, who.target_ip, who.sender_ip), (ArpOperation::Request, REMOTE_IP, LOCAL_IP));
    assert_eq!(o.arm(), Some(Instant(1_000)));
    assert_eq!(ctl(&mut e, 1, ALICE, Op::Status { socket: id }).reply(), ControlReply::State(SocketState::Resolving));

    let o = step(&mut e, 10, Event::Frame(&remote_is_at())).expect("is-at");
    let syn = o.tcp();
    assert!(syn.flags.syn() && !syn.flags.ack());
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::SynSent)));
    let iss = syn.seq.0;

    let o = step(&mut e, 20, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 9000, iss.wrapping_add(1), 8192, &[]))).expect("syn-ack");
    assert_eq!(o.tcp().flags, TcpFlags::ACK);
    assert!(o.notifies().contains(&(id, Notify::Connected)));
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::Established)));
}

#[test]
fn unanswered_resolution_retries_then_fails_the_socket() {
    let mut e = engine();
    let ControlReply::Socket(id) = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: 1 }).reply() else { panic!() };
    let o = step(&mut e, 999, Event::Tick(Instant(999))).expect("tick");
    assert!(o.frame.is_none(), "not due yet");
    for (now, next) in [(1_000u64, 2_000u64), (2_000, 3_000)] {
        let o = step(&mut e, now, Event::Tick(Instant(now))).expect("tick");
        assert_eq!(o.arp().1.target_ip, REMOTE_IP, "retry at {now}");
        assert_eq!(o.arm(), Some(Instant(next)));
    }
    let o = step(&mut e, 3_000, Event::Tick(Instant(3_000))).expect("tick");
    assert!(o.frame.is_none());
    assert!(o.notifies().contains(&(id, Notify::Error(NetError::NoRoute))));
    assert_eq!(e.state(id), None, "the slot is freed");
}

#[test]
fn arp_is_solicit_only_and_requests_for_us_are_answered() {
    let mut e = engine();
    // An unsolicited reply teaches nothing: a later connect still asks.
    let o = step(&mut e, 0, Event::Frame(&remote_is_at())).expect("unsolicited");
    assert!(o.frame.is_none());
    let o = ctl(&mut e, 1, ALICE, Op::Connect { remote: remote(), local_port: 1 });
    assert_eq!(o.arp().1.operation, ArpOperation::Request);

    // A request for our address is answered, and teaches nothing either.
    let mut e = engine();
    let req = ArpPacket { operation: ArpOperation::Request, sender_mac: REMOTE_MAC, sender_ip: REMOTE_IP, target_mac: MacAddress([0; 6]), target_ip: LOCAL_IP };
    let o = step(&mut e, 0, Event::Frame(&arp_frame(&req, MacAddress::BROADCAST))).expect("who-has us");
    let (dst, rep) = o.arp();
    assert_eq!(dst, REMOTE_MAC);
    assert_eq!((rep.operation, rep.sender_mac, rep.sender_ip, rep.target_ip), (ArpOperation::Reply, LOCAL_MAC, LOCAL_IP, REMOTE_IP));
    let o = ctl(&mut e, 1, ALICE, Op::Connect { remote: remote(), local_port: 1 });
    assert_eq!(o.arp().1.operation, ArpOperation::Request, "the request did not resolve REMOTE");
}

#[test]
fn a_pinned_neighbor_needs_no_arp_and_cannot_be_moved() {
    let mut e = engine();
    pin_remote(&mut e);
    // NET-V-030 through the engine: an ARP reply naming another MAC.
    let lie = ArpPacket { operation: ArpOperation::Reply, sender_mac: MacAddress([2, 0, 0, 0, 0, 0x99]), sender_ip: REMOTE_IP, target_mac: LOCAL_MAC, target_ip: LOCAL_IP };
    step(&mut e, 1, Event::Frame(&arp_frame(&lie, LOCAL_MAC))).expect("lie");
    let o = ctl(&mut e, 2, ALICE, Op::Connect { remote: remote(), local_port: 1 });
    let ControlReply::Socket(_) = o.reply() else { panic!() };
    let f = o.frame.as_ref().expect("SYN at once");
    match frame::classify(f, MTU).expect("parses") {
        Classified::Ipv4Tcp { link, segment, .. } => {
            assert_eq!(link.destination, REMOTE_MAC, "the pinned MAC");
            assert!(segment.flags.syn());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn routing_uses_the_gateway_off_link_and_refuses_without_one() {
    let far = SocketAddress { address: IpAddress::V4(Ipv4Address([198, 51, 100, 7])), port: 80 };
    let mut e = engine();
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Connect { remote: far, local_port: 1 }).reply(), ControlReply::Refused(NetError::NoRoute));
    let v6 = SocketAddress { address: IpAddress::V6(Ipv6Address([0; 16])), port: 80 };
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Connect { remote: v6, local_port: 1 }).reply(), ControlReply::Refused(NetError::Unsupported));

    let mut c = cfg();
    c.gateway = Some(GATEWAY);
    let mut e: Eng = Engine::new(c, tx_store(1024)).expect("config");
    let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: far, local_port: 1 });
    assert_eq!(o.arp().1.target_ip, GATEWAY, "ask for the gateway, not the far host");
}

#[test]
fn full_tables_and_the_half_open_budget() {
    let mut e: Engine<'static, 1, 1, 4, 0> = Engine::new(cfg(), tx_store(256)).expect("config");
    ctl(&mut e, 0, BOB, Op::Listen { port: LOCAL_PORT });
    assert_eq!(ctl(&mut e, 0, BOB, Op::Listen { port: 8 }).reply(), ControlReply::Refused(NetError::ResourceLimit));
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Listen { port: LOCAL_PORT }).reply(), ControlReply::Refused(NetError::AddressInUse));
    step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT, TcpFlags::SYN, 1, 0, &[]))).expect("first");
    let err = step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT + 1, TcpFlags::SYN, 1, 0, &[]))).err();
    assert_eq!(err, Some(EngineError::Refused(Refusal::SocketTableFull)), "dropped, not answered");
    assert_eq!(ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: 9 }).reply(), ControlReply::Refused(NetError::ResourceLimit));

    let mut c = cfg();
    c.half_open_per_listener = 1;
    let mut e: Eng = Engine::new(c, tx_store(1024)).expect("config");
    ctl(&mut e, 0, BOB, Op::Listen { port: LOCAL_PORT });
    let sa = step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT, TcpFlags::SYN, 1, 0, &[]))).expect("first");
    let iss = sa.tcp().seq.0;
    let err = step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT + 1, TcpFlags::SYN, 1, 0, &[]))).err();
    assert_eq!(err, Some(EngineError::Refused(Refusal::HalfOpenFull)));
    step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT, TcpFlags::ACK, 2, iss.wrapping_add(1), &[]))).expect("complete");
    let o = step(&mut e, 0, Event::Frame(&frame_from_port(REMOTE_PORT + 2, TcpFlags::SYN, 1, 0, &[]))).expect("room again");
    assert!(o.tcp().flags.syn());
}

#[test]
fn time_wait_lasts_two_msl_then_frees_the_slot() {
    assert_eq!(MSL_MS, 30_000);
    let mut e = engine();
    pin_remote(&mut e);
    let o = ctl(&mut e, 0, ALICE, Op::Connect { remote: remote(), local_port: LOCAL_PORT });
    let ControlReply::Socket(id) = o.reply() else { panic!() };
    let iss = o.tcp().seq.0;
    step(&mut e, 1, Event::Frame(&peer_frame(TcpFlags::SYN.union(TcpFlags::ACK), 500, iss.wrapping_add(1), 8192, &[]))).expect("syn-ack");
    let o = ctl(&mut e, 2, ALICE, Op::Close { socket: id });
    assert_eq!(o.reply(), ControlReply::Done);
    assert!(o.tcp().flags.fin());
    let o = step(&mut e, 10, Event::Frame(&peer_frame(TcpFlags::FIN.union(TcpFlags::ACK), 501, iss.wrapping_add(2), 8192, &[]))).expect("fin");
    assert_eq!(e.state(id), Some(SocketState::Tcp(TcpState::TimeWait)));
    assert_eq!(o.arm(), Some(Instant(10 + 2 * MSL_MS)));
    let o = step(&mut e, 10 + 2 * MSL_MS - 1, Event::Tick(Instant(10 + 2 * MSL_MS - 1))).expect("tick");
    assert!(o.notifies().is_empty());
    let o = step(&mut e, 10 + 2 * MSL_MS, Event::Tick(Instant(10 + 2 * MSL_MS))).expect("tick");
    assert!(o.notifies().contains(&(id, Notify::Closed)));
    assert_eq!(e.state(id), None);
}

#[test]
fn challenge_acks_are_rate_limited_per_socket() {
    let mut e = engine();
    accepted(&mut e);
    let syn = peer_frame(TcpFlags::SYN, 900_000, 0, 8192, &[]);
    assert!(step(&mut e, 100, Event::Frame(&syn)).expect("first").frame.is_some());
    assert!(step(&mut e, 200, Event::Frame(&syn)).expect("second").frame.is_none(), "inside the interval");
    assert!(step(&mut e, 1_100, Event::Frame(&syn)).expect("third").frame.is_some());
}

#[test]
fn iss_is_keyed_per_tuple_and_advances_with_time() {
    let iss_at = |key: [u8; 16], now: u64, port: u16| {
        let mut c = cfg();
        c.iss_key = Some(IssKey(key));
        let mut e: Eng = Engine::new(c, tx_store(1024)).expect("config");
        ctl(&mut e, 0, BOB, Op::Listen { port: LOCAL_PORT });
        step(&mut e, now, Event::Frame(&frame_from_port(port, TcpFlags::SYN, 1, 0, &[]))).expect("syn").tcp().seq.0
    };
    let a = iss_at([7; 16], 0, REMOTE_PORT);
    assert_eq!(a, iss_at([7; 16], 0, REMOTE_PORT), "deterministic");
    assert_eq!(iss_at([7; 16], 1_000, REMOTE_PORT), a.wrapping_add(250_000), "RFC 6528: a 4 µs clock");
    assert_ne!(iss_at([7; 16], 0, REMOTE_PORT + 1), a, "per tuple");
    assert_ne!(iss_at([8; 16], 0, REMOTE_PORT), a, "per key");
}

#[test]
fn udp_through_step() {
    let mut e = engine();
    let ControlReply::Endpoint(u) = ctl(&mut e, 0, BOB, Op::UdpBind { port: 53 }).reply() else { panic!() };
    let route = Ipv4Route { source_mac: REMOTE_MAC, destination_mac: LOCAL_MAC, source: REMOTE_IP, destination: LOCAL_IP, ttl: TTL };
    let mut f = vec![0u8; 1514];
    let n = frame::emit_ipv4_udp(&route, &UdpRepr { source_port: REMOTE_PORT, destination_port: 53 }, b"query", &mut f).expect("emit");
    f.truncate(n);
    let o = step(&mut e, 0, Event::Frame(&f)).expect("datagram");
    let got = o.actions.iter().find_map(|a| if let Action::Datagram { endpoint, from, offset, len } = a { Some((*endpoint, *from, *offset, *len)) } else { None });
    let (endpoint, from, offset, len) = got.expect("delivered");
    assert_eq!((endpoint, from), (u, remote()));
    assert_eq!(&f[offset..offset + len], b"query");

    assert_eq!(ctl(&mut e, 1, ALICE, Op::UdpSend { endpoint: u, remote: remote(), payload: b"x" }).reply(), ControlReply::Refused(NetError::Denied));
    // Unresolved next hop: a who-has goes out and the send is refused,
    // nothing held.
    let o = ctl(&mut e, 2, BOB, Op::UdpSend { endpoint: u, remote: remote(), payload: b"answer" });
    assert_eq!(o.reply(), ControlReply::Refused(NetError::WouldBlock));
    assert_eq!(o.arp().1.target_ip, REMOTE_IP);
    step(&mut e, 3, Event::Frame(&remote_is_at())).expect("is-at");
    let o = ctl(&mut e, 4, BOB, Op::UdpSend { endpoint: u, remote: remote(), payload: b"answer" });
    assert_eq!(o.reply(), ControlReply::Done);
    match frame::classify(o.frame.as_ref().expect("datagram"), MTU).expect("parses") {
        Classified::Ipv4Udp { link, datagram, .. } => {
            assert_eq!(link.destination, REMOTE_MAC);
            assert_eq!((datagram.source_port, datagram.payload), (53, &b"answer"[..]));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn frames_refused_before_any_state() {
    let mut e = engine();
    let elsewhere = {
        let repr = TcpRepr { source_port: REMOTE_PORT, destination_port: LOCAL_PORT, seq: SeqNum(1), ack: SeqNum(0), flags: TcpFlags::SYN, window: 1, mss: None };
        let route = Ipv4Route { source_mac: REMOTE_MAC, destination_mac: LOCAL_MAC, source: REMOTE_IP, destination: Ipv4Address([192, 0, 2, 99]), ttl: TTL };
        let mut b = vec![0u8; 1514];
        let n = frame::emit_ipv4_tcp(&route, &repr, &[], &mut b).expect("emit");
        b.truncate(n);
        b
    };
    assert_eq!(step(&mut e, 0, Event::Frame(&elsewhere)).err(), Some(EngineError::Refused(Refusal::NotForUs)));
    let mut bad = peer_frame(TcpFlags::SYN, 1, 0, 8192, &[]);
    bad[14 + 20 + 4] ^= 1;
    assert!(matches!(step(&mut e, 0, Event::Frame(&bad)).err(), Some(EngineError::Refused(Refusal::Malformed(_)))));
    // No listener: the B-17 reset.
    let o = step(&mut e, 0, Event::Frame(&peer_frame(TcpFlags::SYN, 777, 0, 8192, &[]))).expect("reset");
    let r = o.tcp();
    assert!(r.flags.rst() && r.flags.ack());
    assert_eq!(r.ack, SeqNum(778));
}
