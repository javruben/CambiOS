// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS network stack shell (ADR-039 § 1), the persistent service
//! that replaces `udp-stack` (ADR-039 migration step 6).
//!
//! The shell owns the effects and the engine owns the protocol: frames
//! from the NIC seam become `Event::Frame`, the kernel clock becomes
//! `Event::Tick`, a client request becomes `Event::Control` under the
//! sender's kernel-stamped Principal, and every `Action::Emit` goes back
//! into the seam's TX ring. It serves:
//!
//! - **ep 21**, udp-stack's UDP protocol, as a compatibility surface
//!   ([`compat`]);
//! - **ep 34**, socket control ([`sock`]);
//! - **the wall clock**, udp-stack's NTP duty ([`ntp`]);
//! - **ep 36**, the seam's doorbells from the driver ([`seam`]).
//!
//! The engine's RFC 6528 ISS key comes from `get_entropy` (syscall 76,
//! the CPU's hardware RNG). Without one the engine runs keyless and
//! refuses every TCP open. With one, each TCP socket comes with its two
//! stream channels ([`stream`]).
//!
//! If the driver dies or breaks the ring protocol, the seam is dropped
//! and the stack keeps answering with the network down (ep 21 `ERROR`,
//! ep 34 `NO_DEVICE`). It does not bring the seam up again: nothing
//! restarts a dead driver yet.
//! Revisit when: init gains the ADR-019 restart policy.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

mod compat;
mod dhcp;
mod ntp;
mod seam;
mod sock;
mod stream;

use alloc::boxed::Box;
use alloc::vec;
use cambios_libsys as sys;
use cambios_net_proto as proto;
use cambios_netcore::engine::{Action, Actions, Control, ControlReply, Engine, EngineConfig, Event, Instant, IssKey, Notify, Op, Principal, SocketId, UdpId};
use cambios_netcore::tcp::TcbConfig;
use cambios_netcore::{Ipv4Address, MacAddress, NetError, SocketAddress};
use net_seam::MAX_FRAME;

/// SCAFFOLDING: the heap arena. The engine's socket store (below) plus
/// the engine, the stream table and the ep 21 queues; ADR-039 § 8 sizes the full table at
/// about 2 MiB in a 4 MiB heap, and this runs a quarter of it.
/// Replace when: TCP opens and the stack takes `MAX_SOCKETS = 64`.
const HEAP_BYTES: usize = 1024 * 1024;

cambios_libsys_rt::service_main! {
    name: "NETSTACK",
    endpoint: proto::SEAM_ENDPOINT,
    heap: HEAP_BYTES,
    main: run,
}

/// SCAFFOLDING: table sizes, a quarter of ADR-039 § 8 (`MAX_SOCKETS`
/// 64, `MAX_LISTENERS` 16); neighbours and the hold count are the § 8
/// values. Each socket's stream holds two 5-page channels.
/// Replace when: a client needs more than 16 sockets at once.
pub const SOCKETS: usize = 16;
const LISTENERS: usize = 4;
/// TUNING: ADR-039 § 8 `MAX_ARP_ENTRIES`.
const NEIGHBORS: usize = 32;
/// SCAFFOLDING: UDP endpoints: NTP's and three ep 21 ports.
/// Replace when: a second UDP client needs more ports at once.
const UDP: usize = 4;
/// TUNING: ADR-039 § 8 `MAX_OOO_SEGMENTS`.
const OOO: usize = 4;

/// TUNING: per-socket store: a 16 KiB transmit buffer (ADR-039 § 8
/// `STREAM_PAGES` = 4) plus room to hold `OOO` MSS-sized segments.
const SOCKET_STORE: usize = 16 * 1024 + OOO * 1460;

type Net = Engine<'static, SOCKETS, LISTENERS, NEIGHBORS, UDP, OOO>;

/// SCAFFOLDING: QEMU user networking's fixed addresses (slirp: guest
/// 10.0.2.15/24, gateway 10.0.2.2), udp-stack's static configuration,
/// used from boot until the DHCP client's first lease is applied
/// ([`dhcp`], codex D1). Bounded: once any lease is applied it is never
/// used again, and a lost lease leaves the stack with no address.
/// Replace when: the stack starts unconfigured and waits for a lease.
const LOCAL_IP: Ipv4Address = Ipv4Address([10, 0, 2, 15]);
const PREFIX_LEN: u8 = 24;
const GATEWAY: Ipv4Address = Ipv4Address([10, 0, 2, 2]);

/// HARDWARE: Ethernet's payload limit.
const MTU: u16 = 1500;
/// TUNING: IPv4 TTL (RFC 1700's recommended default).
const TTL: u8 = 64;

/// ARCHITECTURAL: the kernel clock ticks every 10 ms (`get_time`).
const MS_PER_TICK: u64 = 10;
/// TUNING: frames taken from the RX ring per loop pass.
const RX_BUDGET: usize = 64;
/// TUNING: client requests served per endpoint per loop pass, so a
/// flood on one endpoint cannot starve the frames or the other.
const CONTROL_BUDGET: usize = 8;

/// The clock in ms. A refused `get_time` ends the run: every bound in
/// this loop is a deadline, and none can hold without a clock.
fn now_ms() -> Instant {
    match seam::ticks() {
        Some(t) => Instant(t.saturating_mul(MS_PER_TICK)),
        None => {
            sys::print(b"[NETSTACK] clock refused (get-time); stopping\n");
            sys::exit(1);
        }
    }
}

fn print_u64(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    sys::print(&buf[i..]);
}

fn print_hex(bytes: &[u8], sep: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (k, b) in bytes.iter().enumerate() {
        if k > 0 {
            sys::print(&[sep]);
        }
        sys::print(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xF)]]);
    }
}

fn print_ip(ip: Ipv4Address) {
    for (k, b) in ip.0.iter().enumerate() {
        if k > 0 {
            sys::print(b".");
        }
        print_u64(u64::from(*b));
    }
}

/// Carry out one step's effects: transmit, and keep the earliest timer.
/// Returns the step's control reply. `on_datagram` gets each UDP payload
/// (`input` is the frame the step consumed, which `Datagram` indexes).
fn apply(acts: &Actions<'_>, input: &[u8], seam: &mut Option<seam::Seam>, next_tick: &mut Option<Instant>, streams: &mut stream::Streams, mut on_datagram: impl FnMut(UdpId, SocketAddress, &[u8])) -> Option<ControlReply> {
    let mut reply = None;
    for a in acts.iter() {
        match *a {
            Action::Emit { frame_len } => {
                if let (Some(s), Some(f)) = (seam.as_mut(), acts.tx_frame().get(..usize::from(frame_len))) {
                    // A full ring drops the frame; the engine's timers
                    // retransmit what matters (ARP, NTP, TCP).
                    let _ = s.send(f);
                }
            }
            Action::Arm(t) => *next_tick = Some(next_tick.map_or(t, |c| if t.0 < c.0 { t } else { c })),
            Action::Reply { msg, .. } => reply = Some(msg),
            Action::Datagram { endpoint, from, offset, len } => {
                if let Some(p) = offset.checked_add(len).and_then(|end| input.get(offset..end)) {
                    on_datagram(endpoint, from, p);
                }
            }
            // A socket without a stream is either accepted but not yet
            // `ACCEPT`ed (its octets are held) or closed by its client
            // (dropped).
            Action::Notify { socket, what } => match streams.get(socket) {
                Some(s) => s.notified(what),
                None if matches!(what, Notify::Closed | Notify::Reset | Notify::Refused | Notify::Error(_)) => streams.forget(socket),
                None => {}
            },
            Action::Deliver { socket, offset, len } => {
                if let Some(p) = offset.checked_add(len).and_then(|end| input.get(offset..end)) {
                    deliver(streams, socket, p);
                }
            }
            Action::DeliverHeld { socket, offset, len } => {
                if let Some(p) = offset.checked_add(len).and_then(|end| acts.held_data().get(offset..end)) {
                    deliver(streams, socket, p);
                }
            }
        }
    }
    reply
}

/// In-order octets for `socket`: into its RX ring, or held until its
/// owner's `ACCEPT` opens the stream (see [`stream::Streams::hold`]).
fn deliver(streams: &mut stream::Streams, socket: SocketId, bytes: &[u8]) {
    match streams.get(socket) {
        Some(s) => s.deliver(bytes),
        None => streams.hold(socket, bytes),
    }
}

/// The engine as the request handlers see it: one control step whose
/// emitted frames go to the seam. With the seam gone the step is not
/// taken and the answer is `NetworkDown`.
struct Shell<'a> {
    net: &'a mut Net,
    seam: &'a mut Option<seam::Seam>,
    next_tick: &'a mut Option<Instant>,
    streams: &'a mut stream::Streams,
    now: Instant,
}

impl compat::Engine for Shell<'_> {
    fn control(&mut self, c: Control<'_>) -> Option<ControlReply> {
        if self.seam.is_none() {
            return Some(ControlReply::Refused(NetError::NetworkDown));
        }
        let acts = self.net.step(self.now, Event::Control(c)).ok()?;
        // A control step consumes no frame, so it yields no datagram.
        apply(&acts, &[], self.seam, self.next_tick, self.streams, |_, _, _| {})
    }
}

impl sock::Streamed for Shell<'_> {
    fn streams(&mut self) -> &mut stream::Streams {
        self.streams
    }
    fn now_ms(&self) -> u64 {
        self.now.0
    }
}

fn run() -> ! {
    for ep in [proto::UDP_ENDPOINT, proto::TCP_ENDPOINT] {
        if sys::register_endpoint(ep) < 0 {
            sys::print(b"[NETSTACK] endpoint registration refused: ");
            print_u64(u64::from(ep));
            sys::print(b"\n");
            sys::exit(1);
        }
    }

    let mut ignored = 0u32;
    let first = match seam::Seam::bring_up(&mut ignored) {
        Ok(s) => s,
        Err(e) => {
            sys::print(b"[NETSTACK] seam bring-up failed: ");
            sys::print(match e {
                seam::BringUpError::NoReply => b"driver did not answer\n",
                seam::BringUpError::Refused(proto::Status::NoDevice) => b"no NIC\n",
                seam::BringUpError::Refused(_) => b"driver refused\n",
                seam::BringUpError::Malformed => b"malformed reply\n",
                seam::BringUpError::Clock => b"clock refused (get-time)\n",
                seam::BringUpError::Create => b"channel_create failed\n",
                seam::BringUpError::Page => b"unusable mapping\n",
            });
            sys::exit(1);
        }
    };
    let mac = first.mac;
    let driver = first.driver;
    let mut seam = Some(first);
    sys::print(b"[NETSTACK] seam open with the NIC driver, mac ");
    print_hex(&mac, b':');
    sys::print(b"\n");

    let mut own = [0u8; 32];
    if sys::get_principal(&mut own) < 0 {
        sys::print(b"[NETSTACK] no principal\n");
        sys::exit(1);
    }
    let me = Principal(own);

    // RFC 6528 § 3: the ISS key is a secret; the hardware RNG is the only
    // source. Any refusal leaves TCP keyless, so the engine refuses opens.
    let mut key = [0u8; 16];
    let iss_key = (sys::get_entropy(&mut key) == 16).then_some(IssKey(key));
    key = [0u8; 16];
    let _ = core::hint::black_box(&key);

    let config = EngineConfig {
        mac: MacAddress(mac),
        ipv4: LOCAL_IP,
        prefix_len: PREFIX_LEN,
        gateway: Some(GATEWAY),
        ttl: TTL,
        mtu: MTU,
        tcb: TcbConfig { local_mss: MTU - 40, receive_window: 16 * 1024 },
        iss_key,
        half_open_per_listener: 8,        // TUNING: ADR-039 § 8 MAX_HALF_OPEN_PER_LISTENER
        neighbor_ttl_ms: 600_000,         // TUNING: 10 min, a common ARP cache lifetime
        arp_timeout_ms: 1_000,            // TUNING: one second per ARP question
        arp_attempts: 3,                  // TUNING
        challenge_ack_interval_ms: 1_000, // TUNING: ADR-039 § 8 CHALLENGE_ACK_PER_SEC = 1
        max_retransmits: 5,               // TUNING
        hold_per_socket: OOO * 1460,
    };
    let store: &'static mut [u8] = Box::leak(vec![0u8; SOCKETS * SOCKET_STORE].into_boxed_slice());
    let mut net: Box<Net> = match Engine::new(config, store) {
        Ok(e) => Box::new(e),
        Err(_) => {
            sys::print(b"[NETSTACK] engine config refused\n");
            sys::exit(1);
        }
    };
    let mut local = sock::Local { ipv4: LOCAL_IP, prefix_len: PREFIX_LEN, gateway: GATEWAY, mac };
    sys::print(b"[NETSTACK] engine up: ");
    print_ip(LOCAL_IP);
    sys::print(b"/24 via ");
    print_ip(GATEWAY);
    sys::print(if iss_key.is_some() {
        b"; serving ep 21 and ep 34, TCP keyed from the hardware RNG\n" as &[u8]
    } else {
        b"; serving ep 21 and ep 34, TCP closed (no hardware RNG: get_entropy refused)\n"
    });

    let mut next_tick: Option<Instant> = None;
    // The ephemeral ports' starting offset; without a hardware RNG TCP is
    // closed anyway, so the fixed fallback is never used on the wire.
    let mut seed = [0u8; 2];
    let port_seed = if sys::get_entropy(&mut seed) == 2 { u16::from_le_bytes(seed) } else { 0 };
    let mut streams = Box::new(stream::Streams::new(port_seed));
    let start = now_ms();
    let bind = Shell { net: &mut net, seam: &mut seam, next_tick: &mut next_tick, streams: &mut streams, now: start }
        .control_bind(me, ntp::CLIENT_PORT);
    let Some(ntp_id) = bind else {
        sys::print(b"[NETSTACK] NTP port bind refused\n");
        sys::exit(1);
    };
    let mut ntp = ntp::Ntp::new(ntp_id, start);
    let mut compat = Box::new(compat::Compat::new());

    let mut frame = [0u8; MAX_FRAME];
    let mut msg = [0u8; proto::MAX_MESSAGE];
    let mut dhcp = dhcp::Dhcp::new(MacAddress(mac));
    let mut dframe = [0u8; MAX_FRAME];
    let st = dhcp.start(start.0, &mut dframe);
    on_dhcp(st, start, &dframe, &mut net, &mut seam, &mut next_tick, &mut streams, &mut local);
    let mut resp = [0u8; proto::MAX_MESSAGE];

    loop {
        let mut busy = false;

        // Doorbells from the driver only say "look at the ring", which
        // every pass does anyway; anyone else's message is counted.
        while let Some(m) = sys::try_recv_verified(proto::SEAM_ENDPOINT, &mut msg) {
            if *m.sender() != driver {
                ignored = ignored.saturating_add(1);
            }
        }

        for _ in 0..RX_BUDGET {
            let Some(s) = seam.as_mut() else { break };
            match s.recv(&mut frame) {
                seam::Rx::Frame(n) => {
                    busy = true;
                    let input = &frame[..n.min(MAX_FRAME)];
                    let now = now_ms();
                    if let dhcp::Seen::Dhcp(st) = dhcp.on_frame(input, now.0, MTU, &mut dframe) {
                        on_dhcp(st, now, &dframe, &mut net, &mut seam, &mut next_tick, &mut streams, &mut local);
                        continue;
                    }
                    // A refused frame (not for us, malformed) changed nothing.
                    if let Ok(acts) = net.step(now, Event::Frame(input)) {
                        apply(&acts, input, &mut seam, &mut next_tick, &mut streams, |id, from, p| {
                            if id == ntp.endpoint {
                                ntp.answer(from, p, now);
                            } else {
                                compat.deliver(id, from, p);
                            }
                        });
                    }
                }
                seam::Rx::Empty => break,
                seam::Rx::Dead => {
                    sys::print(b"[NETSTACK] seam lost: driver gone; network down\n");
                    if let Some(s) = seam.take() {
                        s.drop_dead();
                    }
                }
                seam::Rx::Untrusted => {
                    sys::print(b"[NETSTACK] seam dropped: driver broke the ring protocol (chan.peer_violation); network down\n");
                    if let Some(s) = seam.take() {
                        s.drop_untrusted();
                    }
                }
            }
        }

        let now = now_ms();
        if dhcp.deadline().is_some_and(|d| now.0 >= d) {
            let st = dhcp.tick(now.0, &mut dframe);
            on_dhcp(st, now, &dframe, &mut net, &mut seam, &mut next_tick, &mut streams, &mut local);
        }
        if next_tick.is_some_and(|t| now.0 >= t.0) {
            next_tick = None;
            if let Ok(acts) = net.step(now, Event::Tick(now)) {
                apply(&acts, &[], &mut seam, &mut next_tick, &mut streams, |_, _, _| {});
            }
        }

        let mut shell = Shell { net: &mut net, seam: &mut seam, next_tick: &mut next_tick, streams: &mut streams, now };
        use compat::Engine as _;
        if let ntp::Due::Send(remote) = ntp.due(now) {
            let op = Op::UdpSend { endpoint: ntp.endpoint, remote, payload: &ntp::REQUEST };
            if let Some(ControlReply::Done) = shell.control(Control { from: me, op }) {
                ntp.sent(now);
            }
        }
        compat.retry(&mut shell, now);

        for _ in 0..CONTROL_BUDGET {
            let Some(m) = sys::try_recv_verified(proto::UDP_ENDPOINT, &mut msg) else { break };
            busy = true;
            let (owner, reply_to) = (Principal(*m.sender().as_bytes()), m.from_endpoint());
            if let compat::Served::Reply(n) = compat.serve(&mut shell, owner, reply_to, m.payload(), &mut resp, (local.ipv4, mac), now) {
                sys::write(reply_to, &resp[..n]);
            }
        }
        for _ in 0..CONTROL_BUDGET {
            let Some(m) = sys::try_recv_verified(proto::TCP_ENDPOINT, &mut msg) else { break };
            busy = true;
            let (owner, reply_to) = (Principal(*m.sender().as_bytes()), m.from_endpoint());
            if let Some(n) = sock::serve(&mut shell, owner, reply_to, m.payload(), &mut resp, &local) {
                sys::write(reply_to, &resp[..n]);
            }
        }
        sock::service(&mut shell);

        if let Some(s) = seam.as_mut() {
            s.flush();
        }
        if !busy {
            sys::yield_now();
        }
    }
}

/// Act on one DHCP step: send its frame, apply an accepted lease to the
/// engine (and to the address copy clients read), report a loss.
#[allow(clippy::too_many_arguments)]
fn on_dhcp(
    st: dhcp::Step,
    now: Instant,
    dframe: &[u8],
    net: &mut Net,
    seam: &mut Option<seam::Seam>,
    next_tick: &mut Option<Instant>,
    streams: &mut stream::Streams,
    local: &mut sock::Local,
) {
    if let (Some(n), Some(s)) = (st.send, seam.as_mut()) {
        // A full ring drops it; the client's own retransmission covers that.
        let _ = s.send(dframe.get(..n).unwrap_or(&[]));
    }
    if let Some(lease) = st.lease {
        let Some(c) = lease.interface() else {
            sys::print(b"[NETSTACK] DHCP lease unusable (mask or router); address unchanged\n");
            return;
        };
        match net.step(now, Event::Interface(c)) {
            Ok(acts) => {
                apply(&acts, &[], seam, next_tick, streams, |_, _, _| {});
                local.ipv4 = c.ipv4;
                local.prefix_len = c.prefix_len;
                local.gateway = c.gateway.unwrap_or(Ipv4Address([0; 4]));
                sys::print(b"[NETSTACK] DHCP lease applied: ");
                print_ip(c.ipv4);
                sys::print(b" via ");
                print_ip(local.gateway);
                sys::print(b"\n");
            }
            Err(_) => sys::print(b"[NETSTACK] DHCP lease refused by the engine; address unchanged\n"),
        }
    }
    if st.lost {
        // The address is no longer ours: the engine stops using it and
        // frees every TCP socket (each owner notified). The static
        // bootstrap address is never restored; only a new lease ends this.
        if let Ok(acts) = net.step(now, Event::AddressLost) {
            apply(&acts, &[], seam, next_tick, streams, |_, _, _| {});
        }
        local.ipv4 = Ipv4Address([0; 4]);
        local.gateway = Ipv4Address([0; 4]);
        sys::print(b"[NETSTACK] DHCP lease lost: no address until the next lease\n");
    }
}

impl Shell<'_> {
    /// Bind a UDP port for `owner`; its endpoint, or `None` if refused.
    fn control_bind(mut self, owner: Principal, port: u16) -> Option<UdpId> {
        use compat::Engine as _;
        match self.control(Control { from: owner, op: Op::UdpBind { port } }) {
            Some(ControlReply::Endpoint(id)) => Some(id),
            _ => None,
        }
    }
}
