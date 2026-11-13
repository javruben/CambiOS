// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The DHCP client's shell half (codex D1). `cambios_netcore::dhcp` is a
//! pure state machine; this module frames what it sends and picks out what
//! it receives, and the accepted lease reaches the engine only as
//! `Event::Interface` (engine-owned state, never a client op).
//!
//! Raw frames, not an engine UDP endpoint: a DISCOVER goes from 0.0.0.0
//! to 255.255.255.255, and offers may be broadcast or sent to an address
//! we do not hold yet. The engine refuses both (its UDP send takes only
//! unicast destinations from the configured address, and its receive path
//! drops anything not addressed to it), as it should for every other
//! socket. So the shell sends DHCP frames itself and takes UDP 67 -> 68
//! frames before the engine sees them.
//!
//! Every message is broadcast, renewals included (RFC 2131 § 4.4.5 allows
//! a broadcast REQUEST while rebinding; a unicast renewal would need the
//! server's link address). Transaction ids and jitter come from the
//! hardware RNG; without one the client falls back to the clock, which an
//! on-link attacker can guess (the static address stays usable either way).

use cambios_libsys as sys;
use cambios_netcore::dhcp::{ClientConfig, DhcpClient, Lease, Output};
use cambios_netcore::wire::dhcpv4;
use cambios_netcore::wire::frame::{self, Classified, Ipv4Route};
use cambios_netcore::wire::udp::UdpRepr;
use cambios_netcore::{Ipv4Address, MacAddress};

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;
/// ARCHITECTURAL: the one interface this stack serves.
const INTERFACE: u8 = 0;
/// TUNING: RFC 2131 § 4.1's suggested first retransmission interval.
const FIRST_RETRY_MS: u64 = 4_000;
/// TUNING: sends of one message before the phase gives up.
const MAX_ATTEMPTS: u8 = 4;
/// TUNING: RFC 2131 § 4.1 randomises each interval by +/- 1 s.
const JITTER_MS: i64 = 1_000;
/// TTL of DHCP frames (RFC 1700 default).
const TTL: u8 = 64;

/// What the client did with one received frame.
pub enum Seen {
    /// Not a DHCP reply: the engine's to handle.
    NotDhcp,
    /// A DHCP reply, consumed; maybe a frame to send and a lease to apply.
    Dhcp(Step),
}

/// One step's outcome for the shell.
#[derive(Default)]
pub struct Step {
    /// Octets of `out` to transmit, if any.
    pub send: Option<usize>,
    /// A lease the client accepted (xid, interface and chaddr checked).
    pub lease: Option<Lease>,
    /// The lease was lost (expired, or a NAK while renewing).
    pub lost: bool,
}

pub struct Dhcp {
    client: DhcpClient,
    mac: MacAddress,
    clock_xid: u32,
}

impl Dhcp {
    pub fn new(mac: MacAddress) -> Self {
        let config = ClientConfig { interface: INTERFACE, mac, pinned: None, first_retry_ms: FIRST_RETRY_MS, max_attempts: MAX_ATTEMPTS };
        Dhcp { client: DhcpClient::new(config), mac, clock_xid: 0 }
    }

    /// When the client next needs [`Dhcp::tick`].
    pub fn deadline(&self) -> Option<u64> {
        self.client.deadline()
    }

    pub fn start(&mut self, now: u64, out: &mut [u8]) -> Step {
        let (xid, jitter) = self.random(now);
        let o = self.client.start(now, xid, jitter);
        self.step(o, out)
    }

    pub fn tick(&mut self, now: u64, out: &mut [u8]) -> Step {
        let (xid, jitter) = self.random(now);
        let o = self.client.tick(now, xid, jitter);
        self.step(o, out)
    }

    /// Take a UDP 67 -> 68 frame, whoever it is addressed to.
    pub fn on_frame(&mut self, input: &[u8], now: u64, mtu: u16, out: &mut [u8]) -> Seen {
        let Ok(Classified::Ipv4Udp { datagram, .. }) = frame::classify(input, mtu) else { return Seen::NotDhcp };
        if datagram.source_port != SERVER_PORT || datagram.destination_port != CLIENT_PORT {
            return Seen::NotDhcp;
        }
        let step = match dhcpv4::parse(datagram.payload) {
            Ok(m) => {
                let o = self.client.on_message(INTERFACE, &m, now);
                self.step(o, out)
            }
            Err(_) => Step::default(), // malformed: consumed, nothing changes
        };
        Seen::Dhcp(step)
    }

    fn step(&mut self, o: Output, out: &mut [u8]) -> Step {
        match o {
            Output::Send(repr) => Step { send: self.frame(&repr, out), ..Step::default() },
            Output::LeaseAcquired(l) => Step { lease: Some(l), ..Step::default() },
            Output::LeaseLost => Step { lost: true, ..Step::default() },
            Output::Nothing | Output::Failed | Output::Ignored(_) => Step::default(),
        }
    }

    fn frame(&self, repr: &dhcpv4::DhcpRepr, out: &mut [u8]) -> Option<usize> {
        let mut payload = [0u8; 576];
        let n = dhcpv4::emit(repr, &mut payload).ok()?;
        let route = Ipv4Route {
            source_mac: self.mac,
            destination_mac: MacAddress::BROADCAST,
            source: repr.ciaddr,
            destination: Ipv4Address([255; 4]),
            ttl: TTL,
        };
        let udp = UdpRepr { source_port: CLIENT_PORT, destination_port: SERVER_PORT };
        frame::emit_ipv4_udp(&route, &udp, payload.get(..n)?, out).ok()
    }

    /// A transaction id and a jitter in [-JITTER_MS, JITTER_MS].
    fn random(&mut self, now: u64) -> (u32, i64) {
        let mut b = [0u8; 8];
        let (xid, j) = if sys::get_entropy(&mut b) == 8 {
            let [x0, x1, x2, x3, j0, j1, ..] = b;
            (u32::from_le_bytes([x0, x1, x2, x3]), u16::from_le_bytes([j0, j1]))
        } else {
            self.clock_xid = self.clock_xid.wrapping_add(0x9E37_79B9);
            let low = u32::try_from(now & 0xFFFF_FFFF).unwrap_or(0);
            (self.clock_xid ^ low, u16::try_from(now & 0xFFFF).unwrap_or(0))
        };
        let span = JITTER_MS.saturating_mul(2).saturating_add(1);
        (xid, i64::from(j).rem_euclid(span).saturating_sub(JITTER_MS))
    }
}
