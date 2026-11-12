// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The ep 21 UDP surface, kept from `udp-stack` as a compatibility
//! surface (ADR-039 § 3: IPv4-only layouts, status 0 OK, 1 ERROR,
//! 2 NO_DATA):
//!
//! ```text
//! 1 UDP_SEND   [dst_ip:4][dst_port:2][src_port:2][payload:N] -> [status]
//! 2 UDP_RECV   [port:2] -> [status][src_ip:4][src_port:2][payload:N]
//! 3 GET_CONFIG -> [status][ip:4][mac:6]
//! 4 SET_CONFIG [ip:4][gateway:4][netmask:4] -> [status]
//! 5 DHCP_SEND  [src_port:2][dst_port:2][payload:N] -> [status]
//! ```
//!
//! Where it differs from udp-stack, and why:
//! - A port belongs to the Principal that first sends from or receives
//!   on it (engine ownership, ADR-039 § 1); another Principal's
//!   `UDP_SEND` from it or `UDP_RECV` on it is `ERROR`. udp-stack had no
//!   owner and handed any datagram to any `UDP_RECV`.
//! - `UDP_RECV` returns datagrams that arrived for that port only, and
//!   the first `UDP_RECV` on a port opens it (`NO_DATA`).
//! - A datagram longer than the reply holds (249 octets) is cut to fit,
//!   as udp-stack cut it; the reply has no length field to say so.
//! - `SET_CONFIG` and `DHCP_SEND` answer `ERROR`, on purpose. Why: the
//!   stack runs the DHCP client itself and applies an accepted lease
//!   through the engine (`dhcp.rs`, codex D1); the interface address is
//!   engine-owned state, never something a client sets. No manifest
//!   service sends either command.
//!   Revisit when: an ADR gives some client authority over the address.

use cambios_libsys as sys;
use cambios_netcore::engine::{Control, ControlReply, Instant, Op, Principal, UdpId};
use cambios_netcore::{IpAddress, Ipv4Address, NetError, SocketAddress};

const CMD_UDP_SEND: u8 = 1;
const CMD_UDP_RECV: u8 = 2;
const CMD_GET_CONFIG: u8 = 3;
const CMD_SET_CONFIG: u8 = 4;
const CMD_DHCP_SEND: u8 = 5;

const OK: u8 = 0;
const ERROR: u8 = 1;
const NO_DATA: u8 = 2;

/// ARCHITECTURAL: the `UDP_RECV` reply header, `[status][ip:4][port:2]`.
const RECV_HEADER: usize = 7;
/// ARCHITECTURAL: the most payload one `UDP_RECV` reply carries.
pub const MAX_PAYLOAD: usize = cambios_net_proto::MAX_MESSAGE - RECV_HEADER;

/// SCAFFOLDING: ports open on ep 21 at once (the engine has `UDP`
/// endpoints; NTP holds one). The least recently used idle port is
/// closed to make room, since the protocol has no close.
/// Replace when: the engine's `UDP` bound grows (ADR-039 § 8).
const PORTS: usize = 3;
/// TUNING: datagrams held per port until `UDP_RECV`; one more drops the
/// oldest, which is counted.
const QUEUE: usize = 4;
/// TUNING: `UDP_SEND`s waiting for ARP at once; one more is `ERROR`.
const PENDING: usize = 4;
/// TUNING: how long a send may wait for its next hop (udp-stack's ARP
/// wait was the same order: three 1 s questions).
const SEND_WAIT_MS: u64 = 3_000;
/// TUNING: how often a waiting send is retried.
const SEND_RETRY_MS: u64 = 200;

#[derive(Clone, Copy)]
struct Datagram {
    from: [u8; 4],
    port: u16,
    len: u16,
    data: [u8; MAX_PAYLOAD],
}

struct Port {
    owner: Principal,
    port: u16,
    id: UdpId,
    queue: [Option<Datagram>; QUEUE],
    head: usize,
    len: usize,
    last_used: u64,
}

struct Pending {
    reply_to: u32,
    owner: Principal,
    id: UdpId,
    remote: SocketAddress,
    len: u16,
    data: [u8; cambios_net_proto::MAX_MESSAGE],
    deadline: u64,
    next_try: u64,
}

pub struct Compat {
    ports: [Option<Port>; PORTS],
    pending: [Option<Pending>; PENDING],
    /// Datagrams dropped because a port's queue was full.
    pub queue_drops: u64,
}

/// How a request was answered.
pub enum Served {
    /// Send `resp[..n]` back now.
    Reply(usize),
    /// The answer waits on ARP; [`Compat::retry`] sends it.
    Later,
}

type Resp = [u8; cambios_net_proto::MAX_MESSAGE];

/// The engine, as the compat layer needs it: one control step, its
/// reply (`None`: the engine refused the step as a whole).
pub trait Engine {
    fn control(&mut self, c: Control<'_>) -> Option<ControlReply>;
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

impl Compat {
    pub fn new() -> Compat {
        Compat { ports: [const { None }; PORTS], pending: [const { None }; PENDING], queue_drops: 0 }
    }

    /// The open port `port`, opening it for `owner` if nobody holds it.
    /// `None`: another Principal holds it, or no slot or endpoint is free.
    fn open(&mut self, eng: &mut impl Engine, owner: Principal, port: u16, now: Instant) -> Option<usize> {
        if let Some(i) = self.ports.iter().position(|p| matches!(p, Some(p) if p.port == port)) {
            let p = self.ports[i].as_mut()?;
            if p.owner != owner {
                return None;
            }
            p.last_used = now.0;
            return Some(i);
        }
        let slot = match self.ports.iter().position(Option::is_none) {
            Some(i) => i,
            None => self.evict(eng)?,
        };
        let Some(ControlReply::Endpoint(id)) = eng.control(Control { from: owner, op: Op::UdpBind { port } }) else {
            return None;
        };
        self.ports[slot] = Some(Port { owner, port, id, queue: [None; QUEUE], head: 0, len: 0, last_used: now.0 });
        Some(slot)
    }

    /// Close the least recently used port with nothing queued or waiting.
    fn evict(&mut self, eng: &mut impl Engine) -> Option<usize> {
        let busy = |id: UdpId| self.pending.iter().flatten().any(|s| s.id == id);
        let i = self
            .ports
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.as_ref().map(|p| (i, p)))
            .filter(|(_, p)| p.len == 0 && !busy(p.id))
            .min_by_key(|(_, p)| p.last_used)
            .map(|(i, _)| i)?;
        let p = self.ports[i].take()?;
        let _ = eng.control(Control { from: p.owner, op: Op::UdpUnbind { endpoint: p.id } });
        Some(i)
    }

    /// One datagram the engine delivered; `false` if it is not ep 21's.
    pub fn deliver(&mut self, id: UdpId, from: SocketAddress, payload: &[u8]) -> bool {
        let Some(p) = self.ports.iter_mut().flatten().find(|p| p.id == id) else {
            return false;
        };
        let IpAddress::V4(Ipv4Address(src)) = from.address else {
            return true; // ep 21 is IPv4-only; nothing to hand over
        };
        let n = payload.len().min(MAX_PAYLOAD);
        let mut d = Datagram { from: src, port: from.port, len: n as u16, data: [0; MAX_PAYLOAD] };
        if let (Some(dst), Some(src)) = (d.data.get_mut(..n), payload.get(..n)) {
            dst.copy_from_slice(src);
        }
        if p.len == QUEUE {
            // Full: drop the oldest, keep the newest.
            p.queue[p.head] = None;
            p.head = (p.head + 1) % QUEUE;
            p.len -= 1;
            self.queue_drops = self.queue_drops.saturating_add(1);
        }
        p.queue[(p.head + p.len) % QUEUE] = Some(d);
        p.len += 1;
        true
    }

    /// Serve one ep 21 request into `resp`.
    #[allow(clippy::too_many_arguments)]
    pub fn serve(&mut self, eng: &mut impl Engine, owner: Principal, reply_to: u32, req: &[u8], resp: &mut Resp, local: (Ipv4Address, [u8; 6]), now: Instant) -> Served {
        let Some((&cmd, data)) = req.split_first() else {
            return status(resp, ERROR);
        };
        match cmd {
            CMD_UDP_SEND => self.send(eng, owner, reply_to, data, resp, now),
            CMD_UDP_RECV => self.recv(eng, owner, data, resp, now),
            CMD_GET_CONFIG => {
                let (ip, mac) = local;
                resp[0] = OK;
                resp[1..5].copy_from_slice(&ip.0);
                resp[5..11].copy_from_slice(&mac);
                Served::Reply(11)
            }
            CMD_SET_CONFIG | CMD_DHCP_SEND => status(resp, ERROR),
            _ => status(resp, ERROR),
        }
    }

    fn send(&mut self, eng: &mut impl Engine, owner: Principal, reply_to: u32, data: &[u8], resp: &mut Resp, now: Instant) -> Served {
        let (Some(ip), Some(dst_port), Some(src_port), Some(payload)) =
            (data.get(..4), be16(data, 4), be16(data, 6), data.get(8..))
        else {
            return status(resp, ERROR);
        };
        let remote = SocketAddress { address: IpAddress::V4(Ipv4Address([ip[0], ip[1], ip[2], ip[3]])), port: dst_port };
        let Some(i) = self.open(eng, owner, src_port, now) else {
            return status(resp, ERROR);
        };
        let Some(id) = self.ports[i].as_ref().map(|p| p.id) else {
            return status(resp, ERROR);
        };
        match eng.control(Control { from: owner, op: Op::UdpSend { endpoint: id, remote, payload } }) {
            Some(ControlReply::Done) => status(resp, OK),
            Some(ControlReply::Refused(NetError::WouldBlock)) => {
                let Some(slot) = self.pending.iter().position(Option::is_none) else {
                    return status(resp, ERROR);
                };
                // A request is at most MAX_MESSAGE octets, so this fits.
                let mut buf = [0u8; cambios_net_proto::MAX_MESSAGE];
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                self.pending[slot] = Some(Pending {
                    reply_to,
                    owner,
                    id,
                    remote,
                    len: n as u16,
                    data: buf,
                    deadline: now.0.saturating_add(SEND_WAIT_MS),
                    next_try: now.0.saturating_add(SEND_RETRY_MS),
                });
                Served::Later
            }
            _ => status(resp, ERROR),
        }
    }

    fn recv(&mut self, eng: &mut impl Engine, owner: Principal, data: &[u8], resp: &mut Resp, now: Instant) -> Served {
        let Some(port) = be16(data, 0) else {
            return status(resp, ERROR);
        };
        let Some(i) = self.open(eng, owner, port, now) else {
            return status(resp, ERROR);
        };
        let Some(p) = self.ports[i].as_mut() else {
            return status(resp, ERROR);
        };
        let Some(d) = p.queue[p.head].take().filter(|_| p.len > 0) else {
            return status(resp, NO_DATA);
        };
        p.head = (p.head + 1) % QUEUE;
        p.len -= 1;
        // `d.len` <= MAX_PAYLOAD, so the reply fits MAX_MESSAGE.
        let n = usize::from(d.len);
        resp[0] = OK;
        resp[1..5].copy_from_slice(&d.from);
        resp[5..7].copy_from_slice(&d.port.to_be_bytes());
        resp[RECV_HEADER..RECV_HEADER + n].copy_from_slice(&d.data[..n]);
        Served::Reply(RECV_HEADER + n)
    }

    /// Retry sends that waited on ARP; each that finishes is answered.
    pub fn retry(&mut self, eng: &mut impl Engine, now: Instant) {
        for slot in &mut self.pending {
            let Some(s) = slot.as_mut() else { continue };
            let verdict = if now.0 >= s.deadline {
                Some(ERROR)
            } else if now.0 < s.next_try {
                None
            } else {
                s.next_try = now.0.saturating_add(SEND_RETRY_MS);
                let payload = s.data.get(..usize::from(s.len)).unwrap_or(&[]);
                match eng.control(Control { from: s.owner, op: Op::UdpSend { endpoint: s.id, remote: s.remote, payload } }) {
                    Some(ControlReply::Done) => Some(OK),
                    Some(ControlReply::Refused(NetError::WouldBlock)) => None,
                    _ => Some(ERROR),
                }
            };
            if let Some(v) = verdict {
                sys::write(s.reply_to, &[v]);
                *slot = None;
            }
        }
    }
}

fn status(resp: &mut Resp, s: u8) -> Served {
    resp[0] = s;
    Served::Reply(1)
}
