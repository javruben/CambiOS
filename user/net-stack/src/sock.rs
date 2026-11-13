// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Socket control on ep 34 (ADR-039 § 3), decoded and encoded by
//! `cambios-net-proto`, and the per-socket stream channels it hands out
//! ([`crate::stream`]).
//!
//! Every request reaches the engine as the kernel-stamped sender's
//! Principal, so ownership (`DENIED` on another's handle) is the
//! engine's rule; for a stream whose engine socket has already ended,
//! the stream's recorded owner is checked here instead.
//!
//! A socket is handed out only with its channels: if they cannot be
//! created the engine socket is closed again and the open is refused
//! (`FULL` when every stream slot is taken, `ERROR` otherwise). Without
//! a hardware RNG the engine has no RFC 6528 key and refuses the opens
//! itself.

use cambios_net_proto as proto;
use cambios_net_proto::{Address, ConfigReply, ConnectReply, Family, Handle, ListenReply, SockRequest, Status, StatusOnly, StatusReply, TcpState as WireState};
use cambios_netcore::engine::{Control, ControlReply, ListenerId, Op, Principal, SocketId, SocketState};
use cambios_netcore::tcp::TcpState;
use cambios_netcore::{IpAddress, Ipv4Address, NetError, SocketAddress};

use crate::compat::Engine;
use crate::stream::{Ended, OpenError, Peer, Streams, Want};

/// The engine plus the streams it delivers into.
pub trait Streamed: Engine {
    fn streams(&mut self) -> &mut Streams;
    /// The clock in ms (the step's `now`).
    fn now_ms(&self) -> u64;
}

/// The interface as `GET_CONFIG` reports it.
pub struct Local {
    pub ipv4: Ipv4Address,
    pub prefix_len: u8,
    pub gateway: Ipv4Address,
    pub mac: [u8; 6],
}

/// The status byte for an engine refusal.
pub fn status_of(e: NetError) -> Status {
    match e {
        NetError::Denied => Status::Denied,
        NetError::AddressInUse => Status::Busy,
        NetError::ResourceLimit => Status::Full,
        NetError::Closed => Status::BadState,
        NetError::WouldBlock => Status::NoData,
        NetError::NetworkDown | NetError::NoAddress => Status::NoDevice,
        NetError::NoRoute | NetError::NoListener | NetError::TimedOut | NetError::Malformed | NetError::Unsupported => Status::Error,
    }
}

fn refused(r: Option<ControlReply>) -> Status {
    match r {
        Some(ControlReply::Refused(e)) => status_of(e),
        _ => Status::Error,
    }
}

/// The RFC 4022 number of an engine state. `Resolving` (no SYN sent yet,
/// waiting on ARP) reads as `SynSent`: to the client the open is under
/// way either way.
fn wire_state(s: SocketState) -> WireState {
    match s {
        SocketState::Resolving => WireState::SynSent,
        SocketState::Tcp(t) => match t {
            TcpState::Closed => WireState::Closed,
            TcpState::Listen => WireState::Listen,
            TcpState::SynSent => WireState::SynSent,
            TcpState::SynReceived => WireState::SynReceived,
            TcpState::Established => WireState::Established,
            TcpState::FinWait1 => WireState::FinWait1,
            TcpState::FinWait2 => WireState::FinWait2,
            TcpState::CloseWait => WireState::CloseWait,
            TcpState::Closing => WireState::Closing,
            TcpState::LastAck => WireState::LastAck,
            TcpState::TimeWait => WireState::TimeWait,
        },
    }
}

/// Give a newly opened engine socket its stream channels, or close it.
fn open_stream(eng: &mut impl Streamed, from: Principal, reply_to: u32, socket: SocketId) -> Result<(u64, u64), Status> {
    let now = eng.now_ms();
    match eng.streams().open(socket, from, reply_to, now) {
        Ok(chans) => Ok(chans),
        Err(e) => {
            let _ = eng.control(Control { from, op: Op::Close { socket } });
            Err(match e {
                OpenError::Full => Status::Full,
                OpenError::Channel => Status::Error,
            })
        }
    }
}

/// TUNING: `Op::Send` calls per stream per pump, so one client's full
/// ring cannot hold the loop (2 KiB each: a 16 KiB ring in one pump).
const SENDS_PER_PUMP: usize = 8;

/// Move what the client of stream slot `i` wrote into the engine.
fn pump(eng: &mut impl Streamed, i: usize) -> Peer {
    let mut buf = [0u8; crate::stream::SEND_CHUNK];
    for _ in 0..SENDS_PER_PUMP {
        let Some(s) = eng.streams().slot(i) else { return Peer::Fine };
        let (owner, socket) = (s.owner, s.socket);
        let (want, peer) = s.pending(&mut buf);
        let Want::Send(n) = want else { return peer };
        let Some(data) = buf.get(..n) else { return Peer::Fine };
        match eng.control(Control { from: owner, op: Op::Send { socket, data } }) {
            Some(ControlReply::Sent(k)) => {
                if let Some(s) = eng.streams().slot(i) {
                    s.sent(k);
                }
                if usize::try_from(k).ok() != Some(n) {
                    return Peer::Fine; // the send buffer is full
                }
            }
            // WouldBlock (buffer full) or a socket not yet able to send:
            // the octets stay in the ring for a later pass.
            _ => return Peer::Fine,
        }
    }
    Peer::Fine
}

/// One pass over every stream: report what clients consumed, send what
/// they wrote, ring their `DATA_READY`, finish a `CLOSE` that waited for
/// its TX ring, and
/// drop a client that died, lied, or never attached.
pub fn service(eng: &mut impl Streamed) {
    let now = eng.now_ms();
    for i in 0..crate::SOCKETS {
        let Some(s) = eng.streams().slot(i) else { continue };
        let (owner, socket, ended) = (s.owner, s.socket, s.ended);
        let (freed, mut peer) = s.refresh(now);
        if freed > 0 && ended == Ended::No {
            let _ = eng.control(Control { from: owner, op: Op::Consumed { socket, octets: freed } });
        }
        if let Peer::Fine = peer {
            peer = pump(eng, i);
        }
        match peer {
            Peer::Fine => {
                let mut done = false;
                if let Some(s) = eng.streams().slot(i) {
                    s.flush();
                    done = s.closing && (s.drained || s.ended != Ended::No);
                }
                if done {
                    finish_close(eng, i, owner, socket, ended);
                }
            }
            Peer::Gone | Peer::Untrusted => {
                cambios_libsys::print(if let Peer::Untrusted = peer {
                    b"[NETSTACK] stream dropped: client broke the ring protocol (chan.peer_violation)\n" as &[u8]
                } else {
                    b"[NETSTACK] stream dropped: client gone (tombstone) or never attached\n"
                });
                if ended == Ended::No {
                    let _ = eng.control(Control { from: owner, op: Op::Close { socket } });
                }
                eng.streams().close_slot(i, peer);
            }
        }
    }
}

/// Serve one ep 34 request into `resp`; the reply length, or `None` for
/// `DOORBELL` (no reply). A request that does not decode is answered
/// `ERROR`. `reply_to` is where the client's `DATA_READY` notices go.
pub fn serve(eng: &mut impl Streamed, from: Principal, reply_to: u32, req: &[u8], resp: &mut [u8; proto::MAX_MESSAGE], local: &Local) -> Option<usize> {
    let encoded = match SockRequest::decode(req) {
        Err(_) => StatusOnly(Status::Error).encode(resp),
        Ok(SockRequest::Doorbell { sock }) => {
            let socket = SocketId::from_wire(sock.0);
            if let Some(i) = slot_of(eng, from, socket) {
                // Peer trouble is acted on by the next `service` pass.
                let _ = pump(eng, i);
            }
            return None;
        }
        Ok(SockRequest::Connect { remote, port }) => {
            let address = match remote {
                Address::V4(o) => IpAddress::V4(Ipv4Address(o)),
                Address::V6(_) => return StatusOnly(Status::Error).encode(resp).ok(),
            };
            // TUNING: ports tried before giving up on a busy range.
            const PORT_TRIES: usize = 8;
            let mut r = None;
            for _ in 0..PORT_TRIES {
                let local_port = eng.streams().ephemeral();
                let op = Op::Connect { remote: SocketAddress { address, port }, local_port };
                r = eng.control(Control { from, op });
                if r != Some(ControlReply::Refused(NetError::AddressInUse)) {
                    break;
                }
            }
            match r {
                Some(ControlReply::Socket(socket)) => match open_stream(eng, from, reply_to, socket) {
                    Ok((tx_chan, rx_chan)) => ConnectReply { status: Status::Ok, sock: Handle(socket.to_wire()), tx_chan, rx_chan }.encode(resp),
                    Err(st) => ConnectReply::refused(st).encode(resp),
                },
                r => ConnectReply::refused(refused(r)).encode(resp),
            }
        }
        Ok(SockRequest::Listen { port }) => match eng.control(Control { from, op: Op::Listen { port } }) {
            Some(ControlReply::Listener(listener)) => ListenReply { status: Status::Ok, listener: Handle(listener.to_wire()) }.encode(resp),
            r => ListenReply::refused(refused(r)).encode(resp),
        },
        Ok(SockRequest::Accept { listener }) => {
            let op = Op::Accept { listener: ListenerId::from_wire(listener.0) };
            match eng.control(Control { from, op }) {
                Some(ControlReply::NoData) => proto::AcceptReply::refused(Status::NoData).encode(resp),
                Some(ControlReply::Accepted { socket, peer }) => {
                    // The engine is IPv4-only (ADR-039 § 5.3).
                    let IpAddress::V4(ip) = peer.address else {
                        let _ = eng.control(Control { from, op: Op::Close { socket } });
                        return proto::AcceptReply::refused(Status::Error).encode(resp).ok();
                    };
                    match open_stream(eng, from, reply_to, socket) {
                        Ok((tx_chan, rx_chan)) => proto::AcceptReply {
                            status: Status::Ok,
                            sock: Handle(socket.to_wire()),
                            tx_chan,
                            rx_chan,
                            peer: Address::V4(ip.0),
                            peer_port: peer.port,
                        }
                        .encode(resp),
                        Err(st) => proto::AcceptReply::refused(st).encode(resp),
                    }
                }
                r => proto::AcceptReply::refused(refused(r)).encode(resp),
            }
        }
        Ok(SockRequest::Close { handle }) => {
            let socket = SocketId::from_wire(handle.0);
            match slot_of(eng, from, socket) {
                Some(i) => {
                    // What the client wrote before closing goes out first;
                    // what does not fit the send buffer yet is sent by
                    // later passes, and the engine close follows it.
                    let _ = pump(eng, i);
                    let state = eng.streams().slot(i).map(|s| (s.ended, s.drained));
                    match state {
                        Some((Ended::No, false)) => {
                            if let Some(s) = eng.streams().slot(i) {
                                s.closing = true;
                            }
                        }
                        Some((ended, _)) => finish_close(eng, i, from, socket, ended),
                        None => {}
                    }
                    StatusOnly(Status::Ok).encode(resp)
                }
                // Not a stream of this Principal's: a listener, or refused.
                None => match eng.control(Control { from, op: Op::Unlisten { listener: ListenerId::from_wire(handle.0) } }) {
                    Some(ControlReply::Done) => StatusOnly(Status::Ok).encode(resp),
                    r => StatusOnly(stream_denied(eng, socket).unwrap_or_else(|| refused(r))).encode(resp),
                },
            }
        }
        Ok(SockRequest::Status { sock }) => {
            let socket = SocketId::from_wire(sock.0);
            match slot_of(eng, from, socket) {
                Some(i) => {
                    let ended = eng.streams().slot(i).map(|s| s.ended);
                    let state = match ended {
                        Some(Ended::No) => match eng.control(Control { from, op: Op::Status { socket } }) {
                            Some(ControlReply::State(st)) => Ok(wire_state(st)),
                            r => Err(refused(r)),
                        },
                        _ => Ok(WireState::Closed),
                    };
                    match (state, eng.streams().slot(i)) {
                        (Ok(state), Some(s)) => StatusReply { status: Status::Ok, state, rx_avail: s.rx_avail(), tx_free: s.tx_free() }.encode(resp),
                        (Err(st), _) => StatusReply::refused(st).encode(resp),
                        (Ok(_), None) => StatusReply::refused(Status::Error).encode(resp),
                    }
                }
                None => {
                    let st = stream_denied(eng, socket).unwrap_or_else(|| refused(eng.control(Control { from, op: Op::Status { socket } })));
                    StatusReply::refused(st).encode(resp)
                }
            }
        }
        Ok(SockRequest::GetConfig { family: Family::V4 }) => ConfigReply {
            status: Status::Ok,
            address: Address::V4(local.ipv4.0),
            prefix_len: local.prefix_len,
            gateway: Address::V4(local.gateway.0),
            mac: local.mac,
        }
        .encode(resp),
        // The engine is IPv4-only (ADR-039 § 5.3).
        Ok(SockRequest::GetConfig { family: Family::V6 }) => ConfigReply::refused(Status::NoDevice).encode(resp),
    };
    Some(encoded.unwrap_or_else(|_| {
        resp[0] = Status::Error as u8;
        1
    }))
}

/// Close the engine socket (if it still exists) and the stream's channels.
fn finish_close(eng: &mut impl Streamed, i: usize, owner: Principal, socket: SocketId, ended: Ended) {
    if ended == Ended::No {
        let _ = eng.control(Control { from: owner, op: Op::Close { socket } });
    }
    eng.streams().close_slot(i, Peer::Fine);
}

/// The stream slot of `socket` if `from` owns it.
fn slot_of(eng: &mut impl Streamed, from: Principal, socket: SocketId) -> Option<usize> {
    (0..crate::SOCKETS).find(|&i| eng.streams().slot(i).is_some_and(|s| s.socket == socket && s.owner == from))
}

/// `DENIED` if `socket` is someone else's stream.
fn stream_denied(eng: &mut impl Streamed, socket: SocketId) -> Option<Status> {
    eng.streams().get(socket).map(|_| Status::Denied)
}
