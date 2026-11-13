// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Per-socket stream channels (ADR-039 § 3): two byte rings per TCP
//! socket, in the seam's two-channel shape.
//!
//! - **TX** (client → stack): created by the stack as `Consumer`; the
//!   client attaches it writable, initialises it, and writes the octets
//!   it wants sent. The stack reads it into `Op::Send` and publishes how
//!   far it read in its own page's `peer_tail`.
//! - **RX** (stack → client): created as `Producer`; the stack writes
//!   every in-order octet the engine delivers, the client attaches it
//!   read-only and publishes its progress in its TX page's `peer_tail`.
//!   What the client consumed becomes `Op::Consumed`, which reopens the
//!   TCP window. The ring holds `receive_window` octets, so a delivery
//!   always fits while the window accounting holds; one that does not is
//!   counted in `lost`, never hidden.
//!
//! `DATA_READY` (`[6][sock:4]`) goes to the endpoint the opening request
//! came from: once when the RX ring goes from empty to non-empty, and on
//! every state change.
//!
//! A stream outlives its engine socket: after `Closed` / `Reset` /
//! `Refused` / `Error` the client may still read what is in its RX ring,
//! and its `STATUS` reads `Closed`. The channels close when the client
//! sends `CLOSE` (after any octets still in its TX ring are handed to the
//! engine), when its page reads as the tombstone (it died), when it has
//! not attached within [`ATTACH_MS`], or when it breaks the ring protocol
//! (`chan.peer_violation` naming it).

use cambios_libsys as sys;
use cambios_net_proto as proto;
use cambios_netcore::engine::{Notify, Principal, SocketId};
use net_seam::mapped::{OwnPage, PeerPage};
use net_seam::{layout, ByteEndpoint, Health, RingError};

/// HARDWARE: CambiOS user mappings are 4 KiB pages.
const PAGE_SIZE: usize = 4096;
/// ARCHITECTURAL: `channel_create` roles (libsys `channel_create` docs).
const ROLE_PRODUCER: u32 = 0;
const ROLE_CONSUMER: u32 = 1;

/// The ring capacity, `proto::STREAM_PAGES` data pages.
pub const CAPACITY: u32 = proto::STREAM_PAGES * PAGE_SIZE as u32;
/// TUNING: octets read from one client's TX ring per `Op::Send`.
pub const SEND_CHUNK: usize = 2048;

/// How a stream ended for its client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// Still open in the engine.
    No,
    /// The engine socket is gone (closed, reset, refused, failed).
    Socket,
}

pub struct Stream {
    pub socket: SocketId,
    pub owner: Principal,
    reply_to: u32,
    tx_chan: u64,
    rx_chan: u64,
    /// RX: our page.
    own: OwnPage,
    /// TX: the client's page.
    peer: PeerPage,
    ep: ByteEndpoint,
    notify: bool,
    pub ended: Ended,
    /// Delivered octets that did not fit the RX ring (see module docs).
    pub lost: u32,
    /// The client's RX progress (`peer_tail`) already reported to the
    /// engine as `Op::Consumed`. Kept apart from the ring's own cached
    /// tail, which every write refreshes, so no consumption is reported
    /// twice or lost.
    credited: u32,
    /// The client's TX ring read as empty at the last look.
    pub drained: bool,
    /// The client sent `CLOSE` while its TX ring still held octets: the
    /// engine close waits until they are sent.
    pub closing: bool,
    /// When the stream was opened (ms), for the attach deadline.
    opened: u64,
}

/// TUNING: how long a client has to attach and initialise its TX page
/// after `CONNECT` / `ACCEPT` before its stream is dropped (a client
/// that exits first leaves an all-zero page that never reads as gone).
pub const ATTACH_MS: u64 = 10_000;

/// Why opening a stream failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Every stream slot is in use.
    Full,
    /// `channel_create` failed or a mapping was unusable.
    Channel,
}

/// What servicing one stream asks of the engine.
pub enum Want {
    Nothing,
    /// Send `buf[..n]`; then call [`Stream::sent`] with what was taken.
    Send(usize),
}

/// What the client's TX page told us.
pub enum Peer {
    Fine,
    /// The client is gone (its page is the tombstone).
    Gone,
    /// The client broke the ring protocol.
    Untrusted,
}

fn create(pages: u32, peer: &[u8; 32], role: u32) -> Option<(u64, *mut u8, usize)> {
    let mut vaddr: u64 = 0;
    let rc = sys::channel_create(pages, peer, role, &mut vaddr);
    if rc < 0 || vaddr == 0 {
        return None;
    }
    let len = usize::try_from(pages).ok()?.checked_mul(PAGE_SIZE)?;
    Some((rc as u64, vaddr as usize as *mut u8, len))
}

impl Stream {
    /// Create both channels with `owner` as their peer and initialise our
    /// RX page.
    #[allow(unsafe_code)] // The two page wraps below; each block is one call with its own SAFETY.
    fn open(socket: SocketId, owner: Principal, reply_to: u32, now: u64) -> Result<Stream, OpenError> {
        let pages = proto::STREAM_PAGES.checked_add(1).ok_or(OpenError::Channel)?;
        let (tx_chan, tx_base, tx_len) = create(pages, &owner.0, ROLE_CONSUMER).ok_or(OpenError::Channel)?;
        let Some((rx_chan, rx_base, rx_len)) = create(pages, &owner.0, ROLE_PRODUCER) else {
            sys::channel_close(tx_chan);
            return Err(OpenError::Channel);
        };
        let fail = || {
            sys::channel_close(tx_chan);
            sys::channel_close(rx_chan);
            Err(OpenError::Channel)
        };
        // SAFETY: `rx_base` is this process's writable mapping of the RX
        // channel just created as `Producer`, `rx_len` octets (`pages` ×
        // 4 KiB), zero-filled by the kernel; the client maps it read-only;
        // this `OwnPage` is its only writer here and no slice over it is
        // ever formed. After a revoke the kernel remaps it to this
        // process's scratch frame (ADR-007 Divergence 8), so a racing
        // write sinks instead of faulting.
        let Some(mut own) = (unsafe { OwnPage::from_raw(rx_base, rx_len) }) else {
            return fail();
        };
        // SAFETY: `tx_base` is this process's read-only mapping of the TX
        // channel just created as `Consumer`, `tx_len` octets, zero-filled;
        // after a revoke it is the zero tombstone, which reads `PeerGone`.
        // No slice over it is ever formed.
        let Some(peer) = (unsafe { PeerPage::from_raw(tx_base, tx_len) }) else {
            return fail();
        };
        let Ok(ep) = ByteEndpoint::new(&mut own, CAPACITY) else {
            return fail();
        };
        Ok(Stream {
            socket,
            owner,
            reply_to,
            tx_chan,
            rx_chan,
            own,
            peer,
            ep,
            notify: false,
            ended: Ended::No,
            lost: 0,
            credited: 0,
            drained: true,
            closing: false,
            opened: now,
        })
    }

    pub const fn channels(&self) -> (u64, u64) {
        (self.tx_chan, self.rx_chan)
    }

    /// Octets in the RX ring the client has not consumed (as of our last
    /// look at its page).
    pub const fn rx_avail(&self) -> u32 {
        self.ep.unread()
    }

    /// Free octets in the client's TX ring, as of our last read of it.
    pub fn tx_free(&self) -> u32 {
        CAPACITY.saturating_sub(self.ep.available())
    }

    /// Engine `Deliver` / `DeliverHeld`: append to the RX ring.
    pub fn deliver(&mut self, bytes: &[u8]) {
        // Read the client's progress first, so "was empty" is current.
        let _ = self.ep.write(&mut self.own, &self.peer, &[]);
        let was_empty = self.ep.unread() == 0;
        let n = self.ep.write(&mut self.own, &self.peer, bytes).unwrap_or(0);
        if n < bytes.len() {
            let short = u32::try_from(bytes.len().saturating_sub(n)).unwrap_or(u32::MAX);
            self.lost = self.lost.saturating_add(short);
        }
        if was_empty && n > 0 {
            self.notify = true;
        }
    }

    /// Engine `Notify`: a state change.
    pub fn notified(&mut self, what: Notify) {
        self.notify = true;
        let why: &[u8] = match what {
            Notify::Closed => b"closed",
            Notify::Reset => b"reset by the peer",
            Notify::Refused => b"refused by the peer",
            Notify::Error(_) => b"failed",
            Notify::Connected | Notify::DataReady | Notify::PeerClosed => return,
        };
        self.ended = Ended::Socket;
        sys::print(b"[NETSTACK] stream socket ");
        sys::print(why);
        sys::print(if self.lost == 0 { b"\n" as &[u8] } else { b" (octets lost: RX ring overrun)\n" });
    }

    /// Read the client's page: how many RX octets it consumed since the
    /// last call (for `Op::Consumed`), and whether it is still sane.
    pub fn refresh(&mut self, now: u64) -> (u32, Peer) {
        let peer = match self.ep.write(&mut self.own, &self.peer, &[]) {
            Err(RingError::PeerGone) => Peer::Gone,
            _ if self.ep.attach_overdue(self.opened, now, ATTACH_MS) => Peer::Gone,
            _ => self.judged(),
        };
        // Credit only forward progress within the ring: a client that
        // moves its tail backwards (it may write its page at will) gets
        // no window for it.
        let tail = self.ep.peer_tail();
        let advance = tail.wrapping_sub(self.credited);
        let freed = if advance <= CAPACITY && self.ep.unread() <= CAPACITY {
            self.credited = tail;
            advance
        } else {
            0
        };
        (freed, peer)
    }

    /// Copy the client's next unsent octets into `buf`.
    pub fn pending(&mut self, buf: &mut [u8; SEND_CHUNK]) -> (Want, Peer) {
        if self.ended != Ended::No {
            return (Want::Nothing, Peer::Fine);
        }
        let r = self.ep.peek(&mut self.own, &self.peer, buf);
        self.drained = r == Err(RingError::Empty);
        match r {
            Ok(n) => (Want::Send(n), Peer::Fine),
            Err(RingError::PeerGone) => (Want::Nothing, Peer::Gone),
            // Empty, or a lie counted with its span dropped: the
            // violation limit decides whether the client is cut off.
            Err(_) => (Want::Nothing, self.judged()),
        }
    }

    fn judged(&self) -> Peer {
        if self.ep.health() == Health::Untrusted {
            Peer::Untrusted
        } else {
            Peer::Fine
        }
    }

    /// The engine took `n` of the octets [`Stream::pending`] copied.
    pub fn sent(&mut self, n: u32) {
        // `n` never exceeds what was offered (`Op::Send` contract); a
        // refusal here would leave the octets to be offered again.
        let _ = self.ep.consume(&mut self.own, n);
    }

    /// Send `DATA_READY` if anything changed since the last one.
    pub fn flush(&mut self) {
        if core::mem::take(&mut self.notify) {
            let mut msg = [0u8; proto::MAX_MESSAGE];
            if let Ok(n) = (proto::ClientNotice::DataReady { sock: proto::Handle(self.socket.to_wire()) }).encode(&mut msg) {
                sys::write(self.reply_to, msg.get(..n).unwrap_or(&[]));
            }
        }
    }

    fn close(self, peer: Peer) {
        if let Peer::Untrusted = peer {
            // The client's control page is the TX channel: that close
            // carries the reason, so the kernel names the client.
            sys::channel_close_peer_violation(self.tx_chan);
        } else {
            sys::channel_close(self.tx_chan);
        }
        sys::channel_close(self.rx_chan);
    }
}

/// TUNING: accepted-but-not-yet-`ACCEPT`ed sockets whose early octets
/// can be held, one receive window each (ADR-039 § 8 backlog is per
/// listener; 4 covers the probe and one server at a time).
/// Replace when: a server needs a deeper accept backlog with data.
const PRE_ACCEPT: usize = 4;

/// Octets an accepted connection's peer sent before its owner's
/// `ACCEPT`: the engine has acknowledged them, so they are held here and
/// written to the RX ring when the stream is opened.
struct Held {
    socket: SocketId,
    len: usize,
    buf: alloc::boxed::Box<[u8]>,
}

/// TUNING: recently client-closed sockets remembered so late octets for
/// them are dropped instead of held (one per stream slot).
const ORPHANS: usize = crate::SOCKETS;

/// Every open stream, one slot per possible engine socket.
pub struct Streams {
    slots: [Option<Stream>; crate::SOCKETS],
    /// The next ephemeral port to try for `CONNECT`.
    next_port: u16,
    held: [Option<Held>; PRE_ACCEPT],
    orphans: [Option<SocketId>; ORPHANS],
    next_orphan: usize,
    /// Octets that arrived for a socket with no stream and no free hold
    /// slot (acknowledged by TCP, then lost; counted, never hidden).
    pub held_lost: u32,
}

/// ARCHITECTURAL: the IANA dynamic port range (RFC 6335 § 6).
const EPHEMERAL_FIRST: u16 = 49_152;
const EPHEMERAL_COUNT: u16 = 16_384;

impl Streams {
    /// `seed` picks where in the dynamic range the ports start (RFC 6056
    /// § 3.3.2's simple-increment algorithm from a random offset).
    pub fn new(seed: u16) -> Self {
        Streams {
            slots: core::array::from_fn(|_| None),
            next_port: seed % EPHEMERAL_COUNT,
            held: core::array::from_fn(|_| None),
            orphans: [None; ORPHANS],
            next_orphan: 0,
            held_lost: 0,
        }
    }

    /// The next ephemeral port, in [`EPHEMERAL_FIRST`] ..= 65535.
    pub fn ephemeral(&mut self) -> u16 {
        let p = EPHEMERAL_FIRST.wrapping_add(self.next_port % EPHEMERAL_COUNT);
        self.next_port = (self.next_port.wrapping_add(1)) % EPHEMERAL_COUNT;
        p
    }

    pub fn open(&mut self, socket: SocketId, owner: Principal, reply_to: u32, now: u64) -> Result<(u64, u64), OpenError> {
        let Some(slot) = self.slots.iter().position(Option::is_none) else {
            self.forget(socket);
            return Err(OpenError::Full);
        };
        let mut s = match Stream::open(socket, owner, reply_to, now) {
            Ok(s) => s,
            Err(e) => {
                self.forget(socket);
                return Err(e);
            }
        };
        if let Some(h) = self.held.iter_mut().find(|h| h.as_ref().is_some_and(|h| h.socket == socket)).and_then(Option::take) {
            s.deliver(h.buf.get(..h.len).unwrap_or(&[]));
        }
        let chans = s.channels();
        if let Some(free) = self.slots.get_mut(slot) {
            *free = Some(s);
        }
        Ok(chans)
    }

    /// Octets for `socket`, which has no stream: hold them for its
    /// `ACCEPT`, unless its client already closed it.
    pub fn hold(&mut self, socket: SocketId, bytes: &[u8]) {
        if self.orphans.contains(&Some(socket)) {
            return;
        }
        let mut at = self.held.iter().position(|h| h.as_ref().is_some_and(|h| h.socket == socket));
        if at.is_none() {
            at = self.held.iter().position(Option::is_none);
            if let Some(slot) = at.and_then(|i| self.held.get_mut(i)) {
                let cap = usize::try_from(CAPACITY).unwrap_or(0);
                *slot = Some(Held { socket, len: 0, buf: alloc::vec![0u8; cap].into_boxed_slice() });
            }
        }
        let kept = match at.and_then(|i| self.held.get_mut(i)).and_then(Option::as_mut) {
            Some(h) => {
                let n = bytes.len().min(h.buf.len().saturating_sub(h.len));
                if let (Some(dst), Some(src)) = (h.buf.get_mut(h.len..h.len.saturating_add(n)), bytes.get(..n)) {
                    dst.copy_from_slice(src);
                    h.len = h.len.saturating_add(n);
                }
                n
            }
            None => 0,
        };
        let lost = u32::try_from(bytes.len().saturating_sub(kept)).unwrap_or(u32::MAX);
        if lost > 0 {
            sys::print(b"[NETSTACK] octets for an unaccepted connection lost: no free hold slot\n");
        }
        self.held_lost = self.held_lost.saturating_add(lost);
    }

    /// A socket with no stream ended: forget anything held or remembered.
    pub fn forget(&mut self, socket: SocketId) {
        for h in self.held.iter_mut() {
            if h.as_ref().is_some_and(|h| h.socket == socket) {
                *h = None;
            }
        }
        for o in self.orphans.iter_mut() {
            if *o == Some(socket) {
                *o = None;
            }
        }
    }

    pub fn get(&mut self, socket: SocketId) -> Option<&mut Stream> {
        self.slots.iter_mut().flatten().find(|s| s.socket == socket)
    }

    pub fn slot(&mut self, i: usize) -> Option<&mut Stream> {
        self.slots.get_mut(i).and_then(Option::as_mut)
    }

    /// Close slot `i`'s channels and free it; `peer` names why.
    pub fn close_slot(&mut self, i: usize, peer: Peer) {
        if let Some(s) = self.slots.get_mut(i).and_then(Option::take) {
            if let Some(o) = self.orphans.get_mut(self.next_orphan) {
                *o = Some(s.socket);
            }
            self.next_orphan = self.next_orphan.wrapping_add(1) % ORPHANS;
            s.close(peer);
        }
    }
}

/// Octet offsets in this module assume the control block is one page.
const _: () = assert!(layout::CONTROL_LEN == PAGE_SIZE);
