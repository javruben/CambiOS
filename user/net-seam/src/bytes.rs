// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The byte ring of a per-socket stream channel pair (ADR-039 § 3, § 4).
//!
//! The same control page as the frame ring, with `slot_size = 0` and
//! `slot_count` read as the ring's capacity in octets (a power of two).
//! `head` counts octets this side produced into its own page and
//! `peer_tail` octets it consumed from the other page; both are
//! free-running `u32`s, and an octet index maps to
//! `CONTROL_LEN + (index & (capacity - 1))`. A write or read that runs
//! past the end of the ring wraps to its start.
//!
//! The peer is hostile exactly as in the frame ring: each field is read
//! once and judged, a peer `peer_tail` claiming more consumed than was
//! produced makes the ring read as full (counted), a peer `head` more
//! than `capacity` ahead drops the untrusted span (counted), and at
//! [`PEER_VIOLATION_LIMIT`] every operation is `PeerUntrusted`.
//!
//! # A peer that has not attached yet
//!
//! A stream channel pair is created by the stack and handed to the
//! client in the `CONNECT` / `ACCEPT` reply, so the stack writes into
//! its ring before the client has attached and initialised its own page.
//! An all-zero peer page is therefore read two ways: before this endpoint
//! has ever seen a valid peer page it is "not attached yet" (a write
//! judges free space by the start index, a read is `Empty`); once a valid
//! page has been seen, all-zero is the ADR-007 tombstone (`PeerGone`).
//! ASSUMPTION: a client never un-initialises its page except by dying
//! (ADR-039 § 3 leaves the attach window unstated).

use crate::{layout, ControlError, Health, Page, PageMut, RingError, PEER_VIOLATION_LIMIT};

/// ARCHITECTURAL: a byte ring's `slot_size` field (ADR-039 § 4).
pub const BYTE_SLOT_SIZE: u32 = 0;

/// A validated byte ring shape: its capacity in octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteGeometry {
    capacity: u32,
}

impl ByteGeometry {
    pub const fn capacity(self) -> u32 {
        self.capacity
    }

    /// Byte offset in the page of ring index `index`.
    fn offset(self, index: u32) -> Option<usize> {
        let at = index & self.capacity.wrapping_sub(1);
        usize::try_from(at).ok()?.checked_add(layout::CONTROL_LEN)
    }

    /// The two page spans `[index, index + len)` occupies, the second
    /// empty unless the span wraps. `len <= capacity`.
    fn spans(self, index: u32, len: usize) -> Option<((usize, usize), (usize, usize))> {
        let cap = usize::try_from(self.capacity).ok()?;
        let at = usize::try_from(index & self.capacity.wrapping_sub(1)).ok()?;
        let first = len.min(cap.checked_sub(at)?);
        let rest = len.checked_sub(first)?;
        Some(((self.offset(index)?, first), (layout::CONTROL_LEN, rest)))
    }
}

fn byte_geometry_for(capacity: u32, page_len: usize) -> Result<ByteGeometry, ControlError> {
    if !capacity.is_power_of_two() {
        return Err(ControlError::BadSlotCount);
    }
    let need = usize::try_from(capacity).ok().and_then(|n| n.checked_add(layout::CONTROL_LEN)).ok_or(ControlError::PageTooSmall)?;
    if need > page_len {
        return Err(ControlError::PageTooSmall);
    }
    Ok(ByteGeometry { capacity })
}

/// Validate a byte-ring control block, reading each field once. A frame
/// ring's page (`slot_size = 2048`) is `BadSlotSize` here, and a byte
/// ring's is `BadSlotSize` to [`crate::validate_control`].
pub fn validate_byte_control<P: Page + ?Sized>(page: &P) -> Result<ByteGeometry, ControlError> {
    if page.page_len() < layout::CONTROL_LEN {
        return Err(ControlError::PageTooSmall);
    }
    let mut magic = [0u8; 8];
    page.load_bytes(layout::MAGIC, &mut magic).ok_or(ControlError::PageTooSmall)?;
    if magic == [0u8; 8] {
        return Err(ControlError::Gone);
    }
    if magic != layout::MAGIC_VALUE {
        return Err(ControlError::BadMagic);
    }
    if page.load_u32(layout::SLOT_SIZE_FIELD).ok_or(ControlError::PageTooSmall)? != BYTE_SLOT_SIZE {
        return Err(ControlError::BadSlotSize);
    }
    let capacity = page.load_u32(layout::SLOT_COUNT).ok_or(ControlError::PageTooSmall)?;
    byte_geometry_for(capacity, page.page_len())
}

/// The peer's page as one operation found it.
enum PeerView {
    Valid(ByteGeometry),
    /// All zero, and no valid page was ever seen: not attached yet.
    NotAttached,
}

/// One side of a stream channel pair: writes octets into its own page and
/// reads the peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteEndpoint {
    own: ByteGeometry,
    /// Octets produced into our own page.
    head: u32,
    /// Octets consumed from the peer's page.
    tail: u32,
    /// The peer's `peer_tail` as last validated: how far it consumed our
    /// ring. Starts at the start index.
    peer_tail: u32,
    /// Octets the last `peek` copied out (what `consume` may take).
    peeked: u32,
    /// The peer's unconsumed octets as the last `peek` found them, less
    /// what was consumed since.
    available: u32,
    drops: u32,
    health: Health,
    peer_seen: bool,
}

impl ByteEndpoint {
    /// Initialise our own page as a ring of `capacity` octets.
    pub fn new<O: PageMut + ?Sized>(own: &mut O, capacity: u32) -> Result<Self, ControlError> {
        Self::with_start(own, capacity, 0)
    }

    /// As [`ByteEndpoint::new`] with every index starting at `start`. Both
    /// sides must use the same start; stream channels use 0. A non-zero
    /// start exercises the index wrap without 2^32 octets.
    pub fn with_start<O: PageMut + ?Sized>(own: &mut O, capacity: u32, start: u32) -> Result<Self, ControlError> {
        if own.page_len() < layout::CONTROL_LEN {
            return Err(ControlError::PageTooSmall);
        }
        let geometry = byte_geometry_for(capacity, own.page_len())?;
        let fields: [(usize, u32); 5] = [
            (layout::SLOT_SIZE_FIELD, BYTE_SLOT_SIZE),
            (layout::SLOT_COUNT, capacity),
            (layout::HEAD, start),
            (layout::PEER_TAIL, start),
            (layout::DROPS, 0),
        ];
        for (off, value) in fields {
            own.store_u32(off, value).ok_or(ControlError::PageTooSmall)?;
        }
        // Magic last: a peer never sees a valid magic over unwritten fields.
        own.store_bytes(layout::MAGIC, &layout::MAGIC_VALUE).ok_or(ControlError::PageTooSmall)?;
        Ok(ByteEndpoint {
            own: geometry,
            head: start,
            tail: start,
            peer_tail: start,
            peeked: 0,
            available: 0,
            drops: 0,
            health: Health::Trusted { violations: 0 },
            peer_seen: false,
        })
    }

    pub const fn capacity(&self) -> u32 {
        self.own.capacity
    }

    pub const fn health(&self) -> Health {
        self.health
    }

    /// Lies counted so far; [`PEER_VIOLATION_LIMIT`] once untrusted.
    pub const fn violations(&self) -> u8 {
        match self.health {
            Health::Trusted { violations } => violations,
            Health::Untrusted => PEER_VIOLATION_LIMIT,
        }
    }

    /// Peer octets discarded by resynchronisation.
    pub const fn drops(&self) -> u32 {
        self.drops
    }

    /// Whether a valid peer page was ever seen (the peer attached).
    pub const fn peer_seen(&self) -> bool {
        self.peer_seen
    }

    /// Whether the attach grace is over: no valid peer page was ever seen
    /// and `limit_ms` has passed since `opened_ms`. Until then an all-zero
    /// peer page reads as `NotAttached`; afterwards the caller takes the
    /// loss path (ADR-039 § 4: never a violation).
    pub const fn attach_overdue(&self, opened_ms: u64, now_ms: u64, limit_ms: u64) -> bool {
        !self.peer_seen && now_ms.saturating_sub(opened_ms) >= limit_ms
    }

    /// The peer's `peer_tail` as last accepted: how far it consumed our
    /// ring (free-running).
    pub const fn peer_tail(&self) -> u32 {
        self.peer_tail
    }

    /// Octets in our ring the peer has not consumed, as of the last
    /// operation that read the peer's page.
    pub const fn unread(&self) -> u32 {
        self.head.wrapping_sub(self.peer_tail)
    }

    /// The peer's octets not yet consumed, as of the last `peek` (less
    /// any `consume` since).
    pub const fn available(&self) -> u32 {
        self.available
    }

    fn violate(&mut self) {
        if let Health::Trusted { violations } = self.health {
            let v = violations.saturating_add(1);
            self.health = if v >= PEER_VIOLATION_LIMIT { Health::Untrusted } else { Health::Trusted { violations: v } };
        }
    }

    fn peer_view<P: Page + ?Sized>(&mut self, peer: &P) -> Result<PeerView, RingError> {
        if matches!(self.health, Health::Untrusted) {
            return Err(RingError::PeerUntrusted);
        }
        match validate_byte_control(peer) {
            Ok(g) => {
                self.peer_seen = true;
                Ok(PeerView::Valid(g))
            }
            Err(ControlError::Gone) if !self.peer_seen => Ok(PeerView::NotAttached),
            Err(ControlError::Gone) => Err(RingError::PeerGone),
            Err(_) => {
                self.violate();
                Err(RingError::PeerMalformed)
            }
        }
    }

    /// Copy as much of `data` as fits into our ring; returns how many
    /// octets went in (a prefix of `data`). `Ok(0)` only for empty
    /// `data`; no room at all is `Full`.
    pub fn write<O, P>(&mut self, own: &mut O, peer: &P, data: &[u8]) -> Result<usize, RingError>
    where
        O: PageMut + ?Sized,
        P: Page + ?Sized,
    {
        if let PeerView::Valid(_) = self.peer_view(peer)? {
            // The peer's progress through OUR ring: read once, judged.
            let claimed = peer.load_u32(layout::PEER_TAIL).ok_or(RingError::PeerMalformed)?;
            if self.head.wrapping_sub(claimed) > self.own.capacity {
                // It claims to have consumed octets we never produced.
                self.violate();
                return Err(RingError::Full);
            }
            self.peer_tail = claimed;
        }
        if data.is_empty() {
            return Ok(0);
        }
        let used = self.head.wrapping_sub(self.peer_tail);
        let free = usize::try_from(self.own.capacity.wrapping_sub(used)).map_err(|_| RingError::OwnPage)?;
        let n = data.len().min(free);
        if n == 0 {
            return Err(RingError::Full);
        }
        let ((a, a_len), (b, b_len)) = self.own.spans(self.head, n).ok_or(RingError::OwnPage)?;
        let (first, rest) = data.get(..n).ok_or(RingError::OwnPage)?.split_at(a_len);
        own.store_bytes(a, first).ok_or(RingError::OwnPage)?;
        if b_len > 0 {
            own.store_bytes(b, rest).ok_or(RingError::OwnPage)?;
        }
        // Release: the octets above are visible before the new head.
        let next = self.head.wrapping_add(u32::try_from(n).map_err(|_| RingError::OwnPage)?);
        own.store_u32(layout::HEAD, next).ok_or(RingError::OwnPage)?;
        self.head = next;
        Ok(n)
    }

    /// Copy up to `out.len()` of the peer's unconsumed octets into `out`
    /// without consuming them; returns how many. Follow with
    /// [`ByteEndpoint::consume`] for the octets actually used.
    pub fn peek<O, P>(&mut self, own: &mut O, peer: &P, out: &mut [u8]) -> Result<usize, RingError>
    where
        O: PageMut + ?Sized,
        P: Page + ?Sized,
    {
        self.peeked = 0;
        self.available = 0;
        let ring = match self.peer_view(peer)? {
            PeerView::Valid(g) => g,
            PeerView::NotAttached => return Err(RingError::Empty),
        };
        // Acquire: octets the peer wrote before this head are visible.
        let peer_head = peer.load_u32(layout::HEAD).ok_or(RingError::PeerMalformed)?;
        let available = peer_head.wrapping_sub(self.tail);
        if available > ring.capacity {
            // More octets than the ring holds: drop the untrusted span.
            self.violate();
            self.drops = self.drops.saturating_add(available);
            self.tail = peer_head;
            own.store_u32(layout::DROPS, self.drops).ok_or(RingError::OwnPage)?;
            own.store_u32(layout::PEER_TAIL, self.tail).ok_or(RingError::OwnPage)?;
            return Err(RingError::Resynced);
        }
        if available == 0 {
            return Err(RingError::Empty);
        }
        let n = out.len().min(usize::try_from(available).map_err(|_| RingError::PeerMalformed)?);
        let ((a, a_len), (b, b_len)) = ring.spans(self.tail, n).ok_or(RingError::PeerMalformed)?;
        let (first, rest) = out.get_mut(..n).ok_or(RingError::OutputTooSmall)?.split_at_mut(a_len);
        peer.load_bytes(a, first).ok_or(RingError::PeerMalformed)?;
        if b_len > 0 {
            peer.load_bytes(b, rest).ok_or(RingError::PeerMalformed)?;
        }
        self.peeked = u32::try_from(n).map_err(|_| RingError::OwnPage)?;
        self.available = available;
        Ok(n)
    }

    /// Consume `n` of the octets the last [`ByteEndpoint::peek`] copied
    /// out, publishing the new tail. More than that is
    /// `ConsumeBeyondPeek` and changes nothing.
    pub fn consume<O: PageMut + ?Sized>(&mut self, own: &mut O, n: u32) -> Result<(), RingError> {
        if n > self.peeked {
            return Err(RingError::ConsumeBeyondPeek);
        }
        // Release: the octets are free for the peer only after the copy.
        let next = self.tail.wrapping_add(n);
        own.store_u32(layout::PEER_TAIL, next).ok_or(RingError::OwnPage)?;
        self.tail = next;
        self.peeked = self.peeked.wrapping_sub(n);
        self.available = self.available.saturating_sub(n);
        Ok(())
    }

    /// [`ByteEndpoint::peek`] then consume everything copied.
    pub fn read<O, P>(&mut self, own: &mut O, peer: &P, out: &mut [u8]) -> Result<usize, RingError>
    where
        O: PageMut + ?Sized,
        P: Page + ?Sized,
    {
        let n = self.peek(own, peer, out)?;
        self.consume(own, u32::try_from(n).map_err(|_| RingError::OwnPage)?)?;
        Ok(n)
    }
}
