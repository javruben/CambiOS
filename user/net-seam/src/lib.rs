// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The packet ring of the NIC-driver <-> network-stack seam.
//!
//! # Scope
//!
//! This one seam only. Per ADR-005 Divergence item 6, a channel's ring
//! layout is a per-consumer convention, not a shared library: this crate is
//! the network seam's convention, the way libgui surfaces and the scanout
//! pixel path carry their own. It is a separate crate for the same reason
//! `cambios-blk-proto` is: both ends of the seam are separate binaries (the
//! stack and each NIC driver) and must run byte-identical ring logic.
//! Channel setup, attach, close and teardown stay on the `libsys` channel
//! syscalls and the verified-principal hand-off pattern of the compositor
//! and scanout drivers; nothing here wraps a channel handle.
//!
//! # Shape
//!
//! A seam is two unidirectional channel pages. Each side *owns* one page
//! (writes it) and *reads* the other. A page is a control block followed by
//! frame slots (ADR-039 § 4):
//!
//! ```text
//! [0..8)    magic "CMBCHAN1"
//! [8..12)   slot_size   (2048)
//! [12..16)  slot_count  (power of two)
//! [16..20)  head        frames this side has produced into this page
//! [20..24)  peer_tail   frames this side has consumed from the OTHER page
//! [24..28)  drops       frames this side discarded from the other page
//! [4096..)  slots: [len:2 LE][payload], slot_size bytes each
//! ```
//!
//! All integers are little-endian. Indices are free-running `u32`s compared
//! with wrapping arithmetic; a slot is `index & (slot_count - 1)`.
//!
//! # The peer is hostile
//!
//! Every value read from the peer's page is untrusted input. Each field is
//! read exactly once per operation, into a local, and validated there; a
//! frame is copied out and its copied length is validated. A lie costs the
//! liar its own frames and is counted; at [`PEER_VIOLATION_LIMIT`] the
//! endpoint refuses all further work ([`RingError::PeerUntrusted`]) and the
//! count freezes. An all-zero peer page is what a revoked channel's RO
//! mapping reads as (ADR-007 Divergence 7, the tombstone): that is
//! [`RingError::PeerGone`], never a violation.
//!
//! # Memory ordering
//!
//! Carried by the [`Page`] contract: index fields are loaded with acquire
//! and stored with release, so payload bytes written before a `head`
//! store are visible to a consumer that loaded that `head`, and a slot is
//! reused only after the consumer's `peer_tail` release-store. The byte
//! slice implementation here is single-threaded (tests, host); the
//! implementation over a live channel mapping is [`mapped`].

#![no_std]
// Only `mapped` may use `unsafe` (it carries its own allow and a SAFETY
// comment per block); everything else stays safe.
#![deny(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]

#[allow(unsafe_code)]
pub mod mapped;

pub mod bytes;
pub use bytes::{validate_byte_control, ByteEndpoint, ByteGeometry};

/// The page layout (see the crate documentation).
pub mod layout {
    /// ARCHITECTURAL: the control block occupies the channel's first 4 KiB
    /// page and frame slots start on the second (ADR-005 Implementation
    /// Notes: ring metadata in the first page, payload from the second).
    pub const CONTROL_LEN: usize = 4096;
    /// ARCHITECTURAL: one frame slot, ADR-039 § 4 (`slot_size = 2048`):
    /// a 2-octet length prefix plus a full Ethernet II frame fits.
    pub const SLOT_SIZE: usize = 2048;
    /// HARDWARE: the slot length prefix is a little-endian u16.
    pub const LEN_PREFIX: usize = 2;

    pub const MAGIC: usize = 0;
    pub const SLOT_SIZE_FIELD: usize = 8;
    pub const SLOT_COUNT: usize = 12;
    pub const HEAD: usize = 16;
    pub const PEER_TAIL: usize = 20;
    pub const DROPS: usize = 24;

    /// ARCHITECTURAL: identifies an initialised seam page. An all-zero
    /// magic is the revoke tombstone, so the magic must never be zero.
    pub const MAGIC_VALUE: [u8; 8] = *b"CMBCHAN1";
}

/// HARDWARE: the largest Ethernet II frame without FCS: 1500-octet MTU plus
/// the 14-octet header.
pub const MAX_FRAME: usize = 1514;

/// TUNING (ADR-039 § 8): lies tolerated from a peer before the endpoint
/// stops trusting it. Enough to tell a bug from an attack; a hostile peer
/// costs at most this many bounded checks.
pub const PEER_VIOLATION_LIMIT: u8 = 8;

/// One side's view of a channel page.
///
/// Index fields (`load_u32` / `store_u32`) carry the ring's ordering:
/// loads are acquire, stores are release. Byte accesses carry no ordering
/// of their own; they are ordered by the index accesses around them.
/// Every access is bounds-checked and returns `None` when out of range.
pub trait Page {
    /// The mapping's length in octets. Known locally, not read from the peer.
    fn page_len(&self) -> usize;
    /// Load a little-endian u32 at `off` (acquire).
    fn load_u32(&self, off: usize) -> Option<u32>;
    /// Copy `out.len()` octets starting at `off` into `out`.
    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()>;
}

/// The page this side owns and writes.
pub trait PageMut: Page {
    /// Store a little-endian u32 at `off` (release: every earlier store is
    /// visible to a peer that acquire-loads this field).
    fn store_u32(&mut self, off: usize, value: u32) -> Option<()>;
    /// Copy `src` to `off`.
    fn store_bytes(&mut self, off: usize, src: &[u8]) -> Option<()>;
}

impl Page for [u8] {
    fn page_len(&self) -> usize {
        self.len()
    }
    fn load_u32(&self, off: usize) -> Option<u32> {
        let end = off.checked_add(4)?;
        let bytes: [u8; 4] = self.get(off..end)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }
    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()> {
        let end = off.checked_add(out.len())?;
        out.copy_from_slice(self.get(off..end)?);
        Some(())
    }
}

impl PageMut for [u8] {
    fn store_u32(&mut self, off: usize, value: u32) -> Option<()> {
        let end = off.checked_add(4)?;
        self.get_mut(off..end)?.copy_from_slice(&value.to_le_bytes());
        Some(())
    }
    fn store_bytes(&mut self, off: usize, src: &[u8]) -> Option<()> {
        let end = off.checked_add(src.len())?;
        self.get_mut(off..end)?.copy_from_slice(src);
        Some(())
    }
}

/// Why a control block is not a usable seam page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// All-zero magic: never initialised, or the revoke tombstone.
    Gone,
    BadMagic,
    BadSlotSize,
    /// Zero or not a power of two.
    BadSlotCount,
    /// Smaller than the control block, or than its declared slots need.
    PageTooSmall,
}

/// Why a ring operation did nothing (or, for `Malformed` / `Resynced`,
/// discarded the peer's frames).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingError {
    /// No free slot (or the peer lied about its progress; counted).
    Full,
    /// Nothing to receive.
    Empty,
    /// A zero-length frame was offered for sending.
    FrameEmpty,
    /// A frame longer than [`MAX_FRAME`] was offered for sending.
    FrameTooLarge,
    /// The output buffer is shorter than the next frame; nothing consumed.
    OutputTooSmall,
    /// The peer's next slot had an invalid length; the slot was skipped
    /// and counted.
    Malformed,
    /// The peer's head ran more than a ring ahead; its untrusted span was
    /// dropped and counted.
    Resynced,
    /// The peer's page is all zero: the peer is gone (not a violation).
    PeerGone,
    /// The peer's control block is invalid; counted.
    PeerMalformed,
    /// The peer exceeded [`PEER_VIOLATION_LIMIT`]; nothing is done.
    PeerUntrusted,
    /// A byte ring `consume` asked for more octets than the last `peek`
    /// copied out; nothing was consumed.
    ConsumeBeyondPeek,
    /// Our own page rejected a write. Unreachable when the page was
    /// validated at construction; reported, never panicked on.
    OwnPage,
}

/// A validated ring shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    slot_count: u32,
}

impl Geometry {
    pub const fn slot_count(self) -> u32 {
        self.slot_count
    }

    /// Byte offset of the slot that `index` maps to.
    fn slot_offset(self, index: u32) -> Option<usize> {
        // slot_count >= 1 is a power of two, so the mask is exact.
        let slot = index & self.slot_count.wrapping_sub(1);
        usize::try_from(slot).ok()?.checked_mul(layout::SLOT_SIZE)?.checked_add(layout::CONTROL_LEN)
    }
}

fn geometry_for(slot_count: u32, page_len: usize) -> Result<Geometry, ControlError> {
    if !slot_count.is_power_of_two() {
        // is_power_of_two() is false for 0 as well.
        return Err(ControlError::BadSlotCount);
    }
    let need = usize::try_from(slot_count)
        .ok()
        .and_then(|n| n.checked_mul(layout::SLOT_SIZE))
        .and_then(|n| n.checked_add(layout::CONTROL_LEN))
        .ok_or(ControlError::PageTooSmall)?;
    if need > page_len {
        return Err(ControlError::PageTooSmall);
    }
    Ok(Geometry { slot_count })
}

/// Validate a control block, reading each field once.
pub fn validate_control<P: Page + ?Sized>(page: &P) -> Result<Geometry, ControlError> {
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
    let slot_size = page.load_u32(layout::SLOT_SIZE_FIELD).ok_or(ControlError::PageTooSmall)?;
    if usize::try_from(slot_size).ok() != Some(layout::SLOT_SIZE) {
        return Err(ControlError::BadSlotSize);
    }
    let slot_count = page.load_u32(layout::SLOT_COUNT).ok_or(ControlError::PageTooSmall)?;
    geometry_for(slot_count, page.page_len())
}

/// Whether this endpoint still trusts its peer. An explicit state, not a
/// flag: `Untrusted` is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    Trusted { violations: u8 },
    Untrusted,
}

/// One side of a seam: produces frames into its own page and consumes the
/// peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    own: Geometry,
    /// Next index this side produces into its own page.
    head: u32,
    /// Next index this side consumes from the peer's page.
    tail: u32,
    drops: u32,
    health: Health,
}

impl Endpoint {
    /// Initialise our own page with `slot_count` slots; indices start at 0.
    pub fn new<O: PageMut + ?Sized>(own: &mut O, slot_count: u32) -> Result<Self, ControlError> {
        Self::with_start(own, slot_count, 0)
    }

    /// As [`Endpoint::new`] with both indices starting at `start`. Both
    /// sides of a seam must use the same start; the seam itself uses 0.
    /// A non-zero start exercises the index wrap without 2^32 frames.
    pub fn with_start<O: PageMut + ?Sized>(own: &mut O, slot_count: u32, start: u32) -> Result<Self, ControlError> {
        if own.page_len() < layout::CONTROL_LEN {
            return Err(ControlError::PageTooSmall);
        }
        let geometry = geometry_for(slot_count, own.page_len())?;
        let slot_size = u32::try_from(layout::SLOT_SIZE).map_err(|_| ControlError::BadSlotSize)?;
        let fields: [(usize, u32); 5] = [
            (layout::SLOT_SIZE_FIELD, slot_size),
            (layout::SLOT_COUNT, slot_count),
            (layout::HEAD, start),
            (layout::PEER_TAIL, start),
            (layout::DROPS, 0),
        ];
        for (off, value) in fields {
            own.store_u32(off, value).ok_or(ControlError::PageTooSmall)?;
        }
        // Magic last: a peer never sees a valid magic over unwritten fields.
        own.store_bytes(layout::MAGIC, &layout::MAGIC_VALUE).ok_or(ControlError::PageTooSmall)?;
        Ok(Endpoint { own: geometry, head: start, tail: start, drops: 0, health: Health::Trusted { violations: 0 } })
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

    /// Peer frames discarded by resynchronisation.
    pub const fn drops(&self) -> u32 {
        self.drops
    }

    fn violate(&mut self) {
        if let Health::Trusted { violations } = self.health {
            let v = violations.saturating_add(1);
            self.health = if v >= PEER_VIOLATION_LIMIT { Health::Untrusted } else { Health::Trusted { violations: v } };
        }
    }

    fn untrusted(&self) -> bool {
        matches!(self.health, Health::Untrusted)
    }

    /// Validate the peer's control block (each field read once). A dead
    /// peer is not a liar; an invalid one is.
    fn peer_geometry<P: Page + ?Sized>(&mut self, peer: &P) -> Result<Geometry, RingError> {
        match validate_control(peer) {
            Ok(geometry) => Ok(geometry),
            Err(ControlError::Gone) => Err(RingError::PeerGone),
            Err(_) => {
                self.violate();
                Err(RingError::PeerMalformed)
            }
        }
    }

    /// Publish one frame into our own page.
    pub fn send<O, P>(&mut self, own: &mut O, peer: &P, frame: &[u8]) -> Result<(), RingError>
    where
        O: PageMut + ?Sized,
        P: Page + ?Sized,
    {
        if self.untrusted() {
            return Err(RingError::PeerUntrusted);
        }
        if frame.is_empty() {
            return Err(RingError::FrameEmpty);
        }
        if frame.len() > MAX_FRAME {
            return Err(RingError::FrameTooLarge);
        }
        self.peer_geometry(peer)?;
        // The peer's progress through OUR ring: read once, then judged.
        let peer_tail = peer.load_u32(layout::PEER_TAIL).ok_or(RingError::PeerMalformed)?;
        let used = self.head.wrapping_sub(peer_tail);
        let capacity = self.own.slot_count;
        if used > capacity {
            // The peer claims to have consumed frames we never produced.
            self.violate();
            return Err(RingError::Full);
        }
        if used == capacity {
            return Err(RingError::Full);
        }
        let off = self.own.slot_offset(self.head).ok_or(RingError::OwnPage)?;
        let len = u16::try_from(frame.len()).map_err(|_| RingError::FrameTooLarge)?;
        let payload_at = off.checked_add(layout::LEN_PREFIX).ok_or(RingError::OwnPage)?;
        own.store_bytes(off, &len.to_le_bytes()).ok_or(RingError::OwnPage)?;
        own.store_bytes(payload_at, frame).ok_or(RingError::OwnPage)?;
        // Release: the slot's bytes above are visible before the new head.
        let next = self.head.wrapping_add(1);
        own.store_u32(layout::HEAD, next).ok_or(RingError::OwnPage)?;
        self.head = next;
        Ok(())
    }

    /// Take the peer's next frame into `out`; returns its length.
    pub fn recv<O, P>(&mut self, own: &mut O, peer: &P, out: &mut [u8]) -> Result<usize, RingError>
    where
        O: PageMut + ?Sized,
        P: Page + ?Sized,
    {
        if self.untrusted() {
            return Err(RingError::PeerUntrusted);
        }
        let ring = self.peer_geometry(peer)?;
        // Acquire: slot bytes the peer wrote before this head are visible.
        let peer_head = peer.load_u32(layout::HEAD).ok_or(RingError::PeerMalformed)?;
        let available = peer_head.wrapping_sub(self.tail);
        if available > ring.slot_count {
            // More frames than the ring can hold: drop the untrusted span.
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
        let off = ring.slot_offset(self.tail).ok_or(RingError::PeerMalformed)?;
        let mut prefix = [0u8; layout::LEN_PREFIX];
        peer.load_bytes(off, &mut prefix).ok_or(RingError::PeerMalformed)?;
        let len = usize::from(u16::from_le_bytes(prefix));
        // MAX_FRAME + LEN_PREFIX < SLOT_SIZE, so this also bounds the slot.
        if len == 0 || len > MAX_FRAME {
            self.violate();
            self.tail = self.tail.wrapping_add(1);
            own.store_u32(layout::PEER_TAIL, self.tail).ok_or(RingError::OwnPage)?;
            return Err(RingError::Malformed);
        }
        // Checked before consuming: a short buffer changes nothing.
        let dst = out.get_mut(..len).ok_or(RingError::OutputTooSmall)?;
        let payload_at = off.checked_add(layout::LEN_PREFIX).ok_or(RingError::PeerMalformed)?;
        peer.load_bytes(payload_at, dst).ok_or(RingError::PeerMalformed)?;
        // Release: the slot is free for the peer only after the copy.
        let next = self.tail.wrapping_add(1);
        own.store_u32(layout::PEER_TAIL, next).ok_or(RingError::OwnPage)?;
        self.tail = next;
        Ok(len)
    }
}
