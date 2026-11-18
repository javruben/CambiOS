// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! [`Page`] / [`PageMut`] over a live channel mapping: the only `unsafe`
//! in this crate.
//!
//! The shell gets a region's base address from `libsys::channel_create`
//! (its own page) or `libsys::channel_attach` (the peer's page) and wraps
//! it here; this crate never calls a syscall and never wraps a channel
//! handle (ADR-005 Divergence item 6: per-consumer convention, no channel
//! library).
//!
//! # How the region is touched
//!
//! - Index fields (`load_u32` / `store_u32`) go through `AtomicU32` at
//!   offsets aligned for `AtomicU32` inside the region: loads are `Acquire`, stores
//!   `Release`. This is the [`Page`] ordering contract: payload written
//!   before a `head` store is visible to whoever acquire-loads that
//!   `head`, and a slot is rewritten only after the consumer's release of
//!   `peer_tail`.
//! - Payload bytes are copied one octet at a time with volatile reads and
//!   writes, as `libgui` and the compositor access mapped surfaces: the
//!   compiler may neither elide nor merge them. They need no ordering of
//!   their own; the index accesses around them order them.
//! - No `&[u8]` or `&mut [u8]` is ever formed over the region: the peer
//!   may write its page at any time, and a Rust slice reference would
//!   promise it does not.
//! - Every access is bounds-checked against the length given at
//!   construction (known locally, never read from the peer), with
//!   overflow-checked offset arithmetic. Pointer arithmetic is the safe
//!   `wrapping_add` on an in-bounds offset; each `unsafe` block is one
//!   dereference.
//!
//! Two view types keep the directions apart: [`PeerPage`] only reads (the
//! peer's page may be mapped read-only), [`OwnPage`] reads and writes.
//!
//! # Residual risk
//!
//! If the kernel revokes the channel while a view is in use, an RO
//! mapping reads as zeros (ADR-007 tombstone, handled as `PeerGone`),
//! but an RW mapping is unmapped and the next write faults the process.
//! ADR-039 § 9's per-process scratch frame removes that window; until it
//! exists, a peer's death can kill the holder of an [`OwnPage`].
//! **Revisit when:** the ADR-007 § Divergence 8 scratch frame lands.

use crate::{layout, Page, PageMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

/// ARCHITECTURAL: the alignment `AtomicU32` requires on this target. This,
/// not the wire layout's 4-octet field spacing, is the safety requirement
/// for forming an atomic over a field; both the region base and every
/// index offset are checked against it. (It is 4 on x86_64, aarch64 and
/// riscv64; the layout's index fields sit at multiples of 4.)
const ATOMIC_ALIGN: usize = core::mem::align_of::<AtomicU32>();

const fn aligned(n: usize) -> bool {
    matches!(n.checked_rem(ATOMIC_ALIGN), Some(0))
}

/// A bounds-checked view of a mapped region.
struct Region {
    base: NonNull<u8>,
    len: usize,
}

impl Region {
    /// # Safety
    ///
    /// As [`OwnPage::from_raw`] / [`PeerPage::from_raw`].
    unsafe fn new(base: *mut u8, len: usize) -> Option<Region> {
        let base = NonNull::new(base)?;
        let addr = base.as_ptr() as usize;
        if !aligned(addr) || len < layout::CONTROL_LEN || addr.checked_add(len).is_none() {
            return None;
        }
        Some(Region { base, len })
    }

    /// `off .. off + n` lies inside the region.
    fn contains(&self, off: usize, n: usize) -> bool {
        matches!(off.checked_add(n), Some(end) if end <= self.len)
    }

    fn atomic(&self, off: usize) -> Option<&AtomicU32> {
        if !aligned(off) || !self.contains(off, 4) {
            return None;
        }
        let p = self.base.as_ptr().wrapping_add(off).cast::<AtomicU32>();
        // SAFETY: the atomic-object contract, point by point.
        // - In bounds: `off + 4 <= len` (checked above), inside the live
        //   mapping the constructor's contract guarantees for `self`'s
        //   lifetime.
        // - Aligned: base and `off` are both multiples of
        //   `align_of::<AtomicU32>()` (checked at construction and above).
        // - Initialised: `AtomicU32` has `u32`'s representation, for which
        //   every bit pattern is valid; the caller guarantees the region is
        //   initialised memory (channel frames are zero-filled by the
        //   kernel), which is part of `from_raw`'s contract.
        // - No racing non-atomic access: every party touches the index
        //   fields only through this module's atomics (both ends of the
        //   seam use this crate; payload bytes are separate offsets), also
        //   part of `from_raw`'s contract.
        // - Read-only peer mapping: a `PeerPage` only ever `load`s through
        //   this reference; Rust's atomics documentation permits atomic
        //   loads (not read-modify-writes) from read-only memory for
        //   types of this size. `OwnPage` (writable) is the only one that
        //   stores.
        Some(unsafe { &*p })
    }

    fn load_u32(&self, off: usize) -> Option<u32> {
        Some(u32::from_le(self.atomic(off)?.load(Ordering::Acquire)))
    }

    fn store_u32(&self, off: usize, value: u32) -> Option<()> {
        self.atomic(off)?.store(value.to_le(), Ordering::Release);
        Some(())
    }

    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()> {
        if !self.contains(off, out.len()) {
            return None;
        }
        for (k, b) in out.iter_mut().enumerate() {
            let p = self.base.as_ptr().wrapping_add(off.checked_add(k)?);
            // SAFETY: `off + k < off + out.len() <= len` (checked above),
            // so `p` is inside the live mapping; a byte read needs no
            // alignment. Volatile, because the peer may write the region
            // at any time and no Rust reference to it exists.
            *b = unsafe { p.read_volatile() };
        }
        Some(())
    }

    fn store_bytes(&self, off: usize, src: &[u8]) -> Option<()> {
        if !self.contains(off, src.len()) {
            return None;
        }
        for (k, &b) in src.iter().enumerate() {
            let p = self.base.as_ptr().wrapping_add(off.checked_add(k)?);
            // SAFETY: inside the live, writable mapping (bounds checked
            // above; writability is the `OwnPage` contract); a byte write
            // needs no alignment. Volatile, for the same reason as reads.
            unsafe { p.write_volatile(b) };
        }
        Some(())
    }
}

/// The page this side owns and writes (its TX ring's channel).
pub struct OwnPage(Region);

/// The page the peer owns; this side only reads it.
pub struct PeerPage(Region);

impl OwnPage {
    /// Wrap a mapped region this side writes. `None` for a null or
    /// non-4-aligned base, a length below the control block, or a range
    /// that wraps the address space.
    ///
    /// # Safety
    ///
    /// For as long as the returned value (or any reference it hands out)
    /// is used:
    /// - `base .. base + len` is mapped readable and writable in this
    ///   process (a `channel_create` Producer region, or equivalent);
    /// - this value is the only writer of the region in this process, and
    ///   the peer maps it read-only (ADR-039 § 2: one writer per page);
    /// - the region is initialised memory (the kernel zero-fills channel
    ///   frames in `handle_channel_create` before mapping them, kernel
    ///   `src/syscalls/dispatcher.rs`, "Zero the channel memory");
    /// - every party accesses the index fields only through this module's
    ///   atomics;
    /// - no `&[u8]` / `&mut [u8]` to the region exists.
    pub unsafe fn from_raw(base: *mut u8, len: usize) -> Option<OwnPage> {
        // SAFETY: the caller upholds this function's contract, which is
        // `Region::new`'s.
        unsafe { Region::new(base, len) }.map(OwnPage)
    }
}

impl PeerPage {
    /// Wrap the peer's mapped region, read-only. `None` as for
    /// [`OwnPage::from_raw`].
    ///
    /// # Safety
    ///
    /// For as long as the returned value is used: `base .. base + len` is
    /// mapped readable in this process (a `channel_attach` region, or the
    /// kernel's zero tombstone after revocation) and is initialised memory;
    /// every party accesses
    /// the index fields only through this module's atomics; and no
    /// `&[u8]` / `&mut [u8]` to the region exists. The peer may write it
    /// at any time: every value read is treated as hostile by the ring.
    pub unsafe fn from_raw(base: *mut u8, len: usize) -> Option<PeerPage> {
        // SAFETY: the caller upholds this function's contract, which is
        // `Region::new`'s (read-only use only: `PeerPage` has no writes).
        unsafe { Region::new(base, len) }.map(PeerPage)
    }
}

impl Page for OwnPage {
    fn page_len(&self) -> usize {
        self.0.len
    }
    fn load_u32(&self, off: usize) -> Option<u32> {
        self.0.load_u32(off)
    }
    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()> {
        self.0.load_bytes(off, out)
    }
}

impl PageMut for OwnPage {
    fn store_u32(&mut self, off: usize, value: u32) -> Option<()> {
        self.0.store_u32(off, value)
    }
    fn store_bytes(&mut self, off: usize, src: &[u8]) -> Option<()> {
        self.0.store_bytes(off, src)
    }
}

impl Page for PeerPage {
    fn page_len(&self) -> usize {
        self.0.len
    }
    fn load_u32(&self, off: usize) -> Option<u32> {
        self.0.load_u32(off)
    }
    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()> {
        self.0.load_bytes(off, out)
    }
}
