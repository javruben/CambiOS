// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The page implementation over a live channel mapping (`mapped`),
//! written before it existed. A 4096-aligned heap buffer stands in for a
//! channel mapping: the same raw-pointer view the shell gets from
//! `libsys::channel_create` / `channel_attach`.
//!
//! Covered: construction refuses null and misaligned bases; bounds and
//! alignment of every access; FIFO and slot wrap through a 4-slot ring;
//! acquire/release publication between two threads, each the sole writer
//! of its own page, as on a real seam; hostile lengths and indices and
//! the revoke tombstone read through the mapped view.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::pattern;
use net_seam::mapped::{OwnPage, PeerPage};
use net_seam::{layout, Endpoint, Page, PageMut, RingError, MAX_FRAME};
use std::alloc::{alloc_zeroed, dealloc, Layout};

/// A zeroed, page-aligned region freed on drop.
struct Region {
    ptr: *mut u8,
    layout: Layout,
}

impl Region {
    fn new(slots: usize) -> Region {
        let layout = Layout::from_size_align(layout::CONTROL_LEN + slots * layout::SLOT_SIZE, 4096).unwrap();
        // SAFETY: the layout has a nonzero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Region { ptr, layout }
    }
    fn len(&self) -> usize {
        self.layout.size()
    }
    fn own(&self) -> OwnPage {
        // SAFETY: `ptr` is a live, 4096-aligned allocation of `len()`
        // octets that outlives the view (the tests drop views first), and
        // only this view writes it.
        unsafe { OwnPage::from_raw(self.ptr, self.len()) }.expect("aligned")
    }
    fn peer(&self) -> PeerPage {
        // SAFETY: as for `own`; this view only reads.
        unsafe { PeerPage::from_raw(self.ptr, self.len()) }.expect("aligned")
    }
    /// Forge bytes as a lying peer would (single-threaded tests only).
    fn poke(&self, off: usize, bytes: &[u8]) {
        assert!(off + bytes.len() <= self.len());
        let dst = self.ptr.wrapping_add(off);
        // SAFETY: `off + bytes.len() <= len()` (asserted), so `dst` and the
        // copied range lie in the live allocation; no view is mid-operation.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

#[test]
fn construction_refuses_null_and_misaligned_bases() {
    let r = Region::new(4);
    // SAFETY: null is refused before any access.
    assert!(unsafe { OwnPage::from_raw(core::ptr::null_mut(), r.len()) }.is_none());
    // SAFETY: a misaligned base is refused before any access.
    assert!(unsafe { PeerPage::from_raw(r.ptr.wrapping_add(1), r.len() - 1) }.is_none());
    // SAFETY: a region too small for the control block is refused.
    assert!(unsafe { OwnPage::from_raw(r.ptr, 16) }.is_none());
}

#[test]
fn every_access_is_bounds_and_alignment_checked() {
    let r = Region::new(4);
    let mut own = r.own();
    let len = own.page_len();
    assert_eq!(len, r.len());
    assert_eq!(own.load_u32(len - 3), None, "past the end");
    assert_eq!(own.load_u32(17), None, "an index field is 4-aligned");
    assert_eq!(own.store_u32(usize::MAX - 1, 1), None, "offset overflow");
    let mut out = [0u8; 8];
    assert_eq!(own.load_bytes(len - 4, &mut out), None);
    assert_eq!(own.store_bytes(len - 4, &[0; 8]), None);
    assert_eq!(own.store_u32(layout::HEAD, 0x0102_0304), Some(()));
    assert_eq!(own.load_u32(layout::HEAD), Some(0x0102_0304));
    let mut le = [0u8; 4];
    own.load_bytes(layout::HEAD, &mut le).unwrap();
    assert_eq!(le, [4, 3, 2, 1], "little-endian on the wire");
}

#[test]
fn fifo_and_wrap_through_four_slots() {
    let (a, b) = (Region::new(4), Region::new(4));
    let (mut a_own, mut b_own) = (a.own(), b.own());
    let (a_peer, b_peer) = (a.peer(), b.peer());
    let mut tx = Endpoint::new(&mut a_own, 4).unwrap();
    let mut rx = Endpoint::new(&mut b_own, 4).unwrap();
    let mut out = [0u8; MAX_FRAME];
    for round in 0..10u8 {
        for k in 0..3u8 {
            let f = pattern(60 + usize::from(round) * 100 + usize::from(k), round ^ k);
            tx.send(&mut a_own, &b_peer, &f).unwrap();
        }
        for k in 0..3u8 {
            let n = rx.recv(&mut b_own, &a_peer, &mut out).unwrap();
            assert_eq!(&out[..n], &pattern(60 + usize::from(round) * 100 + usize::from(k), round ^ k)[..]);
        }
    }
    assert_eq!(rx.recv(&mut b_own, &a_peer, &mut out), Err(RingError::Empty));
    for _ in 0..4 {
        tx.send(&mut a_own, &b_peer, &[1; 64]).unwrap();
    }
    assert_eq!(tx.send(&mut a_own, &b_peer, &[1; 64]), Err(RingError::Full));
}

#[test]
fn acquire_release_publication_between_threads() {
    const FRAMES: u32 = 5_000;
    let (a, b) = (Region::new(4), Region::new(4));
    let (a_addr, b_addr, len) = (a.ptr as usize, b.ptr as usize, a.len());
    // Both control pages are initialised before either thread starts:
    // once running, each page has exactly one writer, as on a real seam.
    let mut tx = Endpoint::new(&mut a.own(), 4).unwrap();
    let mut rx = Endpoint::new(&mut b.own(), 4).unwrap();

    std::thread::scope(|s| {
        s.spawn(move || {
            // SAFETY: page A is written only by this thread; page B only read.
            let mut own = unsafe { OwnPage::from_raw(a_addr as *mut u8, len) }.unwrap();
            // SAFETY: as above.
            let peer = unsafe { PeerPage::from_raw(b_addr as *mut u8, len) }.unwrap();
            let mut seq = 0u32;
            while seq < FRAMES {
                let f = pattern(14 + (seq as usize * 37) % (MAX_FRAME - 14), seq as u8);
                match tx.send(&mut own, &peer, &f) {
                    Ok(()) => seq += 1,
                    Err(RingError::Full) => std::hint::spin_loop(),
                    Err(e) => panic!("send {seq}: {e:?}"),
                }
            }
        });
        s.spawn(move || {
            // SAFETY: page B is written only by this thread; page A only read.
            let mut own = unsafe { OwnPage::from_raw(b_addr as *mut u8, len) }.unwrap();
            // SAFETY: as above.
            let peer = unsafe { PeerPage::from_raw(a_addr as *mut u8, len) }.unwrap();
            let mut out = [0u8; MAX_FRAME];
            let mut seq = 0u32;
            while seq < FRAMES {
                match rx.recv(&mut own, &peer, &mut out) {
                    Ok(n) => {
                        let want = pattern(14 + (seq as usize * 37) % (MAX_FRAME - 14), seq as u8);
                        assert_eq!(&out[..n], &want[..], "frame {seq} torn or reordered");
                        seq += 1;
                    }
                    Err(RingError::Empty) => std::hint::spin_loop(),
                    Err(e) => panic!("recv {seq}: {e:?}"),
                }
            }
            assert_eq!(rx.violations(), 0);
        });
    });
}

#[test]
fn hostile_values_read_through_the_mapping() {
    let (a, b) = (Region::new(4), Region::new(4));
    let (mut a_own, mut b_own) = (a.own(), b.own());
    let a_peer = a.peer();
    Endpoint::new(&mut a_own, 4).unwrap();
    let mut rx = Endpoint::new(&mut b_own, 4).unwrap();
    let mut out = [0xAAu8; MAX_FRAME];

    // A length prefix larger than any frame: refused, nothing copied.
    a.poke(layout::CONTROL_LEN, &0xFFFFu16.to_le_bytes());
    a.poke(layout::HEAD, &1u32.to_le_bytes());
    assert_eq!(rx.recv(&mut b_own, &a_peer, &mut out), Err(RingError::Malformed));
    assert!(out.iter().all(|&x| x == 0xAA));

    // A head far beyond the ring: resynchronised and counted.
    a.poke(layout::HEAD, &50u32.to_le_bytes());
    assert_eq!(rx.recv(&mut b_own, &a_peer, &mut out), Err(RingError::Resynced));
    assert_eq!(rx.violations(), 2);

    // The revoke tombstone: an all-zero peer page is gone, not lying.
    a.poke(0, &vec![0u8; a.len()]);
    assert_eq!(rx.recv(&mut b_own, &a_peer, &mut out), Err(RingError::PeerGone));
    assert_eq!(rx.violations(), 2);
}
