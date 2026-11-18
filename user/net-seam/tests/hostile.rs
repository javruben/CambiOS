// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The hostile-peer contract (ADR-039 § 4): every value read from the
//! peer's page is untrusted. A lie is counted, costs the liar its own
//! frames, and after PEER_VIOLATION_LIMIT lies the peer is cut off. An
//! all-zero peer page (the ADR-007 revoke tombstone) means the peer is
//! gone, which is not a lie.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::*;
use net_seam::{layout, validate_control, ControlError, Endpoint, Page, RingError, MAX_FRAME, PEER_VIOLATION_LIMIT};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[test]
fn malformed_lengths_are_skipped_counted_and_never_copied() {
    for bad in [0u16, 1515, 2047, 0xFFFF] {
        let (mut a, mut b) = pages(4);
        let _tx = Endpoint::new(&mut a[..], 4).unwrap();
        let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
        forge_len(&mut a, 0, bad);
        write_u32(&mut a, layout::HEAD, 1); // the peer claims one frame
        let mut out = [0xAAu8; MAX_FRAME];
        assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Malformed), "len {bad}");
        assert_eq!(rx.violations(), 1, "len {bad}");
        assert!(out.iter().all(|&x| x == 0xAA), "nothing copied for len {bad}");
        assert_eq!(read_u32(&b, layout::PEER_TAIL), 1, "slot skipped for len {bad}");
        assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Empty), "len {bad}");
    }
}

#[test]
fn producer_head_beyond_the_ring_resyncs_and_counts() {
    let (mut a, mut b) = pages(4);
    let _tx = Endpoint::new(&mut a[..], 4).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
    write_u32(&mut a, layout::HEAD, 9); // 9 frames claimed in a 4-slot ring
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Resynced));
    assert_eq!(rx.violations(), 1);
    assert_eq!(rx.drops(), 9);
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 9);
    assert_eq!(read_u32(&b, layout::DROPS), 9, "drops are published for observability");
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Empty));
}

/// Added after the implementation (review request crossed with it), so not
/// red-first: the drop counter saturates rather than wrapping, whatever
/// head deltas a hostile peer claims.
#[test]
fn resync_drop_count_saturates_instead_of_wrapping() {
    let (mut a, mut b) = pages(4);
    let _tx = Endpoint::new(&mut a[..], 4).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
    let mut out = [0u8; MAX_FRAME];
    write_u32(&mut a, layout::HEAD, u32::MAX); // tail 0: u32::MAX frames claimed
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Resynced));
    assert_eq!(rx.drops(), u32::MAX);
    write_u32(&mut a, layout::HEAD, u32::MAX.wrapping_add(10)); // 10 past the new tail
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Resynced));
    assert_eq!(rx.drops(), u32::MAX, "saturated, not wrapped");
    assert_eq!(read_u32(&b, layout::DROPS), u32::MAX);
    assert_eq!(rx.violations(), 2);
}

#[test]
fn consumer_tail_beyond_what_was_produced_reads_as_full_and_counts() {
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let _rx = Endpoint::new(&mut b[..], 4).unwrap();
    tx.send(&mut a[..], &b[..], &[1; 64]).unwrap(); // head = 1
    write_u32(&mut b, layout::PEER_TAIL, 3); // the peer claims 3 consumed
    assert_eq!(tx.send(&mut a[..], &b[..], &[2; 64]), Err(RingError::Full));
    assert_eq!(tx.violations(), 1);
    assert_eq!(read_u32(&a, layout::HEAD), 1, "nothing published");
}

#[test]
fn the_violation_limit_cuts_the_peer_off_and_freezes_the_count() {
    assert_eq!(PEER_VIOLATION_LIMIT, 8);
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let _rx = Endpoint::new(&mut b[..], 4).unwrap();
    write_u32(&mut b, layout::PEER_TAIL, 3); // a persistent lie: 0 - 3 wraps
    for i in 1..=8u8 {
        assert_eq!(tx.send(&mut a[..], &b[..], &[0; 64]), Err(RingError::Full));
        assert_eq!(tx.violations(), i);
    }
    assert_eq!(tx.send(&mut a[..], &b[..], &[0; 64]), Err(RingError::PeerUntrusted));
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(tx.recv(&mut a[..], &b[..], &mut out), Err(RingError::PeerUntrusted));
    write_u32(&mut b, layout::PEER_TAIL, 0); // the peer "behaves" again: too late
    assert_eq!(tx.send(&mut a[..], &b[..], &[0; 64]), Err(RingError::PeerUntrusted));
    assert_eq!(tx.violations(), 8, "the count freezes at the limit");
}

#[test]
fn a_malformed_peer_control_page_is_a_violation() {
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let _rx = Endpoint::new(&mut b[..], 4).unwrap();
    write_u32(&mut b, layout::SLOT_COUNT, 3); // not a power of two
    assert_eq!(tx.send(&mut a[..], &b[..], &[0; 64]), Err(RingError::PeerMalformed));
    assert_eq!(tx.violations(), 1);
}

#[test]
fn control_page_validation() {
    let (mut a, _b) = pages(4);
    Endpoint::new(&mut a[..], 4).unwrap();
    assert!(validate_control(&a[..]).is_ok());

    let mut bad = a.clone();
    bad[layout::MAGIC] ^= 0xFF;
    assert_eq!(validate_control(&bad[..]), Err(ControlError::BadMagic));

    for count in [0u32, 3] {
        let mut bad = a.clone();
        write_u32(&mut bad, layout::SLOT_COUNT, count);
        assert_eq!(validate_control(&bad[..]), Err(ControlError::BadSlotCount), "count {count}");
    }

    let mut bad = a.clone();
    write_u32(&mut bad, layout::SLOT_COUNT, 8); // the page is sized for 4
    assert_eq!(validate_control(&bad[..]), Err(ControlError::PageTooSmall));

    let mut bad = a.clone();
    write_u32(&mut bad, layout::SLOT_SIZE_FIELD, 1024);
    assert_eq!(validate_control(&bad[..]), Err(ControlError::BadSlotSize));

    assert_eq!(validate_control(&vec![0u8; a.len()][..]), Err(ControlError::Gone));
    assert_eq!(validate_control(&[0u8; 8][..]), Err(ControlError::PageTooSmall));

    let mut too_small = vec![0u8; layout::CONTROL_LEN + 3 * layout::SLOT_SIZE];
    assert_eq!(Endpoint::new(&mut too_small[..], 4).err(), Some(ControlError::PageTooSmall));
    assert_eq!(Endpoint::new(&mut a[..], 3).err(), Some(ControlError::BadSlotCount));
    assert_eq!(Endpoint::new(&mut a[..], 0).err(), Some(ControlError::BadSlotCount));
}

#[test]
fn an_all_zero_peer_page_is_peer_gone_not_a_violation() {
    let (mut a, b) = pages(4); // `b` never initialised: same bytes as the tombstone
    let mut ep = Endpoint::new(&mut a[..], 4).unwrap();
    let mut out = [0u8; MAX_FRAME];
    for _ in 0..20 {
        assert_eq!(ep.recv(&mut a[..], &b[..], &mut out), Err(RingError::PeerGone));
        assert_eq!(ep.send(&mut a[..], &b[..], &[1; 64]), Err(RingError::PeerGone));
    }
    assert_eq!(ep.violations(), 0, "a dead peer is not a lying peer");
}

/// A peer page that counts every read, per offset.
struct Counting<'a> {
    bytes: &'a [u8],
    u32_loads: RefCell<BTreeMap<usize, u32>>,
    byte_loads: RefCell<BTreeMap<usize, u32>>,
}

impl<'a> Counting<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Counting { bytes, u32_loads: RefCell::new(BTreeMap::new()), byte_loads: RefCell::new(BTreeMap::new()) }
    }
    fn assert_each_read_once(&self, what: &str) {
        for (off, n) in self.u32_loads.borrow().iter() {
            assert_eq!(*n, 1, "{what}: u32 at offset {off} read {n} times");
        }
        for (off, n) in self.byte_loads.borrow().iter() {
            assert_eq!(*n, 1, "{what}: bytes at offset {off} read {n} times");
        }
    }
}

impl Page for Counting<'_> {
    fn page_len(&self) -> usize {
        self.bytes.len()
    }
    fn load_u32(&self, off: usize) -> Option<u32> {
        *self.u32_loads.borrow_mut().entry(off).or_insert(0) += 1;
        <[u8] as Page>::load_u32(self.bytes, off)
    }
    fn load_bytes(&self, off: usize, out: &mut [u8]) -> Option<()> {
        *self.byte_loads.borrow_mut().entry(off).or_insert(0) += 1;
        <[u8] as Page>::load_bytes(self.bytes, off, out)
    }
}

#[test]
fn every_peer_field_is_read_exactly_once_per_operation() {
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
    tx.send(&mut a[..], &b[..], &[7; 300]).unwrap();

    let peer_a = Counting::new(&a);
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &peer_a, &mut out), Ok(300));
    peer_a.assert_each_read_once("recv");

    let peer_b = Counting::new(&b);
    tx.send(&mut a[..], &peer_b, &[8; 64]).unwrap();
    peer_b.assert_each_read_once("send");
}
