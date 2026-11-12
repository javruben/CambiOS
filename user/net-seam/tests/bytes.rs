// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The byte ring (ADR-039 § 3, § 4): partial writes, index and physical
//! wrap, peek/consume, the not-attached window, the hostile-peer contract.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::*;
use net_seam::{
    layout, validate_byte_control, validate_control, ByteEndpoint, ControlError, Endpoint, Health, RingError, PEER_VIOLATION_LIMIT,
};

type Pair = (Vec<u8>, Vec<u8>, ByteEndpoint, ByteEndpoint);

fn pair_at(cap: u32, start: u32) -> Pair {
    let n = layout::CONTROL_LEN + cap as usize;
    let (mut a, mut b) = (vec![0u8; n], vec![0u8; n]);
    let ea = ByteEndpoint::with_start(&mut a[..], cap, start).unwrap();
    let eb = ByteEndpoint::with_start(&mut b[..], cap, start).unwrap();
    (a, b, ea, eb)
}

fn pair(cap: u32) -> Pair {
    pair_at(cap, 0)
}

/// A way a peer can corrupt its own control block.
type Lie = fn(&mut Vec<u8>);

#[test]
fn round_trip() {
    let (mut a, mut b, mut ea, mut eb) = pair(16);
    assert_eq!(ea.write(&mut a[..], &b[..], b"hello"), Ok(5));
    let mut out = [0u8; 5];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out), Ok(5));
    assert_eq!(&out, b"hello");
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 5);
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out), Err(RingError::Empty));
    assert_eq!(ea.violations(), 0);
}

#[test]
fn write_is_partial_when_nearly_full() {
    let (mut a, mut b, mut ea, mut eb) = pair(16);
    let data = pattern(20, 1);
    assert_eq!(ea.write(&mut a[..], &b[..], &data), Ok(16));
    assert_eq!(ea.write(&mut a[..], &b[..], &data), Err(RingError::Full));
    let mut six = [0u8; 6];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut six), Ok(6));
    assert_eq!(&six[..], &data[..6]);
    let more = pattern(10, 9);
    assert_eq!(ea.write(&mut a[..], &b[..], &more), Ok(6));
    assert_eq!(ea.unread(), 16);
    let mut rest = [0u8; 16];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut rest), Ok(16));
    assert_eq!(&rest[..10], &data[6..16]);
    assert_eq!(&rest[10..], &more[..6]);
}

#[test]
fn index_wrap_and_physical_wrap_together() {
    let start = u32::MAX - 3; // ring offset 12 of 16: 4 octets fit before the end
    let (mut a, mut b, mut ea, mut eb) = pair_at(16, start);
    let data = pattern(10, 3);
    assert_eq!(ea.write(&mut a[..], &b[..], &data), Ok(10));
    assert_eq!(read_u32(&a, layout::HEAD), 6); // wrapped past u32::MAX
    assert_eq!(&a[layout::CONTROL_LEN + 12..layout::CONTROL_LEN + 16], &data[..4]);
    assert_eq!(&a[layout::CONTROL_LEN..layout::CONTROL_LEN + 6], &data[4..]);
    let mut out = [0u8; 10];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out), Ok(10));
    assert_eq!(&out[..], &data[..]);
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 6);
    assert_eq!(eb.violations(), 0);
}

#[test]
fn physical_wrap_at_nonzero_offset() {
    let (mut a, mut b, mut ea, mut eb) = pair(16);
    let first = pattern(12, 5);
    assert_eq!(ea.write(&mut a[..], &b[..], &first), Ok(12));
    let mut out12 = [0u8; 12];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out12), Ok(12));
    assert_eq!(&out12[..], &first[..]);
    let second = pattern(10, 77);
    assert_eq!(ea.write(&mut a[..], &b[..], &second), Ok(10));
    assert_eq!(&a[layout::CONTROL_LEN + 12..layout::CONTROL_LEN + 16], &second[..4]);
    assert_eq!(&a[layout::CONTROL_LEN..layout::CONTROL_LEN + 6], &second[4..]);
    let mut out10 = [0u8; 10];
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out10), Ok(10));
    assert_eq!(&out10[..], &second[..]);
}

#[test]
fn peek_does_not_consume_and_consume_is_bounded_by_peek() {
    let (mut a, mut b, mut ea, mut eb) = pair(16);
    assert_eq!(ea.write(&mut a[..], &b[..], b"ABCDEFGH"), Ok(8));
    let mut four = [0u8; 4];
    assert_eq!(eb.peek(&mut b[..], &a[..], &mut four), Ok(4));
    assert_eq!(&four, b"ABCD");
    assert_eq!(eb.peek(&mut b[..], &a[..], &mut four), Ok(4));
    assert_eq!(&four, b"ABCD");
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 0);
    assert_eq!(eb.consume(&mut b[..], 2), Ok(()));
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 2);
    let mut all = [0u8; 8];
    assert_eq!(eb.peek(&mut b[..], &a[..], &mut all), Ok(6));
    assert_eq!(&all[..6], b"CDEFGH");
    assert_eq!(eb.consume(&mut b[..], 7), Err(RingError::ConsumeBeyondPeek));
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 2);
    // A short out buffer copies only out.len(); consuming one more fails.
    let mut three = [0u8; 3];
    assert_eq!(eb.peek(&mut b[..], &a[..], &mut three), Ok(3));
    assert_eq!(&three, b"CDE");
    assert_eq!(eb.consume(&mut b[..], 4), Err(RingError::ConsumeBeyondPeek));
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 2);
    assert_eq!(eb.consume(&mut b[..], 3), Ok(()));
    assert_eq!(read_u32(&b, layout::PEER_TAIL), 5);
}

#[test]
fn peer_not_attached_then_attached_then_gone() {
    let n = layout::CONTROL_LEN + 16;
    let mut a = vec![0u8; n];
    let mut b = vec![0u8; n]; // the client has not initialised its page yet
    let mut ea = ByteEndpoint::new(&mut a[..], 16).unwrap();
    assert_eq!(ea.write(&mut a[..], &b[..], b"abc"), Ok(3));
    let mut out = [0u8; 4];
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::Empty));
    assert!(!ea.peer_seen());
    assert_eq!(ea.violations(), 0);
    let mut eb = ByteEndpoint::new(&mut b[..], 16).unwrap();
    assert_eq!(ea.write(&mut a[..], &b[..], b"d"), Ok(1));
    assert!(ea.peer_seen());
    assert_eq!(eb.read(&mut b[..], &a[..], &mut out), Ok(4));
    assert_eq!(&out, b"abcd");
    b.fill(0); // the ADR-007 tombstone
    assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Err(RingError::PeerGone));
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::PeerGone));
    assert_eq!(ea.violations(), 0);
}

#[test]
fn attach_grace_holds_until_the_limit_and_ends_on_first_valid_page() {
    let n = layout::CONTROL_LEN + 16;
    let mut a = vec![0u8; n];
    let mut b = vec![0u8; n];
    let mut ea = ByteEndpoint::new(&mut a[..], 16).unwrap();
    // Zero peer page before the limit: still waiting, nothing counted.
    let mut out = [0u8; 4];
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::Empty));
    assert!(!ea.attach_overdue(1_000, 1_000 + 9_999, 10_000));
    assert!(ea.attach_overdue(1_000, 1_000 + 10_000, 10_000));
    assert!(ea.attach_overdue(5_000, 0, 0)); // clock behind opened, zero limit
    assert!(!ea.attach_overdue(5_000, 0, 1)); // clock behind opened saturates
    assert_eq!(ea.violations(), 0);
    // The first valid page ends the grace for good, even past the limit.
    let _eb = ByteEndpoint::new(&mut b[..], 16).unwrap();
    assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Ok(1));
    assert!(!ea.attach_overdue(0, u64::MAX, 10_000));
    assert_eq!(ea.violations(), 0);
}

#[test]
fn peer_head_far_ahead_resyncs_and_counts() {
    let (mut a, mut b, mut ea, _eb) = pair(16);
    write_u32(&mut b, layout::HEAD, 100);
    let mut out = [0u8; 8];
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::Resynced));
    assert_eq!(ea.violations(), 1);
    assert_eq!(ea.drops(), 100);
    assert_eq!(read_u32(&a, layout::DROPS), 100);
    assert_eq!(read_u32(&a, layout::PEER_TAIL), 100);
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::Empty));
}

#[test]
fn peer_tail_claiming_more_than_produced_reads_full() {
    let (mut a, mut b, mut ea, _eb) = pair(16);
    write_u32(&mut b, layout::PEER_TAIL, 5); // we produced nothing
    assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Err(RingError::Full));
    assert_eq!(ea.violations(), 1);
}

#[test]
fn malformed_peer_control_is_counted() {
    let lies: [(&str, Lie); 4] = [
        ("bad magic", |p| p[..8].copy_from_slice(b"XXXXXXXX")),
        ("frame ring slot_size", |p| write_u32(p, layout::SLOT_SIZE_FIELD, 2048)),
        ("capacity not a power of two", |p| write_u32(p, layout::SLOT_COUNT, 12)),
        ("capacity larger than page", |p| write_u32(p, layout::SLOT_COUNT, 1 << 20)),
    ];
    for (name, lie) in lies {
        let (mut a, mut b, mut ea, _eb) = pair(16);
        lie(&mut b);
        let mut out = [0u8; 4];
        assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Err(RingError::PeerMalformed), "{name}");
        assert_eq!(ea.violations(), 1, "{name}");
        assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::PeerMalformed), "{name}");
        assert_eq!(ea.violations(), 2, "{name}");
    }
}

#[test]
fn violation_limit_makes_peer_untrusted_and_freezes_count() {
    let (mut a, mut b, mut ea, _eb) = pair(16);
    b[..8].copy_from_slice(b"XXXXXXXX");
    for i in 1..=PEER_VIOLATION_LIMIT {
        assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Err(RingError::PeerMalformed));
        assert_eq!(ea.violations(), i);
    }
    assert_eq!(ea.health(), Health::Untrusted);
    // Even a repaired peer page does not restore trust.
    let _fixed = ByteEndpoint::new(&mut b[..], 16).unwrap();
    let mut out = [0u8; 4];
    assert_eq!(ea.write(&mut a[..], &b[..], b"x"), Err(RingError::PeerUntrusted));
    assert_eq!(ea.write(&mut a[..], &b[..], b""), Err(RingError::PeerUntrusted));
    assert_eq!(ea.peek(&mut a[..], &b[..], &mut out), Err(RingError::PeerUntrusted));
    assert_eq!(ea.read(&mut a[..], &b[..], &mut out), Err(RingError::PeerUntrusted));
    assert_eq!(ea.violations(), PEER_VIOLATION_LIMIT);
}

#[test]
fn control_validation_rejects_the_other_ring_kind() {
    let mut frame_page = vec![0u8; layout::CONTROL_LEN + 4 * layout::SLOT_SIZE];
    let _f = Endpoint::new(&mut frame_page[..], 4).unwrap();
    assert_eq!(validate_byte_control(&frame_page[..]), Err(ControlError::BadSlotSize));
    let mut byte_page = vec![0u8; layout::CONTROL_LEN + 16];
    let _e = ByteEndpoint::new(&mut byte_page[..], 16).unwrap();
    assert_eq!(validate_control(&byte_page[..]).err(), Some(ControlError::BadSlotSize));
    assert_eq!(validate_byte_control(&byte_page[..]).unwrap().capacity(), 16);
    assert_eq!(validate_byte_control(&vec![0u8; layout::CONTROL_LEN + 16][..]), Err(ControlError::Gone));
    let mut p = vec![0u8; layout::CONTROL_LEN + 16];
    assert_eq!(ByteEndpoint::new(&mut p[..], 0).err(), Some(ControlError::BadSlotCount));
    assert_eq!(ByteEndpoint::new(&mut p[..], 3).err(), Some(ControlError::BadSlotCount));
    assert_eq!(ByteEndpoint::new(&mut p[..], 32).err(), Some(ControlError::PageTooSmall));
}
