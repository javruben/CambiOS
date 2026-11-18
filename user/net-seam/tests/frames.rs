// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The honest-peer contract: full-size frames, full/empty, index wrap,
//! slot recycling, and local misuse. Every test also asserts that an
//! honest exchange counts zero peer violations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::*;
use net_seam::{layout, Endpoint, RingError, MAX_FRAME};

#[test]
fn max_mtu_frame_round_trips() {
    let (mut a, mut b) = pages(16);
    let mut tx = Endpoint::new(&mut a[..], 16).expect("init a");
    let mut rx = Endpoint::new(&mut b[..], 16).expect("init b");
    let frame = pattern(MAX_FRAME, 7);
    assert_eq!(frame.len(), 1514);
    tx.send(&mut a[..], &b[..], &frame).expect("send");
    let mut out = [0u8; MAX_FRAME];
    let n = rx.recv(&mut b[..], &a[..], &mut out).expect("recv");
    assert_eq!(n, 1514);
    assert_eq!(&out[..n], &frame[..]);
    assert_eq!(rx.drops(), 0);
    assert_eq!(tx.violations() + rx.violations(), 0);
}

#[test]
fn empty_then_full_then_drains_in_order() {
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Empty));
    for i in 0..4u8 {
        tx.send(&mut a[..], &b[..], &[i; 60]).unwrap();
    }
    let head_before = read_u32(&a, layout::HEAD);
    assert_eq!(tx.send(&mut a[..], &b[..], &[9; 60]), Err(RingError::Full));
    assert_eq!(read_u32(&a, layout::HEAD), head_before, "a refused send publishes nothing");
    for i in 0..4u8 {
        let n = rx.recv(&mut b[..], &a[..], &mut out).unwrap();
        assert_eq!(&out[..n], &[i; 60][..]);
    }
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Err(RingError::Empty));
    assert_eq!(tx.violations() + rx.violations(), 0);
}

#[test]
fn indices_wrap_past_u32_max() {
    let start = u32::MAX - 2;
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::with_start(&mut a[..], 4, start).unwrap();
    let mut rx = Endpoint::with_start(&mut b[..], 4, start).unwrap();
    let mut out = [0u8; MAX_FRAME];
    let mut next = 0u8;
    let mut expect = 0u8;
    for _ in 0..3 {
        for _ in 0..3 {
            tx.send(&mut a[..], &b[..], &[next; 100]).unwrap();
            next += 1;
        }
        for _ in 0..3 {
            let n = rx.recv(&mut b[..], &a[..], &mut out).unwrap();
            assert_eq!(n, 100);
            assert!(out[..n].iter().all(|&x| x == expect), "FIFO order across the wrap");
            expect += 1;
        }
    }
    assert_eq!(read_u32(&a, layout::HEAD), start.wrapping_add(9));
    assert_eq!(read_u32(&b, layout::PEER_TAIL), start.wrapping_add(9));
    assert_eq!(tx.violations() + rx.violations(), 0);
}

#[test]
fn slot_reuse_waits_for_the_consumer_and_leaves_no_stale_bytes() {
    let (mut a, mut b) = pages(2);
    let mut tx = Endpoint::new(&mut a[..], 2).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 2).unwrap();
    tx.send(&mut a[..], &b[..], &[0x11; 1000]).unwrap();
    tx.send(&mut a[..], &b[..], &[0x22; 50]).unwrap();
    assert_eq!(tx.send(&mut a[..], &b[..], &[0x33; 10]), Err(RingError::Full), "slot 0 not yet consumed");
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Ok(1000));
    tx.send(&mut a[..], &b[..], &[0x33; 10]).unwrap(); // reuses slot 0
    out = [0xAA; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Ok(50));
    assert!(out[..50].iter().all(|&x| x == 0x22));
    assert!(out[50..].iter().all(|&x| x == 0xAA), "nothing written past len");
    out = [0xAA; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Ok(10));
    assert!(out[..10].iter().all(|&x| x == 0x33));
    assert!(out[10..].iter().all(|&x| x == 0xAA), "no stale bytes from the 1000-octet frame");
    assert_eq!(tx.violations() + rx.violations(), 0);
}

#[test]
fn local_misuse_is_refused_without_side_effects() {
    let (mut a, mut b) = pages(4);
    let mut tx = Endpoint::new(&mut a[..], 4).unwrap();
    let mut rx = Endpoint::new(&mut b[..], 4).unwrap();
    assert_eq!(tx.send(&mut a[..], &b[..], &[]), Err(RingError::FrameEmpty));
    assert_eq!(tx.send(&mut a[..], &b[..], &vec![0u8; MAX_FRAME + 1]), Err(RingError::FrameTooLarge));
    tx.send(&mut a[..], &b[..], &[5; 200]).unwrap();
    let mut small = [0u8; 100];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut small), Err(RingError::OutputTooSmall));
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(rx.recv(&mut b[..], &a[..], &mut out), Ok(200), "the frame is still there");
    assert_eq!(tx.violations() + rx.violations(), 0);
}
