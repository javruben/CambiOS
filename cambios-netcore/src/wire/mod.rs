// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Wire formats: bounded parsers and emitters (spec `net.md` § 4).
//!
//! Every parser is a total function over a byte slice: it returns one
//! validated view or one closed [`ParseError`](crate::ParseError), never
//! a partial result (spec B-9). Views borrow the input; nothing is
//! copied or allocated. Every byte access goes through the checked
//! helpers below, so an out-of-range read is an error value, not a panic
//! (INV-net-013).

pub mod arp;
pub mod dhcpv4;
pub mod ethernet;
pub mod frame;
pub mod icmpv4;
pub mod ipv4;
pub mod tcp;
pub mod udp;

/// Read `N` bytes at `at`, or `None` if they are not all present.
pub(crate) fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    let slice = bytes.get(at..end)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Some(out)
}

pub(crate) fn u8_at(bytes: &[u8], at: usize) -> Option<u8> {
    bytes.get(at).copied()
}

pub(crate) fn be16_at(bytes: &[u8], at: usize) -> Option<u16> {
    array_at::<2>(bytes, at).map(u16::from_be_bytes)
}

pub(crate) fn be32_at(bytes: &[u8], at: usize) -> Option<u32> {
    array_at::<4>(bytes, at).map(u32::from_be_bytes)
}

/// Write `src` at `at`, or `None` if `out` is too short.
pub(crate) fn put(out: &mut [u8], at: usize, src: &[u8]) -> Option<()> {
    let end = at.checked_add(src.len())?;
    out.get_mut(at..end)?.copy_from_slice(src);
    Some(())
}
