// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fixtures: two byte buffers stand in for the two channel pages of a seam.
//! Side A owns page `a` (its TX ring) and reads page `b`; side B the
//! reverse.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use net_seam::layout;

/// A pair of zeroed pages sized for `slots` frame slots each.
pub fn pages(slots: u32) -> (Vec<u8>, Vec<u8>) {
    let n = layout::CONTROL_LEN + slots as usize * layout::SLOT_SIZE;
    (vec![0u8; n], vec![0u8; n])
}

/// A recognisable frame body.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

pub fn read_u32(page: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(page[off..off + 4].try_into().unwrap())
}

/// Write a control field directly, as a lying peer would.
pub fn write_u32(page: &mut [u8], off: usize, v: u32) {
    page[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Write a slot's length prefix directly, as a lying peer would.
pub fn forge_len(page: &mut [u8], slot: usize, len: u16) {
    let off = layout::CONTROL_LEN + slot * layout::SLOT_SIZE;
    page[off..off + 2].copy_from_slice(&len.to_le_bytes());
}
