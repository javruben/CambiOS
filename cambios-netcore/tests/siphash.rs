// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! SipHash-2-4 against every published 64-bit test vector.
//!
//! The expected values are the 64 entries of `vectors_sip64` in the
//! reference implementation's `vectors.h` (github.com/veorq/SipHash,
//! CC0-1.0), fetched 2026-11-06 (file sha256 212c4411…9f48d31), read as
//! little-endian u64. Vector i hashes the message 00 01 .. (i-1) under the
//! key 00 01 .. 0f. Entry 15 equals the value printed in the paper's
//! Appendix A (0xa129ca6149be45e5), an independent cross-check of the
//! transcription. Only test data was taken; the implementation was written
//! from the paper.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use cambios_netcore::siphash::siphash24;

const EXPECTED: [u64; 64] = [
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
    0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
    0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572,
];

#[test]
fn all_64_reference_vectors() {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let msg: Vec<u8> = (0u8..64).collect();
    for (i, want) in EXPECTED.iter().enumerate() {
        assert_eq!(siphash24(&key, &msg[..i]), *want, "vector {i}");
    }
    assert_eq!(EXPECTED[15], 0xa129_ca61_49be_45e5, "the paper's Appendix A value");
}
