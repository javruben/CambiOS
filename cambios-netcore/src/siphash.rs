// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! SipHash-2-4 (Aumasson and Bernstein, "SipHash: a fast short-input
//! PRF", 2012), written from the paper's algorithm description: the keyed
//! pseudorandom function RFC 6528 asks for when deriving initial sequence
//! numbers. Checked against the paper's Appendix A test vector.
//!
//! Every loop is over the input's 8-octet words, so its bound is the
//! input length; all arithmetic is the algorithm's modular arithmetic.

/// HARDWARE: SipHash initialisation constants (the paper, § 2:
/// "somepseudorandomlygeneratedbytes" read as four 64-bit words).
const INIT: [u64; 4] = [0x736f_6d65_7073_6575, 0x646f_7261_6e64_6f6d, 0x6c79_6765_6e65_7261, 0x7465_6462_7974_6573];

struct State([u64; 4]);

impl State {
    fn round(&mut self) {
        let [mut v0, mut v1, mut v2, mut v3] = self.0;
        v0 = v0.wrapping_add(v1);
        v1 = v1.rotate_left(13) ^ v0;
        v0 = v0.rotate_left(32);
        v2 = v2.wrapping_add(v3);
        v3 = v3.rotate_left(16) ^ v2;
        v0 = v0.wrapping_add(v3);
        v3 = v3.rotate_left(21) ^ v0;
        v2 = v2.wrapping_add(v1);
        v1 = v1.rotate_left(17) ^ v2;
        v2 = v2.rotate_left(32);
        self.0 = [v0, v1, v2, v3];
    }

    /// Absorb one message word with c = 2 compression rounds.
    fn absorb(&mut self, m: u64) {
        let [v0, v1, v2, v3] = self.0;
        self.0 = [v0, v1, v2, v3 ^ m];
        self.round();
        self.round();
        let [v0, v1, v2, v3] = self.0;
        self.0 = [v0 ^ m, v1, v2, v3];
    }
}

/// SipHash-2-4 of `msg` under the 128-bit `key`.
pub fn siphash24(key: &[u8; 16], msg: &[u8]) -> u64 {
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    let (lo, hi) = key.split_at(8);
    k0.copy_from_slice(lo);
    k1.copy_from_slice(hi);
    let (k0, k1) = (u64::from_le_bytes(k0), u64::from_le_bytes(k1));
    let [c0, c1, c2, c3] = INIT;
    let mut s = State([k0 ^ c0, k1 ^ c1, k0 ^ c2, k1 ^ c3]);

    let mut words = msg.chunks_exact(8);
    for w in &mut words {
        let mut b = [0u8; 8];
        b.copy_from_slice(w);
        s.absorb(u64::from_le_bytes(b));
    }
    // Final word: the remaining octets, little-endian, with the message
    // length mod 256 in the top octet.
    let mut last = [0u8; 8];
    let rest = words.remainder();
    if let Some(dst) = last.get_mut(..rest.len()) {
        dst.copy_from_slice(rest);
    }
    let len_octet = (msg.len() % 256) as u8;
    if let Some(top) = last.get_mut(7) {
        *top = len_octet;
    }
    s.absorb(u64::from_le_bytes(last));

    // Finalisation: d = 4 rounds.
    let [v0, v1, v2, v3] = s.0;
    s.0 = [v0, v1, v2 ^ 0xff, v3];
    s.round();
    s.round();
    s.round();
    s.round();
    let [v0, v1, v2, v3] = s.0;
    v0 ^ v1 ^ v2 ^ v3
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// Totality: for any key and any message of 0..=24 octets (three full
/// words plus every tail length), `siphash24` returns without panic,
/// out-of-bounds access or overflow. All arithmetic is wrapping by the
/// algorithm's definition; this harness checks there is nothing else.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// SCAFFOLDING: message length for the totality harness.
    /// Why: covers several whole 8-octet words and every remainder length;
    /// longer messages repeat the same per-word path.
    /// Replace when: a harness over the 12-octet ISS input alone is
    /// preferred, or CI budget allows a longer bound.
    const SMALL: usize = 24;

    /// Unwind 5: at most three whole words.
    #[kani::proof]
    #[kani::unwind(5)]
    fn siphash24_is_total() {
        let key: [u8; 16] = kani::any();
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        let _ = siphash24(&key, &buf[..len]);
    }
}
