// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The Internet checksum (RFC 1071): the 16-bit one's-complement of the
//! one's-complement sum of the data taken as big-endian 16-bit words.
//!
//! [`Checksum`] accumulates the sum over any number of byte slices fed in
//! order, carrying an odd trailing byte from one slice into the next, so
//! a pseudo-header, a header and a payload can be summed without copying
//! them into one buffer. The running sum is folded after every word: the
//! invariant `sum <= 0xFFFF` holds between calls, so `sum + word` never
//! exceeds `0x1FFFE` and no addition can overflow regardless of input
//! length (INV-net-013: no unchecked wrap).

/// A running Internet-checksum accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checksum {
    /// One's-complement running sum. Invariant: `sum <= 0xFFFF`.
    sum: u32,
    /// The first byte of a word whose second byte has not arrived yet.
    pending: Option<u8>,
}

impl Default for Checksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Checksum {
    pub const fn new() -> Self {
        Checksum { sum: 0, pending: None }
    }

    /// One's-complement add of one 16-bit word; preserves `sum <= 0xFFFF`.
    const fn add_word(sum: u32, word: u16) -> u32 {
        // sum <= 0xFFFF and word <= 0xFFFF, so s <= 0x1FFFE: the add is
        // exact, `wrapping_add` only states that no check is needed.
        let s = sum.wrapping_add(word as u32);
        // End-around carry: (s & 0xFFFF) <= 0xFFFF, (s >> 16) <= 1, and
        // when the carry is 1 the low half is <= 0xFFFE, so the result
        // is again <= 0xFFFF (exact for the same reason).
        (s & 0xFFFF).wrapping_add(s >> 16)
    }

    /// Add a big-endian 16-bit value (a pseudo-header field).
    pub fn add_u16(&mut self, value: u16) {
        let [hi, lo] = value.to_be_bytes();
        self.add_bytes(&[hi, lo]);
    }

    /// Add bytes, continuing from wherever the previous call stopped.
    pub fn add_bytes(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        if let Some(hi) = self.pending {
            match rest.split_first() {
                Some((&lo, tail)) => {
                    self.sum = Self::add_word(self.sum, u16::from_be_bytes([hi, lo]));
                    self.pending = None;
                    rest = tail;
                }
                None => return,
            }
        }
        let mut words = rest.chunks_exact(2);
        for pair in &mut words {
            if let [hi, lo] = *pair {
                self.sum = Self::add_word(self.sum, u16::from_be_bytes([hi, lo]));
            }
        }
        if let [odd] = *words.remainder() {
            self.pending = Some(odd);
        }
    }

    /// The checksum to place in a header: the complement of the sum, with
    /// a trailing odd byte padded by a zero octet (RFC 1071 § 1).
    pub fn finish(self) -> u16 {
        let sum = match self.pending {
            Some(hi) => Self::add_word(self.sum, u16::from_be_bytes([hi, 0])),
            None => self.sum,
        };
        // sum <= 0xFFFF, so the truncation is exact.
        !(sum as u16)
    }

    /// True when the data summed, *including* its transmitted checksum
    /// field, verifies: the complement of the total is zero.
    pub fn verifies(self) -> bool {
        self.finish() == 0
    }
}

/// Checksum of one contiguous slice.
pub fn of(bytes: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add_bytes(bytes);
    c.finish()
}

/// Bounded proofs (run with `cargo kani -Z stubbing`; compiled only under
/// `cfg(kani)`).
///
/// The checksum stage of the P6 frame proof (assume-guarantee, same shape
/// as the TCP option walk in `wire::tcp::proofs`):
///
/// 1. `p6_checksum_is_total_up_to_frame` proves the accumulator alone:
///    starting from ANY state (any running sum, any pending octet),
///    `add_bytes` of any feed up to a full frame, `add_u16`, `finish` and
///    `verifies` each return without panic, out-of-bounds access or
///    overflow. Because the start state is arbitrary, this covers every
///    call sequence a parser makes (each call starts from some state), by
///    induction over the calls. They have no preconditions.
/// 2. The stubs below stand in for the accumulator in composed parser
///    harnesses: `add_bytes` does nothing, and `verifies` returns any
///    value. Every real result is among those values, so the stubs
///    over-approximate the real accumulator. With (1), totality proven
///    with the stubs holds for the real code.
///
/// What this does NOT cover: that the checksum is *correct* (RFC 1071).
/// That is the unit tests' job (known-answer and split-invariance tests
/// below); totality is the only property the composed harness relies on.
#[cfg(kani)]
pub(crate) mod proofs {
    use super::*;

    /// HARDWARE: largest Ethernet II frame without FCS (1500-octet MTU plus
    /// the 14-octet header); no single checksum feed in a parse is longer.
    const MAX_FRAME: usize = 1514;

    fn any_state() -> Checksum {
        Checksum {
            sum: kani::any(),
            pending: if kani::any() { Some(kani::any()) } else { None },
        }
    }

    /// Independent reference for `finish` on a reachable state
    /// (`sum <= 0xFFFF`): fold the pending octet in with u64 arithmetic.
    /// One end-around fold suffices because sum + word <= 0x1FFFE.
    fn finish_reference(c: Checksum) -> u16 {
        let mut s = u64::from(c.sum);
        if let Some(hi) = c.pending {
            s += u64::from(hi) << 8;
        }
        s = (s & 0xFFFF) + (s >> 16);
        !(s as u16)
    }

    /// Stage proof: from any state, every accumulator method is total for
    /// any feed up to frame size, and each call's result is observed by an
    /// assertion (so no call can be dropped as dead code and pass vacuously):
    /// - `add_bytes`: a one-shot feed and the same feed split at any point
    ///   give the same state (from an arbitrary start state);
    /// - `add_u16`: equals feeding the value's big-endian octets;
    /// - `verifies`: equals `finish() == 0` (any state);
    /// - `finish`: equals an independent u64 reference on reachable states
    ///   (`sum <= 0xFFFF`, the invariant `new()` and every method keep).
    /// Unwind 760: each word loop runs at most 1514 / 2 = 757 times.
    #[kani::proof]
    #[kani::unwind(760)]
    fn p6_checksum_is_total_up_to_frame() {
        let buf: [u8; MAX_FRAME] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_FRAME);
        let cut: usize = kani::any();
        kani::assume(cut <= len);

        let start = any_state();
        let mut one = start;
        one.add_bytes(&buf[..len]);
        let mut two = start;
        two.add_bytes(&buf[..cut]);
        two.add_bytes(&buf[cut..len]);
        assert!(one == two);

        let v: u16 = kani::any();
        let mut a = any_state();
        let mut b = a;
        a.add_u16(v);
        b.add_bytes(&v.to_be_bytes());
        assert!(a == b);

        let c = any_state();
        assert!(c.verifies() == (c.finish() == 0));

        let r = any_state();
        kani::assume(r.sum <= 0xFFFF);
        assert!(r.finish() == finish_reference(r));
    }

    /// Totality alone for the one method whose cost grows with the feed:
    /// from any state, `add_bytes` of any feed up to a full frame returns
    /// without panic, out-of-bounds access or overflow, and keeps the
    /// `sum <= 0xFFFF` invariant (asserted on the result, so the call
    /// cannot be dropped as dead code). This is the property the stubbed
    /// parser harnesses rely on. It is one symbolic pass, where
    /// `p6_checksum_is_total_up_to_frame` also proves split invariance
    /// (three passes, a symbolic cut) at the same bound and is heavier.
    #[kani::proof]
    #[kani::unwind(760)]
    fn p6_checksum_add_bytes_is_total_up_to_frame() {
        let buf: [u8; MAX_FRAME] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_FRAME);
        let mut c = any_state();
        kani::assume(c.sum <= 0xFFFF);
        c.add_bytes(&buf[..len]);
        assert!(c.sum <= 0xFFFF);
    }

    /// Stand-in for `Checksum::add_bytes`: changes nothing. Sound with the
    /// stage proof because `verifies` is stubbed to return any value, so
    /// the accumulator state is unobservable on the parse path.
    pub(crate) fn add_bytes_stub(_sum: &mut Checksum, _bytes: &[u8]) {}

    /// Stand-in for `Checksum::verifies`: any outcome.
    pub(crate) fn verifies_stub(_sum: Checksum) -> bool {
        kani::any()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 § 3 worked example: bytes 00 01 f2 03 f4 f5 f6 f7 sum to
    /// ddf2 (one's complement), so the checksum is !ddf2 = 220d.
    #[test]
    fn rfc1071_example() {
        assert_eq!(of(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn split_at_any_point_matches_contiguous() {
        let data = [0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xff];
        let whole = of(&data);
        for cut in 0..=data.len() {
            let (a, b) = data.split_at(cut);
            let mut c = Checksum::new();
            c.add_bytes(a);
            c.add_bytes(b);
            assert_eq!(c.finish(), whole, "cut at {cut}");
        }
    }

    #[test]
    fn inserting_the_checksum_verifies() {
        let mut data = [0x12u8, 0x34, 0x00, 0x00, 0xab, 0xcd, 0xef];
        let ck = of(&data).to_be_bytes();
        data[2] = ck[0];
        data[3] = ck[1];
        let mut c = Checksum::new();
        c.add_bytes(&data);
        assert!(c.verifies());
    }

    #[test]
    fn all_ones_input_does_not_overflow() {
        let data = [0xFFu8; 4096];
        // Sum of 0xFFFF words is 0xFFFF (negative zero); complement is 0.
        assert_eq!(of(&data), 0);
    }
}
