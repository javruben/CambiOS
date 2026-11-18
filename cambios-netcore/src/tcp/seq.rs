// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Sequence-number arithmetic (RFC 9293 § 3.4).
//!
//! Sequence numbers live in a ring of 2^32. Every operation here is
//! explicit modular arithmetic; none can trap (INV-net-013).
//!
//! The primitive is the half-open window test [`SeqNum::in_window`]:
//! `x ∈ [start, start + len)` holds iff `x - start < len` with the
//! subtraction taken mod 2^32. That is exact for every `len`, including
//! windows that straddle the 2^32 wrap (NET-V-091), and it never has to
//! decide which of two numbers is "earlier". The ordered comparisons
//! (`lt`, `le`, …) are RFC 1982 serial-number comparisons and are only
//! meaningful for numbers less than 2^31 apart; at exactly 2^31 they are
//! undefined by the RFC, and the window test is used instead wherever a
//! guard depends on the answer.

/// A TCP sequence or acknowledgement number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SeqNum(pub u32);

impl SeqNum {
    /// `self + n` modulo 2^32.
    pub const fn add(self, n: u32) -> SeqNum {
        SeqNum(self.0.wrapping_add(n))
    }

    /// `self - n` modulo 2^32.
    pub const fn sub(self, n: u32) -> SeqNum {
        SeqNum(self.0.wrapping_sub(n))
    }

    /// Forward distance from `base` to `self`, modulo 2^32.
    pub const fn distance_from(self, base: SeqNum) -> u32 {
        self.0.wrapping_sub(base.0)
    }

    /// `self ∈ [start, start + len)` modulo 2^32. False when `len == 0`.
    pub const fn in_window(self, start: SeqNum, len: u32) -> bool {
        self.distance_from(start) < len
    }

    /// `low < self <= high` modulo 2^32, read as "`self` lies in the
    /// forward span after `low`, up to and including `high`".
    pub const fn in_range_open_closed(self, low: SeqNum, high: SeqNum) -> bool {
        let span = high.distance_from(low);
        let d = self.distance_from(low);
        d != 0 && d <= span
    }

    /// `low <= self <= high` modulo 2^32 (closed span).
    pub const fn in_range_closed(self, low: SeqNum, high: SeqNum) -> bool {
        self.distance_from(low) <= high.distance_from(low)
    }

    /// RFC 1982 serial `self < other`. See the module note at 2^31.
    pub const fn lt(self, other: SeqNum) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    /// RFC 1982 serial `self <= other`.
    pub const fn le(self, other: SeqNum) -> bool {
        self.0 == other.0 || self.lt(other)
    }

    /// RFC 1982 serial `self > other`.
    pub const fn gt(self, other: SeqNum) -> bool {
        other.lt(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_straddling_wrap() {
        let start = SeqNum(u32::MAX - 1);
        assert!(SeqNum(u32::MAX - 1).in_window(start, 4));
        assert!(SeqNum(u32::MAX).in_window(start, 4));
        assert!(SeqNum(0).in_window(start, 4));
        assert!(SeqNum(1).in_window(start, 4));
        assert!(!SeqNum(2).in_window(start, 4));
        assert!(!SeqNum(u32::MAX - 2).in_window(start, 4));
        assert!(!start.in_window(start, 0));
    }

    #[test]
    fn open_closed_range() {
        let lo = SeqNum(u32::MAX);
        let hi = SeqNum(1);
        assert!(!lo.in_range_open_closed(lo, hi));
        assert!(SeqNum(0).in_range_open_closed(lo, hi));
        assert!(SeqNum(1).in_range_open_closed(lo, hi));
        assert!(!SeqNum(2).in_range_open_closed(lo, hi));
    }

    #[test]
    fn serial_order_across_wrap() {
        assert!(SeqNum(u32::MAX).lt(SeqNum(0)));
        assert!(SeqNum(0).gt(SeqNum(u32::MAX)));
        assert!(SeqNum(5).le(SeqNum(5)));
        assert_eq!(SeqNum(u32::MAX).add(2), SeqNum(1));
        assert_eq!(SeqNum(1).sub(2), SeqNum(u32::MAX));
    }
}
