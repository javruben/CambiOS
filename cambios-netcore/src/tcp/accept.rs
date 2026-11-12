// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Segment acceptability (RFC 9293 § 3.10.7.4, first check) and the
//! RFC 5961 window tests. Pure functions over sequence numbers; ADR-039
//! § 6.1 P1 is stated against [`acceptable`].

use super::seq::SeqNum;

/// RFC 9293 § 3.10.7.4 acceptability table, under modular arithmetic:
///
/// | SEG.LEN | RCV.WND | acceptable when |
/// |---|---|---|
/// | 0 | 0 | `SEG.SEQ = RCV.NXT` |
/// | 0 | > 0 | `RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND` |
/// | > 0 | 0 | never |
/// | > 0 | > 0 | the first or the last octet is in the window |
pub fn acceptable(seg_seq: SeqNum, seg_len: u32, rcv_nxt: SeqNum, rcv_wnd: u32) -> bool {
    match (seg_len, rcv_wnd) {
        (0, 0) => seg_seq == rcv_nxt,
        (0, _) => seg_seq.in_window(rcv_nxt, rcv_wnd),
        (_, 0) => false,
        (len, _) => {
            // len > 0 here, so len - 1 cannot underflow.
            let last = seg_seq.add(len.saturating_sub(1));
            seg_seq.in_window(rcv_nxt, rcv_wnd) || last.in_window(rcv_nxt, rcv_wnd)
        }
    }
}

/// How an RST relates to the receive window (RFC 5961 § 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RstCheck {
    /// `SEG.SEQ = RCV.NXT`: reset the connection.
    Exact,
    /// In the window but not exact: send a challenge ACK, change nothing.
    InWindow,
    /// Outside the window: drop silently.
    OutOfWindow,
}

pub fn rst_check(seg_seq: SeqNum, rcv_nxt: SeqNum, rcv_wnd: u32) -> RstCheck {
    if seg_seq == rcv_nxt {
        RstCheck::Exact
    } else if seg_seq.in_window(rcv_nxt, rcv_wnd) {
        RstCheck::InWindow
    } else {
        RstCheck::OutOfWindow
    }
}

/// How an ACK value relates to the send sequence space (RFC 9293
/// § 3.10.7.4 fifth step with RFC 5961 § 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckCheck {
    /// `SND.UNA < SEG.ACK =< SND.NXT`: acknowledges new data.
    New,
    /// `SND.UNA - MAX.SND.WND =< SEG.ACK =< SND.UNA`: a duplicate,
    /// acceptable for window updates, acknowledges nothing new.
    Duplicate,
    /// `SEG.ACK > SND.NXT`: acknowledges data never sent. Answer with an
    /// ACK and drop (RFC 9293).
    Unsent,
    /// `SEG.ACK < SND.UNA - MAX.SND.WND`: too old to be legitimate.
    /// Answer with a challenge ACK and drop (RFC 5961 § 5.2).
    TooOld,
}

pub fn ack_check(seg_ack: SeqNum, snd_una: SeqNum, snd_nxt: SeqNum, max_snd_wnd: u32) -> AckCheck {
    if seg_ack.in_range_open_closed(snd_una, snd_nxt) {
        return AckCheck::New;
    }
    if seg_ack.in_range_closed(snd_una.sub(max_snd_wnd), snd_una) {
        return AckCheck::Duplicate;
    }
    // Neither: decide which side of the acceptable span it fell on.
    // `seg_ack - snd_nxt` read as a signed serial distance: positive
    // means ahead of anything sent.
    if seg_ack.gt(snd_nxt) {
        AckCheck::Unsent
    } else {
        AckCheck::TooOld
    }
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// P1 (ADR-039 § 6.1; INV-net-007): for every `(SEG.SEQ, SEG.LEN,
    /// RCV.NXT, RCV.WND)`, `acceptable` equals the RFC 9293 § 3.10.7.4
    /// table, computed here independently as offsets from RCV.NXT in
    /// `u64` with an explicit modulus instead of `u32` wrapping.
    #[kani::proof]
    fn p1_acceptable_matches_rfc9293_table() {
        let seq: u32 = kani::any();
        let len: u32 = kani::any();
        let nxt: u32 = kani::any();
        let wnd: u32 = kani::any();
        const M: u64 = 1 << 32;
        let first = (u64::from(seq) + M - u64::from(nxt)) % M;
        let in_window = |offset: u64| offset < u64::from(wnd);
        let spec = if len == 0 {
            if wnd == 0 {
                seq == nxt
            } else {
                in_window(first)
            }
        } else if wnd == 0 {
            false
        } else {
            let last = (first + u64::from(len) - 1) % M;
            in_window(first) || in_window(last)
        };
        assert_eq!(acceptable(SeqNum(seq), len, SeqNum(nxt), wnd), spec);
    }

    /// P1 corollary: acceptability depends only on the distance between
    /// SEG.SEQ and RCV.NXT, so shifting both by any amount (including
    /// across 2^32) never changes the answer.
    #[kani::proof]
    fn p1_acceptable_is_translation_invariant() {
        let seq: u32 = kani::any();
        let len: u32 = kani::any();
        let nxt: u32 = kani::any();
        let wnd: u32 = kani::any();
        let k: u32 = kani::any();
        assert_eq!(
            acceptable(SeqNum(seq), len, SeqNum(nxt), wnd),
            acceptable(SeqNum(seq).add(k), len, SeqNum(nxt).add(k), wnd)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows() {
        let nxt = SeqNum(1000);
        assert!(acceptable(SeqNum(1000), 0, nxt, 0));
        assert!(!acceptable(SeqNum(1001), 0, nxt, 0));
        assert!(acceptable(SeqNum(1000), 0, nxt, 10));
        assert!(acceptable(SeqNum(1009), 0, nxt, 10));
        assert!(!acceptable(SeqNum(1010), 0, nxt, 10));
        assert!(!acceptable(SeqNum(1000), 5, nxt, 0));
        // Starts before the window, last octet inside.
        assert!(acceptable(SeqNum(995), 6, nxt, 10));
        assert!(!acceptable(SeqNum(995), 5, nxt, 10));
        // Starts inside, overhangs the right edge.
        assert!(acceptable(SeqNum(1009), 100, nxt, 10));
    }

    #[test]
    fn rst_classes() {
        let nxt = SeqNum(1000);
        assert_eq!(rst_check(SeqNum(1000), nxt, 4096), RstCheck::Exact);
        assert_eq!(rst_check(SeqNum(1200), nxt, 4096), RstCheck::InWindow);
        assert_eq!(rst_check(SeqNum(5096), nxt, 4096), RstCheck::OutOfWindow);
        assert_eq!(rst_check(SeqNum(999), nxt, 4096), RstCheck::OutOfWindow);
    }

    #[test]
    fn ack_classes() {
        let una = SeqNum(500);
        let nxt = SeqNum(600);
        assert_eq!(ack_check(SeqNum(501), una, nxt, 1000), AckCheck::New);
        assert_eq!(ack_check(SeqNum(600), una, nxt, 1000), AckCheck::New);
        assert_eq!(ack_check(SeqNum(500), una, nxt, 1000), AckCheck::Duplicate);
        assert_eq!(ack_check(SeqNum(601), una, nxt, 1000), AckCheck::Unsent);
        assert_eq!(ack_check(SeqNum(u32::MAX - 1000), una, nxt, 1000), AckCheck::TooOld);
    }
}
