// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! How much new data the sender may put on the wire (INV-net-008,
//! ADR-039 § 6.1 P8): never sequence space beyond both the peer's
//! advertised window and the congestion window (RFC 9293 § 3.8.6,
//! RFC 5681 § 3.1). The congestion window is an input here; the
//! algorithm that sets it is not part of this crate yet.

use super::seq::SeqNum;

/// Octets of new data that may be sent now.
///
/// `snd_wnd` is the peer's advertised window and `cwnd` the congestion
/// window, both measured from `snd_una`; `snd_nxt - snd_una` is already
/// in flight. The result is `min(snd_wnd, cwnd) - in_flight`, floored
/// at zero, then capped by `unsent`.
pub fn sendable(snd_una: SeqNum, snd_nxt: SeqNum, snd_wnd: u32, cwnd: u32, unsent: u32) -> u32 {
    let in_flight = snd_nxt.distance_from(snd_una);
    snd_wnd.min(cwnd).saturating_sub(in_flight).min(unsent)
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// P8 (ADR-039 § 6.1; INV-net-008): for every input, the new data
    /// allowed never exceeds the peer window, the congestion window or the
    /// unsent backlog; when what is already in flight fits both windows,
    /// in-flight plus new stays inside `min(snd_wnd, cwnd)`; when it does
    /// not fit, nothing new is sent. Loop-free, so no unwind bound.
    #[kani::proof]
    fn p8_sendable_stays_inside_both_windows() {
        let una: u32 = kani::any();
        let nxt: u32 = kani::any();
        let wnd: u32 = kani::any();
        let cwnd: u32 = kani::any();
        let unsent: u32 = kani::any();
        let n = sendable(SeqNum(una), SeqNum(nxt), wnd, cwnd, unsent);
        assert!(n <= wnd && n <= cwnd && n <= unsent);
        let in_flight = u64::from(nxt.wrapping_sub(una));
        let limit = u64::from(wnd.min(cwnd));
        if in_flight <= limit {
            assert!(in_flight + u64::from(n) <= limit);
        } else {
            assert_eq!(n, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_reduces_the_window() {
        let una = SeqNum(100);
        assert_eq!(sendable(una, SeqNum(100), 1000, 800, 1200), 800);
        assert_eq!(sendable(una, SeqNum(400), 1000, 800, 1200), 500);
        assert_eq!(sendable(una, SeqNum(900), 1000, 800, 1200), 0);
        assert_eq!(sendable(una, SeqNum(1000), 1000, 800, 1200), 0);
        assert_eq!(sendable(una, SeqNum(100), 1000, 800, 10), 10);
    }
}
