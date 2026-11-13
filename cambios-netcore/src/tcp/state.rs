// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! TCP connection states and the one table of legal transitions.
//!
//! Numbering is RFC 4022 `tcpConnectionState` (Closed = 1 … TimeWait =
//! 11), the number ADR-039 § 3 puts on the wire; 0 is never a state, so a
//! zeroed byte fails [`TcpState::from_rfc4022`]. RFC 9293 names the
//! states and assigns no numbers.
//!
//! [`TRANSITIONS`] is the edge set every state change in [`super::tcb`]
//! is checked against (ADR-039 § 6.1 P2). It is the graph of RFC 9293
//! § 3.3.2 and spec `net.md` § 3, with one representation choice: a
//! passive-open connection block that the RFC "returns to LISTEN" goes
//! to `Closed` here and reports [`super::TcbEvent::ReturnedToListen`],
//! because the listener is a separate entry that never left `Listen`.

/// A TCP connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// HARDWARE: the RFC 4022 `tcpConnectionState` value.
    pub const fn to_rfc4022(self) -> u8 {
        match self {
            TcpState::Closed => 1,
            TcpState::Listen => 2,
            TcpState::SynSent => 3,
            TcpState::SynReceived => 4,
            TcpState::Established => 5,
            TcpState::FinWait1 => 6,
            TcpState::FinWait2 => 7,
            TcpState::CloseWait => 8,
            TcpState::LastAck => 9,
            TcpState::Closing => 10,
            TcpState::TimeWait => 11,
        }
    }

    pub const fn from_rfc4022(value: u8) -> Option<TcpState> {
        match value {
            1 => Some(TcpState::Closed),
            2 => Some(TcpState::Listen),
            3 => Some(TcpState::SynSent),
            4 => Some(TcpState::SynReceived),
            5 => Some(TcpState::Established),
            6 => Some(TcpState::FinWait1),
            7 => Some(TcpState::FinWait2),
            8 => Some(TcpState::CloseWait),
            9 => Some(TcpState::LastAck),
            10 => Some(TcpState::Closing),
            11 => Some(TcpState::TimeWait),
            _ => None,
        }
    }

    /// The synchronized states (RFC 9293 § 3.5.2).
    pub const fn is_synchronized(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait
        )
    }

    /// States in which arriving segment text is accepted
    /// (RFC 9293 § 3.10.7.4, seventh step).
    pub const fn accepts_text(self) -> bool {
        matches!(self, TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2)
    }

    pub const ALL: [TcpState; 11] = [
        TcpState::Closed,
        TcpState::Listen,
        TcpState::SynSent,
        TcpState::SynReceived,
        TcpState::Established,
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::CloseWait,
        TcpState::Closing,
        TcpState::LastAck,
        TcpState::TimeWait,
    ];
}

use TcpState::*;

/// Every legal `(from, to)` state change.
/// ARCHITECTURAL: the array length is the edge count of the RFC 9293
/// § 3.3.2 graph as represented here; it changes only with the graph.
pub const TRANSITIONS: [(TcpState, TcpState); 26] = [
    // Opens.
    (Closed, Listen),        // passive OPEN
    (Closed, SynSent),       // active OPEN
    (Listen, SynReceived),   // SYN to a listener creates a half-open block
    (Listen, Closed),        // CLOSE of a listener
    (SynSent, Established),  // SYN+ACK covering our SYN
    (SynSent, SynReceived),  // simultaneous open
    (SynSent, Closed),       // refusal (acceptable RST) or CLOSE
    (SynReceived, Established), // final ACK of the handshake
    (SynReceived, Closed),   // reset; for a passive block, "return to LISTEN"
    (SynReceived, FinWait1), // CLOSE before the handshake completes
    (SynReceived, CloseWait), // FIN in SYN-RECEIVED (RFC 9293 eighth step)
    // Established and the close graph.
    (Established, FinWait1),
    (Established, CloseWait),
    (Established, Closed),   // acceptable RST
    (FinWait1, FinWait2),
    (FinWait1, Closing),
    (FinWait1, TimeWait),
    (FinWait1, Closed),
    (FinWait2, TimeWait),
    (FinWait2, Closed),
    (CloseWait, LastAck),
    (CloseWait, Closed),
    (Closing, TimeWait),
    (Closing, Closed),
    (LastAck, Closed),
    (TimeWait, Closed),
];

/// ARCHITECTURAL: the number of TCP connection states (RFC 9293 § 3.3.2).
pub const STATE_COUNT: usize = 11;

/// Row/column of a state in [`EDGES`]: its RFC 4022 number minus one,
/// so 0..=10.
pub(crate) const fn index(s: TcpState) -> usize {
    (s.to_rfc4022() as usize).wrapping_sub(1)
}

/// [`TRANSITIONS`] as an adjacency matrix, built by the compiler from the
/// table (const evaluation). Nothing in it is written by hand: the table
/// stays the single source, and this is its constant-time form.
#[allow(clippy::indexing_slicing)] // Compile-time only: `index` is 0..=10 by construction, and an out-of-range index would be a build error, not a runtime panic.
const fn edge_matrix() -> [[bool; STATE_COUNT]; STATE_COUNT] {
    let mut m = [[false; STATE_COUNT]; STATE_COUNT];
    let mut i = 0;
    while i < TRANSITIONS.len() {
        let (from, to) = TRANSITIONS[i];
        m[index(from)][index(to)] = true;
        i = i.wrapping_add(1); // Bounded by the loop guard: i < TRANSITIONS.len().
    }
    m
}

pub(crate) const EDGES: [[bool; STATE_COUNT]; STATE_COUNT] = edge_matrix();

/// True when `from -> to` is in [`TRANSITIONS`]. The table holds no
/// self-loops, so "staying" is never a transition. Constant time: one
/// lookup in [`EDGES`], no scan.
pub fn is_allowed(from: TcpState, to: TcpState) -> bool {
    EDGES
        .get(index(from))
        .and_then(|row| row.get(index(to)))
        .copied()
        .unwrap_or(false)
}

/// Bounded proof (run with `cargo kani`; compiled only under `cfg(kani)`).
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_state() -> TcpState {
        match TcpState::from_rfc4022(kani::any()) {
            Some(s) => s,
            None => {
                kani::assume(false);
                TcpState::Closed
            }
        }
    }

    /// The constant-time lookup equals membership in TRANSITIONS, for any
    /// pair of states. Unwind 28: the membership scan covers 26 entries.
    #[kani::proof]
    #[kani::unwind(28)]
    fn edges_equal_transitions_membership() {
        let a = any_state();
        let b = any_state();
        let member = TRANSITIONS.iter().any(|&(f, t)| f == a && t == b);
        assert_eq!(is_allowed(a, b), member);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4022_numbering_round_trips_and_rejects_zero() {
        for s in TcpState::ALL {
            assert_eq!(TcpState::from_rfc4022(s.to_rfc4022()), Some(s));
        }
        assert_eq!(TcpState::from_rfc4022(0), None);
        assert_eq!(TcpState::from_rfc4022(12), None);
    }

    #[test]
    fn spec_section_3_edges_are_present() {
        // Every row of spec net.md § 3 "TCP connection state", in the
        // representation described in the module note.
        let spec = [
            (Closed, SynSent),
            (SynSent, Established),
            (SynSent, SynReceived),
            (SynSent, Closed),
            (Listen, SynReceived),
            (SynReceived, Established),
            (SynReceived, Closed),
            (Established, CloseWait),
            (Established, FinWait1),
            (Established, Closed),
            (FinWait1, FinWait2),
            (FinWait1, Closing),
            (FinWait1, TimeWait),
            (FinWait2, TimeWait),
            (CloseWait, LastAck),
            (LastAck, Closed),
            (Closing, TimeWait),
            (TimeWait, Closed),
        ];
        for (f, t) in spec {
            assert!(is_allowed(f, t), "{f:?} -> {t:?}");
        }
        assert!(!is_allowed(Closed, Established));
        assert!(!is_allowed(TimeWait, Established));
    }

    /// Exhaustive over all 121 state pairs: the constant-time lookup
    /// equals membership in TRANSITIONS. This is exhaustive testing of a
    /// finite relation, not a formal proof.
    #[test]
    fn lookup_equals_table_membership_for_all_pairs() {
        let mut edges = 0;
        for a in TcpState::ALL {
            for b in TcpState::ALL {
                let member = TRANSITIONS.iter().any(|&(f, t)| f == a && t == b);
                assert_eq!(is_allowed(a, b), member, "{a:?} -> {b:?}");
                edges += usize::from(member);
            }
        }
        assert_eq!(edges, TRANSITIONS.len(), "every table entry is distinct and found");
    }

    #[test]
    fn index_is_a_bijection_onto_0_to_10() {
        let mut seen = [false; STATE_COUNT];
        for s in TcpState::ALL {
            let i = index(s);
            assert!(!seen[i]);
            seen[i] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }
}
