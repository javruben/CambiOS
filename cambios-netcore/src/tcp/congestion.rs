// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The congestion window (RFC 5681, ADR-039 § 5.2 "Reno"): slow start,
//! congestion avoidance and the retransmission-timeout response.
//!
//! Pure saturating arithmetic, including the fast-recovery window
//! changes (RFC 5681 § 3.2); detecting duplicate ACKs and resending is the
//! engine's. Not implemented: CUBIC (RFC 9438; ADR-039 keeps the
//! algorithm an enum so it is one more arm).

/// HARDWARE: SMSS thresholds for the initial window (RFC 5681 § 3.1).
const IW_LARGE_SMSS: u32 = 2_190;
const IW_MEDIUM_SMSS: u32 = 1_095;

/// One connection's Reno state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reno {
    cwnd: u32,
    ssthresh: u32,
}

impl Reno {
    /// The initial window for a sender maximum segment size `smss`
    /// (RFC 5681 § 3.1: 2, 3 or 4 segments), and an initial slow-start
    /// threshold "arbitrarily high".
    pub fn new(smss: u16) -> Reno {
        let s = u32::from(smss);
        let segments = if s > IW_LARGE_SMSS {
            2
        } else if s > IW_MEDIUM_SMSS {
            3
        } else {
            4
        };
        Reno { cwnd: s.saturating_mul(segments), ssthresh: u32::MAX }
    }

    pub const fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub const fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// `acked` octets of new data were acknowledged (RFC 5681 § 3.1):
    /// below `ssthresh` grow by at most one SMSS per ACK; at or above it,
    /// by SMSS × SMSS / cwnd (at least one octet).
    pub fn on_ack(&mut self, acked: u32, smss: u16) {
        let s = u32::from(smss);
        let growth = if self.cwnd < self.ssthresh {
            acked.min(s)
        } else {
            s.saturating_mul(s).checked_div(self.cwnd).unwrap_or(s).max(1)
        };
        self.cwnd = self.cwnd.saturating_add(growth);
    }

    /// The retransmission timer expired with `flight` octets outstanding
    /// (RFC 5681 § 3.1, equations 4 and the loss window): ssthresh =
    /// max(flight / 2, 2 × SMSS), cwnd = one SMSS.
    pub fn on_timeout(&mut self, flight: u32, smss: u16) {
        let s = u32::from(smss);
        self.ssthresh = (flight / 2).max(s.saturating_mul(2));
        self.cwnd = s;
    }

    /// The third duplicate ACK (RFC 5681 § 3.2 steps 2 and 3): ssthresh =
    /// max(flight / 2, 2 × SMSS), cwnd = ssthresh + 3 × SMSS.
    pub fn enter_fast_recovery(&mut self, flight: u32, smss: u16) {
        let s = u32::from(smss);
        self.ssthresh = (flight / 2).max(s.saturating_mul(2));
        self.cwnd = self.ssthresh.saturating_add(s.saturating_mul(3));
    }

    /// A further duplicate ACK during fast recovery (step 4).
    pub fn inflate(&mut self, smss: u16) {
        self.cwnd = self.cwnd.saturating_add(u32::from(smss));
    }

    /// The ACK of new data that ends fast recovery (step 6).
    pub fn deflate(&mut self) {
        self.cwnd = self.ssthresh;
    }
}
