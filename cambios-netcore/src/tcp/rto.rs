// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The retransmission timeout estimator (RFC 6298), with the bounds
//! ADR-039 § 5.2 fixes: floor 200 ms, ceiling 60 s, backoff × 2.
//!
//! Pure arithmetic over milliseconds; every operation saturates, so no
//! input sequence can overflow. Karn's rule (no sample from a
//! retransmitted segment) is the caller's: it decides when to call
//! [`RtoEstimator::sample`].

/// HARDWARE: initial RTO before any RTT sample (RFC 6298 § 2.1).
pub const RTO_INITIAL_MS: u64 = 1_000;
/// TUNING: RTO floor, fixed by ADR-039 § 5.2 (RFC 6298 § 2.4 allows a
/// floor below its 1 s recommendation; 200 ms matches Linux).
pub const RTO_MIN_MS: u64 = 200;
/// TUNING: RTO ceiling, fixed by ADR-039 § 5.2 (RFC 6298 § 2.5 permits
/// any ceiling of at least 60 s).
pub const RTO_MAX_MS: u64 = 60_000;
/// HARDWARE: RTO after the SYN timed out, once data transfer begins
/// (RFC 6298 § 5.7).
pub const RTO_AFTER_SYN_LOSS_MS: u64 = 3_000;
/// ARCHITECTURAL: clock granularity G; the engine's clock counts
/// milliseconds.
const CLOCK_GRANULARITY_MS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Estimate {
    srtt_ms: u64,
    rttvar_ms: u64,
}

/// One connection's RTO state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtoEstimator {
    estimate: Option<Estimate>,
    rto_ms: u64,
}

impl Default for RtoEstimator {
    fn default() -> Self {
        Self::new()
    }
}

const fn clamp(ms: u64) -> u64 {
    if ms < RTO_MIN_MS {
        RTO_MIN_MS
    } else if ms > RTO_MAX_MS {
        RTO_MAX_MS
    } else {
        ms
    }
}

impl RtoEstimator {
    pub const fn new() -> Self {
        RtoEstimator { estimate: None, rto_ms: RTO_INITIAL_MS }
    }

    pub const fn rto_ms(&self) -> u64 {
        self.rto_ms
    }

    /// Fold in one round-trip measurement `r_ms` (RFC 6298 § 2.2, § 2.3,
    /// with alpha = 1/8, beta = 1/4, K = 4).
    pub fn sample(&mut self, r_ms: u64) {
        let e = match self.estimate {
            None => Estimate { srtt_ms: r_ms, rttvar_ms: r_ms / 2 },
            Some(Estimate { srtt_ms, rttvar_ms }) => {
                let deviation = srtt_ms.abs_diff(r_ms);
                Estimate {
                    rttvar_ms: rttvar_ms.saturating_mul(3).saturating_add(deviation) / 4,
                    srtt_ms: srtt_ms.saturating_mul(7).saturating_add(r_ms) / 8,
                }
            }
        };
        self.estimate = Some(e);
        let variance_term = e.rttvar_ms.saturating_mul(4).max(CLOCK_GRANULARITY_MS);
        self.rto_ms = clamp(e.srtt_ms.saturating_add(variance_term));
    }

    /// The timer expired: double the RTO, up to the ceiling (§ 5.5).
    pub fn back_off(&mut self) {
        self.rto_ms = clamp(self.rto_ms.saturating_mul(2));
    }

    /// The SYN or SYN-ACK was retransmitted before the handshake
    /// completed (§ 5.7).
    pub fn after_syn_loss(&mut self) {
        self.rto_ms = clamp(RTO_AFTER_SYN_LOSS_MS);
    }
}
