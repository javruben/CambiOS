// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The wall-clock duty `udp-stack` carried (ADR-022 § 5): ask NIST over
//! unauthenticated NTP, publish the answer with `set_wallclock(_, 0)`,
//! and ask again 4 hours after a success or 60 s after a failure. The
//! constants are udp-stack's, moved here unchanged.
//!
//! `set_wallclock` is only ever called with a parsed timestamp, never
//! with 0: 0 is the "unset" sentinel `GetWallclock` hands to readers, so
//! writing it would un-publish the clock (ADR-022 § 5).

use cambios_libsys as sys;
use cambios_netcore::engine::{Instant, UdpId};
use cambios_netcore::{IpAddress, Ipv4Address, SocketAddress};

/// NIST `time-a-g.nist.gov`. NIST asks casual clients to wait 4 h or
/// more between queries. ADR-022 § 5 accepts unauthenticated NTP from
/// a US-government address as the day-1 risk, replaced when NTS,
/// Roughtime or peer-attested setters land.
/// Renumber check: `dig +short time-a-g.nist.gov`.
pub const SERVER: Ipv4Address = Ipv4Address([129, 6, 15, 28]);
/// ARCHITECTURAL: NTP (RFC 5905 § 7.2).
pub const PORT: u16 = 123;
/// TUNING: the client port udp-stack used.
pub const CLIENT_PORT: u16 = 12_345;

/// TUNING: 4 h between successful refreshes, NIST's guidance for casual
/// clients. Replace when: a stricter freshness requirement surfaces, or
/// the trust source moves to NTS / Roughtime with their own cadence.
const REFRESH_OK_MS: u64 = 4 * 60 * 60 * 1000;
/// TUNING: 60 s back-off after a failure: a blip recovers within
/// minutes, an outage does not hammer NIST. Replace when: failure
/// telemetry shows the cadence should adapt.
const RETRY_FAIL_MS: u64 = 60 * 1000;
/// TUNING: how long one query waits for its answer (udp-stack: 3 s).
const ANSWER_MS: u64 = 3_000;
/// TUNING: how often an unsent query is retried while ARP resolves.
const SEND_RETRY_MS: u64 = 200;

/// ARCHITECTURAL: an NTP packet (RFC 5905 § 7.3).
const PACKET_LEN: usize = 48;
/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const UNIX_OFFSET: u64 = 2_208_988_800;

/// LI 0, version 4, mode 3 (client); the rest zero.
pub const REQUEST: [u8; PACKET_LEN] = {
    let mut p = [0u8; PACKET_LEN];
    p[0] = 0x23;
    p
};

/// Unix seconds from a server reply's transmit timestamp, or `None` for
/// anything that is not one.
fn parse(reply: &[u8]) -> Option<u64> {
    let secs = reply.get(40..44)?;
    if reply.len() < PACKET_LEN || reply.first()? & 0x07 != 4 {
        return None; // short, or not mode 4 (server)
    }
    let ntp = u64::from(u32::from_be_bytes([secs[0], secs[1], secs[2], secs[3]]));
    ntp.checked_sub(UNIX_OFFSET).filter(|&s| s != 0)
}

pub struct Ntp {
    pub endpoint: UdpId,
    /// When to send next (a query is due when no answer is awaited).
    next_query: u64,
    /// The deadline of the query in flight, once it was sent.
    awaiting: Option<u64>,
    /// When the query was first attempted (ARP retries keep it unsent).
    started: Option<u64>,
    next_try: u64,
    /// Whether a time was ever published (printed once).
    published: bool,
}

/// What the loop should do for the clock this pass.
pub enum Due {
    Nothing,
    /// Hand `REQUEST` to the engine for `SERVER:PORT`.
    Send(SocketAddress),
}

impl Ntp {
    pub fn new(endpoint: UdpId, now: Instant) -> Ntp {
        Ntp { endpoint, next_query: now.0, awaiting: None, started: None, next_try: now.0, published: false }
    }

    pub fn due(&mut self, now: Instant) -> Due {
        if let Some(deadline) = self.awaiting {
            if now.0 >= deadline {
                sys::print(b"[NETSTACK] NTP timeout (no answer within 3 s)\n");
                self.fail(now);
            }
            return Due::Nothing;
        }
        if now.0 < self.next_query || now.0 < self.next_try {
            return Due::Nothing;
        }
        let started = *self.started.get_or_insert(now.0);
        if now.0.saturating_sub(started) >= ANSWER_MS {
            sys::print(b"[NETSTACK] NTP send failed (next hop unresolved)\n");
            self.fail(now);
            return Due::Nothing;
        }
        self.next_try = now.0.saturating_add(SEND_RETRY_MS);
        Due::Send(SocketAddress { address: IpAddress::V4(SERVER), port: PORT })
    }

    /// The engine accepted the query.
    pub fn sent(&mut self, now: Instant) {
        self.started = None;
        self.awaiting = Some(now.0.saturating_add(ANSWER_MS));
    }

    /// A datagram arrived on the NTP endpoint.
    pub fn answer(&mut self, from: SocketAddress, payload: &[u8], now: Instant) {
        if self.awaiting.is_none() || from.address != IpAddress::V4(SERVER) || from.port != PORT {
            return;
        }
        let Some(unix) = parse(payload) else { return };
        if sys::set_wallclock(unix, 0) < 0 {
            sys::print(b"[NETSTACK] set_wallclock refused\n");
            self.fail(now);
            return;
        }
        if !self.published {
            self.published = true;
            sys::print(b"[NETSTACK] wallclock set from NTP\n");
        }
        self.awaiting = None;
        self.next_query = now.0.saturating_add(REFRESH_OK_MS);
    }

    fn fail(&mut self, now: Instant) {
        self.awaiting = None;
        self.started = None;
        self.next_query = now.0.saturating_add(RETRY_FAIL_MS);
    }
}
