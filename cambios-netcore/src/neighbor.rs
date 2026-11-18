// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! One interface's IPv4 neighbor table (spec B-5, INV-net-005,
//! AT-net-004; ADR-039 § 5.2).
//!
//! ARP data is unauthenticated (B-5). The table therefore holds only
//! link addresses for the one interface it belongs to: an entry affects
//! nothing but which MAC a frame on that interface is sent to, and grants
//! no identity or capability.
//!
//! Learning follows ADR-039 § 5.2: **a reply updates an entry only if we
//! asked.** [`NeighborTable::request`] records the question (a pending
//! entry, live until an instant the caller gives); a reply whose sender
//! is that address resolves it. Requests, unsolicited replies, and
//! replies after the question lapsed change nothing. Operator-pinned
//! entries are never changed or evicted by received packets (NET-V-030).
//! A sender is never accepted when its MAC is a group or zero address,
//! its IP is unspecified, broadcast or multicast, or its IP is this
//! interface's own address.
//!
//! Every entry is in exactly one state: pinned, pending (asked, until an
//! instant), or resolved (a MAC, until an instant). Capacity is the const
//! generic `N`; time and every instant are the caller's inputs, so this
//! module chooses neither a table size nor a lifetime. A slot is reused
//! only when it is empty or its entry has lapsed; a pin may also take a
//! pending or resolved entry's slot, never another pin's.
//!
//! # Not implemented yet
//!
//! Holding packets while a question is pending, retrying a question,
//! RFC 5227 conflict defence and announcements, IPv6 Neighbor Discovery.

use crate::addr::{Ipv4Address, MacAddress};
use crate::wire::arp::{ArpOperation, ArpPacket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pinned { mac: MacAddress },
    Pending { asked_until_ms: u64 },
    Resolved { mac: MacAddress, expires_at_ms: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    ip: Ipv4Address,
    state: State,
}

impl Entry {
    /// Still meaningful at `now_ms`: a pin, an open question, or an
    /// unexpired answer.
    const fn live(&self, now_ms: u64) -> bool {
        match self.state {
            State::Pinned { .. } => true,
            State::Pending { asked_until_ms } => now_ms < asked_until_ms,
            State::Resolved { expires_at_ms, .. } => now_ms < expires_at_ms,
        }
    }

    /// The MAC to use at `now_ms`, if any.
    const fn mac(&self, now_ms: u64) -> Option<MacAddress> {
        match self.state {
            State::Pinned { mac } => Some(mac),
            State::Resolved { mac, expires_at_ms } if now_ms < expires_at_ms => Some(mac),
            State::Resolved { .. } | State::Pending { .. } => None,
        }
    }
}

/// What a received ARP packet did to the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Learn {
    /// A reply answered our open question.
    Resolved,
    /// The table is unchanged.
    Ignored(Ignored),
}

/// Why a received ARP packet changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// The sender's address is operator-pinned.
    Pinned,
    /// Group/zero sender MAC, or unspecified/broadcast/multicast sender IP.
    InvalidSender,
    /// The sender claims this interface's own address.
    OwnAddress,
    /// Not a reply to a question of ours that is still open.
    Unsolicited,
}

/// Why a pin or a question was refused. The table is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborError {
    /// Group/zero MAC, or unspecified/broadcast/multicast IP.
    InvalidAddress,
    /// No empty or lapsed slot (and, for a pin, no unpinned one).
    TableFull,
}

const fn valid_ip(ip: Ipv4Address) -> bool {
    let unspecified = ip.0[0] | ip.0[1] | ip.0[2] | ip.0[3] == 0;
    !unspecified && !ip.is_broadcast() && !ip.is_multicast()
}

const fn valid_mac(mac: MacAddress) -> bool {
    !mac.is_group() && !mac.is_zero()
}

/// The neighbor table for one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborTable<const N: usize> {
    entries: [Option<Entry>; N],
}

impl<const N: usize> Default for NeighborTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NeighborTable<N> {
    pub const fn new() -> Self {
        NeighborTable { entries: [None; N] }
    }

    /// Occupied slots, live or lapsed.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn position(&self, ip: Ipv4Address) -> Option<usize> {
        self.entries.iter().position(|e| matches!(e, Some(e) if e.ip == ip))
    }

    /// A slot for a new entry: empty, or holding a lapsed one.
    fn vacancy(&self, now_ms: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(Option::is_none)
            .or_else(|| self.entries.iter().position(|e| matches!(e, Some(e) if !e.live(now_ms))))
    }

    fn set(&mut self, slot: usize, entry: Entry) -> bool {
        match self.entries.get_mut(slot) {
            Some(e) => {
                *e = Some(entry);
                true
            }
            None => false,
        }
    }

    /// The MAC for `ip` at `now_ms`: a pin, or an unexpired answer.
    pub fn lookup(&self, ip: Ipv4Address, now_ms: u64) -> Option<MacAddress> {
        self.entries.iter().flatten().find(|e| e.ip == ip).and_then(|e| e.mac(now_ms))
    }

    /// Record that we are asking for `ip` (the caller sends the ARP
    /// request), open until `asked_until_ms`. A pinned address or an
    /// unexpired answer needs no question: nothing changes. An open
    /// question is extended.
    pub fn request(&mut self, ip: Ipv4Address, now_ms: u64, asked_until_ms: u64) -> Result<(), NeighborError> {
        if !valid_ip(ip) {
            return Err(NeighborError::InvalidAddress);
        }
        let pending = Entry { ip, state: State::Pending { asked_until_ms } };
        let slot = match self.position(ip) {
            Some(slot) => match self.entries.get(slot).copied().flatten() {
                Some(e) if e.mac(now_ms).is_some() => return Ok(()),
                _ => slot,
            },
            None => self.vacancy(now_ms).ok_or(NeighborError::TableFull)?,
        };
        if self.set(slot, pending) {
            Ok(())
        } else {
            Err(NeighborError::TableFull)
        }
    }

    /// Operator pin: `ip` maps to `mac` until re-pinned. Replaces any
    /// entry for `ip`; otherwise takes an empty slot, then any unpinned
    /// one (pinning is an operator decision; it never evicts another pin).
    pub fn pin(&mut self, ip: Ipv4Address, mac: MacAddress) -> Result<(), NeighborError> {
        if !valid_ip(ip) || !valid_mac(mac) {
            return Err(NeighborError::InvalidAddress);
        }
        let slot = self
            .position(ip)
            .or_else(|| self.entries.iter().position(Option::is_none))
            .or_else(|| {
                self.entries.iter().position(|e| !matches!(e, Some(Entry { state: State::Pinned { .. }, .. })))
            })
            .ok_or(NeighborError::TableFull)?;
        if self.set(slot, Entry { ip, state: State::Pinned { mac } }) {
            Ok(())
        } else {
            Err(NeighborError::TableFull)
        }
    }

    /// Apply one received ARP packet. `our_ip` is this interface's
    /// address; `expires_at_ms` is the instant an answer stops being used.
    pub fn on_arp(&mut self, packet: &ArpPacket, our_ip: Ipv4Address, now_ms: u64, expires_at_ms: u64) -> Learn {
        if !valid_mac(packet.sender_mac) || !valid_ip(packet.sender_ip) {
            return Learn::Ignored(Ignored::InvalidSender);
        }
        if packet.sender_ip == our_ip {
            return Learn::Ignored(Ignored::OwnAddress);
        }
        let Some(slot) = self.position(packet.sender_ip) else {
            return Learn::Ignored(Ignored::Unsolicited);
        };
        let Some(entry) = self.entries.get(slot).copied().flatten() else {
            return Learn::Ignored(Ignored::Unsolicited);
        };
        match entry.state {
            State::Pinned { .. } => Learn::Ignored(Ignored::Pinned),
            State::Pending { asked_until_ms } if packet.operation == ArpOperation::Reply && now_ms < asked_until_ms => {
                let resolved = Entry { ip: packet.sender_ip, state: State::Resolved { mac: packet.sender_mac, expires_at_ms } };
                if self.set(slot, resolved) {
                    Learn::Resolved
                } else {
                    Learn::Ignored(Ignored::Unsolicited)
                }
            }
            State::Pending { .. } | State::Resolved { .. } => Learn::Ignored(Ignored::Unsolicited),
        }
    }
}
