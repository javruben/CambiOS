// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Link and network addresses (spec `net.md` § 2 surface types).
//!
//! IPv6 is present as a type from the first commit (ADR-039 Need 5): the
//! socket tuple is dual-stack even though no IPv6 protocol behaviour is
//! implemented yet. A link or IP address is never an identity
//! (spec B-5); identity is the kernel-stamped Principal.

/// An Ethernet MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The all-ones broadcast address.
    pub const BROADCAST: MacAddress = MacAddress([0xFF; 6]);

    /// Group (multicast or broadcast) addresses have the I/G bit, the
    /// least-significant bit of the first octet, set (IEEE 802).
    pub const fn is_group(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// The all-zero address, invalid as a frame source.
    pub const fn is_zero(&self) -> bool {
        let b = self.0;
        b[0] | b[1] | b[2] | b[3] | b[4] | b[5] == 0
    }
}

/// An IPv4 address, in network order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    /// `255.255.255.255`.
    pub const BROADCAST: Ipv4Address = Ipv4Address([255; 4]);

    /// Class D, `224.0.0.0/4` (RFC 5771).
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0xF0 == 0xE0
    }

    /// The limited broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        let b = self.0;
        b[0] & b[1] & b[2] & b[3] == 0xFF
    }
}

/// An IPv6 address, in network order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Address(pub [u8; 16]);

/// An IP address of either family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4(Ipv4Address),
    V6(Ipv6Address),
}

/// An IP address and a transport port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketAddress {
    pub address: IpAddress,
    pub port: u16,
}
