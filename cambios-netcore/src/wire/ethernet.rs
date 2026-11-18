// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Ethernet II framing (spec `net.md` § 4 "Ethernet II").
//!
//! Frames arrive without the FCS (the NIC strips it). A frame shorter
//! than 60 octets is accepted: padding is the sender's obligation, and
//! the IP layer's own length field separates padding from data.

use super::{array_at, be16_at, put};
use crate::addr::MacAddress;
use crate::error::{EmitError, ParseError};

/// HARDWARE: destination(6) + source(6) + EtherType(2), IEEE 802.3
/// Ethernet II header.
pub const HEADER_LEN: usize = 14;

/// HARDWARE: EtherType for IPv4 (IEEE registry).
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// HARDWARE: EtherType for ARP (IEEE registry).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// HARDWARE: EtherType for IPv6 (IEEE registry).
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// The payload protocol named by the EtherType field. Anything else is
/// carried as `Other` for the caller to count and drop; it is not an
/// error at this layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Other(u16),
}

impl EtherType {
    pub const fn from_u16(value: u16) -> EtherType {
        match value {
            ETHERTYPE_IPV4 => EtherType::Ipv4,
            ETHERTYPE_ARP => EtherType::Arp,
            ETHERTYPE_IPV6 => EtherType::Ipv6,
            other => EtherType::Other(other),
        }
    }

    pub const fn to_u16(self) -> u16 {
        match self {
            EtherType::Ipv4 => ETHERTYPE_IPV4,
            EtherType::Arp => ETHERTYPE_ARP,
            EtherType::Ipv6 => ETHERTYPE_IPV6,
            EtherType::Other(v) => v,
        }
    }
}

/// A validated Ethernet II frame, borrowing its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EtherType,
    pub payload: &'a [u8],
}

/// Parse one frame. `mtu` is the interface MTU: a payload longer than it
/// is refused (INV-net-001).
pub fn parse(frame: &[u8], mtu: u16) -> Result<EthernetFrame<'_>, ParseError> {
    let (header, payload) = frame
        .split_at_checked(HEADER_LEN)
        .ok_or(ParseError::EthernetTooShort)?;
    let destination = array_at::<6>(header, 0).ok_or(ParseError::EthernetTooShort)?;
    let source = array_at::<6>(header, 6).ok_or(ParseError::EthernetTooShort)?;
    let ethertype = be16_at(header, 12).ok_or(ParseError::EthernetTooShort)?;
    if payload.len() > usize::from(mtu) {
        return Err(ParseError::EthernetExceedsMtu);
    }
    let source = MacAddress(source);
    if source.is_group() {
        return Err(ParseError::EthernetGroupSource);
    }
    if source.is_zero() {
        return Err(ParseError::EthernetZeroSource);
    }
    Ok(EthernetFrame {
        destination: MacAddress(destination),
        source,
        ethertype: EtherType::from_u16(ethertype),
        payload,
    })
}

/// Write the 14-octet header at the start of `out`.
pub fn emit_header(
    out: &mut [u8],
    destination: MacAddress,
    source: MacAddress,
    ethertype: EtherType,
) -> Result<(), EmitError> {
    put(out, 0, &destination.0).ok_or(EmitError::BufferTooSmall)?;
    put(out, 6, &source.0).ok_or(EmitError::BufferTooSmall)?;
    put(out, 12, &ethertype.to_u16().to_be_bytes()).ok_or(EmitError::BufferTooSmall)?;
    Ok(())
}
