// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! IPv4 header parse and emit (RFC 791, RFC 1122; spec INV-net-002).
//!
//! Checks run in a fixed order so each refusal names the first rule the
//! packet breaks: minimum length, version, header length, total length
//! against the header and against the bytes available, header checksum,
//! fragmentation, source address. Destination locality is the engine's
//! check (it knows the interface addresses), not the parser's.
//!
//! Header options are length-checked by IHL and skipped; the core acts
//! on none of them. The reserved flag bit is ignored on receipt.

use super::{array_at, be16_at, put, u8_at};
use crate::addr::Ipv4Address;
use crate::checksum;
use crate::error::{EmitError, ParseError};

/// HARDWARE: minimum IPv4 header, IHL = 5 words (RFC 791 § 3.1).
pub const MIN_HEADER_LEN: usize = 20;

/// HARDWARE: IANA protocol number for ICMP.
pub const PROTOCOL_ICMP: u8 = 1;
/// HARDWARE: IANA protocol number for TCP.
pub const PROTOCOL_TCP: u8 = 6;
/// HARDWARE: IANA protocol number for UDP.
pub const PROTOCOL_UDP: u8 = 17;

/// HARDWARE: More-Fragments flag in the flags/offset word (RFC 791).
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
/// HARDWARE: Don't-Fragment flag in the flags/offset word (RFC 791).
const FLAG_DONT_FRAGMENT: u16 = 0x4000;
/// HARDWARE: 13-bit fragment offset mask (RFC 791).
const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;

/// A validated IPv4 packet, borrowing its payload. The payload is cut to
/// the header's total length, so link-layer padding never reaches a
/// transport parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: u8,
    pub ttl: u8,
    pub dscp_ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    /// Header length in bytes (IHL × 4), options included.
    pub header_len: usize,
    pub payload: &'a [u8],
}

/// Parse one IPv4 packet from `bytes` (an Ethernet payload).
pub fn parse(bytes: &[u8]) -> Result<Ipv4Packet<'_>, ParseError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(ParseError::Ipv4TooShort);
    }
    let version_ihl = u8_at(bytes, 0).ok_or(ParseError::Ipv4TooShort)?;
    if version_ihl >> 4 != 4 {
        return Err(ParseError::Ipv4Version);
    }
    // IHL is 4 bits, so header_len <= 60: the multiply cannot overflow.
    let header_len = usize::from(version_ihl & 0x0F).saturating_mul(4);
    if header_len < MIN_HEADER_LEN || header_len > bytes.len() {
        return Err(ParseError::Ipv4HeaderLength);
    }
    let total_len = usize::from(be16_at(bytes, 2).ok_or(ParseError::Ipv4TooShort)?);
    if total_len < header_len {
        return Err(ParseError::Ipv4TotalLengthLessThanHeader);
    }
    if total_len > bytes.len() {
        return Err(ParseError::Ipv4TotalLengthExceedsAvailable);
    }
    let header = bytes.get(..header_len).ok_or(ParseError::Ipv4HeaderLength)?;
    let mut sum = checksum::Checksum::new();
    sum.add_bytes(header);
    if !sum.verifies() {
        return Err(ParseError::Ipv4HeaderChecksum);
    }
    let flags_offset = be16_at(bytes, 6).ok_or(ParseError::Ipv4TooShort)?;
    if flags_offset & FLAG_MORE_FRAGMENTS != 0 || flags_offset & FRAGMENT_OFFSET_MASK != 0 {
        return Err(ParseError::Ipv4Fragment);
    }
    let source = Ipv4Address(array_at::<4>(bytes, 12).ok_or(ParseError::Ipv4TooShort)?);
    if source.is_broadcast() || source.is_multicast() {
        return Err(ParseError::Ipv4InvalidSource);
    }
    let destination = Ipv4Address(array_at::<4>(bytes, 16).ok_or(ParseError::Ipv4TooShort)?);
    let payload = bytes
        .get(header_len..total_len)
        .ok_or(ParseError::Ipv4TotalLengthExceedsAvailable)?;
    Ok(Ipv4Packet {
        source,
        destination,
        protocol: u8_at(bytes, 9).ok_or(ParseError::Ipv4TooShort)?,
        ttl: u8_at(bytes, 8).ok_or(ParseError::Ipv4TooShort)?,
        dscp_ecn: u8_at(bytes, 1).ok_or(ParseError::Ipv4TooShort)?,
        identification: be16_at(bytes, 4).ok_or(ParseError::Ipv4TooShort)?,
        dont_fragment: flags_offset & FLAG_DONT_FRAGMENT != 0,
        header_len,
        payload,
    })
}

/// What to put in an outgoing IPv4 header. The emitter writes no
/// options, sets DF (ADR-039 § 5.2: the core never fragments) and uses
/// identification 0, which RFC 6864 § 4.1 permits for atomic datagrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Repr {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: u8,
    /// Supplied by the caller; the core holds no default hop limit.
    pub ttl: u8,
    pub payload_len: usize,
}

/// Write a 20-octet header with a valid checksum at the start of `out`.
/// Returns the header length.
pub fn emit(repr: &Ipv4Repr, out: &mut [u8]) -> Result<usize, EmitError> {
    let total = MIN_HEADER_LEN
        .checked_add(repr.payload_len)
        .ok_or(EmitError::TooLong)?;
    let total = u16::try_from(total).map_err(|_| EmitError::TooLong)?;
    let header = out
        .get_mut(..MIN_HEADER_LEN)
        .ok_or(EmitError::BufferTooSmall)?;
    header.fill(0);
    let fields: [(usize, &[u8]); 7] = [
        (0, &[0x45, 0x00]),
        (2, &total.to_be_bytes()),
        (6, &FLAG_DONT_FRAGMENT.to_be_bytes()),
        (8, &[repr.ttl]),
        (9, &[repr.protocol]),
        (12, &repr.source.0),
        (16, &repr.destination.0),
    ];
    for (at, bytes) in fields {
        put(header, at, bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    let ck = checksum::of(header);
    put(header, 10, &ck.to_be_bytes()).ok_or(EmitError::BufferTooSmall)?;
    Ok(MIN_HEADER_LEN)
}
