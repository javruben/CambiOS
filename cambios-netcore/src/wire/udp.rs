// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! UDP header parse and emit over IPv4 (RFC 768; spec INV-net-006,
//! B-11).
//!
//! Checks run in a fixed order: minimum length, the length field against
//! the header (below 8 is malformed) and against the bytes available
//! (above is malformed), then the checksum. On IPv4 a zero checksum
//! field means the sender computed none, and the datagram is accepted
//! (B-11); a computed checksum of zero is transmitted as all ones. Octets
//! after the length field's end are not payload.
//!
//! IPv6 UDP (mandatory checksum, INV-net-020) is not implemented.

use super::{be16_at, put};
use crate::addr::Ipv4Address;
use crate::checksum::Checksum;
use crate::error::{EmitError, ParseError};
use crate::wire::ipv4::PROTOCOL_UDP;

/// HARDWARE: UDP header length (RFC 768).
pub const HEADER_LEN: usize = 8;

/// A validated UDP datagram, borrowing its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    /// False when the checksum field was zero: none was computed.
    pub checksum_present: bool,
    pub payload: &'a [u8],
}

/// An outgoing datagram header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpRepr {
    pub source_port: u16,
    pub destination_port: u16,
}

fn pseudo_header(source: Ipv4Address, destination: Ipv4Address, udp_len: u16) -> Checksum {
    let mut c = Checksum::new();
    c.add_bytes(&source.0);
    c.add_bytes(&destination.0);
    c.add_bytes(&[0, PROTOCOL_UDP]);
    c.add_u16(udp_len);
    c
}

/// Parse a UDP datagram carried in IPv4 between `source` and
/// `destination` (the pseudo-header addresses), verifying the checksum
/// when one is present.
pub fn parse_ipv4(bytes: &[u8], source: Ipv4Address, destination: Ipv4Address) -> Result<UdpDatagram<'_>, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::UdpTooShort);
    }
    let length = be16_at(bytes, 4).ok_or(ParseError::UdpTooShort)?;
    let len = usize::from(length);
    if len < HEADER_LEN {
        return Err(ParseError::UdpLength);
    }
    let datagram = bytes.get(..len).ok_or(ParseError::UdpLengthExceedsPacket)?;
    let checksum = be16_at(datagram, 6).ok_or(ParseError::UdpTooShort)?;
    let checksum_present = checksum != 0;
    if checksum_present {
        let mut sum = pseudo_header(source, destination, length);
        sum.add_bytes(datagram);
        if !sum.verifies() {
            return Err(ParseError::UdpChecksum);
        }
    }
    Ok(UdpDatagram {
        source_port: be16_at(datagram, 0).ok_or(ParseError::UdpTooShort)?,
        destination_port: be16_at(datagram, 2).ok_or(ParseError::UdpTooShort)?,
        checksum_present,
        payload: datagram.get(HEADER_LEN..).ok_or(ParseError::UdpTooShort)?,
    })
}

/// Write header + `payload` at the start of `out` with the IPv4
/// pseudo-header checksum (always computed). Returns the datagram length.
pub fn emit_ipv4(
    repr: &UdpRepr,
    payload: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
    out: &mut [u8],
) -> Result<usize, EmitError> {
    let total = HEADER_LEN.checked_add(payload.len()).ok_or(EmitError::TooLong)?;
    let udp_len = u16::try_from(total).map_err(|_| EmitError::TooLong)?;
    let d = out.get_mut(..total).ok_or(EmitError::BufferTooSmall)?;
    let fields: [(usize, [u8; 2]); 4] = [
        (0, repr.source_port.to_be_bytes()),
        (2, repr.destination_port.to_be_bytes()),
        (4, udp_len.to_be_bytes()),
        (6, [0, 0]),
    ];
    for (at, bytes) in fields {
        put(d, at, &bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    put(d, HEADER_LEN, payload).ok_or(EmitError::BufferTooSmall)?;
    let mut sum = pseudo_header(source, destination, udp_len);
    sum.add_bytes(d);
    // RFC 768: a computed zero is sent as all ones; zero means "none".
    let checksum = match sum.finish() {
        0 => 0xFFFF,
        c => c,
    };
    put(d, 6, &checksum.to_be_bytes()).ok_or(EmitError::BufferTooSmall)?;
    Ok(total)
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// P6 (INV-net-013): the UDP parser is total for every input of 0..=80
/// octets between any two addresses: a value or a closed error, no
/// panic, out-of-bounds access or overflow, and the payload lies inside
/// the input.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// SCAFFOLDING: input length for the UDP parser harness.
    /// Why: the same solver-cheap bound as the IPv4 and TCP parser
    /// harnesses; covers the header and a 72-octet payload.
    /// Replace when: the full-frame harness runs in CI within budget.
    const SMALL: usize = 80;

    /// Unwind 45: the checksum walks at most 80 / 2 words.
    #[kani::proof]
    #[kani::unwind(45)]
    fn p6_udp_parse_is_total() {
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        let source = Ipv4Address(kani::any());
        let destination = Ipv4Address(kani::any());
        if let Ok(d) = parse_ipv4(&buf[..len], source, destination) {
            assert!(d.payload.len() + HEADER_LEN <= len);
        }
    }
}
