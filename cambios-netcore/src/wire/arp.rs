// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ARP for Ethernet and IPv4 (RFC 826; spec § 4 ARP rows).
//!
//! Only the Ethernet/IPv4 profile is carried: hardware type 1, protocol
//! type 0x0800, address lengths 6 and 4. Any other combination is a
//! well-formed packet this profile does not speak, refused as
//! `ArpUnsupported`. Octets after the 28-octet packet (Ethernet padding)
//! are ignored. Whether a sender may be learned is the neighbor table's
//! rule, not the parser's.

use super::{array_at, be16_at, put, u8_at};
use crate::addr::{Ipv4Address, MacAddress};
use crate::error::{EmitError, ParseError};
use crate::wire::ethernet::ETHERTYPE_IPV4;

/// HARDWARE: length of an Ethernet/IPv4 ARP packet (RFC 826).
pub const PACKET_LEN: usize = 28;
/// HARDWARE: ARP hardware type for Ethernet (IANA).
const HTYPE_ETHERNET: u16 = 1;
/// HARDWARE: MAC address length.
const HLEN: u8 = 6;
/// HARDWARE: IPv4 address length.
const PLEN: u8 = 4;
/// HARDWARE: ARP opcodes (RFC 826).
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// An Ethernet/IPv4 ARP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Address,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Address,
}

/// Parse the ARP packet at the start of an Ethernet payload.
pub fn parse(bytes: &[u8]) -> Result<ArpPacket, ParseError> {
    let p = bytes.get(..PACKET_LEN).ok_or(ParseError::ArpTooShort)?;
    let htype = be16_at(p, 0).ok_or(ParseError::ArpTooShort)?;
    let ptype = be16_at(p, 2).ok_or(ParseError::ArpTooShort)?;
    let hlen = u8_at(p, 4).ok_or(ParseError::ArpTooShort)?;
    let plen = u8_at(p, 5).ok_or(ParseError::ArpTooShort)?;
    if htype != HTYPE_ETHERNET || ptype != ETHERTYPE_IPV4 || hlen != HLEN || plen != PLEN {
        return Err(ParseError::ArpUnsupported);
    }
    let operation = match be16_at(p, 6).ok_or(ParseError::ArpTooShort)? {
        OP_REQUEST => ArpOperation::Request,
        OP_REPLY => ArpOperation::Reply,
        _ => return Err(ParseError::ArpOperation),
    };
    Ok(ArpPacket {
        operation,
        sender_mac: MacAddress(array_at::<6>(p, 8).ok_or(ParseError::ArpTooShort)?),
        sender_ip: Ipv4Address(array_at::<4>(p, 14).ok_or(ParseError::ArpTooShort)?),
        target_mac: MacAddress(array_at::<6>(p, 18).ok_or(ParseError::ArpTooShort)?),
        target_ip: Ipv4Address(array_at::<4>(p, 24).ok_or(ParseError::ArpTooShort)?),
    })
}

/// Write the packet at the start of `out`. Returns [`PACKET_LEN`].
pub fn emit(packet: &ArpPacket, out: &mut [u8]) -> Result<usize, EmitError> {
    let p = out.get_mut(..PACKET_LEN).ok_or(EmitError::BufferTooSmall)?;
    let op = match packet.operation {
        ArpOperation::Request => OP_REQUEST,
        ArpOperation::Reply => OP_REPLY,
    };
    let fields: [(usize, &[u8]); 8] = [
        (0, &HTYPE_ETHERNET.to_be_bytes()),
        (2, &ETHERTYPE_IPV4.to_be_bytes()),
        (4, &[HLEN, PLEN]),
        (6, &op.to_be_bytes()),
        (8, &packet.sender_mac.0),
        (14, &packet.sender_ip.0),
        (18, &packet.target_mac.0),
        (24, &packet.target_ip.0),
    ];
    for (at, bytes) in fields {
        put(p, at, bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    Ok(PACKET_LEN)
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// P6 (INV-net-013): the ARP parser is total for every input of 0..=64
/// octets (past the 28-octet packet and any Ethernet padding length).
///
/// [`proofs::emit_stub`] is the stand-in for [`emit`] in the engine
/// harness (owner approval 2026-11-14); `p6_arp_emit_meets_its_contract`
/// proves that `emit` keeps its contract.
#[cfg(kani)]
pub(crate) mod proofs {
    use super::*;

    /// SCAFFOLDING: widest `out` in this emitter's contract proof and stand-in.
    /// Why: `frame` hands each emitter `out` cut to what it writes (at most
    /// 40 octets), so 64 covers every call; a 1514-octet `out` exhausted
    /// CBMC's memory (OOM at 24 GiB, seat m5090-5529).
    /// Replace when: an emitter is called with a wider buffer.
    pub(crate) const OUT_MAX: usize = 64;

    /// The result `emit` must return: the packet length when `out` holds
    /// it, else `BufferTooSmall`.
    fn expected(out_len: usize) -> Result<usize, EmitError> {
        if out_len < PACKET_LEN {
            Err(EmitError::BufferTooSmall)
        } else {
            Ok(PACKET_LEN)
        }
    }

    /// Stand-in for `emit` in the engine harness.
    ///
    /// Contract (proved for `emit` by `p6_arp_emit_meets_its_contract`, for
    /// any packet and any `out` up to `OUT_MAX` octets):
    /// - the return value is exactly [`expected`];
    /// - on `Ok`, only `out[..28]` may change; on `Err`, nothing changes;
    /// - `emit` never panics.
    ///
    /// The stand-in keeps the first point exactly and writes arbitrary
    /// octets into `out[..28]` on `Ok`, so it allows every outcome `emit`
    /// can produce, and more.
    pub(crate) fn emit_stub(_packet: &ArpPacket, out: &mut [u8]) -> Result<usize, EmitError> {
        // Proved for `out` up to `OUT_MAX` only; asserted, not assumed.
        assert!(out.len() <= OUT_MAX);
        let r = expected(out.len());
        if r.is_ok() {
            let any: [u8; PACKET_LEN] = kani::any();
            if let Some(p) = out.get_mut(..PACKET_LEN) {
                p.copy_from_slice(&any);
            }
        }
        r
    }

    /// `emit` meets the stand-in's contract for any packet and any `out` of
    /// 0..=`OUT_MAX` octets.
    #[kani::proof]
    fn p6_arp_emit_meets_its_contract() {
        let mut out: [u8; OUT_MAX] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= OUT_MAX);
        let packet = ArpPacket {
            operation: if kani::any() { ArpOperation::Request } else { ArpOperation::Reply },
            sender_mac: MacAddress(kani::any()),
            sender_ip: Ipv4Address(kani::any()),
            target_mac: MacAddress(kani::any()),
            target_ip: Ipv4Address(kani::any()),
        };
        // One arbitrary position, chosen before the call; only its old
        // octet is kept (copying the whole buffer exhausted CBMC's memory).
        let p: usize = kani::any();
        kani::assume(p < OUT_MAX);
        let old_p = out[p];
        let r = emit(&packet, &mut out[..n]);
        assert_eq!(r, expected(n));
        let written = match r {
            Ok(len) => len,
            Err(_) => 0,
        };
        if p >= written {
            assert_eq!(out[p], old_p);
        }
    }

    /// SCAFFOLDING: input length for the ARP parser harness.
    /// Why: exceeds the 28-octet packet and the 46-octet minimum Ethernet
    /// payload; the parser reads a fixed prefix, so longer inputs add
    /// nothing to its paths.
    /// Replace when: the full-frame harness runs in CI within budget.
    const SMALL: usize = 64;

    #[kani::proof]
    fn p6_arp_parse_is_total() {
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        if parse(&buf[..len]).is_ok() {
            assert!(len >= PACKET_LEN);
        }
    }
}
