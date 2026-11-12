// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! TCP header parse and emit (RFC 9293 § 3.1, § 3.2; spec § 4).
//!
//! The checksum covers the IPv4 pseudo-header (RFC 9293 § 3.1); only
//! IPv4 is implemented. Options are walked once, bounded by the 40
//! option octets the data offset can describe: each iteration consumes
//! at least one octet, so the walk ends in at most 40 steps. MSS is
//! honoured; Window Scale, SACK-permitted and Timestamps are parsed,
//! length-checked and reported but not acted on (ADR-039 § 5.2);
//! unknown options are skipped by their length. The reserved bits are
//! ignored on receipt and written as zero (RFC 9293 § 3.1).

use super::{be16_at, be32_at, put, u8_at};
use crate::addr::Ipv4Address;
use crate::checksum::Checksum;
use crate::error::{EmitError, ParseError};
use crate::tcp::seq::SeqNum;
use crate::wire::ipv4::PROTOCOL_TCP;

/// HARDWARE: minimum TCP header, data offset 5 (RFC 9293 § 3.1).
pub const MIN_HEADER_LEN: usize = 20;
/// HARDWARE: maximum TCP header, the 4-bit data offset × 4 (RFC 9293).
pub const MAX_HEADER_LEN: usize = 60;
/// HARDWARE: on-wire length of the MSS option (RFC 9293 § 3.2).
const MSS_OPTION_LEN: usize = 4;

/// HARDWARE: option kinds (IANA TCP option registry).
const OPT_END: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WINDOW_SCALE: u8 = 3;
const OPT_SACK_PERMITTED: u8 = 4;
const OPT_TIMESTAMPS: u8 = 8;

/// The control bits of the flags octet (RFC 9293 § 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    pub const fn empty() -> TcpFlags {
        TcpFlags(0)
    }
    pub const fn union(self, other: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | other.0)
    }
    pub const fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn fin(self) -> bool {
        self.contains(TcpFlags::FIN)
    }
    pub const fn syn(self) -> bool {
        self.contains(TcpFlags::SYN)
    }
    pub const fn rst(self) -> bool {
        self.contains(TcpFlags::RST)
    }
    pub const fn ack(self) -> bool {
        self.contains(TcpFlags::ACK)
    }
}

/// Options found in a received header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<(u32, u32)>,
}

/// A validated TCP segment, borrowing its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    /// SEG.LEN: payload octets plus one each for SYN and FIN
    /// (RFC 9293 § 3.4). The parser bounds the payload to the 16-bit
    /// pseudo-header length, so this sum cannot overflow a `u32`.
    pub fn seg_len(&self) -> u32 {
        let payload = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        payload
            .saturating_add(u32::from(self.flags.syn()))
            .saturating_add(u32::from(self.flags.fin()))
    }
}

fn pseudo_header(source: Ipv4Address, destination: Ipv4Address, tcp_len: u16) -> Checksum {
    let mut c = Checksum::new();
    c.add_bytes(&source.0);
    c.add_bytes(&destination.0);
    c.add_bytes(&[0, PROTOCOL_TCP]);
    c.add_u16(tcp_len);
    c
}

/// Walk the option area of one header. `pub(crate)` only so the bounded
/// proofs can name it as a stub target; nothing else calls it.
pub(crate) fn parse_options(options: &[u8]) -> Result<TcpOptions, ParseError> {
    let mut out = TcpOptions::default();
    let mut at = 0usize;
    // Bounded: options.len() <= 40 and every iteration advances `at` by
    // at least one, so the loop body runs at most 40 times.
    for _ in 0..MAX_HEADER_LEN {
        let Some(kind) = u8_at(options, at) else {
            break;
        };
        match kind {
            OPT_END => break,
            OPT_NOP => {
                at = at.saturating_add(1);
                continue;
            }
            _ => {}
        }
        let len = usize::from(u8_at(options, at.saturating_add(1)).ok_or(ParseError::TcpOptionLength)?);
        let end = at.checked_add(len).ok_or(ParseError::TcpOptionLength)?;
        if len < 2 || end > options.len() {
            return Err(ParseError::TcpOptionLength);
        }
        let body = options
            .get(at.saturating_add(2)..end)
            .ok_or(ParseError::TcpOptionLength)?;
        match kind {
            OPT_MSS => {
                out.mss = Some(be16_at(body, 0).filter(|_| len == MSS_OPTION_LEN).ok_or(ParseError::TcpOptionValue)?);
            }
            OPT_WINDOW_SCALE => {
                out.window_scale = Some(u8_at(body, 0).filter(|_| len == 3).ok_or(ParseError::TcpOptionValue)?);
            }
            OPT_SACK_PERMITTED => {
                if len != 2 {
                    return Err(ParseError::TcpOptionValue);
                }
                out.sack_permitted = true;
            }
            OPT_TIMESTAMPS => {
                if len != 10 {
                    return Err(ParseError::TcpOptionValue);
                }
                let val = be32_at(body, 0).ok_or(ParseError::TcpOptionValue)?;
                let ecr = be32_at(body, 4).ok_or(ParseError::TcpOptionValue)?;
                out.timestamps = Some((val, ecr));
            }
            // SACK blocks and unknown kinds: length already validated, skip.
            _ => {}
        }
        at = end;
    }
    Ok(out)
}

/// Parse and checksum-verify a TCP segment carried in IPv4 between
/// `source` and `destination` (the pseudo-header addresses).
pub fn parse_ipv4(
    bytes: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Result<TcpSegment<'_>, ParseError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(ParseError::TcpTooShort);
    }
    let tcp_len = u16::try_from(bytes.len()).map_err(|_| ParseError::TcpSegmentTooLong)?;
    let offset_byte = u8_at(bytes, 12).ok_or(ParseError::TcpTooShort)?;
    // 4-bit field × 4 <= 60: cannot overflow.
    let header_len = usize::from(offset_byte >> 4).saturating_mul(4);
    if header_len < MIN_HEADER_LEN || header_len > bytes.len() {
        return Err(ParseError::TcpDataOffset);
    }
    let mut sum = pseudo_header(source, destination, tcp_len);
    sum.add_bytes(bytes);
    if !sum.verifies() {
        return Err(ParseError::TcpChecksum);
    }
    let options = parse_options(bytes.get(MIN_HEADER_LEN..header_len).ok_or(ParseError::TcpDataOffset)?)?;
    Ok(TcpSegment {
        source_port: be16_at(bytes, 0).ok_or(ParseError::TcpTooShort)?,
        destination_port: be16_at(bytes, 2).ok_or(ParseError::TcpTooShort)?,
        seq: SeqNum(be32_at(bytes, 4).ok_or(ParseError::TcpTooShort)?),
        ack: SeqNum(be32_at(bytes, 8).ok_or(ParseError::TcpTooShort)?),
        flags: TcpFlags(u8_at(bytes, 13).ok_or(ParseError::TcpTooShort)?),
        window: be16_at(bytes, 14).ok_or(ParseError::TcpTooShort)?,
        urgent: be16_at(bytes, 18).ok_or(ParseError::TcpTooShort)?,
        options,
        payload: bytes.get(header_len..).ok_or(ParseError::TcpDataOffset)?,
    })
}

/// An outgoing segment header. `mss` is written as the only option, and
/// only when present (RFC 9293 § 3.7.1: MSS is sent on SYN segments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpRepr {
    pub source_port: u16,
    pub destination_port: u16,
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
}

impl TcpRepr {
    pub const fn header_len(&self) -> usize {
        match self.mss {
            Some(_) => MIN_HEADER_LEN + MSS_OPTION_LEN,
            None => MIN_HEADER_LEN,
        }
    }
}

/// Write header + `payload` at the start of `out` with the IPv4
/// pseudo-header checksum. Returns the segment length.
pub fn emit_ipv4(
    repr: &TcpRepr,
    payload: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
    out: &mut [u8],
) -> Result<usize, EmitError> {
    let header_len = repr.header_len();
    let total = header_len.checked_add(payload.len()).ok_or(EmitError::TooLong)?;
    let tcp_len = u16::try_from(total).map_err(|_| EmitError::TooLong)?;
    let seg = out.get_mut(..total).ok_or(EmitError::BufferTooSmall)?;
    seg.fill(0);
    // header_len is 20 or 24, so header_len / 4 fits the 4-bit field.
    let offset_byte = u8::try_from(header_len / 4).map_err(|_| EmitError::TooLong)? << 4;
    let fields: [(usize, &[u8]); 7] = [
        (0, &repr.source_port.to_be_bytes()),
        (2, &repr.destination_port.to_be_bytes()),
        (4, &repr.seq.0.to_be_bytes()),
        (8, &repr.ack.0.to_be_bytes()),
        (12, &[offset_byte]),
        (13, &[repr.flags.0]),
        (14, &repr.window.to_be_bytes()),
    ];
    for (at, bytes) in fields {
        put(seg, at, bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    if let Some(mss) = repr.mss {
        let [hi, lo] = mss.to_be_bytes();
        put(seg, MIN_HEADER_LEN, &[OPT_MSS, 4, hi, lo]).ok_or(EmitError::BufferTooSmall)?;
    }
    put(seg, header_len, payload).ok_or(EmitError::BufferTooSmall)?;
    let mut sum = pseudo_header(source, destination, tcp_len);
    sum.add_bytes(seg);
    put(seg, 16, &sum.finish().to_be_bytes()).ok_or(EmitError::BufferTooSmall)?;
    Ok(total)
}

/// Bounded proofs (run with `cargo kani -Z stubbing`; compiled only under
/// `cfg(kani)`).
///
/// P6 for the TCP parser, by assume-guarantee over its two stages:
///
/// 1. `p6_tcp_options_walk_is_total` proves the option walk alone: for
///    every option area of 0..=40 octets it returns without panic,
///    out-of-bounds access or overflow, and its only errors are
///    `TcpOptionLength` and `TcpOptionValue`.
/// 2. `p6_tcp_parse_is_total` proves the whole parser with the walk
///    replaced by [`proofs::parse_options_stub`], which (a) asserts the
///    walk's precondition at the call site (at most 40 octets) and (b)
///    returns *any* value stage 1 allows. The stub over-approximates the
///    real walk, so totality proven with it holds for the real parser.
///
/// The bounded claim is the one the single harness made before: any TCP
/// segment of 0..=80 octets between any two addresses. The split exists
/// because the solver had to satisfy the checksum and explore the option
/// paths at once (that single harness did not finish within 300 s).
#[cfg(kani)]
pub(crate) mod proofs {
    use super::*;

    /// HARDWARE: the largest option area a header can carry, the 60-octet
    /// maximum header minus the 20-octet fixed part (RFC 9293 § 3.1).
    pub(crate) const MAX_OPTIONS: usize = MAX_HEADER_LEN - MIN_HEADER_LEN;

    /// SCAFFOLDING: segment length for the composed parser harness.
    /// Why: keeps the checksum stage cheap while covering a full 60-octet
    /// header with options plus payload; the frame-level harness carries
    /// the full 1514-octet claim.
    /// Replace when: the composed harness runs within budget at the full
    /// 1480-octet TCP segment size.
    const SEGMENT_MAX: usize = 80;

    /// Stage 1: the option walk, for every option area of 0..=40 octets.
    /// Unwind 61: the walk's loop is bounded by 60 iterations.
    #[kani::proof]
    #[kani::unwind(61)]
    fn p6_tcp_options_walk_is_total() {
        let buf: [u8; MAX_OPTIONS] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_OPTIONS);
        let r = parse_options(&buf[..len]);
        assert!(matches!(
            r,
            Ok(_) | Err(ParseError::TcpOptionLength) | Err(ParseError::TcpOptionValue)
        ));
    }

    /// The stand-in for `parse_options` in composed harnesses. Sound only
    /// together with stage 1: it checks the walk's precondition and returns
    /// any member of the walk's proven output set.
    pub(crate) fn parse_options_stub(options: &[u8]) -> Result<TcpOptions, ParseError> {
        assert!(options.len() <= MAX_OPTIONS);
        if kani::any() {
            Ok(TcpOptions {
                mss: if kani::any() { Some(kani::any()) } else { None },
                window_scale: if kani::any() { Some(kani::any()) } else { None },
                sack_permitted: kani::any(),
                timestamps: if kani::any() { Some((kani::any(), kani::any())) } else { None },
            })
        } else if kani::any() {
            Err(ParseError::TcpOptionLength)
        } else {
            Err(ParseError::TcpOptionValue)
        }
    }

    /// Stage 2: the whole TCP parser, any segment of 0..=80 octets between
    /// any two addresses, with the option walk stubbed as described above.
    /// Unwind 45: the checksum walks at most 80 / 2 = 40 words.
    #[kani::proof]
    #[kani::stub(super::parse_options, parse_options_stub)]
    #[kani::unwind(45)]
    fn p6_tcp_parse_is_total() {
        let buf: [u8; SEGMENT_MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SEGMENT_MAX);
        let src = Ipv4Address(kani::any());
        let dst = Ipv4Address(kani::any());
        if let Ok(s) = parse_ipv4(&buf[..len], src, dst) {
            assert!(s.payload.len() + MIN_HEADER_LEN <= len);
        }
    }
}
