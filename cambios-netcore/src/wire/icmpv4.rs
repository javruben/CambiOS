// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ICMPv4 message parse and echo emit (RFC 792; spec § 4 ICMP rows).
//!
//! Wire format only. The checksum covers the whole message (no
//! pseudo-header). Echo request and echo reply are decoded, and their
//! code must be 0 (spec: "code valid for type"). Every other type is
//! reported by type and code, uninterpreted: no error message is acted
//! on here, and no quoted packet is parsed.
//!
//! Answering echo requests is the engine's (`engine::Engine::step`). Not
//! implemented: generating error messages (port unreachable, time
//! exceeded) and acting on received errors.

use super::{be16_at, put, u8_at};
use crate::checksum::{self, Checksum};
use crate::error::{EmitError, ParseError};

/// HARDWARE: the fixed ICMP header: type, code, checksum and four
/// type-specific octets (RFC 792).
pub const HEADER_LEN: usize = 8;
/// HARDWARE: ICMP types (RFC 792).
const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQUEST: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoKind {
    Request,
    Reply,
}

/// The fields of an echo request or reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub kind: EchoKind,
    pub identifier: u16,
    pub sequence: u16,
}

/// A checksum-verified ICMPv4 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmpv4Message<'a> {
    Echo { echo: Echo, data: &'a [u8] },
    /// A well-formed message of a type this core does not interpret.
    Other { message_type: u8, code: u8 },
}

/// Parse one ICMPv4 message (an IPv4 payload).
pub fn parse(bytes: &[u8]) -> Result<Icmpv4Message<'_>, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::IcmpTooShort);
    }
    if checksum::of(bytes) != 0 {
        return Err(ParseError::IcmpChecksum);
    }
    let message_type = u8_at(bytes, 0).ok_or(ParseError::IcmpTooShort)?;
    let code = u8_at(bytes, 1).ok_or(ParseError::IcmpTooShort)?;
    let kind = match message_type {
        TYPE_ECHO_REQUEST => EchoKind::Request,
        TYPE_ECHO_REPLY => EchoKind::Reply,
        _ => return Ok(Icmpv4Message::Other { message_type, code }),
    };
    if code != 0 {
        return Err(ParseError::IcmpCode);
    }
    Ok(Icmpv4Message::Echo {
        echo: Echo {
            kind,
            identifier: be16_at(bytes, 4).ok_or(ParseError::IcmpTooShort)?,
            sequence: be16_at(bytes, 6).ok_or(ParseError::IcmpTooShort)?,
        },
        data: bytes.get(HEADER_LEN..).ok_or(ParseError::IcmpTooShort)?,
    })
}

/// Write an echo request or reply carrying `data` at the start of `out`.
/// Returns the message length.
pub fn emit_echo(echo: &Echo, data: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    let total = HEADER_LEN.checked_add(data.len()).ok_or(EmitError::TooLong)?;
    let m = out.get_mut(..total).ok_or(EmitError::BufferTooSmall)?;
    let message_type = match echo.kind {
        EchoKind::Request => TYPE_ECHO_REQUEST,
        EchoKind::Reply => TYPE_ECHO_REPLY,
    };
    let fields: [(usize, &[u8]); 5] = [
        (0, &[message_type, 0]),
        (2, &[0, 0]),
        (4, &echo.identifier.to_be_bytes()),
        (6, &echo.sequence.to_be_bytes()),
        (HEADER_LEN, data),
    ];
    for (at, bytes) in fields {
        put(m, at, bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    let mut sum = Checksum::new();
    sum.add_bytes(m);
    put(m, 2, &sum.finish().to_be_bytes()).ok_or(EmitError::BufferTooSmall)?;
    Ok(total)
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// P6 (INV-net-013): the ICMPv4 parser is total for every input of
/// 0..=80 octets, and echo data lies inside the input.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// SCAFFOLDING: input length for the ICMPv4 parser harness.
    /// Why: the same solver-cheap bound as the IPv4 and TCP parser
    /// harnesses.
    /// Replace when: the full-frame harness runs in CI within budget.
    const SMALL: usize = 80;

    /// Unwind 45: the checksum walks at most 80 / 2 words.
    #[kani::proof]
    #[kani::unwind(45)]
    fn p6_icmpv4_parse_is_total() {
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        if let Ok(Icmpv4Message::Echo { data, .. }) = parse(&buf[..len]) {
            assert!(data.len() + HEADER_LEN == len);
        }
    }
}
