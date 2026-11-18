// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! DHCPv4 message parse and emit (RFC 2131 § 2 fixed header, RFC 2132
//! options; spec § 4 "DHCPv4 fixed header" and "DHCPv4 options").
//!
//! Wire format only: no client state machine, no timers, no lease
//! handling. Only Ethernet hardware addresses are carried (htype 1, hlen
//! 6). The options the client needs are decoded and length-checked;
//! unknown options are skipped by their length; option overload (52),
//! which moves options into `sname` / `file`, is refused rather than
//! half-parsed. The option walk consumes at least one octet per step, so
//! it ends within the message length.

use super::{array_at, be16_at, be32_at, put, u8_at};
use crate::addr::{Ipv4Address, MacAddress};
use crate::error::{EmitError, ParseError};

/// HARDWARE: the fixed BOOTP header, through `file` (RFC 2131 Figure 1).
pub const FIXED_LEN: usize = 236;
/// HARDWARE: the DHCP magic cookie (RFC 2131 § 3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// HARDWARE: field offsets (RFC 2131 Figure 1).
const OFF_XID: usize = 4;
const OFF_SECS: usize = 8;
const OFF_FLAGS: usize = 10;
const OFF_CIADDR: usize = 12;
const OFF_YIADDR: usize = 16;
const OFF_SIADDR: usize = 20;
const OFF_CHADDR: usize = 28;
/// HARDWARE: the broadcast bit of `flags` (RFC 2131 § 2).
const FLAG_BROADCAST: u16 = 0x8000;
/// HARDWARE: option codes (RFC 2132).
const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_OVERLOAD: u8 = 52;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMETER_LIST: u8 = 55;
const OPT_RENEWAL_TIME: u8 = 58;
const OPT_REBINDING_TIME: u8 = 59;
const OPT_END: u8 = 255;
/// The parameters a client asks for: mask, router, lease, server, T1, T2.
const PARAMETER_LIST: [u8; 6] = [OPT_SUBNET_MASK, OPT_ROUTER, OPT_LEASE_TIME, OPT_SERVER_ID, OPT_RENEWAL_TIME, OPT_REBINDING_TIME];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootOp {
    Request,
    Reply,
}

/// DHCP message types (RFC 2132 § 9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    const fn from_u8(v: u8) -> Option<MessageType> {
        match v {
            1 => Some(MessageType::Discover),
            2 => Some(MessageType::Offer),
            3 => Some(MessageType::Request),
            4 => Some(MessageType::Decline),
            5 => Some(MessageType::Ack),
            6 => Some(MessageType::Nak),
            7 => Some(MessageType::Release),
            8 => Some(MessageType::Inform),
            _ => None,
        }
    }
    const fn to_u8(self) -> u8 {
        match self {
            MessageType::Discover => 1,
            MessageType::Offer => 2,
            MessageType::Request => 3,
            MessageType::Decline => 4,
            MessageType::Ack => 5,
            MessageType::Nak => 6,
            MessageType::Release => 7,
            MessageType::Inform => 8,
        }
    }
}

/// A parsed DHCPv4 message: the fixed fields and the decoded options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpMessage {
    pub op: BootOp,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Address,
    pub yiaddr: Ipv4Address,
    pub siaddr: Ipv4Address,
    pub chaddr: MacAddress,
    pub message_type: MessageType,
    pub server_id: Option<Ipv4Address>,
    pub subnet_mask: Option<Ipv4Address>,
    /// The first router listed (RFC 2132 § 3.5: in order of preference).
    pub router: Option<Ipv4Address>,
    pub lease_secs: Option<u32>,
    pub requested_ip: Option<Ipv4Address>,
    pub renewal_secs: Option<u32>,
    pub rebinding_secs: Option<u32>,
}

fn ipv4_at(b: &[u8], at: usize) -> Option<Ipv4Address> {
    array_at::<4>(b, at).map(Ipv4Address)
}

/// Parse one DHCPv4 message (a UDP payload).
pub fn parse(bytes: &[u8]) -> Result<DhcpMessage, ParseError> {
    let cookie_end = FIXED_LEN.checked_add(MAGIC_COOKIE.len()).ok_or(ParseError::DhcpTooShort)?;
    if bytes.len() < cookie_end {
        return Err(ParseError::DhcpTooShort);
    }
    let op = match u8_at(bytes, 0) {
        Some(1) => BootOp::Request,
        Some(2) => BootOp::Reply,
        _ => return Err(ParseError::DhcpOp),
    };
    if u8_at(bytes, 1) != Some(1) || u8_at(bytes, 2) != Some(6) {
        return Err(ParseError::DhcpUnsupported);
    }
    if array_at::<4>(bytes, FIXED_LEN) != Some(MAGIC_COOKIE) {
        return Err(ParseError::DhcpCookie);
    }
    let flags = be16_at(bytes, OFF_FLAGS).ok_or(ParseError::DhcpTooShort)?;
    let mut m = DhcpMessage {
        op,
        xid: be32_at(bytes, OFF_XID).ok_or(ParseError::DhcpTooShort)?,
        secs: be16_at(bytes, OFF_SECS).ok_or(ParseError::DhcpTooShort)?,
        broadcast: flags & FLAG_BROADCAST != 0,
        ciaddr: ipv4_at(bytes, OFF_CIADDR).ok_or(ParseError::DhcpTooShort)?,
        yiaddr: ipv4_at(bytes, OFF_YIADDR).ok_or(ParseError::DhcpTooShort)?,
        siaddr: ipv4_at(bytes, OFF_SIADDR).ok_or(ParseError::DhcpTooShort)?,
        chaddr: MacAddress(array_at::<6>(bytes, OFF_CHADDR).ok_or(ParseError::DhcpTooShort)?),
        // Placeholder, overwritten after the option walk; a message with
        // no type option is refused there (`DhcpMessageType`).
        message_type: MessageType::Discover,
        server_id: None,
        subnet_mask: None,
        router: None,
        lease_secs: None,
        requested_ip: None,
        renewal_secs: None,
        rebinding_secs: None,
    };
    let mut message_type = None;
    let options = bytes.get(cookie_end..).ok_or(ParseError::DhcpTooShort)?;
    let mut at = 0usize;
    while let Some(code) = u8_at(options, at) {
        if code == OPT_PAD {
            at = at.checked_add(1).ok_or(ParseError::DhcpOptionLength)?;
            continue;
        }
        if code == OPT_END {
            break;
        }
        let len_at = at.checked_add(1).ok_or(ParseError::DhcpOptionLength)?;
        let len = usize::from(u8_at(options, len_at).ok_or(ParseError::DhcpOptionLength)?);
        let start = len_at.checked_add(1).ok_or(ParseError::DhcpOptionLength)?;
        let end = start.checked_add(len).ok_or(ParseError::DhcpOptionLength)?;
        let body = options.get(start..end).ok_or(ParseError::DhcpOptionLength)?;
        let four = || if len == 4 { ipv4_at(body, 0).ok_or(ParseError::DhcpOptionLength) } else { Err(ParseError::DhcpOptionLength) };
        let secs = || if len == 4 { be32_at(body, 0).ok_or(ParseError::DhcpOptionLength) } else { Err(ParseError::DhcpOptionLength) };
        match code {
            OPT_MESSAGE_TYPE => {
                if len != 1 {
                    return Err(ParseError::DhcpOptionLength);
                }
                let v = u8_at(body, 0).ok_or(ParseError::DhcpOptionLength)?;
                message_type = Some(MessageType::from_u8(v).ok_or(ParseError::DhcpMessageType)?);
            }
            OPT_SERVER_ID => m.server_id = Some(four()?),
            OPT_SUBNET_MASK => m.subnet_mask = Some(four()?),
            OPT_REQUESTED_IP => m.requested_ip = Some(four()?),
            OPT_ROUTER => {
                if len < 4 || len.checked_rem(4) != Some(0) {
                    return Err(ParseError::DhcpOptionLength);
                }
                m.router = Some(ipv4_at(body, 0).ok_or(ParseError::DhcpOptionLength)?);
            }
            OPT_LEASE_TIME => m.lease_secs = Some(secs()?),
            OPT_RENEWAL_TIME => m.renewal_secs = Some(secs()?),
            OPT_REBINDING_TIME => m.rebinding_secs = Some(secs()?),
            OPT_OVERLOAD => return Err(ParseError::DhcpUnsupported),
            _ => {}
        }
        at = end;
    }
    m.message_type = message_type.ok_or(ParseError::DhcpMessageType)?;
    Ok(m)
}

/// An outgoing message. A client request carries the parameter request
/// list; the address and lease fields are written only when present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpRepr {
    pub op: BootOp,
    pub message_type: MessageType,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Address,
    pub yiaddr: Ipv4Address,
    pub chaddr: MacAddress,
    pub requested_ip: Option<Ipv4Address>,
    pub server_id: Option<Ipv4Address>,
    pub subnet_mask: Option<Ipv4Address>,
    pub router: Option<Ipv4Address>,
    pub lease_secs: Option<u32>,
}

/// Append one option at `*at`, advancing it.
fn option(out: &mut [u8], at: &mut usize, code: u8, body: &[u8]) -> Result<(), EmitError> {
    let len = u8::try_from(body.len()).map_err(|_| EmitError::TooLong)?;
    put(out, *at, &[code, len]).ok_or(EmitError::BufferTooSmall)?;
    let body_at = at.checked_add(2).ok_or(EmitError::TooLong)?;
    put(out, body_at, body).ok_or(EmitError::BufferTooSmall)?;
    *at = body_at.checked_add(body.len()).ok_or(EmitError::TooLong)?;
    Ok(())
}

/// Write the message at the start of `out`. Returns its length.
pub fn emit(repr: &DhcpRepr, out: &mut [u8]) -> Result<usize, EmitError> {
    let cookie_end = FIXED_LEN.checked_add(MAGIC_COOKIE.len()).ok_or(EmitError::TooLong)?;
    out.get_mut(..cookie_end).ok_or(EmitError::BufferTooSmall)?.fill(0);
    let op = match repr.op {
        BootOp::Request => 1u8,
        BootOp::Reply => 2,
    };
    let flags = if repr.broadcast { FLAG_BROADCAST } else { 0 };
    let fields: [(usize, &[u8]); 8] = [
        (0, &[op, 1, 6, 0]),
        (OFF_XID, &repr.xid.to_be_bytes()),
        (OFF_SECS, &repr.secs.to_be_bytes()),
        (OFF_FLAGS, &flags.to_be_bytes()),
        (OFF_CIADDR, &repr.ciaddr.0),
        (OFF_YIADDR, &repr.yiaddr.0),
        (OFF_CHADDR, &repr.chaddr.0),
        (FIXED_LEN, &MAGIC_COOKIE),
    ];
    for (at, bytes) in fields {
        put(out, at, bytes).ok_or(EmitError::BufferTooSmall)?;
    }
    let mut at = cookie_end;
    option(out, &mut at, OPT_MESSAGE_TYPE, &[repr.message_type.to_u8()])?;
    if let Some(ip) = repr.requested_ip {
        option(out, &mut at, OPT_REQUESTED_IP, &ip.0)?;
    }
    if let Some(ip) = repr.server_id {
        option(out, &mut at, OPT_SERVER_ID, &ip.0)?;
    }
    if let Some(ip) = repr.subnet_mask {
        option(out, &mut at, OPT_SUBNET_MASK, &ip.0)?;
    }
    if let Some(ip) = repr.router {
        option(out, &mut at, OPT_ROUTER, &ip.0)?;
    }
    if let Some(s) = repr.lease_secs {
        option(out, &mut at, OPT_LEASE_TIME, &s.to_be_bytes())?;
    }
    if repr.op == BootOp::Request {
        option(out, &mut at, OPT_PARAMETER_LIST, &PARAMETER_LIST)?;
    }
    put(out, at, &[OPT_END]).ok_or(EmitError::BufferTooSmall)?;
    at.checked_add(1).ok_or(EmitError::TooLong)
}

/// Bounded proofs (run with `cargo kani`; compiled only under `cfg(kani)`).
///
/// P6 (INV-net-013): the DHCPv4 parser is total for every input of
/// 0..=260 octets: a value or a closed error, no panic, out-of-bounds
/// access or overflow. This covers the 240-octet fixed part and a short
/// option area; a full lease (300 octets and up) is covered only by the
/// parser and vector tests, so the claim for longer packets is partial.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// SCAFFOLDING: input length for the DHCPv4 parser harness.
    /// Why: the 240-octet fixed part plus a 20-octet option area; the
    /// 300-octet bound ran out of memory under CBMC (codex ruling
    /// 2026-11-12: reduce to 0..=260).
    /// Replace when: the harness runs in CI and a longer option area
    /// (up to the 1472-octet UDP payload) is affordable.
    const SMALL: usize = 260;

    /// Unwind 22: the option walk takes at most one step per option octet.
    #[kani::proof]
    #[kani::unwind(22)]
    fn p6_dhcpv4_parse_is_total() {
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        let _ = parse(&buf[..len]);
    }
}
