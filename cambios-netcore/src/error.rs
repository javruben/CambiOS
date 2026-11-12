// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Closed error vocabularies.
//!
//! [`NetError`] is the spec's client-visible set (`net.md` § 2, crosswalk
//! R-1). [`ParseError`] is the parser's precise reason; every reason maps
//! to exactly one `NetError` class, so a parser can never produce an
//! error the client vocabulary cannot express. Reasons carry no packet
//! bytes (INV-net-017): they are safe to count and to log.

/// The client-visible network error set, in the spec's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetError {
    Denied,
    NoRoute,
    NoAddress,
    AddressInUse,
    NoListener,
    WouldBlock,
    TimedOut,
    Closed,
    Malformed,
    Unsupported,
    ResourceLimit,
    NetworkDown,
}

/// Why a parser refused its input. One variant per distinct rule, so a
/// counter keyed on the reason tells an operator which rule fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseError {
    // ---- Ethernet II ----
    /// Fewer bytes than the 14-octet Ethernet header.
    EthernetTooShort,
    /// Payload longer than the interface MTU (INV-net-001).
    EthernetExceedsMtu,
    /// Source MAC is a group (multicast/broadcast) address.
    EthernetGroupSource,
    /// Source MAC is all zero.
    EthernetZeroSource,

    // ---- IPv4 ----
    /// Fewer bytes than the 20-octet minimum IPv4 header.
    Ipv4TooShort,
    /// Version field is not 4.
    Ipv4Version,
    /// IHL below 5, or the header it declares does not fit the input.
    Ipv4HeaderLength,
    /// Total length is smaller than the header (NET-V-011).
    Ipv4TotalLengthLessThanHeader,
    /// Total length is larger than the bytes available.
    Ipv4TotalLengthExceedsAvailable,
    /// Header checksum does not verify (NET-V-010).
    Ipv4HeaderChecksum,
    /// Source address is broadcast or multicast (RFC 1122 § 3.2.1.3).
    Ipv4InvalidSource,
    /// The packet is a fragment. Reassembly is not part of the core
    /// (ADR-039 § 5.2, crosswalk R-8), so this is `Unsupported`, not
    /// `Malformed`.
    Ipv4Fragment,

    // ---- TCP ----
    /// Fewer bytes than the 20-octet minimum TCP header.
    TcpTooShort,
    /// Data offset below 5, or past the end of the segment.
    TcpDataOffset,
    /// An option's length octet is below 2 or runs past the header.
    TcpOptionLength,
    /// A known option has the wrong length (e.g. MSS not 4).
    TcpOptionValue,
    /// Checksum over the pseudo-header and segment does not verify.
    TcpChecksum,
    /// Segment too long for the pseudo-header's 16-bit length.
    TcpSegmentTooLong,

    // ---- ARP ----
    /// Fewer bytes than the 28-octet Ethernet/IPv4 ARP packet.
    ArpTooShort,
    /// Hardware/protocol type or address lengths other than
    /// Ethernet/IPv4: well-formed, but not this profile.
    ArpUnsupported,
    /// Opcode other than request (1) or reply (2).
    ArpOperation,

    // ---- DHCPv4 ----
    /// Fewer bytes than the fixed header plus the magic cookie.
    DhcpTooShort,
    /// `op` is neither BOOTREQUEST (1) nor BOOTREPLY (2).
    DhcpOp,
    /// Not Ethernet hardware addressing, or option overload (52):
    /// well-formed, not carried by this profile.
    DhcpUnsupported,
    /// The magic cookie is wrong.
    DhcpCookie,
    /// An option runs past the message, or a known option has the wrong
    /// length.
    DhcpOptionLength,
    /// The message-type option is missing or unknown.
    DhcpMessageType,

    // ---- ICMPv4 ----
    /// Fewer bytes than the 8-octet ICMP header.
    IcmpTooShort,
    /// Checksum over the message does not verify.
    IcmpChecksum,
    /// Code not valid for the type (echo codes must be 0).
    IcmpCode,

    // ---- UDP ----
    /// Fewer bytes than the 8-octet UDP header.
    UdpTooShort,
    /// Length field below the 8-octet header.
    UdpLength,
    /// Length field larger than the bytes available (NET-V-041).
    UdpLengthExceedsPacket,
    /// Checksum present and not verifying (NET-V-043).
    UdpChecksum,
}

impl ParseError {
    /// The client-visible class of this reason.
    pub const fn net_error(self) -> NetError {
        match self {
            ParseError::Ipv4Fragment | ParseError::ArpUnsupported | ParseError::DhcpUnsupported => NetError::Unsupported,
            ParseError::EthernetTooShort
            | ParseError::EthernetExceedsMtu
            | ParseError::EthernetGroupSource
            | ParseError::EthernetZeroSource
            | ParseError::Ipv4TooShort
            | ParseError::Ipv4Version
            | ParseError::Ipv4HeaderLength
            | ParseError::Ipv4TotalLengthLessThanHeader
            | ParseError::Ipv4TotalLengthExceedsAvailable
            | ParseError::Ipv4HeaderChecksum
            | ParseError::Ipv4InvalidSource
            | ParseError::TcpTooShort
            | ParseError::TcpDataOffset
            | ParseError::TcpOptionLength
            | ParseError::TcpOptionValue
            | ParseError::TcpChecksum
            | ParseError::TcpSegmentTooLong
            | ParseError::ArpTooShort
            | ParseError::ArpOperation
            | ParseError::DhcpTooShort
            | ParseError::DhcpOp
            | ParseError::DhcpCookie
            | ParseError::DhcpOptionLength
            | ParseError::DhcpMessageType
            | ParseError::IcmpTooShort
            | ParseError::IcmpChecksum
            | ParseError::IcmpCode
            | ParseError::UdpTooShort
            | ParseError::UdpLength
            | ParseError::UdpLengthExceedsPacket
            | ParseError::UdpChecksum => NetError::Malformed,
        }
    }

    /// True for a checksum failure, which the spec counts separately
    /// (`NetStats::checksum_failure`).
    pub const fn is_checksum(self) -> bool {
        matches!(self, ParseError::Ipv4HeaderChecksum | ParseError::TcpChecksum | ParseError::UdpChecksum | ParseError::IcmpChecksum)
    }
}

/// Why an emitter could not write a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EmitError {
    /// The output buffer is smaller than the packet.
    BufferTooSmall,
    /// The packet would exceed a 16-bit length field.
    TooLong,
    /// The address family is not implemented by this emitter.
    UnsupportedFamily,
}
