// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Whole-frame paths for ARP, and TCP, UDP and ICMP over IPv4, over Ethernet II: one
//! parse that applies every layer's checks in order, and an emit per
//! transport that writes every layer's header with valid checksums.

use super::arp::{self, ArpPacket};
use super::ethernet::{self, EtherType, EthernetFrame};
use super::icmpv4::{self, Echo, Icmpv4Message};
use super::ipv4::{self, Ipv4Packet, Ipv4Repr, PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP};
use super::tcp::{self, TcpRepr, TcpSegment};
use super::udp::{self, UdpDatagram, UdpRepr};
use crate::addr::{Ipv4Address, MacAddress};
use crate::error::{EmitError, ParseError};

/// What one received frame turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classified<'a> {
    /// A checksum-verified TCP segment in an IPv4 packet.
    Ipv4Tcp {
        link: EthernetFrame<'a>,
        ip: Ipv4Packet<'a>,
        segment: TcpSegment<'a>,
    },
    /// A checksum-verified (or checksum-less, B-11) UDP datagram in an
    /// IPv4 packet.
    Ipv4Udp {
        link: EthernetFrame<'a>,
        ip: Ipv4Packet<'a>,
        datagram: UdpDatagram<'a>,
    },
    /// A checksum-verified ICMPv4 message in an IPv4 packet.
    Ipv4Icmp {
        link: EthernetFrame<'a>,
        ip: Ipv4Packet<'a>,
        message: Icmpv4Message<'a>,
    },
    /// A well-formed IPv4 packet for a transport this path does not
    /// carry. The caller counts it; it is not an error.
    Ipv4Other { link: EthernetFrame<'a>, ip: Ipv4Packet<'a> },
    /// An Ethernet/IPv4 ARP packet.
    Arp { link: EthernetFrame<'a>, arp: ArpPacket },
    /// A well-formed frame for an EtherType this path does not carry.
    OtherEtherType { link: EthernetFrame<'a> },
}

/// Parse a received frame as far as this path goes.
pub fn classify(frame: &[u8], mtu: u16) -> Result<Classified<'_>, ParseError> {
    let link = ethernet::parse(frame, mtu)?;
    match link.ethertype {
        EtherType::Ipv4 => {}
        EtherType::Arp => return Ok(Classified::Arp { link, arp: arp::parse(link.payload)? }),
        EtherType::Ipv6 | EtherType::Other(_) => return Ok(Classified::OtherEtherType { link }),
    }
    let ip = ipv4::parse(link.payload)?;
    match ip.protocol {
        PROTOCOL_TCP => {
            let segment = tcp::parse_ipv4(ip.payload, ip.source, ip.destination)?;
            Ok(Classified::Ipv4Tcp { link, ip, segment })
        }
        PROTOCOL_UDP => {
            let datagram = udp::parse_ipv4(ip.payload, ip.source, ip.destination)?;
            Ok(Classified::Ipv4Udp { link, ip, datagram })
        }
        PROTOCOL_ICMP => {
            let message = icmpv4::parse(ip.payload)?;
            Ok(Classified::Ipv4Icmp { link, ip, message })
        }
        _ => Ok(Classified::Ipv4Other { link, ip }),
    }
}

/// Link and network addressing for one outgoing frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Route {
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub ttl: u8,
}

/// Write a complete Ethernet + IPv4 + TCP frame into `out`. Returns the
/// frame length.
pub fn emit_ipv4_tcp(
    route: &Ipv4Route,
    segment: &TcpRepr,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, EmitError> {
    let ip_at = ethernet::HEADER_LEN;
    let tcp_at = ip_at.checked_add(ipv4::MIN_HEADER_LEN).ok_or(EmitError::TooLong)?;
    let tcp_out = out.get_mut(tcp_at..).ok_or(EmitError::BufferTooSmall)?;
    let tcp_len = tcp::emit_ipv4(segment, payload, route.source, route.destination, tcp_out)?;
    let ip_out = out.get_mut(ip_at..).ok_or(EmitError::BufferTooSmall)?;
    ipv4::emit(
        &Ipv4Repr {
            source: route.source,
            destination: route.destination,
            protocol: PROTOCOL_TCP,
            ttl: route.ttl,
            payload_len: tcp_len,
        },
        ip_out,
    )?;
    ethernet::emit_header(out, route.destination_mac, route.source_mac, EtherType::Ipv4)?;
    tcp_at.checked_add(tcp_len).ok_or(EmitError::TooLong)
}

/// Write a complete Ethernet + ARP frame into `out`. Returns the frame
/// length (42; the NIC pads to the Ethernet minimum).
pub fn emit_arp(source_mac: MacAddress, destination_mac: MacAddress, packet: &ArpPacket, out: &mut [u8]) -> Result<usize, EmitError> {
    let arp_out = out.get_mut(ethernet::HEADER_LEN..).ok_or(EmitError::BufferTooSmall)?;
    let len = arp::emit(packet, arp_out)?;
    ethernet::emit_header(out, destination_mac, source_mac, EtherType::Arp)?;
    ethernet::HEADER_LEN.checked_add(len).ok_or(EmitError::TooLong)
}

/// Write a complete Ethernet + IPv4 frame carrying an already-encoded
/// ICMPv4 `message` (checksum included) into `out`. Returns the frame
/// length.
pub fn emit_ipv4_icmp(route: &Ipv4Route, message: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    let icmp_at = ethernet::HEADER_LEN.checked_add(ipv4::MIN_HEADER_LEN).ok_or(EmitError::TooLong)?;
    let end = icmp_at.checked_add(message.len()).ok_or(EmitError::TooLong)?;
    out.get_mut(icmp_at..end).ok_or(EmitError::BufferTooSmall)?.copy_from_slice(message);
    finish_ipv4(route, PROTOCOL_ICMP, icmp_at, message.len(), out)
}

/// Write a complete Ethernet + IPv4 + ICMPv4 echo frame into `out`.
/// Returns the frame length.
pub fn emit_ipv4_icmp_echo(route: &Ipv4Route, echo: &Echo, data: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    let icmp_at = ethernet::HEADER_LEN.checked_add(ipv4::MIN_HEADER_LEN).ok_or(EmitError::TooLong)?;
    let icmp_out = out.get_mut(icmp_at..).ok_or(EmitError::BufferTooSmall)?;
    let len = icmpv4::emit_echo(echo, data, icmp_out)?;
    finish_ipv4(route, PROTOCOL_ICMP, icmp_at, len, out)
}

/// Write the IPv4 and Ethernet headers in front of a `payload_len`-octet
/// transport message already at `out[payload_at..]`.
fn finish_ipv4(route: &Ipv4Route, protocol: u8, payload_at: usize, payload_len: usize, out: &mut [u8]) -> Result<usize, EmitError> {
    let ip_out = out.get_mut(ethernet::HEADER_LEN..).ok_or(EmitError::BufferTooSmall)?;
    ipv4::emit(
        &Ipv4Repr { source: route.source, destination: route.destination, protocol, ttl: route.ttl, payload_len },
        ip_out,
    )?;
    ethernet::emit_header(out, route.destination_mac, route.source_mac, EtherType::Ipv4)?;
    payload_at.checked_add(payload_len).ok_or(EmitError::TooLong)
}

/// Write a complete Ethernet + IPv4 + UDP frame into `out`. Returns the
/// frame length.
pub fn emit_ipv4_udp(route: &Ipv4Route, repr: &UdpRepr, payload: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    let ip_at = ethernet::HEADER_LEN;
    let udp_at = ip_at.checked_add(ipv4::MIN_HEADER_LEN).ok_or(EmitError::TooLong)?;
    let udp_out = out.get_mut(udp_at..).ok_or(EmitError::BufferTooSmall)?;
    let udp_len = udp::emit_ipv4(repr, payload, route.source, route.destination, udp_out)?;
    let ip_out = out.get_mut(ip_at..).ok_or(EmitError::BufferTooSmall)?;
    ipv4::emit(
        &Ipv4Repr {
            source: route.source,
            destination: route.destination,
            protocol: PROTOCOL_UDP,
            ttl: route.ttl,
            payload_len: udp_len,
        },
        ip_out,
    )?;
    ethernet::emit_header(out, route.destination_mac, route.source_mac, EtherType::Ipv4)?;
    udp_at.checked_add(udp_len).ok_or(EmitError::TooLong)
}

/// Bounded proofs (run with `cargo kani -Z stubbing`; compiled only under
/// `cfg(kani)`).
///
/// P6 (ADR-039 § 6.1; INV-net-013, B-9): parsing is total. For every
/// input up to the stated length, the parser returns a value or a closed
/// error, with no panic, no out-of-bounds access and no arithmetic
/// overflow (Kani checks all three), and every borrowed view lies inside
/// its input. These harnesses cover the parsers only; no harness covers
/// `engine::Engine::step`, so "step is total" is not claimed.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// HARDWARE: largest Ethernet II frame without FCS, 1500-octet MTU
    /// plus the 14-octet header.
    const MAX_FRAME: usize = 1514;

    /// SCAFFOLDING: input length for the per-layer IPv4 harness.
    /// Why: a solver-cheap bound that still covers a 60-octet IPv4 header
    /// with options; the full-frame harness below carries the 1514-octet
    /// claim.
    /// Replace when: the full-frame harness runs in CI within budget, which
    /// makes these redundant.
    const SMALL: usize = 80;

    /// P6 at full size: any frame of 0..=1514 octets, any MTU.
    ///
    /// Composed by assume-guarantee from two separately proven stages:
    /// - the TCP option walk is replaced by
    ///   `wire::tcp::proofs::parse_options_stub` (sound with
    ///   `p6_tcp_options_walk_is_total`);
    /// - the checksum accumulator is replaced by the stubs in
    ///   `checksum::proofs` (sound with `p6_checksum_is_total_up_to_frame`):
    ///   `add_bytes` is a no-op and `verifies` returns any value, which
    ///   over-approximates every real checksum result. (`finish` is not
    ///   reached on this path: its only caller here is `verifies`.)
    /// The frame bound (1514) and the assertions are unchanged; only the
    /// stage internals are abstracted. Run with `-Z stubbing`.
    /// Unwind 760: the previous bound, kept as a margin. With both stages
    /// stubbed, no loop remains on this path.
    #[kani::proof]
    #[kani::stub(crate::wire::tcp::parse_options, crate::wire::tcp::proofs::parse_options_stub)]
    #[kani::stub(crate::checksum::Checksum::add_bytes, crate::checksum::proofs::add_bytes_stub)]
    #[kani::stub(crate::checksum::Checksum::verifies, crate::checksum::proofs::verifies_stub)]
    #[kani::unwind(760)]
    fn p6_classify_is_total_up_to_1514() {
        let buf: [u8; MAX_FRAME] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_FRAME);
        let mtu: u16 = kani::any();
        let input = &buf[..len];
        match classify(input, mtu) {
            Ok(Classified::Ipv4Tcp { link, ip, segment }) => {
                assert!(link.payload.len() + ethernet::HEADER_LEN == len);
                assert!(ip.payload.len() + ip.header_len <= link.payload.len());
                assert!(segment.payload.len() <= ip.payload.len());
            }
            Ok(Classified::Ipv4Udp { link, ip, datagram }) => {
                assert!(link.payload.len() + ethernet::HEADER_LEN == len);
                assert!(ip.payload.len() + ip.header_len <= link.payload.len());
                assert!(datagram.payload.len() <= ip.payload.len());
            }
            Ok(Classified::Ipv4Icmp { link, ip, .. }) => {
                assert!(link.payload.len() + ethernet::HEADER_LEN == len);
                assert!(ip.payload.len() + ip.header_len <= link.payload.len());
            }
            Ok(Classified::Ipv4Other { link, ip }) => {
                assert!(ip.payload.len() + ip.header_len <= link.payload.len());
            }
            Ok(Classified::Arp { link, .. }) => {
                assert!(link.payload.len() + ethernet::HEADER_LEN == len);
            }
            Ok(Classified::OtherEtherType { link }) => {
                assert!(link.payload.len() + ethernet::HEADER_LEN == len);
            }
            Err(_) => {}
        }
    }

    /// P6 for the IPv4 parser alone, inputs of 0..=80 octets.
    /// Unwind 45: header checksum over at most 60 / 2 = 30 words.
    #[kani::proof]
    #[kani::unwind(45)]
    fn p6_ipv4_parse_is_total() {
        let buf: [u8; SMALL] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= SMALL);
        if let Ok(p) = ipv4::parse(&buf[..len]) {
            assert!(p.header_len >= ipv4::MIN_HEADER_LEN);
            assert!(p.header_len + p.payload.len() <= len);
        }
    }

    // The TCP parser's harnesses live in `wire::tcp::proofs`, split into
    // the option-walk stage and the composed parser (assume-guarantee).
}
