// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The pure protocol core of the CambiOS network stack (ADR-039 § 5).
//!
//! This crate is the BuddyAllocator shape applied to TCP/IP: every
//! function is a pure function of its inputs, there is no I/O, no
//! allocation, no `unsafe`, and no clock or randomness of its own. Time
//! arrives as an argument (`engine::Instant`, milliseconds); every secret
//! or random value is injected by the caller: the RFC 6528 ISS key as
//! `engine::EngineConfig::iss_key` (`None` without a hardware random
//! source: TCP opens are then refused, never keyed weakly), DHCP transaction ids and
//! retransmission jitter as arguments to `dhcp::DhcpClient`. Bytes leave
//! as slices the caller copies. The stack shell (`user/net-stack`, not
//! yet written) owns every effect.
//!
//! The normative source is the requirements contract in
//! `spec/crates/net.md` and the RFCs it names; the language-neutral
//! vectors in `spec/vectors/net/` are replayed by this crate's tests. No
//! code here is derived from another TCP/IP implementation.
//!
//! # Verification status
//!
//! Bounded-proof evidence (Kani, 2026-11-10, current tree; see
//! `spec/claims/net.md`): the sequence, acceptability, send-window and TCB
//! harnesses and the IPv4, TCP, UDP, ARP and ICMPv4 parser harnesses pass;
//! the checksum stage, TCP option walk, DHCPv4 parser and engine `step`
//! harnesses gave no verdict, so the full-frame and engine bounds are
//! unproven. The whole crate's test suite (129 tests) built
//! and passed on 2026-11-10 (x86_64 Linux host; the library also builds
//! for x86_64-unknown-none, aarch64-unknown-none and
//! riscv64gc-unknown-none-elf, and `cargo clippy --lib -D warnings` is
//! clean). Everything marked *(tested only)* below has that test
//! evidence and nothing more: no proof covers it beyond the harnesses
//! listed above, and there are no interoperability runs.
//!
//! # What is implemented
//!
//! - [`wire::ethernet`]: Ethernet II parse and emit.
//! - [`wire::ipv4`]: IPv4 header parse and emit; fragments are refused
//!   with a typed error (ADR-039 § 5.2: TCP sets DF, the core does not
//!   reassemble).
//! - [`wire::tcp`]: TCP header + option parse and emit, with the IPv4
//!   pseudo-header checksum.
//! - [`tcp::seq`]: RFC 9293 § 3.4 serial-number arithmetic.
//! - [`tcp::accept`]: RFC 9293 § 3.10.7.4 segment acceptability and the
//!   RFC 5961 window tests.
//! - [`tcp::send`]: the sender's usable window, `min(snd_wnd, cwnd)`.
//! - [`tcp::tcb`]: one connection's transition function: passive and
//!   active open, the full close graph, RFC 5961 § 3 / § 4 / § 5
//!   challenge ACKs (marked; the engine rate-limits them), in-order
//!   segment-text acceptance, the reset for a segment that matches no
//!   connection, and *(tested only)* `retransmit` (regenerates the
//!   outstanding SYN, SYN-ACK or FIN), `send_data` and `data_header`
//!   (sequence accounting and headers for stream data).
//! - [`tcp::congestion`] *(tested only)*: RFC 5681 Reno slow start,
//!   congestion avoidance, timeout response and fast-recovery window.
//! - [`tcp::rto`] *(tested only)*: the RFC 6298 retransmission-timeout
//!   estimator with the ADR-039 § 5.2 floor, ceiling and backoff.
//! - [`wire::udp`] *(tested only)*: UDP header parse and emit over IPv4
//!   (RFC 768), with the IPv4 zero-checksum allowance (spec B-11).
//! - [`wire::arp`] *(tested only)*: Ethernet/IPv4 ARP parse and emit
//!   (RFC 826).
//! - [`wire::icmpv4`] *(tested only)*: ICMPv4 parse (echo decoded, other
//!   types reported by type and code) and echo emit (RFC 792).
//! - [`wire::dhcpv4`] *(tested only)*: DHCPv4 message parse and emit
//!   (RFC 2131 fixed header, RFC 2132 options; option overload refused).
//! - [`wire::frame`]: the whole-frame parse and emit that joins the
//!   layers; *(tested only)* its UDP, ARP and ICMP arms and emitters.
//! - [`neighbor`] *(tested only)*: one interface's IPv4 neighbor table,
//!   solicit-only (ADR-039 § 5.2): a reply resolves only an address we
//!   asked about; operator-pinned entries cannot be changed by received
//!   packets; caller-supplied time and expiry; typed refusal when full.
//! - [`siphash`] *(tested only)*: SipHash-2-4, the keyed function the
//!   engine uses to derive RFC 6528 initial sequence numbers from the
//!   injected key.
//! - [`dhcp`] *(tested only)*: the DHCPv4 client (`DhcpClient`) as a pure
//!   state machine (Selecting, Requesting, Bound, Renewing; interface,
//!   transaction and operator-pin checks). Not wired to the engine.
//! - [`engine`] *(tested only)*: the ADR-039 § 5.1 engine, one entry point
//!   `Engine::step(now, Event) -> Actions`, over fixed tables of sockets,
//!   listeners, neighbors and UDP endpoints: passive and active open,
//!   accept, close, TIME-WAIT expiry, RFC 6298 retransmission of SYN,
//!   SYN-ACK and FIN, solicit-only ARP resolution with retries, one-prefix
//!   routing with a gateway, Principal ownership of every handle,
//!   per-listener half-open budget, rate-limited challenge ACKs, UDP
//!   endpoints, ICMP echo replies, RFC 6528 ISS, and stream SEND with
//!   a bounded per-socket buffer, RFC 5681 slow start / congestion
//!   avoidance / fast retransmit and fast recovery, data retransmission, zero-window probing, and bounded
//!   out-of-order reassembly (held in the engine, replayed into the
//!   unchanged connection block). Its own "not
//!   implemented" list is in the module docs.
//!
//! # What is not implemented yet
//!
//! CUBIC (RFC 9438);
//! sender silly-window avoidance and Nagle; SACK;
//! ICMP beyond echo replies;
//! UDP broadcast and multicast; applying a DHCPv4 lease to the engine
//! (and DHCP REBINDING, DECLINE, RELEASE); IPv4 fragment reassembly;
//! per-Principal accounting; the ADR-039 § 10 policy query; and every
//! IPv6 protocol behaviour. The types for IPv6 addresses exist (`addr`),
//! the behaviour does not. Each missing item is a typed refusal or simply
//! absent; nothing here pretends to handle it.

#![no_std]
#![forbid(unsafe_code)]
// The panic / indexing / arithmetic denials in Cargo.toml guard the
// library; unit tests may index and unwrap freely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod addr;
pub mod checksum;
pub mod dhcp;
pub mod engine;
pub mod error;
pub mod neighbor;
pub mod siphash;
pub mod tcp;
pub mod wire;

pub use addr::{IpAddress, Ipv4Address, Ipv6Address, MacAddress, SocketAddress};
pub use error::{EmitError, NetError, ParseError};
