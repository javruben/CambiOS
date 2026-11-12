<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 CambiOS contributors -->

# Claim ledger: CambiOS network stack

Rows classify evidence for the invariants in `spec/crates/net.md`. `proposed`
means no implementation or proof has run. A successful local proof does not
establish protocol conformance or hardware correctness.

Status values: `proposed` (nothing has run); `tested` (unit, vector or
integration tests pass: existential evidence, not universal); `proved
(bounded)` (a Kani harness passed for the stated bound; it establishes only
that harness's property, not the whole invariant and not RFC conformance);
`implemented (unverified)` (source and tests for part of the invariant
exist in the current tree, and none of them has been built, run or
proved; no row currently has this status); `partial` (part of the invariant has one of the above; the gap
names the rest). A row moves only on evidence from the exact tree it
names.

Evidence source for every `tested` / `proved (bounded)` claim below: crate
`cambios-netcore`, tree `8e9f0dda…b20b7b0` (41 files), run 2026-11-03/04
on m5090 (seat m5090-0464): `cargo test --locked` 37/37 on Rust 1.94.0
stable, x86_64 Linux; Kani 0.67.0 with `-Z stubbing`, 23 of 24 harnesses
successful, 1 timeout. That evidence is about that tree only.

The current tree differs from it. Its tests ran once (current-tree test
evidence below), and Kani ran on it on 2026-11-10 (results in the rows and
in the `kani` row of the verification-route table: 27 of 32 harnesses
SUCCESSFUL, 5 with no verdict). The difference: the checksum proof stage (proof-only); new modules
`engine` (the ADR-039 § 5.1 `step` shape), `neighbor`, `siphash`, `tcp::rto`, `tcp::congestion`,
`wire::udp`, `wire::arp`, `wire::icmpv4`, `wire::dhcpv4`, `dhcp`; changed modules `wire::frame` (`classify` gained UDP, ARP and
ICMP arms, `emit_ipv4_udp`, `emit_arp`, `emit_ipv4_icmp`,
`emit_ipv4_icmp_echo`; the P6 classify harness gained
matching arms), `error` (new UDP/ARP/ICMP reasons), `lib`; and new test
files `step.rs`, `step_icmp.rs`, `step_rto.rs`, `siphash.rs`, `udp.rs`, `arp.rs`, `icmp.rs`, `dhcp.rs`, `dhcp_client.rs`, `tcb_send.rs`, `step_send.rs`, `step_ooo.rs`, `step_fastrtx.rs`, `step_wndupd.rs`. The modules the old evidence covers
unchanged are `wire::{ethernet, ipv4, tcp}`, `tcp::*` except `tcp::tcb` (which gained the read-only `retransmit`)
and the new `tcp::rto`, and `checksum` (production code). A `tested` claim that goes through `classify` was
observed on the old `classify` and again on the current one.

Current-tree test evidence: crates `cambios-netcore` + `user/net-seam`, 54
files, file-list hash `3201236b…0291` (sha256 of the sorted per-file
`shasum -a 256` list; afterwards only the `cambios-netcore/src/lib.rs` doc
comment, this file, and one `#[cfg(kani)]` harness added to
`cambios-netcore/src/checksum.rs` changed; none is compiled into the
tested build), run 2026-11-10 on build1 (seat
build1-3385), toolchain nightly-2026-02-07 (rustc 1.95.0-nightly
efc9e1b50), x86_64 Linux: `cargo test --locked --no-fail-fast` 125 passed,
0 failed, 0 ignored; `cargo clippy --lib -- -D warnings` clean; `cargo build
--lib` for x86_64-unknown-none, aarch64-unknown-none and
riscv64gc-unknown-none-elf; net-seam `cargo test` 19 passed and `cargo
clippy --lib --tests -- -D warnings` clean. Five files were edited after
the first run to get there: `tests/udp.rs` (two temporaries dropped while
borrowed), `engine.rs` (clippy: two identical branches merged, same
behaviour), `tcp/state.rs` (clippy: const-loop increment), and two test
bugs: `tests/step_fastrtx.rs` (the peer reused a sequence number it had
already sent, which RFC 9293 § 3.10.7.4 correctly answers with an ACK) and
`tests/step_ooo.rs` (the wrap test placed its tail one octet past the end
of the gap). The tests were written before the code, but no red run of
them was observed, so TDD red/green is NOT claimed. Clippy covered the
library, not the netcore tests.

Follow-up run, 2026-11-10 (seat build1-3463, same toolchain): after
`EngineConfig::iss_key` became `Option<IssKey>` (owner ruling 2026-11-10:
no entropy source yet, so TCP fails closed, never a weak key) and the new
`tests/step_nokey.rs`, the netcore tree (file-list hash `7768d961…`)
passed 129 tests, 0 failed, 0 ignored, with clippy and the three no_std
builds clean. Negative control: with the two refusal gates removed and a
zero key substituted in the staged copy only,
`step_nokey::opens_are_refused_and_send_nothing` FAILED, then the copy was
restored byte-identical. The tests were written before the change but
first run after it, so no red run is claimed.

| crate | id | class | harness | bound | status | gap |
|---|---|---|---|---|---|---|
| net | INV-net-001 | kani | tests: `tests/vectors.rs::net_v_001_short_frame_is_malformed`, `tests/boundaries.rs::ethernet_input_length_partition`; kani: `wire::frame::proofs::p6_classify_is_total_up_to_1514` | tests: NET-V-001 + length partition; kani: frames 0..=1514 octets | partial: tested | the 1514-octet Kani harness timed out on 8e9f0dda (600 s, 1238 s); on the current tree (2026-11-10) it was SUCCESSFUL (64 s build1-3387, 69 s .15-3381) with the checksum accumulator stubbed, but both checksum stage harnesses gave no verdict (split: timeout 600 s / 1800 s; one-pass totality: out of memory at 3.5 and 12 GiB), so the bound is still UNPROVEN. MTU rule tested only at 1500 and 20. No `Stack::input` exists: link-header completeness is shown for the parser, not for stack delivery |
| net | INV-net-002 | tests | `tests/vectors.rs::net_v_010_011_ipv4_refusals`, `tests/boundaries.rs::ipv4_total_length_and_ihl_partition`; kani `wire::frame::proofs::p6_ipv4_parse_is_total` (totality only) | NET-V-010/011, IHL 0..=15, total-length partition; kani: inputs 0..=80 octets | partial: tested | version, IHL, total length, header checksum, fragment fields (fragments refused, not reassembled) and broadcast/multicast source are checked by the parser. Destination locality is checked by `engine::Engine::step` (`Refusal::NotForUs`); its test `tests/step.rs::frames_refused_before_any_state` passes (2026-11-10). The Kani harness proves no panic/OOB/overflow, not validity |
| net | INV-net-003 | tests | - | packet vectors | proposed | no parser or test exists |
| net | INV-net-004 | kani | - | 8 headers, 2048 bytes | proposed | no parser or harness exists |
| net | INV-net-005 | tests | `tests/arp.rs` (9 pass, 2026-11-10) | neighbor table capacity (const generic `N`) | partial: tested | `neighbor::NeighborTable` is one interface's table (one per engine, so an entry can affect only that interface), holds only IP→MAC, and never lets a received packet change or evict an operator-pinned entry (NET-V-030); a reply resolves an entry only if we asked (ADR-039 § 5.2: pending question, solicited reply); invalid and own-address senders are never accepted. Tests pass (2026-11-10). The engine owns the table inside `Engine::step` (ADR-039 § 5.1): an active open to an unresolved next hop sends a broadcast request, retries on `Tick` up to `arp_attempts`, then fails with `NoRoute`; a UDP send to one sends the request and is refused `WouldBlock`; requests for our address are answered; a pinned entry is used without ARP and cannot be moved through the engine (`tests/step.rs`, passes). No IPv6 Neighbor Discovery, no RFC 5227 defence, no gratuitous announcements |
| net | INV-net-006 | tests | `tests/udp.rs`, `tests/step.rs::udp_through_step` (pass, 2026-11-10) | NET-V-040, 041, 043, 044 | partial: tested | `wire::udp` parses and emits IPv4 UDP (length rules, checksum, B-11 zero-checksum allowance); the engine delivers a datagram only to an endpoint bound to its destination port on this interface's address (`Action::Datagram`, else `Refusal::NoEndpoint`); endpoints are owned by the binding Principal (other Principals' sends are `Denied`). The tests pass (2026-11-10). MISSING half of the invariant: the "permitted endpoint" check. `Op::UdpBind` is unchecked and no capability/policy check exists anywhere yet; the tests cover only destination-port binding and delivery. NET-V-042 (IPv6) not covered |
| net | INV-net-007 | model | kani: `tcp::state::proofs::edges_equal_transitions_membership`, `tcp::tcb::proofs::{p2_reach2_is_the_two_edge_closure, p2_segment_from_* (11 states), p2_close_takes_one_table_edge}`, `tcp::accept::proofs::{p1_acceptable_matches_rfc9293_table, p1_acceptable_is_translation_invariant}`; tests: NET-V-050/051, `tests/slice.rs` | kani: fully symbolic TCB, any segment flags/seq/ack/window, payload 0..=2 octets; acceptability over all u32 | partial: proved (bounded) | proved: every state change on any arriving segment or local close follows ≤2 edges of the code's `TRANSITIONS` table and never reports an illegal transition; segment acceptability equals the RFC 9293 §3.10.7.4 table as transcribed independently in the harness (u64 offsets; the transcription is reviewed, not machine-checked against the RFC). NOT proved: that `TRANSITIONS` itself matches RFC 9293 §3.3.2 (hand-derived; unit-tested against spec §3), or that every guard matches the RFC (tested only). In the current tree: timers, a send buffer and bounded out-of-order reassembly exist in the engine, outside the block (`tests/step_rto.rs`, `tests/step_send.rs`, `tests/step_ooo.rs`, passing 2026-11-10); none is covered by these proofs. TREE NOTE: these proofs and tests ran on 8e9f0dda. `tcp/tcb.rs` has since gained `Tcb::retransmit` (read-only), `Tcb::data_header` (read-only), `Tcb::ack_header` (read-only) and `Tcb::send_data` (advances SND.NXT by a caller-chosen length in ESTABLISHED / CLOSE-WAIT). `on_segment` and `close` are unchanged in source, and the P2-P4 harnesses start from a fully symbolic block (any SND.NXT), and on 2026-11-10 every harness named in this row was re-run on the current tree (stage tar `df50cb2b`, Kani 0.67.0, seat build1-3387) and was SUCCESSFUL (state edges; p2 reach2 in 535 s, close, all 11 per-state segment harnesses; p3 x2; p4; p1 x2). No harness covers the four new functions; `tests/tcb_send.rs` (6 tests) passes (2026-11-10). |
| net | INV-net-008 | kani | kani `tcp::send::proofs::p8_sendable_stays_inside_both_windows`; test NET-V-052 | all u32 inputs | partial: proved (bounded) | proved for the send-size function `sendable`: new data ≤ min(snd_wnd, cwnd, unsent), and in-flight + new ≤ min(snd_wnd, cwnd). No send path consumes it yet (the core emits control segments only), and no congestion-control algorithm sets cwnd TREE NOTE: proved on 8e9f0dda only; `tcp::send::sendable` is unchanged in source; `p8_sendable_stays_inside_both_windows` was re-run on the current tree on 2026-11-10 (build1-3387) and was SUCCESSFUL. The engine's SEND path now consumes it, with the congestion window from `tcp::congestion::Reno` (RFC 5681 slow start / congestion avoidance / timeout / fast recovery; no CUBIC); `tests/step_send.rs` and `tests/tcb_send.rs` pass (2026-11-10), and no harness covers the engine's send path or `Reno`. |
| net | INV-net-009 | tests | kani `tcp::tcb::proofs::{p3_non_exact_rst_changes_nothing, p3_exact_rst_closes, p4_syn_in_synchronized_state_is_challenged}`; tests NET-V-060/061, `tests/slice.rs` | fully symbolic TCB in SYN-RECEIVED or any synchronized state, any segment, payload 0..=2 octets | partial: proved (bounded) | proved: a non-exact RST leaves the whole TCB unchanged and yields exactly one challenge ACK in-window, nothing out of window; a SYN in a synchronized state leaves it unchanged and yields one challenge ACK. NOT implemented: the RFC 5961 §7 challenge-ACK rate limit (unit and value open, crosswalk R-6); challenge ACKs are only marked. Passive SYN-RECEIVED follows the RFC 9293 check order (a duplicate SYN gets a plain ACK) |
| net | INV-net-010 | model | `tests/step_rto.rs`, `tests/step_send.rs`, `tests/step.rs::time_wait_lasts_two_msl_then_frees_the_slot` (pass, 2026-11-10) | configured timer range | partial: tested | control-segment retransmission (SYN, SYN-ACK, FIN) per RFC 6298 with the ADR-039 § 5.2 bounds (`tcp::rto`: initial 1 s, floor 200 ms, ceiling 60 s, × 2 backoff, Karn's rule, § 5.7 3 s after a lost SYN; retries bounded by configuration) and TIME-WAIT of 2 × MSL (30 s) exist in the engine. Tests pass (2026-11-10); no model, no harness, no interoperability evidence. Data retransmission from the transmit buffer (oldest unacknowledged octets, cwnd collapsed to one SMSS) and zero-window probing (RFC 9293 § 3.8.6.1; probes answered by the peer do not count toward the retry bound) now exist too (`tests/step_send.rs`, passes). The congestion-window half of the invariant names RFC 9438 (CUBIC), which is absent; what exists is RFC 5681 Reno slow start / congestion avoidance / timeout response and fast retransmit / fast recovery on the third duplicate ACK (`tests/step_fastrtx.rs`, passes). Keep-alive does not exist |
| net | INV-net-011 | kani | - | every `NetLimits` field | partial: tested | the engine's socket, listener, neighbor and UDP tables have fixed const-generic capacities with typed refusals at the bound (`Refusal::{SocketTableFull, HalfOpenFull}` for SYNs, `ResourceLimit` replies for control ops), and a per-listener half-open budget from configuration; `tests/step.rs::full_tables_and_the_half_open_budget` passes (2026-11-10), and no harness exists. No `NetLimits` type, no per-Principal accounting |
| net | INV-net-012 | model | - | per-principal resource model | proposed | no isolation model exists |
| net | INV-net-013 | kani | kani `wire::frame::proofs::p6_ipv4_parse_is_total`, `wire::tcp::proofs::{p6_tcp_options_walk_is_total, p6_tcp_parse_is_total}` (assume-guarantee), `wire::frame::proofs::p6_classify_is_total_up_to_1514`, `checksum::proofs::p6_checksum_is_total_up_to_frame`; tests `tests/boundaries.rs` (length partitions + 20 000-input seeded sweep) | IPv4 parser 0..=80 octets; TCP parser 0..=80 octets; option area 0..=40 octets; full frame 0..=1514 octets | partial: proved (bounded) | proved: the IPv4 and TCP parsers have no panic, OOB or overflow up to 80 octets (the TCP proof composes the option-walk stage via a sound over-approximating stub). Current tree, 2026-11-10 (Kani 0.67.0, stage tar `df50cb2b`): `p6_ipv4_parse_is_total`, `p6_tcp_parse_is_total`, `p6_udp_parse_is_total`, `p6_arp_parse_is_total` and `p6_icmpv4_parse_is_total` SUCCESSFUL; the option-walk stage `p6_tcp_options_walk_is_total` gave NO verdict (timeout 600 s on build1, out of memory at 6 GiB and timeout 1800 s at 10 GiB on .15; it passed on 8e9f0dda in 815 s on m5090), so on the current tree the TCP result rests on an unre-proved stage. UNPROVEN: full frames up to 1514 octets (the classify harness passes only with the checksum stubbed, and neither checksum stage harness finished; see INV-net-001). `engine::Engine::step` has a bounded P6 harness, `engine::proofs::p6_step_on_any_small_frame_is_total` (frames 0..=64 octets, an engine with one listener and one UDP endpoint, then a tick) that gave NO verdict on 2026-11-10 (out of memory at 3.5 GiB; timeout 1800 s at 16 GiB); a smaller bound is with codex; "step is total" is NOT claimed. The UDP, ARP, ICMPv4 and DHCPv4 parsers exist in the current tree with P6 harnesses `wire::udp::proofs::p6_udp_parse_is_total`, `wire::arp::proofs::p6_arp_parse_is_total`, `wire::icmpv4::proofs::p6_icmpv4_parse_is_total`, `wire::dhcpv4::proofs::p6_dhcpv4_parse_is_total`; on 2026-11-10 the UDP, ARP and ICMPv4 harnesses were SUCCESSFUL. The DHCPv4 harness gave NO verdict at 0..=300 octets (out of memory at 3.5 GiB; timeout 1800 s at 16 GiB). Re-bounded to 0..=260 octets (the 240-octet fixed part plus a 20-octet option area, unwind 22), it was SUCCESSFUL on 2026-11-12: cc4fb7f, seat m5090-4124, Kani 0.67.0, 8 GiB cap, 168 s, log sha256 `fc501b70…f375`. That covers no panic, OOB or overflow for those lengths only. Longer packets, including a full 300-octet lease, rest on the parser and vector tests. Absent: `Stack::input`, and the IPv6 and DNS parsers. The P6 classify harness's body changed after the 8e9f0dda run (UDP/ARP/ICMP arms) |
| net | INV-net-014 | tests | - | capability operation matrix | proposed | no network IPC or test exists |
| net | INV-net-015 | tests | - | DNS vectors and TTL bounds | proposed | no resolver or test exists |
| net | INV-net-016 | tests | `tests/dhcp_client.rs` (NET-V-120, 121, 123), `tests/dhcp.rs` (pass, 2026-11-10) | DHCP transaction vectors | partial: tested | `dhcp::DhcpClient` accepts a reply only for its interface, transaction id and hardware address, of the type its state expects, and refuses an acknowledgement that would replace an operator-pinned address; `wire::dhcpv4` parses and emits the messages (P6 parser harness SUCCESSFUL for inputs 0..=260 octets on 2026-11-12; see INV-net-013). Tests pass (2026-11-10); no harness for the client. NOT implemented: applying a lease to the engine's interface address, DHCPv6 (NET-V-122), REBINDING, DECLINE, RELEASE |
| net | INV-net-017 | tests | - | diagnostic capture | proposed | no stats/log interface or test exists |
| net | INV-net-018 | kani | - | 64 fragments, 4 MiB | proposed | no reassembly model or harness exists |
| net | INV-net-019 | tests | - | capability operation matrix | proposed | no listener service or test exists |
| net | INV-net-020 | tests | - | IPv6 UDP vectors | proposed | no UDP service or test exists |
| net | INV-net-021 | tests | - | MAX_ROUTES entries, longest-prefix/metric/interface tie-break | proposed | no route table or test exists |
| net | INV-net-022 | tests | - | one DAD interval and address lifetime | proposed | no SLAAC service or test exists |

**Shell, stage 1 (QEMU evidence, 2026-11-10, build1-3484).** `user/net-stack` brings up the ADR-039 § 2 seam with `virtio-net`, drives the engine with no ISS key on QEMU's static user-network address, and sends one DNS query to 10.0.2.3. Under KVM (`-enable-kvm`, QEMU 8.2.2) the serial line `[NETSTACK] self-test PASS: DNS reply from 10.0.2.3 len=61 rcode=0 answers=2 in 200 ms; frames in=4 out=2` was observed in 38 of 67 boots, over six builds that differ only in diagnostics. The final build passed 3 of 6. Every failure traced so far is outside the stack:
- PCI scan not finished when drivers ask (TCG never finishes it);
- the policy service denies `get-time` to a just-spawned process on a reused pid as "unknown principal" (net-stack now exits `clock refused`);
- a task that is no longer scheduled.

A control image without net-stack also stalled the boot wave in 2 of 6 boots.

**Kernel scratch frame (ADR-039 § 9 / ADR-007 Divergence 8, build1-3571, 2026-11-11).** Each process owns the first whole page after its in-place buddy allocator, reserved and zeroed at creation. `teardown_channel_mappings` remaps every page of a revoked writable mapping to that side's own frame. After `CLOSE_SEAM`, net-stack reads its revoked TX page, writes `0xA5` and reads it back. On 8 interleaved boots per kernel:
- **Unpatched kernel (red):** in all 4 boots that reached the probe, the process was reaped with `PageFault at 0x10000000`.
- **Patched kernel (green):** in all 4 boots that reached the probe, it printed `post-revoke write survived: first=0 readback=165 (scratch frame)`, with no fault.

Both kernels passed DNS in 4 of 8 boots. Tri-arch kernel build and clippy are clean, and the 942 host tests pass, including one that pins the scratch page inside the reserved prefix. A first version that took the frame from the frame allocator stalled every boot after policy-service readiness (6 of 6, plus experiments A and C); the root cause of that is unknown. Not shown: aarch64 and riscv64 runtime.

**`chan.peer_violation` (ADR-039 § 4, build1-3583, 2026-11-11).** `SYS_CHANNEL_CLOSE` takes a reason in arg2: `CHANNEL_CLOSE_REASON_NORMAL` (0) or `CHANNEL_CLOSE_REASON_PEER_VIOLATION` (1). Any other value is refused with `InvalidArg` before anything closes. A peer-violation close emits audit kind 23, `chan.peer_violation` (security class; subject is the closer, `arg0` the other side's pid), and then `chan.closed`. The kernel cannot check the accusation, so the event records a claim. `AUDIT_TAXONOMY_VERSION` is now 2. The NIC seam uses it on `PeerUntrusted`/`PeerMalformed`: the driver accuses on the stack's TX channel and the stack on the driver's RX channel. The test was an experiment build that is not in the worktree: net-stack drops the seam with the violation reason after its DNS test. The red build is the same ISO with only the kernel emit branch disabled. On 45 s KVM boots, `audit-tail` showed:
- **Force (green):** in all 4 boots that reached the drop, `chan.peer_violation` and then two `chan.closed` lines, in that order.
- **Red:** no `chan.peer_violation` in the 3 boots where its `chan.closed` lines were visible. Of the other two boots, one never reached the drop. In the other, `audit-tail` never showed the close events, so that boot counts for neither side.
- **Plain (the worktree code):** no `chan.peer_violation` on the ordinary close (2 boots with `chan.closed` visible). DNS passed 2 of 3, and the scratch probe survived in both boots that reached it.

Tri-arch build and clippy are clean, the 943 kernel host tests and 12 ABI tests pass, the deferral, assumption, unsafe-coverage and fail-open gates are OK, and `docs/generated/audit-taxonomy.md` was regenerated. Not shown: the `PEER_VIOLATION_LIMIT` path against a real lying peer on a booted system (net-seam's host `hostile` tests cover the counting), and aarch64 and riscv64 runtime.

**Shell, stage 2: net-stack replaces udp-stack on x86_64 (ADR-039 migration step 6, build1-3598, 2026-11-11).** `user/net-stack` is now persistent. It serves:
- ep 21: udp-stack's UDP protocol, with per-Principal port ownership. `SET_CONFIG`/`DHCP_SEND` answer `ERROR`; that deferral is in `compat.rs`.
- ep 34: socket control through `cambios-net-proto`. `CONNECT`/`LISTEN`/`ACCEPT` are refused by the engine because it has no ISS key.
- The NTP wall clock (udp-stack's constants, `set_wallclock(_, 0)`).

On x86_64 the manifest, ISO and limine no longer carry udp-stack. It stays on aarch64/riscv64, whose images do not stage net-stack yet, and both arches' manifests still build. A one-shot test client, `user/net-probe` (ep 35), checks the surfaces from outside. Under KVM, 45 s boots:
- **First build:** `[NETPROBE] PASS 9/9` in 3 of 3 boots. The checks: ep 21 `GET_CONFIG`; `UDP_RECV` opening a port; `UDP_SEND` of a DNS query and `UDP_RECV` of the resolver's answer; `SET_CONFIG` refused; ep 34 `GET_CONFIG`; and `CONNECT`, `LISTEN` and `STATUS` refused. One of those boots printed no NTP outcome at all, cause unknown.
- **Second build:** a tenth check reads `get_wallclock` directly; `PASS 10/10` in 4 of 4 boots.

No `[UDP]` line from udp-stack appeared. net-stack and net-probe have 0 clippy warnings, and the deferral, assumption, unsafe-coverage, fail-open and banned-path gates are OK. A comment-only `sock.rs` reflow for the deferral gate came after the boots.

**Stage 2 on aarch64 and riscv64 (build1-3608, 2026-11-11).** The udp-stack manifest row is gone. `img-aarch64` and `img-riscv64` stage net-stack and net-probe and both build. QEMU 8.2.2 (Ubuntu debs extracted into the seat directory) ran under TCG:
- **riscv64:** with `-device virtio-net-device` (virtio-mmio), net-probe printed `PASS 10/10` in 2 of 2 boots, including NTP. Inference: this kernel carries the kernel changes, because it contains the `peer_violation=` string, which only the patched dispatcher has. With `virtio-net-pci` the driver reports no NIC (it probes MMIO on riscv64), so net-stack exits and the probe fails 0/10.
- **aarch64: unverified at this venue.** A pristine branch-HEAD image (4627224) hangs after AP bring-up, before init starts. Our image reaches init, but `policy-service` faults (EL0 read at `0x1395b00e8`) with both the original and the patched kernel, so init never settles. Neither result shows that our change is the cause, and neither rules it out.

`user/udp-stack` and its Makefile targets are still in the tree, unused.

**Hardware entropy, `SYS_GET_ENTROPY` = 76 (owner ruling 2026-11-10; build1-3618, 2026-11-11).** The syscall fills 1..=256 octets from the CPU's generator: x86_64 RDSEED, else RDRAND, 10 tries; aarch64 RNDR when `ID_AA64ISAR0_EL1` reports it; riscv64 none (the Zkr `seed` CSR traps without firmware grant). It returns `Enosys` with no generator and `WouldBlock` on exhaustion. Nothing comes from software, and the kernel-stack copy is wiped. net-stack takes its 16-octet RFC 6528 ISS key from it and is keyless (TCP refused) on any error. On KVM, same ISO:
- default `qemu64` CPU (no RDRAND/RDSEED in CPUID): `TCP closed (no hardware RNG: get_entropy refused)` in 2 of 2 boots;
- `-cpu host` (build1 reports `rdrand rdseed`): `TCP keyed from the hardware RNG` in 2 of 2.

net-probe passed in all 4 boots. Tri-arch build and clippy are clean, the 944 kernel host tests pass (one runs the real instruction on the build host and checks two draws differ, or that both report unsupported), the ABI syscall-table tests pass, and the gates are OK. Not shown: aarch64 RNDR on hardware that has it.

**TCP data over per-socket stream channels (ADR-039 § 3 / § 4; build1-3626, 2026-11-11).** `net-seam` gains the byte ring: the same control page with `slot_size = 0` and `slot_count` read as the capacity in octets. It applies the frame ring's hostile-peer rules. A peer page that has never been valid reads as "not attached yet", not as the tombstone, because the stack writes before the client attaches. That is a 🔴 ASSUMPTION; the ADR is silent on the attach window. `tests/bytes.rs` passes 11/11 and clippy is clean.

net-stack gives each opened or accepted socket two `STREAM_PAGES` + 1 page channels: TX, where the stack is `Consumer`, and RX, where the stack is `Producer`.
- Engine deliveries go into the RX ring.
- Client consumption becomes `Op::Consumed`.
- The client's TX ring feeds `Op::Send`, pumped every pass and on `DOORBELL`.
- `DATA_READY` goes to the opening request's endpoint.
- `STATUS` reports the RFC 4022 state and the ring counts.
- A client whose page tombstones is dropped. One that breaks the ring protocol is dropped with the `chan.peer_violation` close reason on its TX channel.

The shell picks `CONNECT`'s local port from the IANA dynamic range, starting at an offset from the hardware RNG. The engine now refuses port 0 on either end; test `active_open_refuses_port_zero_on_either_end`, netcore 130/0.

Two defects were found by a pcap of the first runs (QEMU `filter-dump`) and fixed:
- the shell passed `local_port: 0`, which went on the wire;
- virtio-net's single TX bounce buffer was overwritten while the device still owned it once a completion came late. Earlier frames were lost and the last one was sent several times, and TCP recovered only by backed-off RTOs. virtio-net now has one buffer per in-flight descriptor (`TX_RING_SIZE` 16).

On KVM with `-cpu host`, net-probe CONNECTs to a host echo server (slirp 10.0.2.2:18080 → 127.0.0.1:18080). It attaches both channels, reaches ESTABLISHED, and echoes 40 000 octets (more than twice each ring) back unchanged. It sees `DATA_READY` and CLOSEs. The server logged 40 000 per connection. Then LISTEN and CLOSE of the listener: PASS 16/16 in 2 of 2 boots that got a NIC. On the keyless arms the probe expects CONNECT/LISTEN refused: `qemu64` KVM PASS 10/10 (1 of 1 boot that got a NIC), riscv64 TCG PASS 10/10 (1 of 1). The "no NIC" bring-up failure hit 2 of the 8 final-ISO boots; it is the known kernel flake. Gates, and clippy on x86_64/aarch64/riscv64, are clean.

**Inbound TCP through ACCEPT, and the "no NIC" boot flake (build1-3644 / build1-3652, 2026-11-11).** A connection the engine completes before its owner's `ACCEPT` can carry data; net-stack used to drop those `Deliver`s (no stream yet) after TCP had acknowledged them. It now holds them, one receive window each, for up to `PRE_ACCEPT` = 4 sockets; overflow is counted in `held_lost`. They are written into the RX ring when `ACCEPT` opens the stream, and late octets for a client-closed socket are dropped. The probe's keyed arm now also `ACCEPT`s a host client (QEMU `hostfwd` 127.0.0.1:18081 → 8080) and echoes 20 000 octets, which the client checks: PASS 19/19 in 4 of 4 KVM boots. Before the hold, 2 of 3 boots lost the data. 🟡 The same run raised the client's receive timeout from 20 s to 60 s, so the two changes are not separated by a red arm.

The "no NIC" flake was the kernel. On x86_64, `kmain` enabled the APIC timer before `pci::scan()`. When the timer switched the boot context out for init, `kmain` did not resume during the boot wave. No PCI scan meant every driver found no device, and the APs never started: those boots show no `PCI:` line and no task on CPU 1. The scan now runs before interrupts are enabled: 8 of 8 KVM boots found all 8 devices and passed, against 2 of 8 "no NIC" before. The AP start (`start_application_processors`) still follows interrupt enable, so that window remains. It is not fixed here; the kernel owner should decide.

virtio-net TX red arm (today's driver with only the single-buffer `send_packet` restored): the echo stalled at 7 300 of 40 000 octets in 1 of 2 boots and passed in the other. The defect depends on timing, which is why the pcap, not the pass rate, is the evidence for it.

**Review fixes (independent read-only review; build1-3654, 2026-11-11).**
- The RX-window credit was computed from the ring's cached client tail, which every delivery also refreshed. So consumption seen during a delivery was never reported as `Op::Consumed`, and the TCP window leaked shut under sustained traffic. Credit now has its own counter, forward moves only. A client moving its tail backwards gets no window.
- The empty→non-empty `DATA_READY` decision now reads the client's tail first.
- `CLOSE` with octets still in the client's TX ring keeps the stream until they reach the engine. It used to discard them.
- A client that never attaches is dropped after `ATTACH_MS` = 10 s. An all-zero page that was never valid otherwise reads as "not attached" forever.
- A failed `ACCEPT` open frees its held octets.

The probe's outbound echo is now 400 000 octets (about 25 ring-fulls). With the fixes: PASS 19/19 in 6 of 6 KVM boots, and the host echo server logged 400 000 per connection. The pre-fix stack with the same probe stalled at about 145 000 octets in 1 of 2 boots and passed in the other. build1-3655 then addressed two of the remaining review items: virtio-net uses at most min(16, TX queue size) buffers, and a lost pre-ACCEPT octet prints a line besides counting in `held_lost`. Result: PASS 19/19 in 2 of 2 boots. A third boot failed only because the host echo server's lifetime had run out (no listener, RST). Still open: a stale handle given to `CLOSE` falls through to `Unlisten`, which affects only the caller's own listeners. Seen once in 21 recent KVM boots and outside the network path: `[POLICY] deny: unknown principal (pid 7) asked for print` while virtio-blk was spawning on CPU 1, a spawn/identity-binding race that boots using CPU 1 can expose.

Not shown: throughput, aarch64 runtime, a seam re-bring-up after driver death (nothing restarts a driver yet), and any non-QEMU NIC. i219-net was read, not run: it already keeps one bounce buffer per TX ring slot, so the shared-buffer defect does not apply there.


DHCP lease applied to the interface (codex D1, 2026-11-12, uncommitted tree; seat build1-4060). The engine takes an accepted lease only as `Event::Interface(InterfaceConfig)`, never as a client op. It is validated first: a unicast address, prefix 1-32, no network or broadcast host address for prefixes up to /30, and a gateway, if any, that is another unicast host on-link. An invalid one is refused with nothing changed. The same address and prefix (a renewal, or a new gateway) keeps every socket. A new address or prefix frees every TCP socket, and each claimed one is notified `Error(NoAddress)`. A slot is not reused until its notice is out, so no notice is dropped. `Event::AddressLost` (lease expired, or NAKed while renewing) leaves no address: all IPv4 is `NotForUs`, ARP is neither answered nor learned, and opens and UDP sends are refused `NoAddress` until the next lease. net-stack runs `cambios_netcore::dhcp` over raw frames (DISCOVER from 0.0.0.0; UDP 67->68 taken before the engine). The slirp static address is used only until the first lease and never after a loss. The DHCP client binds an ACK or NAK to the selected offer or current lease (server identifier required, RFC 2131 Table 3; an ACK must also be for the requested address); there is no REBINDING state, so no other server is accepted.
Evidence (build1-4060, logs `/root/netcore-s/logs/s4-*`, summary `~/.naoms/agent-comms/_shared/netcore-b1-4060-evidence.md`):
- Red first: on stubbed copies, `tests/step_lease.rs` failed 6/7 and the binding test in `tests/dhcp_client.rs` failed.
- Green: `cargo test` 138 passed, 0 failed; clippy `--lib --tests` clean; gates ok; iso sha256 `5002753e...`.
- KVM, 10 boots of the D1 build: 7 PASS 19/19, and "DHCP lease applied" in 9/9 boots that reached net-stack.
  - One boot: the kernel spawn race.
  - One boot: the echo stall.
  - One boot (s14b-2): net-stack never answered ep 21 `GET_CONFIG` within `START_TICKS`, and the probe then printed nothing more. This is OPEN; diagnostics were added to net-probe and a targeted boot is pending.
- Control, the pre-D1 ISO, 6 boots: 5 PASS, and the one failure was the same echo stall. So the echo stall predates D1.
- riscv64 TCG with udp-stack restored: 2/2.
Kani on the re-bounded harnesses (engine P6 at 0..=42, DHCPv4 P6 at 0..=260): both "Out of memory" at a 3.5 GiB cap on build1-4060, so NO VERDICT. Rerun on m5090-4124 (cc4fb7f, 8 GiB cap, 2026-11-12): DHCPv4 P6 was SUCCESSFUL (168 s). Engine P6 failed again with CBMC "Out of memory" (status 6) after 168 s, while unwinding the per-octet loop in `TxRing::push`. That is NO VERDICT, not a counterexample. "step is total" is not claimed.

CI (`.github/workflows/proofs.yml`, `kani (cambios-netcore)`): on 2026-11-12 the job ran every harness in one `cargo kani` invocation. The hosted runner shut down 7 minutes into `p6_checksum_add_bytes_is_total_up_to_frame` (inference: out of memory), with NO verdict for any harness. The CI entry now names the 27 harnesses that were SUCCESSFUL locally on 2026-11-10. Five harnesses run only on a large-host seat: both checksum stages, the TCP option walk, DHCPv4 P6 and engine P6. A green CI check covers the 27 and nothing more. The new CI entry ran on cc4fb7f and 5c4cfd1 (2026-11-12): "27 successfully verified harnesses, 0 failures". Of the five large-host harnesses, DHCPv4 P6 now has a SUCCESSFUL verdict (m5090-4124). The other four still have NO verdict.
Not shown: renewal and expiry on the wire (slirp leases outlast a boot), a lease that changes the address on a real network, and multiple DHCP servers.

## Verification-route decision (draft)

Kani remains the planned Rust-side bounded checker for parsers, integer/serial arithmetic, and resource accounting. `proposed` means no harness exists. Lean is a candidate for the pure state-transition model, with Aeneas as a possible translator for a safe sequential Rust subset. A Lean theorem would establish only the stated property of that model under its axioms and imported lemmas; it would not establish RFC conformance or match the implementation unless a refinement relation is separately specified and checked. Unsafe device/IPC boundaries and concurrent behavior remain outside this candidate route. No Lean proof has been run. Bounded Kani proofs have run for the `cambios-netcore` slice; see the rows above.

| candidate | property | status | gap |
|---|---|---|---|
| lean + aeneas | TCP transition safety of a pure sequential model | proposed | no model, translation, refinement theorem, or proof exists |
| kani | Rust parser memory safety and bounded resource arithmetic | partial | Current tree, run 2026-11-10 (Kani 0.67.0, CBMC 6.8.0, `-Z stubbing`, stage tar `df50cb2b`; seats build1-3387, .15-3381, .15-3408): 32 harnesses (the 31 from the source census plus `checksum::proofs::p6_checksum_add_bytes_is_total_up_to_frame`, a proof-only one-pass totality harness added that day; the split harness is unchanged). 27 SUCCESSFUL: `siphash24_is_total`; `p1_acceptable_matches_rfc9293_table`, `p1_acceptable_is_translation_invariant`; `p8_sendable_stays_inside_both_windows`; `edges_equal_transitions_membership`; all 17 `tcp::tcb` harnesses; the IPv4, TCP, UDP, ARP and ICMPv4 parse harnesses; `p6_classify_is_total_up_to_1514` (checksum stubbed). 5 gave NO verdict, and none produced a counterexample: the checksum split (timeout 600 s / 1800 s) and one-pass totality (out of memory at 3.5 and 12 GiB) harnesses, `p6_tcp_options_walk_is_total` (timeout 600 s; out of memory at 6 GiB; timeout 1800 s at 10 GiB), `p6_dhcpv4_parse_is_total` (at 0..=300: out of memory at 3.5 GiB, timeout 1800 s at 16 GiB; re-bounded to 0..=260 it was SUCCESSFUL on 2026-11-12, m5090-4124, cc4fb7f), and `engine::proofs::p6_step_on_any_small_frame_is_total` (out of memory at 3.5 GiB; timeout 1800 s at 16 GiB). Old-tree evidence (8e9f0dda): 24 ran, 23 passed, 1 timed out. `neighbor` and `dhcp` have no harness. Resource accounting: the engine's fixed tables exist (tests pass, 2026-11-10); no harness |
| vectors + interop | observable RFC-profile behavior | partial | `tests/vectors.rs` replays NET-V-001, 010, 011, 050, 051, 052, 060, 061 and 091 from this directory's vectors (passing); NET-V-090 is covered for its Ethernet, IPv4 and TCP length fields only (`tests/boundaries.rs`); its ARP and UDP parts are not covered (the parsers exist and are unit-tested in the current tree, and no NET-V-090 replay was written for them); its IPv6, DNS and DHCP parts are not covered (no such parsers exist). `tests/udp.rs` and `tests/arp.rs` replay NET-V-040/041/043/044 and NET-V-030: passing (2026-11-10). The other vectors need components that do not exist. No peer traces or interop runs |
