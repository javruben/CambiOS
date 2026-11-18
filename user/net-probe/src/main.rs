// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! One-shot boot probe of net-stack's client surfaces, from the
//! ADR-039 test-client endpoint (35). Each check prints `ok` or `FAIL`
//! with what it saw, and the process exits 0 only if all pass:
//!
//! - ep 21 `GET_CONFIG` reports the stack's address;
//! - ep 21 `UDP_RECV` on a fresh port opens it (`NO_DATA`);
//! - ep 21 `UDP_SEND` of a DNS query to QEMU's resolver is accepted,
//!   and `UDP_RECV` then returns the resolver's answer to that query;
//! - ep 21 `SET_CONFIG` is refused (the engine's address is fixed);
//! - ep 34 `GET_CONFIG` (IPv4) reports the same address;
//! - with a hardware RNG (`get_entropy` answers), ep 34 `CONNECT` to
//!   the echo server at 10.0.2.2:18080 (QEMU user networking forwards it
//!   to the host's 127.0.0.1:18080) hands out both stream channels,
//!   reaches `ESTABLISHED`, and [`ECHO_OCTETS`] octets written into the
//!   TX ring come back through the RX ring unchanged, with at least one
//!   `DATA_READY` notice; `CLOSE` is `OK`; `LISTEN` on 8080 is `OK`, and
//!   the test runner's host client (QEMU `hostfwd` 127.0.0.1:18081 ->
//!   guest 8080) is `ACCEPT`ed and gets [`INBOUND_OCTETS`] echoed back;
//!   `CLOSE` of the socket and the listener are `OK`;
//! - without one, `CONNECT` and `LISTEN` are refused (the engine has no
//!   RFC 6528 key);
//! - `STATUS` of a handle never issued is refused;
//! - the wall clock is published (`get_wallclock` non-zero), which only
//!   net-stack's NTP duty does on x86_64.
//!
//! The DNS query's ID is fixed: this probe only checks that the answer
//! came back through the stack, it never trusts the answer.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_libsys as sys;
use cambios_net_proto as proto;
use net_seam::mapped::{OwnPage, PeerPage};
use net_seam::ByteEndpoint;
use proto::{Address, ConfigReply, ConnectReply, Family, Handle, ListenReply, SockRequest, Status, StatusOnly, StatusReply, TcpState};

cambios_libsys_rt::service_main! {
    name: "NETPROBE",
    endpoint: proto::TEST_CLIENT_ENDPOINT,
    main: run,
}

/// TUNING: how long one request waits for its reply, in 10 ms ticks
/// (net-stack answers an ep 21 send after at most 3 s of ARP).
const REPLY_TICKS: u64 = 500;
/// TUNING: how long net-stack may take to start serving, in ticks
/// (its seam bring-up waits up to 5 s per driver reply).
const START_TICKS: u64 = 2_000;
/// TUNING: how long the DNS answer may take, in ticks.
const ANSWER_TICKS: u64 = 1_000;
/// TUNING: how long NTP may take to publish the clock, in ticks (one
/// query waits 3 s; a failure retries after 60 s, past this bound).
const CLOCK_TICKS: u64 = 1_000;
/// TUNING: the probe's UDP port (IANA dynamic range).
const PORT: u16 = 49_154;
const RESOLVER: [u8; 4] = [10, 0, 2, 3];
const LOCAL: [u8; 4] = [10, 0, 2, 15];

/// TUNING: the echo server's port on the host (the test runner starts it).
const ECHO_PORT: u16 = 18_080;
const HOST: [u8; 4] = [10, 0, 2, 2];
/// TUNING: octets echoed: about 25 times the 16 KiB rings, so both wrap
/// many times and the RX window has to reopen (`Op::Consumed`) over and
/// over; a window that leaks credit stalls well before the end.
const ECHO_OCTETS: usize = 400_000;
/// TUNING: how long the echo may take, in ticks.
const ECHO_TICKS: u64 = 3_000;
/// TUNING: how long the host client may take to connect, in ticks.
const ACCEPT_TICKS: u64 = 1_500;
/// TUNING: octets the host client sends through `hostfwd` and expects back.
const INBOUND_OCTETS: usize = 20_000;
/// HARDWARE: 4 KiB pages.
const PAGE: usize = 4096;

const DNS_ID: u16 = 0x4E50;
const DNS_QUERY: [u8; 29] = [
    0x4E, 0x50, // ID
    0x01, 0x00, // RD
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QD=1
    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    0x00, 0x01, 0x00, 0x01, // A, IN
];

fn ticks() -> u64 {
    u64::try_from(sys::get_time() as i64).unwrap_or(u64::MAX)
}

/// Send `req` to `ep` and wait for the stack's reply into `out`. Only a
/// message the kernel stamped as from net-stack (whose first endpoint
/// is the seam's, 36) counts.
///
/// A `DATA_READY` notice (`[6][sock:4]`: no reply is five octets starting
/// with 6, since a refusal is one octet) is counted in [`NOTICES`]
/// instead.
fn ask(ep: u32, req: &[u8], out: &mut [u8; proto::MAX_MESSAGE]) -> Option<usize> {
    if sys::write(ep, req) < 0 {
        return None;
    }
    let deadline = ticks().saturating_add(REPLY_TICKS);
    let mut buf = [0u8; proto::MAX_MESSAGE];
    while ticks() < deadline {
        if let Some(m) = sys::try_recv_verified(proto::TEST_CLIENT_ENDPOINT, &mut buf) {
            if m.from_endpoint() == proto::SEAM_ENDPOINT {
                let p = m.payload();
                if is_notice(p) {
                    continue;
                }
                let n = p.len().min(out.len());
                out[..n].copy_from_slice(&p[..n]);
                return Some(n);
            }
            continue;
        }
        sys::yield_now();
    }
    None
}

static NOTICES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn is_notice(p: &[u8]) -> bool {
    let notice = p.len() == 5 && p.first() == Some(&proto::NOTICE_DATA_READY);
    if notice {
        NOTICES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    notice
}

/// Take any notices waiting on ep 35.
fn drain_notices() {
    let mut buf = [0u8; proto::MAX_MESSAGE];
    while let Some(m) = sys::try_recv_verified(proto::TEST_CLIENT_ENDPOINT, &mut buf) {
        if m.from_endpoint() == proto::SEAM_ENDPOINT {
            is_notice(m.payload());
        }
    }
}

fn check(name: &[u8], ok: bool, passed: &mut u32, total: &mut u32) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    sys::print(b"[NETPROBE] ");
    sys::print(name);
    sys::print(if ok { b": ok\n" } else { b": FAIL\n" });
}

fn sock(req: SockRequest, out: &mut [u8; proto::MAX_MESSAGE]) -> Option<usize> {
    let mut r = [0u8; proto::MAX_MESSAGE];
    let n = req.encode(&mut r).ok()?;
    ask(proto::TCP_ENDPOINT, &r[..n], out)
}

fn run() -> ! {
    let (mut passed, mut total) = (0u32, 0u32);
    let mut rep = [0u8; proto::MAX_MESSAGE];

    // net-stack registers ep 21 only after its seam is up, so the first
    // request may find no endpoint yet: retry it for a while.
    let started = ticks();
    let deadline = started.saturating_add(START_TICKS);
    let mut attempts = 1u64;
    let mut r = ask(proto::UDP_ENDPOINT, &[3], &mut rep);
    while r.is_none() && ticks() < deadline {
        sys::yield_now();
        attempts += 1;
        r = ask(proto::UDP_ENDPOINT, &[3], &mut rep);
    }
    let ok = r == Some(11) && rep[0] == 0 && rep[1..5] == LOCAL;
    check(b"ep21 GET_CONFIG reports 10.0.2.15", ok, &mut passed, &mut total);
    if !ok {
        // codex 2026-11-12 (s14b-2): tell no reply from a wrong reply or a
        // starved probe. Reply bytes: [status][ip:4][mac:6].
        sys::print(b"[NETPROBE] diag GET_CONFIG attempts=");
        print_dec(attempts);
        sys::print(b" ticks=");
        print_dec(started);
        sys::print(b"..");
        print_dec(ticks());
        match r {
            None => sys::print(b" reply=none\n"),
            Some(n) => {
                sys::print(b" len=");
                print_dec(n as u64);
                sys::print(b" bytes=");
                for b in rep.iter().take(n.min(11)) {
                    print_dec(u64::from(*b));
                    sys::print(b",");
                }
                sys::print(b"\n");
            }
        }
    }

    let recv = [2, (PORT >> 8) as u8, PORT as u8];
    let r = ask(proto::UDP_ENDPOINT, &recv, &mut rep);
    check(b"ep21 UDP_RECV on a fresh port is NO_DATA", r == Some(1) && rep[0] == 2, &mut passed, &mut total);

    let mut send = [0u8; 9 + DNS_QUERY.len()];
    send[0] = 1;
    send[1..5].copy_from_slice(&RESOLVER);
    send[5..7].copy_from_slice(&53u16.to_be_bytes());
    send[7..9].copy_from_slice(&PORT.to_be_bytes());
    send[9..].copy_from_slice(&DNS_QUERY);
    let r = ask(proto::UDP_ENDPOINT, &send, &mut rep);
    check(b"ep21 UDP_SEND of a DNS query is OK", r == Some(1) && rep[0] == 0, &mut passed, &mut total);

    let deadline = ticks().saturating_add(ANSWER_TICKS);
    let mut answered = false;
    while !answered && ticks() < deadline {
        if let Some(n) = ask(proto::UDP_ENDPOINT, &recv, &mut rep) {
            let ours = n >= 7 + 12 && rep[0] == 0 && rep[1..5] == RESOLVER && rep[5..7] == 53u16.to_be_bytes();
            answered = ours && u16::from_be_bytes([rep[7], rep[8]]) == DNS_ID && rep[9] & 0x80 != 0;
        }
        if !answered {
            for _ in 0..10 {
                sys::yield_now();
            }
        }
    }
    check(b"ep21 UDP_RECV returns the resolver's answer", answered, &mut passed, &mut total);

    let r = ask(proto::UDP_ENDPOINT, &[4, 10, 0, 2, 99, 10, 0, 2, 2, 255, 255, 255, 0], &mut rep);
    check(b"ep21 SET_CONFIG is ERROR", r == Some(1) && rep[0] == 1, &mut passed, &mut total);

    let ok = sock(SockRequest::GetConfig { family: Family::V4 }, &mut rep)
        .and_then(|n| ConfigReply::decode(&rep[..n]).ok())
        .is_some_and(|c| c.status == Status::Ok && c.address == Address::V4(LOCAL) && c.prefix_len == 24);
    check(b"ep34 GET_CONFIG reports 10.0.2.15/24", ok, &mut passed, &mut total);

    // The same kernel source the stack keys TCP from.
    let keyed = sys::get_entropy(&mut [0u8; 1]) == 1;
    if keyed {
        tcp_echo(&mut rep, &mut passed, &mut total);
        let listener = sock(SockRequest::Listen { port: 8080 }, &mut rep)
            .and_then(|n| ListenReply::decode(&rep[..n]).ok())
            .filter(|l| l.status == Status::Ok)
            .map(|l| l.listener);
        check(b"ep34 LISTEN is OK (TCP keyed)", listener.is_some(), &mut passed, &mut total);
        if let Some(h) = listener {
            tcp_accept(h, &mut rep, &mut passed, &mut total);
        }
        let closed = listener.is_some_and(|h| close(h, &mut rep));
        check(b"ep34 CLOSE of the listener is OK", closed, &mut passed, &mut total);
    } else {
        let refused = sock(SockRequest::Connect { remote: Address::V4(HOST), port: ECHO_PORT }, &mut rep)
            .and_then(|n| ConnectReply::decode(&rep[..n]).ok())
            .is_some_and(|c| c.status != Status::Ok);
        check(b"ep34 CONNECT is refused (no hardware RNG)", refused, &mut passed, &mut total);

        let refused = sock(SockRequest::Listen { port: 8080 }, &mut rep)
            .and_then(|n| ListenReply::decode(&rep[..n]).ok())
            .is_some_and(|l| l.status != Status::Ok);
        check(b"ep34 LISTEN is refused (no hardware RNG)", refused, &mut passed, &mut total);
    }

    let refused = sock(SockRequest::Status { sock: Handle(0x0001_0000) }, &mut rep)
        .and_then(|n| StatusReply::decode(&rep[..n]).ok())
        .is_some_and(|s| s.status != Status::Ok);
    check(b"ep34 STATUS of an unissued handle is refused", refused, &mut passed, &mut total);

    let deadline = ticks().saturating_add(CLOCK_TICKS);
    while sys::get_wallclock() == 0 && ticks() < deadline {
        sys::yield_now();
    }
    check(b"wall clock published (NTP)", sys::get_wallclock() != 0, &mut passed, &mut total);

    sys::print(if passed == total { b"[NETPROBE] PASS " } else { b"[NETPROBE] FAIL " });
    sys::print(&[b'0' + (passed / 10 % 10) as u8, b'0' + (passed % 10) as u8, b'/', b'0' + (total / 10 % 10) as u8, b'0' + (total % 10) as u8, b'\n']);
    sys::exit(if passed == total { 0 } else { 1 });
}

fn close(h: Handle, rep: &mut [u8; proto::MAX_MESSAGE]) -> bool {
    sock(SockRequest::Close { handle: h }, rep).and_then(|n| StatusOnly::decode(&rep[..n]).ok()) == Some(StatusOnly(Status::Ok))
}

fn status(h: Handle, rep: &mut [u8; proto::MAX_MESSAGE]) -> Option<StatusReply> {
    sock(SockRequest::Status { sock: h }, rep).and_then(|n| StatusReply::decode(&rep[..n]).ok())
}

/// The octet at `i` of the echo payload.
fn echo_byte(i: usize) -> u8 {
    (i as u8).wrapping_mul(31).wrapping_add((i >> 8) as u8)
}

/// Attach one stream channel; its mapping, `STREAM_PAGES` + 1 pages.
fn attach(chan: u64) -> Option<(*mut u8, usize)> {
    let v = sys::channel_attach(chan);
    if v <= 0 {
        return None;
    }
    Some((v as usize as *mut u8, (proto::STREAM_PAGES as usize + 1) * PAGE))
}

/// Attach a socket's two stream channels and initialise our TX ring.
#[allow(unsafe_code)] // The two page wraps below; each block is one call with its own SAFETY.
fn open_ring(tx_chan: u64, rx_chan: u64) -> Option<(OwnPage, PeerPage, ByteEndpoint)> {
    let ((tx, tx_len), (rx, rx_len)) = attach(tx_chan).zip(attach(rx_chan))?;
    // SAFETY: the TX channel was created by net-stack as `Consumer` with
    // this process's AID as peer, so this attach maps it writable here and
    // read-only there; `len` is the size both ends use (`STREAM_PAGES` +
    // 1 pages), zero-filled by the kernel; this `OwnPage` is its only
    // writer and no slice over it is ever formed.
    let mut own = unsafe { OwnPage::from_raw(tx, tx_len) }?;
    // SAFETY: the RX channel was created as `Producer`, so this mapping is
    // read-only here; after a revoke it is the zero tombstone. No slice
    // over it is ever formed.
    let peer = unsafe { PeerPage::from_raw(rx, rx_len) }?;
    let ep = ByteEndpoint::new(&mut own, proto::STREAM_PAGES * PAGE as u32).ok()?;
    Some((own, peer, ep))
}

fn doorbell(sock: Handle) {
    let mut d = [0u8; proto::MAX_MESSAGE];
    if let Ok(len) = (SockRequest::Doorbell { sock }).encode(&mut d) {
        sys::write(proto::TCP_ENDPOINT, &d[..len]);
    }
}

/// ACCEPT the host client's connection on `listener` (QEMU `hostfwd`
/// 127.0.0.1:18081 -> guest 8080, opened by the test runner) and echo
/// [`INBOUND_OCTETS`] back to it; the client checks the bytes.
fn tcp_accept(listener: Handle, rep: &mut [u8; proto::MAX_MESSAGE], passed: &mut u32, total: &mut u32) {
    let deadline = ticks().saturating_add(ACCEPT_TICKS);
    let mut acc = None;
    while acc.is_none() && ticks() < deadline {
        acc = sock(SockRequest::Accept { listener }, rep)
            .and_then(|n| proto::AcceptReply::decode(&rep[..n]).ok())
            .filter(|a| a.status == Status::Ok && a.tx_chan != 0 && a.rx_chan != 0);
        if acc.is_none() {
            for _ in 0..10 {
                sys::yield_now();
            }
        }
    }
    check(b"ep34 ACCEPT hands out two stream channels (host client via hostfwd)", acc.is_some_and(|a| a.peer == Address::V4(HOST)), passed, total);
    let Some(a) = acc else { return };
    let ring = open_ring(a.tx_chan, a.rx_chan);
    let Some((mut own, peer, mut ep)) = ring else {
        check(b"accepted stream channels attach", false, passed, total);
        let _ = close(a.sock, rep);
        return;
    };
    // Echo: whatever comes in goes straight back out.
    let mut buf = [0u8; 1024];
    let (mut held, mut got, mut back) = (0usize, 0usize, 0usize);
    let deadline = ticks().saturating_add(ECHO_TICKS);
    while back < INBOUND_OCTETS && ticks() < deadline {
        let mut moved = false;
        if held == 0 {
            if let Ok(r) = ep.read(&mut own, &peer, &mut buf) {
                held = r;
                got += r;
                moved = true;
            }
        }
        if held > 0 {
            if let Ok(w) = ep.write(&mut own, &peer, &buf[..held]) {
                buf.copy_within(w..held, 0);
                held -= w;
                back += w;
                moved = true;
                doorbell(a.sock);
            }
        }
        drain_notices();
        if !moved {
            sys::yield_now();
        }
    }
    check(b"20000 inbound octets echoed back to the host client", got == INBOUND_OCTETS && back == INBOUND_OCTETS, passed, total);
    // Let the last octets leave before the close.
    let deadline = ticks().saturating_add(REPLY_TICKS);
    while status(a.sock, rep).is_some_and(|s| s.tx_free < proto::STREAM_PAGES * PAGE as u32) && ticks() < deadline {
        sys::yield_now();
    }
    check(b"ep34 CLOSE of the accepted socket is OK", close(a.sock, rep), passed, total);
}

/// CONNECT to the host echo server and push `ECHO_OCTETS` through it.
fn tcp_echo(rep: &mut [u8; proto::MAX_MESSAGE], passed: &mut u32, total: &mut u32) {
    let reply = sock(SockRequest::Connect { remote: Address::V4(HOST), port: ECHO_PORT }, rep)
        .and_then(|n| ConnectReply::decode(&rep[..n]).ok())
        .filter(|c| c.status == Status::Ok && c.tx_chan != 0 && c.rx_chan != 0);
    check(b"ep34 CONNECT to 10.0.2.2:18080 hands out two stream channels", reply.is_some(), passed, total);
    let Some(c) = reply else { return };

    let ring = open_ring(c.tx_chan, c.rx_chan);
    check(b"stream channels attach and the TX ring initialises", ring.is_some(), passed, total);
    let Some((mut own, peer, mut ep)) = ring else {
        let _ = close(c.sock, rep);
        return;
    };

    let deadline = ticks().saturating_add(ANSWER_TICKS);
    let mut st = status(c.sock, rep);
    while st.is_some_and(|s| s.state != TcpState::Established) && ticks() < deadline {
        sys::yield_now();
        st = status(c.sock, rep);
    }
    check(b"ep34 STATUS reaches ESTABLISHED", st.is_some_and(|s| s.status == Status::Ok && s.state == TcpState::Established), passed, total);

    let (mut sent, mut got, mut same) = (0usize, 0usize, true);
    let mut chunk = [0u8; 1024];
    let deadline = ticks().saturating_add(ECHO_TICKS);
    let mut next_report = ticks().saturating_add(200);
    while got < ECHO_OCTETS && ticks() < deadline {
        let mut moved = false;
        if sent < ECHO_OCTETS {
            let n = chunk.len().min(ECHO_OCTETS - sent);
            for (k, b) in chunk[..n].iter_mut().enumerate() {
                *b = echo_byte(sent + k);
            }
            if let Ok(w) = ep.write(&mut own, &peer, &chunk[..n]) {
                if w > 0 {
                    sent += w;
                    moved = true;
                    doorbell(c.sock);
                }
            }
        }
        if let Ok(r) = ep.read(&mut own, &peer, &mut chunk) {
            for (k, b) in chunk[..r].iter().enumerate() {
                same &= *b == echo_byte(got + k);
            }
            got += r;
            moved = true;
        }
        drain_notices();
        if ticks() >= next_report {
            next_report = ticks().saturating_add(200);
            sys::print(b"[NETPROBE] echo progress sent=");
            print_dec(sent as u64);
            sys::print(b" got=");
            print_dec(got as u64);
            sys::print(b"\n");
        }
        if !moved {
            sys::yield_now();
        }
    }
    check(b"400000 octets echoed back through the rings unchanged", got == ECHO_OCTETS && same, passed, total);
    check(b"DATA_READY notices arrived on ep 35", NOTICES.load(core::sync::atomic::Ordering::Relaxed) > 0, passed, total);
    check(b"ep34 CLOSE of the socket is OK", close(c.sock, rep), passed, total);
}

fn print_dec(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    sys::print(&buf[i..]);
}
