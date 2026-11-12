// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The stack side of the ADR-039 § 2 NIC seam.
//!
//! Hand-off, in the ADR's order: ask the driver `GET_MAC` on ep 20 and
//! read its AID off the kernel-stamped reply; create the TX channel as
//! `Producer` (we write, the driver maps it read-only) and the RX channel
//! as `Consumer` (the driver writes, our mapping is read-only), both with
//! that AID as peer; initialise our TX control page; send `OPEN_SEAM`.
//! Every later reply on ep 36 is accepted only from the same AID.
//!
//! # Driver death
//!
//! Our TX page is writable here. If the driver dies the kernel revokes
//! both channels: the read-only RX mapping becomes the zero tombstone
//! (the ring then reads `PeerGone`), and the writable TX mapping is
//! remapped to this process's own scratch frame (ADR-039 § 9, ADR-007
//! Divergence 8), so a write racing the revoke sinks instead of
//! faulting. build1-3571 showed both kernels side by side.

use cambios_libsys as sys;
use cambios_net_proto as proto;
use net_seam::mapped::{OwnPage, PeerPage};
use net_seam::{layout, Endpoint, RingError, MAX_FRAME};

/// HARDWARE: CambiOS user mappings are 4 KiB pages.
const PAGE_SIZE: usize = 4096;

/// TUNING: slots per seam ring (ADR-039 § 8 `SEAM_SLOTS`): 1 ms of 1 GbE
/// line rate is 81 frames, 25%-rule → 324, next power of two.
pub const SEAM_SLOTS: u32 = 512;

/// ARCHITECTURAL: `channel_create` roles (libsys `channel_create` docs).
const ROLE_PRODUCER: u32 = 0;
const ROLE_CONSUMER: u32 = 1;

/// TUNING: how long the stack waits for one ep 20 reply before giving
/// up on the driver, in 10 ms kernel ticks (5 s). The driver answers
/// from its service loop; seconds of silence mean it is not serving.
const REPLY_TIMEOUT_TICKS: u64 = 500;

/// The kernel clock in 10 ms ticks, or `None` when `get_time` was
/// refused: the syscall returns a negative error code, which read as a
/// `u64` would be a time far in the future and make every deadline
/// unreachable.
pub fn ticks() -> Option<u64> {
    u64::try_from(sys::get_time() as i64).ok()
}

/// Why bring-up failed. Each is printed and the stack stops; nothing is
/// retried behind the operator's back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// The driver did not answer within `REPLY_TIMEOUT_TICKS`.
    NoReply,
    /// The driver answered with a non-`Ok` status (e.g. `NO_DEVICE`).
    Refused(proto::Status),
    /// The reply did not decode.
    Malformed,
    /// `get_time` was refused, so no wait can be bounded.
    Clock,
    /// `channel_create` failed (no `create-channel` grant, no memory).
    Create,
    /// A mapping was unusable or the control page would not initialise.
    Page,
}

/// An open seam: the two mappings, our ring end, and the driver's AID.
pub struct Seam {
    pub driver: sys::Principal,
    pub mac: [u8; 6],
    tx_chan: u64,
    rx_chan: u64,
    own: OwnPage,
    peer: PeerPage,
    ep: Endpoint,
    /// A frame went into the TX ring since the last doorbell.
    tx_pending: bool,
}

/// What one RX poll produced.
pub enum Rx {
    Frame(usize),
    Empty,
    /// The driver's page reads as the tombstone: it is gone.
    Dead,
    /// The driver broke the ring protocol past `PEER_VIOLATION_LIMIT`, or
    /// its control block is invalid: drop it with [`Seam::drop_untrusted`].
    Untrusted,
}

/// Wait for one ep 36 message; `from` restricts the sender once the
/// driver's AID is known. Messages from anyone else are dropped and
/// counted in `ignored`. Returns the payload length copied into `out`.
///
/// Only bring-up waits for replies, before any seam is open, so a
/// driver doorbell (`DOORBELL_RX = 7`, the same byte as `BAD_STATE`)
/// cannot arrive here to be misread as a reply.
fn await_reply(from: Option<&sys::Principal>, out: &mut [u8], ignored: &mut u32) -> Result<(sys::Principal, usize), BringUpError> {
    let mut buf = [0u8; proto::MAX_MESSAGE];
    let deadline = ticks().ok_or(BringUpError::Clock)?.saturating_add(REPLY_TIMEOUT_TICKS);
    loop {
        if let Some(msg) = sys::try_recv_verified(proto::SEAM_ENDPOINT, &mut buf) {
            let sender = *msg.sender();
            // Before the driver's AID is known, only a message the kernel
            // stamped as coming from ep 20 is the driver's: ep 20 is
            // reserved to the driver's AID in the manifest, and
            // `from_endpoint` is the sender's first registered endpoint.
            // (The kernel falls back to the process slot number for a
            // sender with no endpoint at all, so a process in slot 20 that
            // registered nothing could pass this check; it would then be
            // the seam's peer and see only the frames it was sent.
            // Revisit when: the kernel offers endpoint-owner lookup.)
            let wanted = match from {
                Some(f) => *f == sender,
                None => msg.from_endpoint() == proto::NIC_ENDPOINT,
            };
            if wanted {
                let p = msg.payload();
                let n = p.len().min(out.len());
                if let (Some(dst), Some(src)) = (out.get_mut(..n), p.get(..n)) {
                    dst.copy_from_slice(src);
                }
                return Ok((sender, n));
            }
            *ignored = ignored.saturating_add(1);
            continue;
        }
        if ticks().is_none_or(|t| t >= deadline) {
            return Err(BringUpError::NoReply);
        }
        sys::yield_now();
    }
}

/// Create one channel with `peer` as the peer; returns (id, base, len).
fn create(pages: u32, peer: &sys::Principal, role: u32) -> Result<(u64, *mut u8, usize), BringUpError> {
    let mut vaddr: u64 = 0;
    let rc = sys::channel_create(pages, peer.as_bytes(), role, &mut vaddr);
    if rc < 0 || vaddr == 0 {
        return Err(BringUpError::Create);
    }
    let len = usize::try_from(pages).ok().and_then(|p| p.checked_mul(PAGE_SIZE)).ok_or(BringUpError::Page)?;
    Ok((rc as u64, vaddr as usize as *mut u8, len))
}

impl Seam {
    /// Run the ADR-039 § 2 hand-off with the driver on ep 20.
    #[allow(unsafe_code)] // The two page wraps below; each block is one call with its own SAFETY.
    pub fn bring_up(ignored: &mut u32) -> Result<Seam, BringUpError> {
        let mut req = [0u8; proto::MAX_MESSAGE];
        let mut rep = [0u8; proto::MAX_MESSAGE];

        let n = proto::NicRequest::GetMac.encode(&mut req).map_err(|_| BringUpError::Malformed)?;
        sys::write(proto::NIC_ENDPOINT, req.get(..n).unwrap_or(&[]));
        let (driver, n) = await_reply(None, &mut rep, ignored)?;
        let mac = match proto::MacReply::decode(rep.get(..n).unwrap_or(&[])) {
            Ok(r) if r.status == proto::Status::Ok => r.mac,
            Ok(r) => return Err(BringUpError::Refused(r.status)),
            Err(_) => return Err(BringUpError::Malformed),
        };

        let ring_len = (SEAM_SLOTS as usize).checked_mul(layout::SLOT_SIZE).and_then(|b| b.checked_add(layout::CONTROL_LEN)).ok_or(BringUpError::Page)?;
        let pages = u32::try_from(ring_len.div_ceil(PAGE_SIZE)).map_err(|_| BringUpError::Page)?;
        let (tx_chan, tx_base, tx_len) = create(pages, &driver, ROLE_PRODUCER)?;
        let (rx_chan, rx_base, rx_len) = match create(pages, &driver, ROLE_CONSUMER) {
            Ok(r) => r,
            Err(e) => {
                sys::channel_close(tx_chan);
                return Err(e);
            }
        };
        let fail = |e| {
            sys::channel_close(tx_chan);
            sys::channel_close(rx_chan);
            Err(e)
        };
        // SAFETY: `tx_base` is this process's writable mapping of the TX
        // channel we just created as `Producer`, `tx_len` octets
        // (`pages` × 4 KiB, the size we asked for), zero-filled by the
        // kernel; the driver maps it read-only; this `OwnPage` is its only
        // writer here and no slice over it is ever formed. It stays mapped
        // until `close` (or a driver-death revoke: the residual risk in
        // the module docs).
        let Some(mut own) = (unsafe { OwnPage::from_raw(tx_base, tx_len) }) else {
            return fail(BringUpError::Page);
        };
        // SAFETY: `rx_base` is this process's read-only mapping of the RX
        // channel we just created as `Consumer`, `rx_len` octets, zero-
        // filled; after a revoke it is the kernel's zero tombstone, which
        // the ring reads as `PeerGone`. No slice over it is ever formed.
        let Some(peer) = (unsafe { PeerPage::from_raw(rx_base, rx_len) }) else {
            return fail(BringUpError::Page);
        };
        let Ok(ep) = Endpoint::new(&mut own, SEAM_SLOTS) else {
            return fail(BringUpError::Page);
        };

        let Ok(n) = (proto::NicRequest::OpenSeam { tx_chan, rx_chan }).encode(&mut req) else {
            return fail(BringUpError::Malformed);
        };
        sys::write(proto::NIC_ENDPOINT, req.get(..n).unwrap_or(&[]));
        let n = match await_reply(Some(&driver), &mut rep, ignored) {
            Ok((_, n)) => n,
            Err(e) => return fail(e),
        };
        match proto::StatusOnly::decode(rep.get(..n).unwrap_or(&[])) {
            Ok(proto::StatusOnly(proto::Status::Ok)) => {}
            Ok(proto::StatusOnly(s)) => return fail(BringUpError::Refused(s)),
            Err(_) => return fail(BringUpError::Malformed),
        }
        Ok(Seam { driver, mac, tx_chan, rx_chan, own, peer, ep, tx_pending: false })
    }

    /// Take the next frame the driver queued.
    pub fn recv(&mut self, out: &mut [u8; MAX_FRAME]) -> Rx {
        // Bounded: a run of skipped slots ends this call as `Empty`; the
        // next pass resumes. The ring caps the run at `SEAM_SLOTS`.
        for _ in 0..SEAM_SLOTS {
            match self.ep.recv(&mut self.own, &self.peer, out) {
                Ok(n) => return Rx::Frame(n),
                Err(RingError::Empty) => return Rx::Empty,
                // The bad slot or span was skipped and counted; go on.
                Err(RingError::Malformed | RingError::Resynced) => {}
                Err(RingError::PeerGone) => return Rx::Dead,
                Err(RingError::PeerUntrusted | RingError::PeerMalformed) => return Rx::Untrusted,
                Err(_) => return Rx::Empty,
            }
        }
        Rx::Empty
    }

    /// Queue one frame for the driver. `false`: the ring is full or dead
    /// and the frame was dropped (Ethernet tolerates loss; TCP retransmits).
    pub fn send(&mut self, frame: &[u8]) -> bool {
        let ok = self.ep.send(&mut self.own, &self.peer, frame).is_ok();
        self.tx_pending |= ok;
        ok
    }

    /// Ring the driver's doorbell once if anything went in since the last.
    pub fn flush(&mut self) {
        if core::mem::take(&mut self.tx_pending) {
            sys::write(proto::NIC_ENDPOINT, &[proto::NIC_DOORBELL_TX]);
        }
    }

    /// Drop a driver that broke the ring protocol (ADR-039 § 4). Its
    /// control page lives on the RX channel, so that close carries the
    /// peer-violation reason and the kernel emits `chan.peer_violation`
    /// naming the driver; the TX close is ordinary. No `CLOSE_SEAM`: a
    /// liar is not waited on.
    pub fn drop_untrusted(self) {
        sys::channel_close_peer_violation(self.rx_chan);
        sys::channel_close(self.tx_chan);
    }

    /// The driver is gone (its page reads as the tombstone): drop both
    /// channels. Nothing is asked of a dead driver.
    pub fn drop_dead(self) {
        sys::channel_close(self.tx_chan);
        sys::channel_close(self.rx_chan);
    }
}
