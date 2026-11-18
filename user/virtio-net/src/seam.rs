// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The driver side of the ADR-039 § 2 NIC seam: frames in a channel
//! pair, control on ep 20.
//!
//! The stack creates both channels with this driver's AID as peer and
//! sends `OPEN_SEAM [tx_chan:8][rx_chan:8]`. The TX channel is the
//! stack's (`Producer`: the stack writes, this driver maps it read-only);
//! the RX channel is ours to write (the stack created it as `Consumer`,
//! so the peer mapping, ours, is the writable one). Each side publishes
//! its indices in the page it owns, so neither ever writes the other's
//! page. The ring protocol and its hostile-peer rules are
//! `user/net-seam`'s; this module only attaches, wraps and pumps.
//!
//! Exactly one seam at a time: a second `OPEN_SEAM` is `BUSY`, and the
//! seam remembers the AID that opened it, so a different AID's
//! `CLOSE_SEAM` or `DOORBELL_TX` is `DENIED`.
//!
//! # Stack death
//!
//! The RX page is mapped writable here. If the stack dies, the kernel
//! revokes the channel and remaps that page to this driver's own scratch
//! frame (ADR-007 Divergence entry 8, ADR-039 § 9), so a write racing the
//! revoke sinks instead of faulting the driver. The dead stack is
//! noticed through the TX page (read-only, now the all-zero tombstone:
//! `PeerGone`) and the seam is dropped.

use cambios_libsys as sys;
use cambios_net_proto as proto;
use cambios_net_proto::SEAM_DOORBELL_RX;
use net_seam::mapped::{OwnPage, PeerPage};
use net_seam::{layout, Endpoint, RingError, MAX_FRAME};

/// HARDWARE: CambiOS user mappings are 4 KiB pages; `channel_info`
/// reports a channel's size in them.
const PAGE_SIZE: usize = 4096;

/// ARCHITECTURAL: the `channel_info` descriptor is 46 bytes; the page
/// count is the little-endian `u32` at bytes 2..6
/// (`SyscallDispatcher::handle_channel_info`).
const CHANNEL_INFO_LEN: usize = 46;

/// An open seam.
pub struct Seam {
    /// The AID that opened it; only it may close it or ring.
    stack: sys::Principal,
    tx_chan: u64,
    rx_chan: u64,
    /// The stack's TX page (read-only here).
    peer: PeerPage,
    /// Our RX page.
    own: OwnPage,
    ep: Endpoint,
}

/// Why `OPEN_SEAM` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// `channel_attach` refused (wrong peer, stale id, …).
    Attach,
    /// `channel_info` failed or reported an unusable size.
    Info,
    /// The mapping was null, misaligned or too small for any ring.
    Page,
}

/// Why the pump dropped the seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// The stack's page reads as the tombstone: it is gone.
    PeerGone,
    /// The stack broke the ring protocol past the violation limit, or its
    /// control block is invalid.
    PeerUntrusted,
}

/// The largest power-of-two slot count a page of `len` octets holds.
fn slot_count_for(len: usize) -> Option<u32> {
    let slots = len.checked_sub(layout::CONTROL_LEN)?.checked_div(layout::SLOT_SIZE)?;
    let slots = u32::try_from(slots).ok()?;
    if slots == 0 {
        return None;
    }
    // Round down to a power of two: keep the highest set bit.
    Some(1u32 << (31u32.saturating_sub(slots.leading_zeros())))
}

/// Attach one channel; returns its base and length in octets.
fn attach(chan: u64) -> Result<(*mut u8, usize), OpenError> {
    let rc = sys::channel_attach(chan);
    if rc <= 0 {
        return Err(OpenError::Attach);
    }
    let mut info = [0u8; CHANNEL_INFO_LEN];
    if sys::channel_info(chan, &mut info) != 0 {
        return Err(OpenError::Info);
    }
    let pages = info.get(2..6).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_le_bytes).ok_or(OpenError::Info)?;
    let len = usize::try_from(pages).ok().and_then(|p| p.checked_mul(PAGE_SIZE)).ok_or(OpenError::Info)?;
    Ok((rc as usize as *mut u8, len))
}

impl Seam {
    /// Attach both channels the stack offered and initialise our RX page.
    /// On failure every channel this call attached is closed again, so a
    /// failed open leaves no mapping behind.
    #[allow(unsafe_code)] // The two page wraps below; each block is one call with its own SAFETY.
    pub fn open(stack: sys::Principal, tx_chan: u64, rx_chan: u64) -> Result<Seam, OpenError> {
        let (tx_base, tx_len) = attach(tx_chan)?;
        let (rx_base, rx_len) = match attach(rx_chan) {
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
        // SAFETY: `tx_base` is this process's mapping of the TX channel,
        // just returned by `channel_attach`, `tx_len` octets long as the
        // kernel reports through `channel_info`; it stays mapped until
        // this seam closes the channel (or the kernel revokes it, which
        // leaves the read-only tombstone, read as `PeerGone`).
        let Some(peer) = (unsafe { PeerPage::from_raw(tx_base, tx_len) }) else {
            return fail(OpenError::Page);
        };
        // SAFETY: `rx_base` is this process's writable mapping of the RX
        // channel, just returned by `channel_attach`, `rx_len` octets long
        // per `channel_info`; it stays mapped until this seam closes the
        // channel. Revocation by the kernel is the residual risk named in
        // the module docs.
        let Some(mut own) = (unsafe { OwnPage::from_raw(rx_base, rx_len) }) else {
            return fail(OpenError::Page);
        };
        let Some(slots) = slot_count_for(rx_len) else {
            return fail(OpenError::Page);
        };
        let Ok(ep) = Endpoint::new(&mut own, slots) else {
            return fail(OpenError::Page);
        };
        Ok(Seam { stack, tx_chan, rx_chan, peer, own, ep })
    }

    pub fn opened_by(&self, principal: &sys::Principal) -> bool {
        self.stack == *principal
    }

    /// Close both channels (both mappings go away).
    pub fn close(self) {
        sys::channel_close(self.tx_chan);
        sys::channel_close(self.rx_chan);
    }

    /// Close both channels after the stack broke the ring protocol
    /// (ADR-039 § 4). The stack's control page lives on the TX channel,
    /// so that close carries the peer-violation reason and the kernel
    /// emits `chan.peer_violation` naming the stack; the RX close is
    /// ordinary.
    pub fn close_untrusted(self) {
        sys::channel_close_peer_violation(self.tx_chan);
        sys::channel_close(self.rx_chan);
    }

    /// Take frames the stack queued and hand each to `transmit`, at most
    /// `budget` per call. `Err` means the seam must be dropped.
    pub fn pump_tx(&mut self, budget: usize, mut transmit: impl FnMut(&[u8])) -> Result<(), Dropped> {
        let mut frame = [0u8; MAX_FRAME];
        for _ in 0..budget {
            match self.ep.recv(&mut self.own, &self.peer, &mut frame) {
                Ok(n) => {
                    if let Some(f) = frame.get(..n) {
                        transmit(f);
                    }
                }
                Err(RingError::Empty) => return Ok(()),
                // The bad slot or span was skipped and counted; go on.
                Err(RingError::Malformed | RingError::Resynced) => {}
                Err(RingError::PeerGone) => return Err(Dropped::PeerGone),
                Err(RingError::PeerUntrusted | RingError::PeerMalformed) => return Err(Dropped::PeerUntrusted),
                // `frame` is MAX_FRAME long and the ring never carries
                // more, so the rest cannot happen; stop this pass.
                Err(_) => return Ok(()),
            }
        }
        Ok(())
    }

    /// Queue received frames from `next` (which fills the buffer and
    /// returns the frame length, 0 when the device has nothing) for the
    /// stack, at most `budget` per call, and ring the stack's doorbell
    /// once if any went in. A full ring drops the frame (the stack is
    /// behind; Ethernet tolerates loss). `Err` means drop the seam.
    pub fn pump_rx(&mut self, budget: usize, mut next: impl FnMut(&mut [u8]) -> usize) -> Result<(), Dropped> {
        let mut frame = [0u8; MAX_FRAME];
        let mut queued = false;
        for _ in 0..budget {
            let n = next(&mut frame);
            let Some(f) = frame.get(..n).filter(|f| !f.is_empty()) else {
                break;
            };
            match self.ep.send(&mut self.own, &self.peer, f) {
                Ok(()) => queued = true,
                Err(RingError::Full) => {}
                Err(RingError::PeerGone) => return Err(Dropped::PeerGone),
                Err(RingError::PeerUntrusted | RingError::PeerMalformed) => return Err(Dropped::PeerUntrusted),
                Err(_) => {}
            }
        }
        if queued {
            sys::write(cambios_net_proto::SEAM_ENDPOINT, &[SEAM_DOORBELL_RX]);
        }
        Ok(())
    }
}

/// `OPEN_SEAM` / `CLOSE_SEAM` / `DOORBELL_TX` (ADR-039 § 2). Returns the
/// reply length, or `None` for the doorbell, which has no reply.
pub fn handle_command(
    seam: &mut Option<Seam>,
    sender: &sys::Principal,
    payload: &[u8],
    response: &mut [u8],
) -> Option<usize> {
    let status = match proto::NicRequest::decode(payload) {
        Ok(proto::NicRequest::OpenSeam { tx_chan, rx_chan }) => match seam {
            Some(_) => proto::Status::Busy,
            None => match Seam::open(*sender, tx_chan, rx_chan) {
                Ok(s) => {
                    *seam = Some(s);
                    sys::print(b"[NIC] seam open\n");
                    proto::Status::Ok
                }
                Err(_) => proto::Status::Error,
            },
        },
        Ok(proto::NicRequest::CloseSeam) => match seam.take() {
            Some(s) if s.opened_by(sender) => {
                s.close();
                proto::Status::Ok
            }
            Some(s) => {
                *seam = Some(s);
                proto::Status::Denied
            }
            None => proto::Status::BadState,
        },
        Ok(proto::NicRequest::DoorbellTx) => match seam {
            // The ring is drained on every pass while a seam is open;
            // the doorbell only wakes the loop, so it needs no work.
            Some(s) if s.opened_by(sender) => return None,
            Some(_) => proto::Status::Denied,
            None => proto::Status::BadState,
        },
        _ => proto::Status::Error,
    };
    proto::StatusOnly(status).encode(response).ok()
}

/// What a driver's device does for the seam.
pub trait Nic {
    /// Put one frame on the wire (best effort; a failure drops it).
    fn transmit(&mut self, frame: &[u8]);
    /// Copy the next received frame into `buf`; its length, 0 for none.
    fn receive(&mut self, buf: &mut [u8]) -> usize;
}

/// One pass of a driver's seam duty: move up to `tx_budget` frames from
/// the stack to the device, then up to `rx_budget` received frames from
/// the device to the stack. A broken seam is reported and dropped, and
/// the driver goes back to waiting for an `OPEN_SEAM`.
pub fn service(seam: &mut Option<Seam>, nic: &mut impl Nic, tx_budget: usize, rx_budget: usize) {
    let Some(s) = seam.as_mut() else { return };
    let pumped = s
        .pump_tx(tx_budget, |frame| nic.transmit(frame))
        .and_then(|()| s.pump_rx(rx_budget, |buf| nic.receive(buf)));
    if let Err(why) = pumped {
        sys::print(match why {
            Dropped::PeerGone => b"[NIC] seam closed: stack gone\n",
            Dropped::PeerUntrusted => b"[NIC] seam closed: stack broke the ring protocol\n",
        });
        if let Some(s) = seam.take() {
            match why {
                Dropped::PeerGone => s.close(),
                Dropped::PeerUntrusted => s.close_untrusted(),
            }
        }
    }
}
