// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Virtio-Net Driver — user-space network device driver
//!
//! Runs as a ring-3 process. Discovers the virtio-net PCI device via the
//! DeviceInfo syscall, initializes the legacy virtio transport, sets up
//! TX and RX virtqueues with DMA bounce buffers, and exposes a packet
//! send/receive interface over IPC.
//!
//! ## Hostile device model
//!
//! All values read from device memory are validated via `DeviceValue<T>`.
//! Protocol violations (bad indices, non-monotonic counters, length overflows)
//! kill the device — no recovery attempted. Bounce buffers isolate the driver's
//! internal memory from device DMA.
//!
//! ## IPC protocol (endpoint 20, 256-byte payload)
//!
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   Commands:
//!     1 = SEND_PACKET: [cmd:1][packet:N]  → [status:1]
//!     2 = RECV_PACKET: [cmd:1]            → [status:1][packet:N]
//!     3 = GET_MAC:     [cmd:1]            → [status:1][mac:6]
//!     4 = GET_STATUS:  [cmd:1]            → [status:1][link_up:1]
//!
//!   Status: 0=OK, 1=ERROR, 2=NO_DATA, 3=NO_DEVICE

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod device;
mod pci;
mod seam;
#[allow(unsafe_code)]
mod transport;
#[allow(unsafe_code)]
mod virtqueue;

use cambios_libsys as sys;
use cambios_net_proto as proto;
use transport::{LegacyMmioTransport, ModernPciTransport, NotifyToken, Transport};
use virtqueue::{BounceBuffer, VirtQueue};

// ============================================================================
// Panic handler
// ============================================================================


// ============================================================================
// IPC protocol
// ============================================================================

const NET_ENDPOINT: u32 = 20;

/// TUNING: frames taken from the TX ring per loop pass, so a busy stack
/// cannot starve ep 20 or the RX direction.
const SEAM_TX_BUDGET: usize = 32;

const CMD_SEND_PACKET: u8 = 1;
const CMD_RECV_PACKET: u8 = 2;
const CMD_GET_MAC: u8 = 3;
const CMD_GET_STATUS: u8 = 4;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const STATUS_NO_DATA: u8 = 2;
const STATUS_NO_DEVICE: u8 = 3;

// ============================================================================
// Virtio-net constants
// ============================================================================

/// Virtio-net header size for the legacy carrier without MRG_RXBUF (10
/// bytes; ARCHITECTURAL — `struct virtio_net_hdr`, virtio §5.1.6).
const VIRTIO_NET_HDR_SIZE_LEGACY: usize = 10;
/// Virtio-net header size for modern carriers (`VIRTIO_F_VERSION_1`
/// negotiated; 12 bytes — `struct virtio_net_hdr_v1` always includes the
/// `num_buffers` field per virtio §5.1.6.1, regardless of MRG_RXBUF).
const VIRTIO_NET_HDR_SIZE_MODERN: usize = 12;

/// Number of pre-posted RX bounce buffers.
const RX_RING_SIZE: usize = 16;
/// TUNING: TX bounce buffers, one per descriptor in flight. A single
/// shared buffer let a second frame overwrite the first while the device
/// was still reading it (build1-3626 pcap: earlier frames lost, the last
/// one sent several times) as soon as one completion arrived late.
const TX_RING_SIZE: usize = 16;

/// RX queue index in virtio-net (queue 0 = receiveq).
const RX_QUEUE: u16 = 0;
/// TX queue index in virtio-net (queue 1 = transmitq).
const TX_QUEUE_IDX: u16 = 1;

// ============================================================================
// Driver state
// ============================================================================

struct NetDriver {
    transport: Transport,
    /// Per-queue notify tokens returned by `Transport::setup_queue`. Modern-pci
    /// uses them as the per-queue doorbell offset; legacy-mmio ignores the
    /// value and notifies by queue index alone.
    rx_notify: NotifyToken,
    tx_notify: NotifyToken,
    mac: [u8; 6],
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    /// Pre-allocated RX bounce buffers. Posted to the RX queue at init;
    /// recycled after each received packet.
    rx_bufs: [Option<BounceBuffer>; RX_RING_SIZE],
    /// TX bounce buffers; `tx_busy[k]` while buffer `k` is posted and its
    /// completion has not been reaped.
    tx_bufs: [Option<BounceBuffer>; TX_RING_SIZE],
    tx_busy: [bool; TX_RING_SIZE],
    /// Buffers usable at once: never more than the TX queue's descriptors,
    /// so a free buffer always has a free descriptor.
    tx_slots: usize,
    /// Wire-format virtio-net header size (10 legacy / 12 modern; see
    /// VIRTIO_NET_HDR_SIZE_* constants). Must match what the device
    /// expects or 2 bytes of every packet are misinterpreted.
    hdr_size: usize,
}

impl NetDriver {
    fn init(transport: Transport) -> Option<Self> {
        let is_modern = matches!(transport, Transport::ModernPci(_));

        // Step 1: Reset (virtio §3.1 step 1)
        transport.reset();
        for _ in 0..32 {
            if transport.status() == 0 {
                break;
            }
        }

        // Step 2: Acknowledge + Driver (§3.1 steps 2-3)
        transport.set_status(transport::STATUS_ACKNOWLEDGE);
        transport.set_status(transport::STATUS_DRIVER);

        // Step 3: Negotiate features (§3.1 steps 4-5)
        let device_features = transport.device_features();
        let mut accepted: u64 = 0;
        if device_features & transport::VIRTIO_NET_F_MAC != 0 {
            accepted |= transport::VIRTIO_NET_F_MAC;
        }
        if is_modern {
            // Modern-pci requires the driver to declare VIRTIO_F_VERSION_1.
            // Without it the device may refuse FEATURES_OK or silently fall
            // back to legacy mode, and our addressing calls use modern-only
            // registers.
            if device_features & transport::VIRTIO_F_VERSION_1 == 0 {
                sys::print(b"[NET] ERROR: modern device lacks VIRTIO_F_VERSION_1\n");
                transport.set_status(transport::STATUS_FAILED);
                return None;
            }
            accepted |= transport::VIRTIO_F_VERSION_1;
        }
        transport.set_driver_features(accepted);

        // Modern-only FEATURES_OK handshake (§3.1 step 6). Legacy MMIO has no
        // FEATURES_OK bit, so we skip the verification step there.
        if is_modern {
            transport.set_status(transport::STATUS_FEATURES_OK);
            if transport.status() & transport::STATUS_FEATURES_OK == 0 {
                sys::print(b"[NET] ERROR: device rejected FEATURES_OK\n");
                transport.set_status(transport::STATUS_FAILED);
                return None;
            }
        }

        // Step 4: Set up RX queue (queue 0)
        transport.select_queue(RX_QUEUE);
        let rx_qsize = transport.queue_size();
        if rx_qsize == 0 {
            sys::print(b"[NET] ERROR: RX queue size is 0\n");
            return None;
        }
        // Clamp to our fixed pending-buffer capacity. Modern-pci's
        // CC_QUEUE_SIZE is writable so the device accepts the negotiated
        // value; legacy-mmio's QUEUE_NUM is writable for the same reason.
        let rx_qsize = core::cmp::min(rx_qsize, virtqueue::MAX_QUEUE_SIZE);
        let rx_queue = VirtQueue::new(rx_qsize)?;
        let (rx_desc, rx_avail, rx_used) = rx_queue.ring_addrs();
        let rx_notify = transport.setup_queue(RX_QUEUE, rx_qsize, rx_desc, rx_avail, rx_used);

        // Step 5: Set up TX queue (queue 1)
        transport.select_queue(TX_QUEUE_IDX);
        let tx_qsize = transport.queue_size();
        if tx_qsize == 0 {
            sys::print(b"[NET] ERROR: TX queue size is 0\n");
            return None;
        }
        let tx_qsize = core::cmp::min(tx_qsize, virtqueue::MAX_QUEUE_SIZE);
        let tx_queue = VirtQueue::new(tx_qsize)?;
        let (tx_desc, tx_avail, tx_used) = tx_queue.ring_addrs();
        let tx_notify = transport.setup_queue(TX_QUEUE_IDX, tx_qsize, tx_desc, tx_avail, tx_used);

        // Step 6: Mark DRIVER_OK (§3.1 step 8)
        transport.set_status(transport::STATUS_DRIVER_OK);

        if transport.status() & transport::STATUS_FAILED != 0 {
            sys::print(b"[NET] ERROR: device set FAILED status during init\n");
            return None;
        }

        // Read MAC address
        let mac = transport.read_mac();

        // Step 7: Allocate TX bounce buffers
        let mut tx_bufs: [Option<BounceBuffer>; TX_RING_SIZE] = core::array::from_fn(|_| None);
        for b in tx_bufs.iter_mut() {
            *b = Some(BounceBuffer::new()?);
        }

        // Step 8: Allocate and post RX bounce buffers
        let rx_bufs: [Option<BounceBuffer>; RX_RING_SIZE] =
            core::array::from_fn(|_| None);

        let hdr_size = if is_modern {
            VIRTIO_NET_HDR_SIZE_MODERN
        } else {
            VIRTIO_NET_HDR_SIZE_LEGACY
        };

        let mut driver = NetDriver {
            transport,
            rx_notify,
            tx_notify,
            mac,
            rx_queue,
            tx_queue,
            rx_bufs,
            tx_bufs,
            tx_busy: [false; TX_RING_SIZE],
            tx_slots: TX_RING_SIZE.min(usize::from(tx_qsize)),
            hdr_size,
        };

        // Post initial RX buffers
        driver.fill_rx_ring();

        Some(driver)
    }

    /// Post available RX bounce buffers to the RX queue.
    fn fill_rx_ring(&mut self) {
        for i in 0..RX_RING_SIZE {
            if self.rx_bufs[i].is_some() {
                continue; // Already has a buffer
            }
            let buf = match BounceBuffer::new() {
                Some(b) => b,
                None => break, // Out of DMA memory
            };
            buf.zero();

            // Post to RX queue — device writes into this buffer
            if self.rx_queue.push_buffer(
                buf.paddr,
                buf.vaddr,
                buf.size,
                true, // device-writable
            ).is_some() {
                self.rx_bufs[i] = Some(buf);
            } else {
                break; // Queue full
            }
        }

        // Notify device that RX buffers are available
        self.transport.notify(RX_QUEUE, self.rx_notify);
    }

    /// Free every TX buffer whose descriptor the device has completed.
    fn reap_tx(&mut self) {
        while let Some((done, _len)) = self.tx_queue.pop_used() {
            for (b, busy) in self.tx_bufs.iter().zip(self.tx_busy.iter_mut()) {
                if b.as_ref().is_some_and(|b| b.paddr == done.paddr) {
                    *busy = false;
                }
            }
        }
    }

    /// A TX buffer not in flight, reaping completions first; if all are in
    /// flight, yield a bounded number of times for the device to finish.
    fn free_tx(&mut self) -> Option<usize> {
        // QEMU TCG processes virtio TX in its event loop, which runs when
        // the guest halts: yielding lets the idle task hlt.
        for attempt in 0..=20 {
            self.reap_tx();
            if let Some(k) = self.tx_busy.iter().take(self.tx_slots).position(|b| !b) {
                return Some(k);
            }
            if attempt < 20 {
                sys::yield_now();
            }
        }
        None
    }

    /// Send a packet: copy it with the virtio-net header into a free TX
    /// bounce buffer, post it and notify the device. Completion is reaped
    /// later, so frames sent back to back each keep their own buffer.
    /// `false`: dropped (dead queue, too large, or every buffer in flight).
    fn send_packet(&mut self, packet: &[u8]) -> bool {
        if self.tx_queue.is_dead() {
            return false;
        }
        let Some(k) = self.free_tx() else { return false };
        let hdr_size = self.hdr_size;
        let Some(buf) = self.tx_bufs.get_mut(k).and_then(Option::as_mut) else { return false };
        let total_len = hdr_size + packet.len();
        if total_len > buf.size as usize {
            return false; // Packet too large
        }

        // Build virtio-net header (all zeros = no offload)
        buf.zero();
        // Copy packet data after the header
        let dst = (buf.vaddr + hdr_size as u64) as *mut u8;
        // SAFETY: `dst .. dst + packet.len()` lies inside this bounce
        // buffer (`total_len <= size` above), driver memory that no posted
        // descriptor references (`tx_busy[k]` is false), and `packet` is a
        // separate slice.
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::copy_nonoverlapping(packet.as_ptr(), dst, packet.len());
        }
        let (paddr, vaddr) = (buf.paddr, buf.vaddr);

        // Post to TX queue
        if self.tx_queue.push_buffer(paddr, vaddr, total_len as u32, false).is_none() {
            return false;
        }
        if let Some(busy) = self.tx_busy.get_mut(k) {
            *busy = true;
        }
        self.transport.notify(TX_QUEUE_IDX, self.tx_notify);
        true
    }

    /// Poll for a received packet. Returns the number of payload bytes
    /// copied to `out`, or 0 if no packet available.
    fn recv_packet(&mut self, out: &mut [u8]) -> usize {
        if self.rx_queue.is_dead() {
            return 0;
        }

        if let Some((pending, validated_len)) = self.rx_queue.pop_used() {
            // validated_len includes the virtio-net header
            if (validated_len as usize) <= self.hdr_size {
                // No actual payload — repost buffer
                self.recycle_rx_buffer(pending);
                return 0;
            }

            let payload_len = validated_len as usize - self.hdr_size;
            let copy_len = core::cmp::min(payload_len, out.len());

            // Read payload from bounce buffer (skip virtio-net header)
            let src = (pending.vaddr + self.hdr_size as u64) as *const u8;
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), copy_len);
            }

            // Recycle this buffer back to the RX ring
            self.recycle_rx_buffer(pending);

            copy_len
        } else {
            0
        }
    }

    /// Return a used RX bounce buffer to the ring for reuse.
    fn recycle_rx_buffer(&mut self, pending: virtqueue::PendingBuffer) {
        // Find the slot this buffer came from and repost it
        for i in 0..RX_RING_SIZE {
            if let Some(ref buf) = self.rx_bufs[i] {
                if buf.paddr == pending.paddr {
                    buf.zero();
                    self.rx_queue.push_buffer(
                        buf.paddr, buf.vaddr, buf.size, true,
                    );
                    self.transport.notify(RX_QUEUE, self.rx_notify);
                    return;
                }
            }
        }
        // Buffer not found in our tracking — don't repost (defensive)
    }
}

#[allow(dead_code)] // Kept for future diagnostic use
fn print_mac(mac: &[u8; 6]) {
    let mut buf = [0u8; 17];
    for i in 0..6 {
        let hi = mac[i] >> 4;
        let lo = mac[i] & 0xF;
        buf[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        buf[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        if i < 5 { buf[i * 3 + 2] = b':'; }
    }
    sys::print(&buf);
}

// ============================================================================
// Request handlers
// ============================================================================

impl seam::Nic for NetDriver {
    fn transmit(&mut self, frame: &[u8]) {
        let _ = self.send_packet(frame);
    }
    fn receive(&mut self, buf: &mut [u8]) -> usize {
        self.recv_packet(buf)
    }
}

fn handle_get_mac(driver: &NetDriver, response: &mut [u8]) -> usize {
    response[0] = STATUS_OK;
    response[1..7].copy_from_slice(&driver.mac);
    7
}

fn handle_get_status(driver: &NetDriver, response: &mut [u8]) -> usize {
    let dead = driver.rx_queue.is_dead() || driver.tx_queue.is_dead();
    let hw_failed = driver.transport.status() & transport::STATUS_FAILED != 0;
    response[0] = STATUS_OK;
    response[1] = if dead || hw_failed { 0 } else { 1 };
    2
}

fn handle_send_packet(driver: &mut NetDriver, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }
    if driver.send_packet(payload) {
        response[0] = STATUS_OK;
    } else {
        response[0] = STATUS_ERROR;
    }
    1
}

fn handle_recv_packet(driver: &mut NetDriver, response: &mut [u8]) -> usize {
    // Max packet payload in 256-byte IPC frame: 255 - 1 status byte = 254
    let max_payload = response.len() - 1;
    let n = driver.recv_packet(&mut response[1..1 + max_payload]);
    if n > 0 {
        response[0] = STATUS_OK;
        1 + n
    } else {
        response[0] = STATUS_NO_DATA;
        1
    }
}

// ============================================================================
// Entry point
// ============================================================================

cambios_libsys_rt::service_main! {
    name: "NET",
    main: run,
}

fn run() -> ! {
    // Step 1: Find the virtio-net PCI device (silent on success)
    let dev = match pci::PciDeviceInfo::find_virtio_net() {
        Some(d) => d,
        None => {
            // Not an error — expected when running with a non-virtio NIC (e.g., i219)
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
    };

    // Step 2: Build the appropriate transport. BAR 0 classification selects
    // the carrier: is_io=true → virtio-pci (x86_64; we speak modern via
    // capability walk — legacy PCI's read-only QueueSize is incompatible
    // with our fixed pending-buffer size); is_io=false → virtio-mmio legacy
    // (aarch64 / riscv64 QEMU virt). Kernel-side discovery populates the
    // same DeviceInfo schema regardless (see ADR-013).
    let bar0 = dev.bars[0];
    let transport = if bar0.is_io {
        // Modern virtio-pci: walk the kernel-parsed capability layout and
        // map the BAR it points at. The kernel rejects an x86_64 virtio-net
        // device that presents only legacy I/O caps (caps.present == 0);
        // we bail cleanly in that case rather than speaking a protocol the
        // device cannot follow safely.
        let caps = match sys::virtio_modern_caps(dev.index) {
            Some(c) => c,
            None => {
                sys::print(b"[NET] ERROR: virtio_modern_caps syscall failed\n");
                sys::register_endpoint(NET_ENDPOINT);
                no_device_loop();
            }
        };
        if caps.present == 0 {
            sys::print(b"[NET] ERROR: device lacks modern virtio-pci caps (legacy-only)\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
        let cap_bar = caps.common_cfg.bar as usize;
        if cap_bar >= 6 {
            sys::print(b"[NET] ERROR: caps.common_cfg.bar out of range\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
        let bar = dev.bars[cap_bar];
        if bar.addr == 0 || bar.size == 0 || bar.is_io {
            sys::print(b"[NET] ERROR: modern caps point at missing or I/O BAR\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
        match ModernPciTransport::new(&caps, bar.addr, bar.size as u64) {
            Ok(t) => Transport::ModernPci(t),
            Err(_) => {
                sys::print(b"[NET] ERROR: ModernPciTransport::new failed\n");
                sys::register_endpoint(NET_ENDPOINT);
                no_device_loop();
            }
        }
    } else {
        let pages = ((bar0.size as u64 + 0xFFF) / 0x1000).max(1) as u32;
        let mapped = sys::map_mmio(bar0.addr, pages);
        if mapped < 0 {
            sys::print(b"[NET] ERROR: map_mmio failed for virtio-mmio region\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
        match LegacyMmioTransport::new(mapped as u64) {
            Some(t) => Transport::LegacyMmio(t),
            None => {
                sys::print(b"[NET] ERROR: virtio-mmio region rejected magic/version/device check\n");
                sys::register_endpoint(NET_ENDPOINT);
                no_device_loop();
            }
        }
    };

    // Step 3: Initialize the virtio device + queues
    let mut driver = match NetDriver::init(transport) {
        Some(d) => d,
        None => {
            sys::print(b"[NET] ERROR: device initialization failed\n");
            sys::register_endpoint(NET_ENDPOINT);
            no_device_loop();
        }
    };

    // Step 4: Register IPC endpoint
    sys::register_endpoint(NET_ENDPOINT);
    sys::print(b"[NET] ready on endpoint 20 (virtio-net)\n");
    cambios_libsys_rt::ready();

    // Step 5: Service loop — recv_verified rejects anonymous senders.
    //
    // Without a seam the loop blocks on ep 20 as before (the legacy
    // SEND_PACKET / RECV_PACKET path udp-stack uses). With a seam open it
    // polls: ep 20 without blocking, then the TX ring, then the device's
    // RX queue into the RX ring, then yields.
    // Deferred: SEND_PACKET / RECV_PACKET removal (ADR-039 § 2).
    // Why: udp-stack, the only client of the 256-byte frame path, is
    //   replaced by net-stack in a later change; removing them first would
    //   leave the image without NTP or UDP in between.
    // Revisit when: user/net-stack replaces udp-stack in manifest.toml.
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];
    let mut seam: Option<seam::Seam> = None;

    loop {
        let polled = seam.is_some();
        let msg = if polled {
            sys::try_recv_verified(NET_ENDPOINT, &mut recv_buf)
        } else {
            sys::recv_verified(NET_ENDPOINT, &mut recv_buf)
        };
        let got_msg = msg.is_some();

        if let Some(msg) = msg {
            if let Some((cmd, cmd_data)) = msg.command() {
                let reply_len = match cmd {
                    CMD_SEND_PACKET => Some(handle_send_packet(&mut driver, cmd_data, &mut resp_buf)),
                    CMD_RECV_PACKET => Some(handle_recv_packet(&mut driver, &mut resp_buf)),
                    CMD_GET_MAC => Some(handle_get_mac(&driver, &mut resp_buf)),
                    CMD_GET_STATUS => Some(handle_get_status(&driver, &mut resp_buf)),
                    proto::NIC_OPEN_SEAM | proto::NIC_CLOSE_SEAM | proto::NIC_DOORBELL_TX => {
                        seam::handle_command(&mut seam, msg.sender(), msg.payload(), &mut resp_buf)
                    }
                    _ => {
                        resp_buf[0] = STATUS_ERROR;
                        Some(1)
                    }
                };
                if let Some(n) = reply_len {
                    sys::write(msg.from_endpoint(), &resp_buf[..n]);
                }
            }
        }

        seam::service(&mut seam, &mut driver, SEAM_TX_BUDGET, RX_RING_SIZE);

        if polled && !got_msg {
            sys::yield_now();
        }
    }
}

fn no_device_loop() -> ! {
    // Ping init ready so dependents (udp-stack) can spawn. Every entry point
    // into this function has already registered NET_ENDPOINT, so the service
    // is observably up even though it has no device to serve.
    cambios_libsys_rt::ready();

    let mut recv_buf = [0u8; 256];
    let resp_buf = [STATUS_NO_DEVICE; 1];

    loop {
        let msg = match sys::recv_verified(NET_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };
        sys::write(msg.from_endpoint(), &resp_buf);
    }
}
