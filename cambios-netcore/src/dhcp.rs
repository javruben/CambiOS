// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The DHCPv4 client (RFC 2131), one per interface, as a pure state
//! machine over the spec's "DHCP client state" table (B-16, INV-net-016):
//!
//! ```text
//! Stopped    -start->              Selecting
//! Selecting  -valid OFFER->        Requesting
//! Requesting -valid ACK->          Bound        (not over an operator pin)
//! Requesting -NAK / timeout->      Selecting    (fresh transaction)
//! Bound      -renewal deadline->   Renewing
//! Renewing   -valid ACK->          Bound
//! Renewing   -NAK / expiry->       Selecting    (lease dropped first)
//! any        -stop->               Stopped      (lease dropped)
//! ```
//!
//! A reply changes state only when it is a BOOTREPLY for this client's
//! interface, its transaction (`xid`) and its hardware address, of the
//! type the state expects, with a nonzero address and a server
//! identifier; otherwise it is [`Output::Ignored`] with the reason. An
//! acknowledgement whose address differs from an operator-pinned one is
//! refused (NET-V-121).
//!
//! Nothing here is random or timed: the caller supplies `now`, every
//! transaction id (RFC 2131 § 4.1 requires a random one) and the
//! retransmission jitter (§ 4.1: randomised ±1 s), and sends the
//! [`DhcpRepr`] it is handed. The retransmission interval doubles from
//! `first_retry_ms` up to 64 s, for at most `max_attempts` sends per
//! phase.
//!
//! # Not implemented
//!
//! REBINDING (T2) as a separate state (the spec's table has none: renewal
//! retries continue to lease expiry), DECLINE after an ARP conflict
//! probe, INIT-REBOOT, RELEASE on stop, and applying the lease to an
//! interface (the engine's address is configuration today).

use crate::addr::{Ipv4Address, MacAddress};
use crate::wire::dhcpv4::{BootOp, DhcpMessage, DhcpRepr, MessageType};

/// HARDWARE: the longest retransmission interval (RFC 2131 § 4.1: "up to
/// a maximum of 64 seconds").
const MAX_RETRY_MS: u64 = 64_000;
/// HARDWARE: the shortest renewal retransmission interval (RFC 2131
/// § 4.4.5: "down to a minimum of 60 seconds").
const MIN_RENEW_RETRY_MS: u64 = 60_000;
const MS_PER_SEC: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    /// The interface this client serves (B-16: replies for another are
    /// ignored).
    pub interface: u8,
    pub mac: MacAddress,
    /// An operator-pinned address: no lease may replace it.
    pub pinned: Option<Ipv4Address>,
    /// First retransmission interval (RFC 2131 § 4.1 suggests 4 s).
    pub first_retry_ms: u64,
    /// Sends of one message before the phase gives up; at least 1.
    pub max_attempts: u8,
}

/// An acquired lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Address,
    pub mask: Ipv4Address,
    pub router: Option<Ipv4Address>,
    pub server: Ipv4Address,
    pub bound_at_ms: u64,
    /// T1: when renewal starts.
    pub renew_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Lease {
    /// The interface configuration this lease gives, for
    /// [`crate::engine::Event::Interface`]: `None` for a non-contiguous
    /// mask or a configuration the engine would refuse.
    pub fn interface(&self) -> Option<crate::engine::InterfaceConfig> {
        let m = u32::from_be_bytes(self.mask.0);
        let prefix = m.leading_ones();
        if m.checked_shl(prefix).unwrap_or(0) != 0 {
            return None; // ones after a zero: not a prefix mask
        }
        let c = crate::engine::InterfaceConfig {
            ipv4: self.address,
            prefix_len: u8::try_from(prefix).ok()?,
            gateway: self.router,
        };
        c.is_valid().then_some(c)
    }
}

/// The client's state, as the spec's table names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Stopped,
    Selecting,
    Requesting,
    Bound,
    Renewing,
}

/// Why a reply changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    WrongInterface,
    /// Another transaction id or hardware address.
    WrongTransaction,
    /// Not a reply, or not the type this state expects.
    Unexpected,
    /// No address, no server identifier, or no lease time or mask.
    Invalid,
    /// The acknowledged address differs from the operator-pinned one.
    OperatorPin,
    /// An ACK or NAK under our transaction naming a server other than the
    /// one we requested from, or an ACK for another address (RFC 2131
    /// § 4.3.1-4.3.2: only the selected server commits the requested
    /// binding).
    NotSelected,
}

/// What the caller must do after one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Nothing,
    /// Send this message (broadcast unless `broadcast` is false and
    /// `ciaddr` is set, as in renewal).
    Send(DhcpRepr),
    /// A lease was acquired or renewed: apply it.
    LeaseAcquired(Lease),
    /// The lease is gone: remove the address before reusing it.
    LeaseLost,
    /// Selection ran out of attempts; the client stopped.
    Failed,
    Ignored(Ignored),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retry {
    xid: u32,
    /// Sends made so far in this phase; 0 means "begin with a fresh
    /// transaction at `deadline`".
    attempts: u8,
    interval_ms: u64,
    deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Offer {
    address: Ipv4Address,
    server: Ipv4Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stopped,
    Selecting(Retry),
    Requesting(Retry, Offer),
    Bound(Lease),
    Renewing { xid: u32, lease: Lease, deadline_ms: u64 },
}

/// One interface's DHCPv4 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpClient {
    config: ClientConfig,
    state: State,
}

const fn zero(ip: Ipv4Address) -> bool {
    ip.0[0] | ip.0[1] | ip.0[2] | ip.0[3] == 0
}

fn at(now: u64, after_ms: u64, jitter_ms: i64) -> u64 {
    now.saturating_add(after_ms).saturating_add_signed(jitter_ms)
}

/// Whether an ACK or NAK belongs to the binding we asked for: from
/// `server`, and an ACK for `address` (a NAK carries no address). The
/// server identifier is required: RFC 2131 § 4.3.1 Table 3 says servers
/// MUST send it in DHCPACK and DHCPNAK (RFC 2132 § 9.7 says "may"; the
/// two conflict, and this client follows RFC 2131, codex ruling
/// 2026-11-12). RENEWING binds to the lease's server; there is no
/// REBINDING state, so no other server is ever accepted. DHCP is
/// unauthenticated: this stops strays and other servers' answers, not an
/// on-link forger.
fn from_binding(m: &DhcpMessage, server: Ipv4Address, address: Ipv4Address) -> bool {
    let ours = m.server_id == Some(server);
    match m.message_type {
        MessageType::Ack => ours && m.yiaddr == address,
        _ => ours,
    }
}

impl DhcpClient {
    pub const fn new(config: ClientConfig) -> Self {
        DhcpClient { config, state: State::Stopped }
    }

    pub const fn state(&self) -> ClientState {
        match self.state {
            State::Stopped => ClientState::Stopped,
            State::Selecting(_) => ClientState::Selecting,
            State::Requesting(..) => ClientState::Requesting,
            State::Bound(_) => ClientState::Bound,
            State::Renewing { .. } => ClientState::Renewing,
        }
    }

    pub const fn lease(&self) -> Option<Lease> {
        match self.state {
            State::Bound(l) | State::Renewing { lease: l, .. } => Some(l),
            State::Stopped | State::Selecting(_) | State::Requesting(..) => None,
        }
    }

    /// When the client next needs a `tick`.
    pub const fn deadline(&self) -> Option<u64> {
        match self.state {
            State::Stopped => None,
            State::Selecting(r) | State::Requesting(r, _) => Some(r.deadline_ms),
            State::Bound(l) => Some(l.renew_at_ms),
            State::Renewing { deadline_ms, .. } => Some(deadline_ms),
        }
    }

    fn message(&self, message_type: MessageType, xid: u32) -> DhcpRepr {
        DhcpRepr {
            op: BootOp::Request,
            message_type,
            xid,
            secs: 0,
            broadcast: true,
            ciaddr: Ipv4Address([0; 4]),
            yiaddr: Ipv4Address([0; 4]),
            chaddr: self.config.mac,
            requested_ip: None,
            server_id: None,
            subnet_mask: None,
            router: None,
            lease_secs: None,
        }
    }

    fn first_retry(&self, xid: u32, now: u64, jitter_ms: i64) -> Retry {
        let interval_ms = self.config.first_retry_ms.min(MAX_RETRY_MS);
        Retry { xid, attempts: 1, interval_ms, deadline_ms: at(now, interval_ms, jitter_ms) }
    }

    fn request(&self, xid: u32, offer: Offer) -> DhcpRepr {
        DhcpRepr { requested_ip: Some(offer.address), server_id: Some(offer.server), ..self.message(MessageType::Request, xid) }
    }

    /// Begin (or restart) selection: a DISCOVER under transaction `xid`.
    pub fn start(&mut self, now: u64, xid: u32, jitter_ms: i64) -> Output {
        self.state = State::Selecting(self.first_retry(xid, now, jitter_ms));
        Output::Send(self.message(MessageType::Discover, xid))
    }

    /// Stop; a held lease is dropped.
    pub fn stop(&mut self) -> Output {
        let had_lease = self.lease().is_some();
        self.state = State::Stopped;
        if had_lease {
            Output::LeaseLost
        } else {
            Output::Nothing
        }
    }

    /// Advance time. `fresh_xid` is used only if a new transaction
    /// begins; `jitter_ms` only if a retransmission is scheduled.
    pub fn tick(&mut self, now: u64, fresh_xid: u32, jitter_ms: i64) -> Output {
        match self.state {
            State::Stopped => Output::Nothing,
            State::Selecting(r) if now < r.deadline_ms => Output::Nothing,
            State::Selecting(r) => {
                if r.attempts == 0 {
                    return self.start(now, fresh_xid, jitter_ms);
                }
                if r.attempts >= self.config.max_attempts {
                    self.state = State::Stopped;
                    return Output::Failed;
                }
                self.state = State::Selecting(self.backed_off(r, now, jitter_ms));
                Output::Send(self.message(MessageType::Discover, r.xid))
            }
            State::Requesting(r, _) if now < r.deadline_ms => Output::Nothing,
            State::Requesting(r, offer) => {
                if r.attempts >= self.config.max_attempts {
                    self.state = State::Selecting(Retry { xid: r.xid, attempts: 0, interval_ms: 0, deadline_ms: now });
                    return Output::Nothing;
                }
                self.state = State::Requesting(self.backed_off(r, now, jitter_ms), offer);
                Output::Send(self.request(r.xid, offer))
            }
            State::Bound(l) if now < l.renew_at_ms => Output::Nothing,
            State::Bound(lease) => self.renew(now, fresh_xid, lease),
            State::Renewing { lease, .. } if now >= lease.expires_at_ms => self.lose(now),
            State::Renewing { deadline_ms, .. } if now < deadline_ms => Output::Nothing,
            State::Renewing { xid, lease, .. } => self.renew(now, xid, lease),
        }
    }

    fn backed_off(&self, r: Retry, now: u64, jitter_ms: i64) -> Retry {
        let interval_ms = r.interval_ms.saturating_mul(2).min(MAX_RETRY_MS);
        Retry { xid: r.xid, attempts: r.attempts.saturating_add(1), interval_ms, deadline_ms: at(now, interval_ms, jitter_ms) }
    }

    /// Send (or resend) the renewal REQUEST, unicast from the leased
    /// address, retried at half the remaining lease, at least 60 s apart,
    /// never past expiry (RFC 2131 § 4.4.5).
    fn renew(&mut self, now: u64, xid: u32, lease: Lease) -> Output {
        let remaining = lease.expires_at_ms.saturating_sub(now);
        let wait = (remaining / 2).max(MIN_RENEW_RETRY_MS);
        let deadline_ms = now.saturating_add(wait).min(lease.expires_at_ms);
        self.state = State::Renewing { xid, lease, deadline_ms };
        Output::Send(DhcpRepr { broadcast: false, ciaddr: lease.address, ..self.message(MessageType::Request, xid) })
    }

    /// Drop the lease and restart selection with a fresh transaction.
    fn lose(&mut self, now: u64) -> Output {
        self.state = State::Selecting(Retry { xid: 0, attempts: 0, interval_ms: 0, deadline_ms: now });
        Output::LeaseLost
    }

    /// Apply one received DHCP message from interface `interface`.
    pub fn on_message(&mut self, interface: u8, m: &DhcpMessage, now: u64) -> Output {
        if m.op != BootOp::Reply {
            return Output::Ignored(Ignored::Unexpected);
        }
        if interface != self.config.interface {
            return Output::Ignored(Ignored::WrongInterface);
        }
        let xid = match self.state {
            State::Stopped => return Output::Ignored(Ignored::Unexpected),
            State::Selecting(r) | State::Requesting(r, _) => r.xid,
            State::Bound(_) => return Output::Ignored(Ignored::Unexpected),
            State::Renewing { xid, .. } => xid,
        };
        if m.xid != xid || m.chaddr != self.config.mac {
            return Output::Ignored(Ignored::WrongTransaction);
        }
        match (self.state, m.message_type) {
            (State::Selecting(r), MessageType::Offer) if r.attempts > 0 => {
                let Some(server) = m.server_id.filter(|_| !zero(m.yiaddr)) else {
                    return Output::Ignored(Ignored::Invalid);
                };
                let offer = Offer { address: m.yiaddr, server };
                self.state = State::Requesting(self.first_retry(r.xid, now, 0), offer);
                Output::Send(self.request(r.xid, offer))
            }
            (State::Requesting(_, offer), MessageType::Ack | MessageType::Nak) if !from_binding(m, offer.server, offer.address) => {
                Output::Ignored(Ignored::NotSelected)
            }
            (State::Renewing { lease, .. }, MessageType::Ack | MessageType::Nak) if !from_binding(m, lease.server, lease.address) => {
                Output::Ignored(Ignored::NotSelected)
            }
            (State::Requesting(_, offer), MessageType::Ack) => self.acknowledged(m, offer.server, now),
            (State::Renewing { lease, .. }, MessageType::Ack) => self.acknowledged(m, lease.server, now),
            (State::Requesting(r, _), MessageType::Nak) => {
                self.state = State::Selecting(Retry { xid: r.xid, attempts: 0, interval_ms: 0, deadline_ms: now });
                Output::Nothing
            }
            (State::Renewing { .. }, MessageType::Nak) => self.lose(now),
            _ => Output::Ignored(Ignored::Unexpected),
        }
    }

    /// `server`: the one this ACK was checked against ([`from_binding`]).
    fn acknowledged(&mut self, m: &DhcpMessage, server: Ipv4Address, now: u64) -> Output {
        let (Some(mask), Some(lease_secs)) = (m.subnet_mask, m.lease_secs) else {
            return Output::Ignored(Ignored::Invalid);
        };
        if zero(m.yiaddr) {
            return Output::Ignored(Ignored::Invalid);
        }
        if matches!(self.config.pinned, Some(p) if p != m.yiaddr) {
            return Output::Ignored(Ignored::OperatorPin);
        }
        let lease_ms = u64::from(lease_secs).saturating_mul(MS_PER_SEC);
        let renew_ms = m.renewal_secs.map_or(lease_ms / 2, |t1| u64::from(t1).saturating_mul(MS_PER_SEC).min(lease_ms));
        let lease = Lease {
            address: m.yiaddr,
            mask,
            router: m.router,
            server,
            bound_at_ms: now,
            renew_at_ms: now.saturating_add(renew_ms),
            expires_at_ms: now.saturating_add(lease_ms),
        };
        self.state = State::Bound(lease);
        Output::LeaseAcquired(lease)
    }
}
