// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! The ADR-039 § 2 and § 3 wire contract, written before the encoders:
//! every message round-trips, every field sits at the offset the ADR's
//! tables give, and every malformed input is refused with a typed error
//! rather than guessed at.

use cambios_net_proto::*;

fn enc<const N: usize>(f: impl FnOnce(&mut [u8]) -> Result<usize, EncodeError>) -> Vec<u8> {
    let mut buf = [0u8; N];
    let n = f(&mut buf).expect("encodes");
    buf[..n].to_vec()
}

#[test]
fn endpoints_and_status_bytes_are_the_adr_numbers() {
    assert_eq!((NIC_ENDPOINT, UDP_ENDPOINT, TCP_ENDPOINT, TEST_CLIENT_ENDPOINT, SEAM_ENDPOINT), (20, 21, 34, 35, 36));
    let all = [Status::Ok, Status::Error, Status::NoData, Status::NoDevice, Status::Busy, Status::Denied, Status::Full, Status::BadState];
    for (i, s) in all.iter().enumerate() {
        assert_eq!(*s as u8, i as u8);
        assert_eq!(Status::from_u8(i as u8), Some(*s));
    }
    assert_eq!(Status::from_u8(8), None);
}

#[test]
fn nic_requests_have_the_table_layouts() {
    assert_eq!(enc::<64>(|b| NicRequest::GetMac.encode(b)), [3]);
    assert_eq!(enc::<64>(|b| NicRequest::GetStatus.encode(b)), [4]);
    assert_eq!(enc::<64>(|b| NicRequest::CloseSeam.encode(b)), [6]);
    assert_eq!(enc::<64>(|b| NicRequest::DoorbellTx.encode(b)), [7]);
    let open = enc::<64>(|b| NicRequest::OpenSeam { tx_chan: 0x0102_0304_0506_0708, rx_chan: 9 }.encode(b));
    assert_eq!(open.len(), 17);
    assert_eq!(open[0], 5);
    assert_eq!(&open[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&open[9..17], &9u64.to_le_bytes());
    for r in [NicRequest::GetMac, NicRequest::GetStatus, NicRequest::OpenSeam { tx_chan: 1, rx_chan: 2 }, NicRequest::CloseSeam, NicRequest::DoorbellTx] {
        assert_eq!(NicRequest::decode(&enc::<64>(|b| r.encode(b))), Ok(r));
    }
}

#[test]
fn the_removed_frame_commands_are_refused() {
    // SEND_PACKET = 1 and RECV_PACKET = 2 are removed, not kept beside the ring.
    assert_eq!(NicRequest::decode(&[1, 0, 0]), Err(DecodeError::UnknownCommand(1)));
    assert_eq!(NicRequest::decode(&[2]), Err(DecodeError::UnknownCommand(2)));
    assert_eq!(NicRequest::decode(&[]), Err(DecodeError::Truncated));
    assert_eq!(NicRequest::decode(&[5, 1, 2, 3]), Err(DecodeError::Truncated));
}

#[test]
fn seam_doorbell_is_one_byte() {
    assert_eq!(SEAM_DOORBELL_RX, 7);
    assert_eq!(enc::<4>(|b| SeamMessage::DoorbellRx.encode(b)), [7]);
    assert_eq!(SeamMessage::decode(&[7]), Ok(SeamMessage::DoorbellRx));
    assert_eq!(SeamMessage::decode(&[6]), Err(DecodeError::UnknownCommand(6)));
}

#[test]
fn addresses_are_family_plus_sixteen_octets() {
    let v4 = Address::V4([192, 0, 2, 1]);
    let mut b = [0xEEu8; ADDRESS_LEN];
    v4.encode(&mut b).expect("fits");
    assert_eq!(b[0], 4);
    assert_eq!(&b[1..5], &[192, 0, 2, 1]);
    assert_eq!(&b[5..], &[0u8; 12], "the rest of an IPv4 address is zero");
    assert_eq!(Address::decode(&b), Ok(v4));

    let v6 = Address::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v6.encode(&mut b).expect("fits");
    assert_eq!(b[0], 6);
    assert_eq!(Address::decode(&b), Ok(v6));

    let mut bad = [0u8; ADDRESS_LEN];
    bad[0] = 5;
    assert_eq!(Address::decode(&bad), Err(DecodeError::BadFamily(5)));
    // An IPv4 address with stray bytes in the padding is not silently accepted.
    let mut dirty = [0u8; ADDRESS_LEN];
    dirty[0] = 4;
    dirty[16] = 1;
    assert_eq!(Address::decode(&dirty), Err(DecodeError::NonZeroPadding));
    assert_eq!(Address::decode(&dirty[..10]), Err(DecodeError::Truncated));
}

#[test]
fn socket_requests_have_the_table_layouts() {
    let c = enc::<64>(|b| SockRequest::Connect { remote: Address::V4([10, 0, 2, 2]), port: 0x1F90 }.encode(b));
    assert_eq!(c.len(), 1 + 17 + 2);
    assert_eq!(c[0], 1);
    assert_eq!(c[1], 4);
    assert_eq!(&c[18..20], &[0x1F, 0x90], "ports are in network order");
    assert_eq!(enc::<64>(|b| SockRequest::Listen { port: 80 }.encode(b)), [2, 0, 80]);
    assert_eq!(enc::<64>(|b| SockRequest::Accept { listener: Handle(0x0A0B_0C0D) }.encode(b)), [3, 0x0D, 0x0C, 0x0B, 0x0A]);
    assert_eq!(enc::<64>(|b| SockRequest::Close { handle: Handle(1) }.encode(b)), [4, 1, 0, 0, 0]);
    assert_eq!(enc::<64>(|b| SockRequest::Status { sock: Handle(2) }.encode(b)), [5, 2, 0, 0, 0]);
    assert_eq!(enc::<64>(|b| SockRequest::Doorbell { sock: Handle(3) }.encode(b)), [6, 3, 0, 0, 0]);
    assert_eq!(enc::<64>(|b| SockRequest::GetConfig { family: Family::V6 }.encode(b)), [7, 6]);
    let all = [
        SockRequest::Connect { remote: Address::V6([1; 16]), port: 443 },
        SockRequest::Listen { port: 7 },
        SockRequest::Accept { listener: Handle(5) },
        SockRequest::Close { handle: Handle(6) },
        SockRequest::Status { sock: Handle(7) },
        SockRequest::Doorbell { sock: Handle(8) },
        SockRequest::GetConfig { family: Family::V4 },
    ];
    for r in all {
        assert_eq!(SockRequest::decode(&enc::<64>(|b| r.encode(b))), Ok(r));
    }
    assert_eq!(SockRequest::decode(&[0]), Err(DecodeError::UnknownCommand(0)));
    assert_eq!(SockRequest::decode(&[8]), Err(DecodeError::UnknownCommand(8)));
    assert_eq!(SockRequest::decode(&[7, 5]), Err(DecodeError::BadFamily(5)));
    assert_eq!(SockRequest::decode(&[2, 0]), Err(DecodeError::Truncated));
}

#[test]
fn replies_round_trip_and_carry_their_status() {
    let connect = ConnectReply { status: Status::Ok, sock: Handle(9), tx_chan: 11, rx_chan: 12 };
    let b = enc::<64>(|b| connect.encode(b));
    assert_eq!(b.len(), 1 + 4 + 8 + 8);
    assert_eq!(ConnectReply::decode(&b), Ok(connect));

    let accept = AcceptReply { status: Status::Ok, sock: Handle(1), tx_chan: 2, rx_chan: 3, peer: Address::V4([192, 0, 2, 9]), peer_port: 40_000 };
    let b = enc::<64>(|b| accept.encode(b));
    assert_eq!(b.len(), 1 + 4 + 8 + 8 + 17 + 2);
    assert_eq!(AcceptReply::decode(&b), Ok(accept));

    let listen = ListenReply { status: Status::Ok, listener: Handle(4) };
    assert_eq!(ListenReply::decode(&enc::<64>(|b| listen.encode(b))), Ok(listen));

    let status = StatusReply { status: Status::Ok, state: TcpState::Established, rx_avail: 100, tx_free: 16_384 };
    let b = enc::<64>(|b| status.encode(b));
    assert_eq!(b, [0, 5, 100, 0, 0, 0, 0, 0x40, 0, 0]);
    assert_eq!(StatusReply::decode(&b), Ok(status));

    let config = ConfigReply { status: Status::Ok, address: Address::V4([10, 0, 2, 15]), prefix_len: 24, gateway: Address::V4([10, 0, 2, 2]), mac: [2, 0, 0, 0, 0, 1] };
    let b = enc::<64>(|b| config.encode(b));
    assert_eq!(b.len(), 1 + 1 + 16 + 1 + 16 + 6);
    assert_eq!(ConfigReply::decode(&b), Ok(config));
}

#[test]
fn an_error_reply_is_just_the_status_byte() {
    // A refused request carries no handles; the client must not read
    // zeroed fields as a socket.
    let b = enc::<64>(|b| ConnectReply::refused(Status::Denied).encode(b));
    assert_eq!(b, [Status::Denied as u8]);
    assert_eq!(ConnectReply::decode(&b), Ok(ConnectReply::refused(Status::Denied)));
    assert_eq!(ConnectReply::decode(&[Status::Ok as u8]), Err(DecodeError::Truncated));
    assert_eq!(ConnectReply::decode(&[0xFF]), Err(DecodeError::BadStatus(0xFF)));
}

#[test]
fn tcp_state_uses_rfc4022_numbers_and_zero_is_never_a_state() {
    let all = [
        TcpState::Closed,
        TcpState::Listen,
        TcpState::SynSent,
        TcpState::SynReceived,
        TcpState::Established,
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::CloseWait,
        TcpState::LastAck,
        TcpState::Closing,
        TcpState::TimeWait,
    ];
    for (i, s) in all.iter().enumerate() {
        assert_eq!(*s as u8, i as u8 + 1);
        assert_eq!(TcpState::from_u8(i as u8 + 1), Some(*s));
    }
    assert_eq!(TcpState::from_u8(0), None);
    assert_eq!(TcpState::from_u8(12), None);
    assert_eq!(StatusReply::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DecodeError::BadState(0)));
}

#[test]
fn data_ready_is_command_six_with_the_socket() {
    assert_eq!(enc::<8>(|b| ClientNotice::DataReady { sock: Handle(0x0102_0304) }.encode(b)), [6, 4, 3, 2, 1]);
    assert_eq!(ClientNotice::decode(&[6, 4, 3, 2, 1]), Ok(ClientNotice::DataReady { sock: Handle(0x0102_0304) }));
}

#[test]
fn every_message_fits_one_control_payload() {
    assert!(MAX_MESSAGE <= 256);
    let mut tiny = [0u8; 3];
    assert_eq!(NicRequest::OpenSeam { tx_chan: 1, rx_chan: 2 }.encode(&mut tiny), Err(EncodeError::BufferTooSmall));
}
