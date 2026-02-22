use malwi_websocket::{
    encode_frame, CloseStatusCode, Connection, ConnectionConfig, ConnectionState, EncodeConfig,
    Event, Frame, Message, OpCode, PeerRole,
};

#[test]
fn end_to_end_message_then_close() {
    let mut server = Connection::new(ConnectionConfig {
        role: PeerRole::Server,
        ..ConnectionConfig::default()
    });

    let frame = Frame::text("hello");
    let inbound = encode_frame(
        &frame,
        &EncodeConfig {
            role: PeerRole::Client,
        },
        Some([1, 2, 3, 4]),
    )
    .expect("encode");

    let ev = server.ingest(&inbound, None).expect("ingest");
    assert_eq!(ev, vec![Event::Message(Message::Text("hello".to_string()))]);

    server
        .initiate_close(Some(CloseStatusCode::Normal), Some("bye"), None)
        .expect("close");
    assert_eq!(server.state(), ConnectionState::CloseSent);

    let close = Frame::close(Some(CloseStatusCode::Normal), None).expect("frame");
    let inbound_close = encode_frame(
        &close,
        &EncodeConfig {
            role: PeerRole::Client,
        },
        Some([4, 3, 2, 1]),
    )
    .expect("encode");

    let ev = server.ingest(&inbound_close, None).expect("ingest close");
    assert!(ev.iter().any(|e| matches!(e, Event::Closed)));
    assert_eq!(server.state(), ConnectionState::Closed);
}

#[test]
fn fragmented_binary_reassembles() {
    let mut server = Connection::new(ConnectionConfig {
        role: PeerRole::Server,
        ..ConnectionConfig::default()
    });

    let mut first = Frame::new(OpCode::BINARY, vec![1, 2]);
    first.fin = false;
    let second = Frame::new(OpCode::CONTINUATION, vec![3, 4]);

    let first_wire = encode_frame(
        &first,
        &EncodeConfig {
            role: PeerRole::Client,
        },
        Some([6, 6, 6, 6]),
    )
    .expect("encode");

    let second_wire = encode_frame(
        &second,
        &EncodeConfig {
            role: PeerRole::Client,
        },
        Some([7, 7, 7, 7]),
    )
    .expect("encode");

    assert!(server
        .ingest(&first_wire, None)
        .expect("ingest1")
        .is_empty());
    let ev = server.ingest(&second_wire, None).expect("ingest2");
    assert_eq!(ev, vec![Event::Message(Message::Binary(vec![1, 2, 3, 4]))]);
}
