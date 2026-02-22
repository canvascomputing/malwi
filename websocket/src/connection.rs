use std::collections::VecDeque;

use crate::codec::{encode_frame, DecodeConfig, Decoder, EncodeConfig};
use crate::{CloseFrame, CloseStatusCode, Error, Frame, OpCode, PeerRole, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Message(Message),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    CloseReceived(CloseFrame),
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Open,
    CloseSent,
    CloseReceived,
    Closed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub role: PeerRole,
    pub max_frame_payload_len: usize,
    pub max_message_len: usize,
    pub allow_reserved_bits: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            role: PeerRole::Server,
            max_frame_payload_len: 16 * 1024 * 1024,
            max_message_len: 64 * 1024 * 1024,
            allow_reserved_bits: false,
        }
    }
}

#[derive(Debug, Clone)]
struct FragmentState {
    opcode: OpCode,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Connection {
    config: ConnectionConfig,
    decoder: Decoder,
    encode: EncodeConfig,
    state: ConnectionState,
    outbox: VecDeque<Vec<u8>>,
    fragment: Option<FragmentState>,
    close_sent: bool,
    close_received: bool,
}

impl Connection {
    pub fn new(config: ConnectionConfig) -> Self {
        let decoder = Decoder::new(DecodeConfig {
            role: config.role,
            max_payload_len: config.max_frame_payload_len,
            allow_reserved_bits: config.allow_reserved_bits,
        });

        Self {
            encode: EncodeConfig { role: config.role },
            config,
            decoder,
            state: ConnectionState::Open,
            outbox: VecDeque::new(),
            fragment: None,
            close_sent: false,
            close_received: false,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn ingest(&mut self, data: &[u8], mask_key: Option<[u8; 4]>) -> Result<Vec<Event>> {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Failed
        ) {
            return Err(Error::StateViolation("cannot ingest in terminal state"));
        }

        self.decoder.ingest(data);
        let mut events = Vec::new();

        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(e) => {
                    self.state = ConnectionState::Failed;
                    return Err(e);
                }
            };

            self.handle_frame(frame, &mut events, mask_key)?;
        }

        Ok(events)
    }

    pub fn send_message(&mut self, message: Message, mask_key: Option<[u8; 4]>) -> Result<()> {
        if self.state != ConnectionState::Open {
            return Err(Error::StateViolation(
                "cannot send data message while connection is closing/closed",
            ));
        }

        let frame = match message {
            Message::Text(text) => Frame::text(text),
            Message::Binary(bin) => Frame::binary(bin),
        };
        self.enqueue_frame(frame, mask_key)
    }

    pub fn send_ping(&mut self, payload: Vec<u8>, mask_key: Option<[u8; 4]>) -> Result<()> {
        if payload.len() > 125 {
            return Err(Error::InvalidFrame("ping payload too large"));
        }

        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Failed
        ) {
            return Err(Error::StateViolation("cannot send ping in terminal state"));
        }

        self.enqueue_frame(Frame::new(OpCode::PING, payload), mask_key)
    }

    pub fn initiate_close(
        &mut self,
        code: Option<CloseStatusCode>,
        reason: Option<&str>,
        mask_key: Option<[u8; 4]>,
    ) -> Result<()> {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Failed
        ) {
            return Err(Error::StateViolation("connection already terminal"));
        }

        if self.close_sent {
            return Ok(());
        }

        let frame = Frame::close(code, reason)?;
        self.enqueue_frame(frame, mask_key)?;
        self.close_sent = true;
        self.state = if self.close_received {
            ConnectionState::Closed
        } else {
            ConnectionState::CloseSent
        };
        Ok(())
    }

    pub fn poll_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    fn handle_frame(
        &mut self,
        frame: Frame,
        events: &mut Vec<Event>,
        mask_key: Option<[u8; 4]>,
    ) -> Result<()> {
        if self.close_received && frame.opcode.is_data() {
            self.state = ConnectionState::Failed;
            return Err(Error::ProtocolViolation("received data after close frame"));
        }

        match frame.opcode {
            OpCode::CONTINUATION => {
                let frag = self
                    .fragment
                    .as_mut()
                    .ok_or(Error::ProtocolViolation("unexpected continuation frame"))?;

                let next_size = frag.payload.len() + frame.payload.len();
                if next_size > self.config.max_message_len {
                    self.state = ConnectionState::Failed;
                    return Err(Error::PayloadTooLarge {
                        configured_max: self.config.max_message_len,
                        actual: next_size,
                    });
                }

                frag.payload.extend_from_slice(&frame.payload);
                if frame.fin {
                    let frag = self.fragment.take().expect("fragment present");
                    let event = finalize_message(frag.opcode, frag.payload)?;
                    events.push(Event::Message(event));
                }
            }
            OpCode::TEXT | OpCode::BINARY => {
                if self.fragment.is_some() {
                    self.state = ConnectionState::Failed;
                    return Err(Error::ProtocolViolation(
                        "new data frame while fragmented message is in progress",
                    ));
                }

                if frame.fin {
                    let event = finalize_message(frame.opcode, frame.payload)?;
                    events.push(Event::Message(event));
                } else {
                    if frame.payload.len() > self.config.max_message_len {
                        self.state = ConnectionState::Failed;
                        return Err(Error::PayloadTooLarge {
                            configured_max: self.config.max_message_len,
                            actual: frame.payload.len(),
                        });
                    }
                    self.fragment = Some(FragmentState {
                        opcode: frame.opcode,
                        payload: frame.payload,
                    });
                }
            }
            OpCode::PING => {
                if !matches!(
                    self.state,
                    ConnectionState::Closed | ConnectionState::Failed
                ) {
                    self.enqueue_frame(Frame::new(OpCode::PONG, frame.payload.clone()), mask_key)?;
                }
                events.push(Event::Ping(frame.payload));
            }
            OpCode::PONG => {
                events.push(Event::Pong(frame.payload));
            }
            OpCode::CLOSE => {
                let close = CloseFrame::parse(&frame.payload)?;
                events.push(Event::CloseReceived(close));

                self.close_received = true;
                if !self.close_sent {
                    let reply = Frame::new(OpCode::CLOSE, frame.payload);
                    self.enqueue_frame(reply, mask_key)?;
                    self.close_sent = true;
                }

                self.state = if self.close_sent && self.close_received {
                    events.push(Event::Closed);
                    ConnectionState::Closed
                } else {
                    ConnectionState::CloseReceived
                };
            }
            _ => {
                self.state = ConnectionState::Failed;
                return Err(Error::ProtocolViolation("unexpected opcode"));
            }
        }

        if self.close_sent && self.close_received {
            self.state = ConnectionState::Closed;
        }

        Ok(())
    }

    fn enqueue_frame(&mut self, frame: Frame, mask_key: Option<[u8; 4]>) -> Result<()> {
        let encoded = encode_frame(&frame, &self.encode, mask_key)?;
        self.outbox.push_back(encoded);
        Ok(())
    }
}

fn finalize_message(opcode: OpCode, payload: Vec<u8>) -> Result<Message> {
    if opcode == OpCode::TEXT {
        let text = String::from_utf8(payload)?;
        return Ok(Message::Text(text));
    }

    Ok(Message::Binary(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_text_with_ping_interleave() {
        let mut c = Connection::new(ConnectionConfig {
            role: PeerRole::Server,
            ..ConnectionConfig::default()
        });

        let mut part1 = Frame::new(OpCode::TEXT, b"he".to_vec());
        part1.fin = false;
        let ping = Frame::new(OpCode::PING, b"x".to_vec());
        let part2 = Frame::new(OpCode::CONTINUATION, b"llo".to_vec());

        let in1 = encode_frame(
            &part1,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([1, 2, 3, 4]),
        )
        .expect("encode");
        let in2 = encode_frame(
            &ping,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([1, 2, 3, 4]),
        )
        .expect("encode");
        let in3 = encode_frame(
            &part2,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([1, 2, 3, 4]),
        )
        .expect("encode");

        let ev = c.ingest(&in1, None).expect("ingest 1");
        assert!(ev.is_empty());

        let ev = c.ingest(&in2, None).expect("ingest 2");
        assert_eq!(ev, vec![Event::Ping(b"x".to_vec())]);
        assert!(c.poll_outbound().is_some()); // pong

        let ev = c.ingest(&in3, None).expect("ingest 3");
        assert_eq!(ev, vec![Event::Message(Message::Text("hello".to_string()))]);
    }

    #[test]
    fn close_handshake_transitions_to_closed() {
        let mut c = Connection::new(ConnectionConfig {
            role: PeerRole::Server,
            ..ConnectionConfig::default()
        });

        c.initiate_close(Some(CloseStatusCode::Normal), None, None)
            .expect("close");
        assert_eq!(c.state(), ConnectionState::CloseSent);

        let remote_close = Frame::close(Some(CloseStatusCode::Normal), None).expect("frame");
        let wire = encode_frame(
            &remote_close,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([9, 8, 7, 6]),
        )
        .expect("encode");

        let ev = c.ingest(&wire, None).expect("ingest");
        assert!(ev.iter().any(|e| matches!(e, Event::Closed)));
        assert_eq!(c.state(), ConnectionState::Closed);
    }

    #[test]
    fn invalid_continuation_sequence_fails() {
        let mut c = Connection::new(ConnectionConfig {
            role: PeerRole::Server,
            ..ConnectionConfig::default()
        });

        let cont = Frame::new(OpCode::CONTINUATION, b"x".to_vec());
        let wire = encode_frame(
            &cont,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([1, 1, 1, 1]),
        )
        .expect("encode");

        let err = c.ingest(&wire, None).expect_err("must fail");
        assert!(matches!(err, Error::ProtocolViolation(_)));
    }
}
