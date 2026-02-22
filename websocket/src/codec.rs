use crate::frame::apply_mask;
use crate::{Error, Frame, OpCode, PeerRole, Result};

#[derive(Debug, Clone)]
pub struct DecodeConfig {
    pub role: PeerRole,
    pub max_payload_len: usize,
    pub allow_reserved_bits: bool,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            role: PeerRole::Server,
            max_payload_len: 16 * 1024 * 1024,
            allow_reserved_bits: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncodeConfig {
    pub role: PeerRole,
}

impl Default for EncodeConfig {
    fn default() -> Self {
        Self {
            role: PeerRole::Server,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    config: DecodeConfig,
    buf: Vec<u8>,
    cursor: usize,
}

impl Decoder {
    pub fn new(config: DecodeConfig) -> Self {
        Self {
            config,
            buf: Vec::new(),
            cursor: 0,
        }
    }

    pub fn ingest(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        let available = self.buf.len().saturating_sub(self.cursor);
        if available < 2 {
            return Ok(None);
        }

        let start = self.cursor;
        let b0 = self.buf[start];
        let b1 = self.buf[start + 1];

        let fin = b0 & 0x80 != 0;
        let rsv1 = b0 & 0x40 != 0;
        let rsv2 = b0 & 0x20 != 0;
        let rsv3 = b0 & 0x10 != 0;
        let opcode = OpCode::from_raw(b0 & 0x0F)?;

        if !self.config.allow_reserved_bits && (rsv1 || rsv2 || rsv3) {
            return Err(Error::ProtocolViolation(
                "RSV bits set but no extension negotiated",
            ));
        }

        let masked = b1 & 0x80 != 0;
        match self.config.role {
            PeerRole::Server if !masked => {
                return Err(Error::ProtocolViolation(
                    "client-to-server frames must be masked",
                ));
            }
            PeerRole::Client if masked => {
                return Err(Error::ProtocolViolation(
                    "server-to-client frames must not be masked",
                ));
            }
            _ => {}
        }

        let mut offset = start + 2;
        let payload_marker = (b1 & 0x7F) as usize;

        let payload_len = match payload_marker {
            0..=125 => payload_marker,
            126 => {
                if self.buf.len().saturating_sub(offset) < 2 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([self.buf[offset], self.buf[offset + 1]]) as usize;
                if len < 126 {
                    return Err(Error::ProtocolViolation(
                        "non-minimal payload length encoding",
                    ));
                }
                offset += 2;
                len
            }
            127 => {
                if self.buf.len().saturating_sub(offset) < 8 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    self.buf[offset],
                    self.buf[offset + 1],
                    self.buf[offset + 2],
                    self.buf[offset + 3],
                    self.buf[offset + 4],
                    self.buf[offset + 5],
                    self.buf[offset + 6],
                    self.buf[offset + 7],
                ]);
                if len & (1u64 << 63) != 0 {
                    return Err(Error::ProtocolViolation("invalid 64-bit payload length"));
                }
                if len <= u16::MAX as u64 {
                    return Err(Error::ProtocolViolation(
                        "non-minimal payload length encoding",
                    ));
                }
                if len > usize::MAX as u64 {
                    return Err(Error::ProtocolViolation(
                        "frame payload length overflows usize",
                    ));
                }
                offset += 8;
                len as usize
            }
            _ => return Err(Error::InvalidFrame("invalid payload length marker")),
        };

        if payload_len > self.config.max_payload_len {
            return Err(Error::PayloadTooLarge {
                configured_max: self.config.max_payload_len,
                actual: payload_len,
            });
        }

        let masking_key = if masked {
            if self.buf.len().saturating_sub(offset) < 4 {
                return Ok(None);
            }
            let key = [
                self.buf[offset],
                self.buf[offset + 1],
                self.buf[offset + 2],
                self.buf[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        if self.buf.len().saturating_sub(offset) < payload_len {
            return Ok(None);
        }

        let mut payload = self.buf[offset..offset + payload_len].to_vec();
        if let Some(key) = masking_key {
            apply_mask(&mut payload, key);
        }

        self.cursor = offset + payload_len;
        self.compact();

        let frame = Frame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            payload,
            masking_key,
        };
        frame.validate()?;

        Ok(Some(frame))
    }

    fn compact(&mut self) {
        if self.cursor == 0 {
            return;
        }

        if self.cursor >= self.buf.len() {
            self.buf.clear();
            self.cursor = 0;
            return;
        }

        if self.cursor > 4096 || self.cursor * 2 > self.buf.len() {
            self.buf.drain(0..self.cursor);
            self.cursor = 0;
        }
    }
}

pub fn encode_frame(
    frame: &Frame,
    config: &EncodeConfig,
    mask_key: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    frame.validate()?;

    let masked = match config.role {
        PeerRole::Client => true,
        PeerRole::Server => false,
    };

    let mut out = Vec::new();
    let mut b0 = frame.opcode.raw();
    if frame.fin {
        b0 |= 0x80;
    }
    if frame.rsv1 {
        b0 |= 0x40;
    }
    if frame.rsv2 {
        b0 |= 0x20;
    }
    if frame.rsv3 {
        b0 |= 0x10;
    }
    out.push(b0);

    let len = frame.payload.len();
    let mask_bit = if masked { 0x80 } else { 0x00 };
    if len <= 125 {
        out.push(mask_bit | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if masked {
        let key = mask_key.ok_or(Error::InvalidFrame(
            "client frame encoding requires mask key",
        ))?;
        out.extend_from_slice(&key);
        let mut payload = frame.payload.clone();
        apply_mask(&mut payload, key);
        out.extend_from_slice(&payload);
    } else {
        if mask_key.is_some() {
            return Err(Error::InvalidFrame(
                "server frame encoding must not include a mask key",
            ));
        }
        out.extend_from_slice(&frame.payload);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift32(state: &mut u32) -> u32 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *state = x;
        x
    }

    #[test]
    fn masked_text_frame_roundtrip() {
        let frame = Frame::text("hello");
        let data = encode_frame(
            &frame,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([1, 2, 3, 4]),
        )
        .expect("encode");

        let mut decoder = Decoder::new(DecodeConfig {
            role: PeerRole::Server,
            ..DecodeConfig::default()
        });

        decoder.ingest(&data);
        let parsed = decoder.next_frame().expect("decode").expect("frame");
        assert_eq!(parsed.opcode, OpCode::TEXT);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn fragmented_input_is_handled_incrementally() {
        let frame = Frame::binary(vec![1, 2, 3, 4, 5]);
        let data = encode_frame(
            &frame,
            &EncodeConfig {
                role: PeerRole::Client,
            },
            Some([9, 8, 7, 6]),
        )
        .expect("encode");

        let mut decoder = Decoder::new(DecodeConfig {
            role: PeerRole::Server,
            ..DecodeConfig::default()
        });

        decoder.ingest(&data[..2]);
        assert!(decoder.next_frame().expect("partial").is_none());
        decoder.ingest(&data[2..]);

        let parsed = decoder.next_frame().expect("decode").expect("frame");
        assert_eq!(parsed.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn control_frame_constraints_enforced() {
        let mut frame = Frame::new(OpCode::PING, vec![0u8; 126]);
        let err = frame.validate().expect_err("must fail");
        assert!(matches!(err, Error::ProtocolViolation(_)));

        frame.payload.truncate(1);
        frame.fin = false;
        let err = frame.validate().expect_err("must fail");
        assert!(matches!(err, Error::ProtocolViolation(_)));
    }

    #[test]
    fn unmasked_client_frame_is_rejected() {
        let frame = Frame::text("hello");
        let data = encode_frame(
            &frame,
            &EncodeConfig {
                role: PeerRole::Server,
            },
            None,
        )
        .expect("encode");

        let mut decoder = Decoder::new(DecodeConfig {
            role: PeerRole::Server,
            ..DecodeConfig::default()
        });
        decoder.ingest(&data);
        let err = decoder.next_frame().expect_err("must fail");
        assert!(matches!(err, Error::ProtocolViolation(_)));
    }

    #[test]
    fn non_minimal_length_encoding_is_rejected() {
        let wire = [0x81, 0x7E, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut decoder = Decoder::new(DecodeConfig {
            role: PeerRole::Client,
            ..DecodeConfig::default()
        });
        decoder.ingest(&wire);
        let err = decoder.next_frame().expect_err("must fail");
        assert!(matches!(err, Error::ProtocolViolation(_)));
    }

    #[test]
    fn random_roundtrip_chunks() {
        let mut seed = 0x1234_5678;

        for _ in 0..128 {
            let len = (xorshift32(&mut seed) % 2048) as usize;
            let mut payload = vec![0u8; len];
            for b in &mut payload {
                *b = (xorshift32(&mut seed) & 0xFF) as u8;
            }

            let frame = Frame::new(OpCode::BINARY, payload.clone());
            let mask = [
                (xorshift32(&mut seed) & 0xFF) as u8,
                (xorshift32(&mut seed) & 0xFF) as u8,
                (xorshift32(&mut seed) & 0xFF) as u8,
                (xorshift32(&mut seed) & 0xFF) as u8,
            ];

            let data = encode_frame(
                &frame,
                &EncodeConfig {
                    role: PeerRole::Client,
                },
                Some(mask),
            )
            .expect("encode");

            let mut decoder = Decoder::new(DecodeConfig {
                role: PeerRole::Server,
                ..DecodeConfig::default()
            });

            let mut i = 0usize;
            while i < data.len() {
                let step = ((xorshift32(&mut seed) % 19) + 1) as usize;
                let end = (i + step).min(data.len());
                decoder.ingest(&data[i..end]);
                i = end;
            }

            let parsed = decoder.next_frame().expect("decode").expect("frame");
            assert_eq!(parsed.payload, payload);
        }
    }
}
