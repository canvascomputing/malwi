use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpCode(u8);

impl OpCode {
    pub const CONTINUATION: Self = Self(0x0);
    pub const TEXT: Self = Self(0x1);
    pub const BINARY: Self = Self(0x2);
    pub const CLOSE: Self = Self(0x8);
    pub const PING: Self = Self(0x9);
    pub const PONG: Self = Self(0xA);

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn is_control(self) -> bool {
        self.0 & 0x08 != 0
    }

    pub fn is_data(self) -> bool {
        matches!(self, Self::TEXT | Self::BINARY)
    }

    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA => Ok(Self(raw)),
            0x3..=0x7 => Err(Error::ProtocolViolation("reserved non-control opcode")),
            0xB..=0xF => Err(Error::ProtocolViolation("reserved control opcode")),
            _ => Err(Error::InvalidFrame("invalid opcode")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: OpCode,
    pub payload: Vec<u8>,
    pub masking_key: Option<[u8; 4]>,
}

impl Frame {
    pub fn new(opcode: OpCode, payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            payload,
            masking_key: None,
        }
    }

    pub fn text(payload: impl Into<String>) -> Self {
        Self::new(OpCode::TEXT, payload.into().into_bytes())
    }

    pub fn binary(payload: Vec<u8>) -> Self {
        Self::new(OpCode::BINARY, payload)
    }

    pub fn close(code: Option<CloseStatusCode>, reason: Option<&str>) -> Result<Self> {
        let mut payload = Vec::new();
        if let Some(code) = code {
            payload.extend_from_slice(&code.to_u16().to_be_bytes());
            if let Some(reason) = reason {
                payload.extend_from_slice(reason.as_bytes());
            }
        } else if reason.is_some() {
            return Err(Error::InvalidFrame(
                "close reason requires close status code",
            ));
        }

        let frame = Self::new(OpCode::CLOSE, payload);
        frame.validate_control_frame_constraints()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<()> {
        if self.rsv1 || self.rsv2 || self.rsv3 {
            return Err(Error::ProtocolViolation(
                "RSV bits set but no extension negotiated",
            ));
        }

        if self.opcode.is_control() {
            self.validate_control_frame_constraints()?;
        }

        if self.opcode == OpCode::CLOSE {
            validate_close_payload(&self.payload)?;
        }

        Ok(())
    }

    fn validate_control_frame_constraints(&self) -> Result<()> {
        if !self.fin {
            return Err(Error::ProtocolViolation(
                "control frames must not be fragmented",
            ));
        }

        if self.payload.len() > 125 {
            return Err(Error::ProtocolViolation(
                "control frame payload length must be <= 125",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseStatusCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    InvalidFramePayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalServerError = 1011,
    ServiceRestart = 1012,
    TryAgainLater = 1013,
    BadGateway = 1014,
}

impl CloseStatusCode {
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: Option<u16>,
    pub reason: String,
}

impl CloseFrame {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        validate_close_payload(payload)?;

        if payload.is_empty() {
            return Ok(Self {
                code: None,
                reason: String::new(),
            });
        }

        let code = u16::from_be_bytes([payload[0], payload[1]]);
        let reason = String::from_utf8(payload[2..].to_vec())?;

        Ok(Self {
            code: Some(code),
            reason,
        })
    }
}

pub(crate) fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[idx % 4];
    }
}

pub fn is_reserved_close_code(code: u16) -> bool {
    matches!(code, 1004 | 1005 | 1006 | 1015)
}

pub fn is_valid_close_code(code: u16) -> bool {
    (1000..=1014).contains(&code) && !is_reserved_close_code(code) || (3000..=4999).contains(&code)
}

fn validate_close_payload(payload: &[u8]) -> Result<()> {
    if payload.len() == 1 {
        return Err(Error::ProtocolViolation(
            "close payload length 1 is invalid",
        ));
    }

    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !is_valid_close_code(code) {
            return Err(Error::ProtocolViolation("invalid close status code"));
        }
        let _ = std::str::from_utf8(&payload[2..])?;
    }

    Ok(())
}
