//! RFC 6455 WebSocket protocol primitives.
//!
//! This crate provides strict handshake validation and frame codec utilities
//! without coupling to any async runtime.

mod codec;
mod connection;
mod error;
mod frame;
mod handshake;

pub use codec::{encode_frame, DecodeConfig, Decoder, EncodeConfig};
pub use connection::{Connection, ConnectionConfig, ConnectionState, Event, Message};
pub use error::{Error, Result};
pub use frame::{
    is_reserved_close_code, is_valid_close_code, CloseFrame, CloseStatusCode, Frame, OpCode,
    PeerRole,
};
pub use handshake::{
    build_client_handshake_request, build_server_handshake_response, parse_client_handshake,
    parse_client_handshake_with_len, parse_server_handshake_response,
    parse_server_handshake_response_with_len, websocket_accept_key, ClientHandshakeRequest,
    ClientHandshakeResponse, HandshakeHeaders, HandshakeParseConfig, HandshakeRequest,
};
