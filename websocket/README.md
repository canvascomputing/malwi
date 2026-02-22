# malwi-websocket

Dependency-free RFC 6455 core protocol implementation for `malwi`.

## Scope

Implemented:
- Handshake parse/build/validate (client + server)
- Frame encode/decode with strict RFC checks
- Incremental decoder
- Fragmentation and message reassembly
- Ping/Pong handling
- Close handshake state machine

Not implemented:
- Extension compression implementations (for example `permessage-deflate`)

## Defaults

`ConnectionConfig::default()`:
- max frame payload: 16 MiB
- max reassembled message: 64 MiB
- reserved bits disabled

`HandshakeParseConfig::default()`:
- max handshake bytes: 16 KiB
- max headers: 64
- max line length: 4096 bytes

## Usage

- Parse/build handshake with `parse_client_handshake_with_len`, `build_server_handshake_response`
- Exchange frames/messages using `Connection`
- Pull encoded outbound bytes via `poll_outbound`
