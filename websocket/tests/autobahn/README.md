# Autobahn Harness

This directory contains a lightweight harness scaffold to run Autobahn against
an external server/client adapter built on `malwi-websocket::Connection`.

## Generate configs

```bash
./websocket/tests/autobahn/run_autobahn.sh
```

## Run Autobahn

Use Docker (no Rust dependencies required):

```bash
docker run --rm --network host -v "$PWD/websocket/tests/autobahn:/config" crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json
```

```bash
docker run --rm --network host -v "$PWD/websocket/tests/autobahn:/config" crossbario/autobahn-testsuite wstest -m fuzzingserver -s /config/fuzzingserver.json
```
