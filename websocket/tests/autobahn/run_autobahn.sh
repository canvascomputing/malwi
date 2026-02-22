#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
CASES_DIR="$ROOT_DIR/websocket/tests/autobahn"
REPORT_DIR="$CASES_DIR/reports"
mkdir -p "$REPORT_DIR"

cat > "$CASES_DIR/fuzzingclient.json" <<JSON
{
  "url": "ws://127.0.0.1:9002",
  "outdir": "${REPORT_DIR}",
  "cases": ["*"],
  "exclude-cases": [],
  "exclude-agent-cases": {}
}
JSON

cat > "$CASES_DIR/fuzzingserver.json" <<JSON
{
  "url": "ws://127.0.0.1:9001",
  "outdir": "${REPORT_DIR}",
  "cases": ["*"],
  "exclude-cases": [],
  "exclude-agent-cases": {}
}
JSON

echo "Autobahn harness scaffold created."
echo "Run your websocket test server/client on 9001/9002, then execute:"
echo "  docker run --rm --network host -v \"$CASES_DIR:/config\" crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json"
echo "  docker run --rm --network host -v \"$CASES_DIR:/config\" crossbario/autobahn-testsuite wstest -m fuzzingserver -s /config/fuzzingserver.json"
