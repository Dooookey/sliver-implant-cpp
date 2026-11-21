#!/usr/bin/env bash
# tls-selftest.sh - Linux/WSL counterpart of tls-selftest.ps1
set -euo pipefail

CONFIG="${CONFIG:-wsl-gcc-debug}"
PORT="${PORT:-9443}"
ADDR="${ADDR:-127.0.0.1}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="$root/build/$CONFIG"
fixtures="$build/tls-fixtures"
server="$build/tls-testserver"
client="$build/bin/implant"

[ -x "$client" ] || { echo "missing $client (cmake --preset $CONFIG && cmake --build --preset $CONFIG)"; exit 1; }
mkdir -p "$fixtures"

echo "==> building the Go TLS fixture server"
(cd "$root/tests/tls-testserver" && go build -o "$server" .)

echo "==> starting $server on ${ADDR}:${PORT}"
"$server" -addr "${ADDR}:${PORT}" -out "$fixtures" >"$build/tls-server.log" 2>&1 &
srv=$!
trap 'kill $srv 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  [ -f "$fixtures/client.key" ] && break
  sleep 0.25
done
[ -f "$fixtures/client.key" ] || { echo "fixture server did not produce certificates"; cat "$build/tls-server.log"; exit 1; }

echo "==> handshake"
"$client" --tls-selftest "$ADDR" "$PORT" \
  "$fixtures/ca.pem" "$fixtures/client.pem" "$fixtures/client.key"

echo "==> handshake selftest passed"
