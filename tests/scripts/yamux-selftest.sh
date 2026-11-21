#!/usr/bin/env bash
# yamux-selftest.sh - Linux/WSL counterpart of yamux-selftest.ps1
set -euo pipefail

CONFIG="${CONFIG:-wsl-gcc-debug}"
PORT="${PORT:-9444}"
ADDR="${ADDR:-127.0.0.1}"
AGE_PRIV="${AGE_PRIV:-AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="$root/build/$CONFIG"
fixtures="$build/yamux-fixtures"
server="$build/yamux-testserver"
client="$build/bin/implant"

[ -x "$client" ] || { echo "missing $client"; exit 1; }
mkdir -p "$fixtures"

echo "==> building the Go yamux interop server"
(cd "$root/tests/yamux-testserver" && go build -o "$server" .)

echo "==> starting $server on ${ADDR}:${PORT}"
"$server" -addr "${ADDR}:${PORT}" -age-priv "$AGE_PRIV" -out "$fixtures" \
  >"$build/yamux-server.log" 2>&1 &
srv=$!
trap 'kill $srv 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  [ -f "$fixtures/server.pub" ] && break
  sleep 0.25
done
[ -f "$fixtures/server.pub" ] || { echo "server.pub was not produced"; cat "$build/yamux-server.log"; exit 1; }

echo "==> yamux + frame roundtrip"
"$client" --yamux-selftest "$ADDR" "$PORT" "$AGE_PRIV" "$fixtures/server.pub"

cat "$build/yamux-server.log" || true
echo "==> yamux selftest passed"
