#!/usr/bin/env bash
set -euo pipefail

GATEWAY=${GATEWAY:-./build/tls/pqm-tls-gateway}
OPENSSL=${OPENSSL:-openssl}
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

start_upstream() {
  local port=$1 cert=$2 key=$3 groups=$4 log=$5
  "$OPENSSL" s_server -quiet -www -accept "$port" -cert "$cert" -key "$key" \
    -tls1_3 -groups "$groups" >"$log" 2>&1 &
  pids+=("$!")
}

start_gateway() {
  local config=$1 log=$2
  "$GATEWAY" --config "$config" >"$log" 2>&1 &
  pids+=("$!")
  sleep 1
  kill -0 "${pids[-1]}"
}

expect_http_success() {
  local port=$1
  printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 "$OPENSSL" s_client \
    -connect "127.0.0.1:${port}" -tls1_2 -quiet 2>/dev/null | grep -q 'HTTP/1.0 200 ok'
}

expect_handshake_failure() {
  local port=$1 mode=$2
  if printf 'GET / HTTP/1.0\r\n\r\n' | timeout 6 "$OPENSSL" s_client \
      -connect "127.0.0.1:${port}" "$mode" -quiet >"$work/rejected.out" 2>"$work/rejected.err"; then
    if grep -q 'HTTP/1.0 200 ok' "$work/rejected.out"; then
      echo "unexpected successful handshake on port ${port} with ${mode}" >&2
      return 1
    fi
  fi
}

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost' \
  -keyout "$work/trusted.key" -out "$work/trusted.crt" -days 1 >/dev/null 2>&1
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost' \
  -keyout "$work/untrusted.key" -out "$work/untrusted.crt" -days 1 >/dev/null 2>&1

# Verified hybrid upstream: classical downstream remains supported, TLS 1.1 is rejected.
start_upstream 29443 "$work/trusted.crt" "$work/trusted.key" X25519MLKEM768 "$work/hybrid-upstream.log"
cat >"$work/hybrid.json" <<JSON
{
  "revision":"security-hybrid",
  "listen":"127.0.0.1:28443",
  "upstream":"127.0.0.1:29443",
  "serverName":"localhost",
  "certificate":"$work/trusted.crt",
  "privateKey":"$work/trusted.key",
  "caFile":"$work/trusted.crt",
  "groups":["X25519MLKEM768"],
  "provider":"default",
  "verifyUpstream":true,
  "telemetryFile":"$work/hybrid.jsonl"
}
JSON
"$GATEWAY" --check-config "$work/hybrid.json"
start_gateway "$work/hybrid.json" "$work/hybrid-gateway.log"
expect_http_success 28443
expect_handshake_failure 28443 -tls1_1
grep -q '"group":"X25519MLKEM768"' "$work/hybrid.jsonl"

# Malformed and plaintext traffic must not terminate the process.
python3 - <<'PY'
import os
import socket
for payload in (b"GET / HTTP/1.0\r\n\r\n", b"\x16\x03\x03\xff\xff", os.urandom(4096)):
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", 28443), timeout=1) as sock:
                sock.sendall(payload)
        except OSError:
            pass
PY
kill -0 "${pids[-1]}"
expect_http_success 28443

# A classical-only upstream must not be accepted when the policy requires ML-KEM.
start_upstream 29444 "$work/trusted.crt" "$work/trusted.key" X25519 "$work/classical-upstream.log"
cat >"$work/classical.json" <<JSON
{
  "revision":"security-classical-reject",
  "listen":"127.0.0.1:28444",
  "upstream":"127.0.0.1:29444",
  "serverName":"localhost",
  "certificate":"$work/trusted.crt",
  "privateKey":"$work/trusted.key",
  "caFile":"$work/trusted.crt",
  "groups":["X25519MLKEM768"],
  "provider":"default",
  "verifyUpstream":true,
  "telemetryFile":"$work/classical.jsonl"
}
JSON
start_gateway "$work/classical.json" "$work/classical-gateway.log"
expect_handshake_failure 28444 -tls1_2
if grep -q '"result":"success"' "$work/classical.jsonl" 2>/dev/null; then
  echo 'classical upstream was incorrectly accepted' >&2
  exit 1
fi

# An untrusted upstream certificate must be rejected even with the correct group.
start_upstream 29445 "$work/untrusted.crt" "$work/untrusted.key" X25519MLKEM768 "$work/untrusted-upstream.log"
cat >"$work/untrusted.json" <<JSON
{
  "revision":"security-untrusted-reject",
  "listen":"127.0.0.1:28445",
  "upstream":"127.0.0.1:29445",
  "serverName":"localhost",
  "certificate":"$work/trusted.crt",
  "privateKey":"$work/trusted.key",
  "caFile":"$work/trusted.crt",
  "groups":["X25519MLKEM768"],
  "provider":"default",
  "verifyUpstream":true,
  "telemetryFile":"$work/untrusted.jsonl"
}
JSON
start_gateway "$work/untrusted.json" "$work/untrusted-gateway.log"
expect_handshake_failure 28445 -tls1_2
if grep -q '"result":"success"' "$work/untrusted.jsonl" 2>/dev/null; then
  echo 'untrusted upstream certificate was incorrectly accepted' >&2
  exit 1
fi

printf '%s\n' 'TLS gateway adversarial validation passed'
