#!/bin/sh
set -eu
GATEWAY=${GATEWAY:-./build/tls/pqm-tls-gateway}
work=$(mktemp -d)
upstream_pid=
gateway_pid=
cleanup() {
  [ -z "$gateway_pid" ] || kill "$gateway_pid" 2>/dev/null || true
  [ -z "$upstream_pid" ] || kill "$upstream_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 >/dev/null 2>&1
cat > "$work/gateway.json" <<JSON
{
  "revision":"smoke",
  "kind":"tls",
  "listen":"127.0.0.1:18443",
  "upstream":"127.0.0.1:19443",
  "serverName":"localhost",
  "certificate":"$work/cert.pem",
  "privateKey":"$work/key.pem",
  "groups":["X25519MLKEM768"],
  "provider":"default",
  "verifyUpstream":false,
  "telemetryFile":"$work/telemetry.jsonl"
}
JSON
"$GATEWAY" --check-config "$work/gateway.json"
openssl s_server -quiet -www -accept 19443 -cert "$work/cert.pem" -key "$work/key.pem" \
  -tls1_3 -groups X25519MLKEM768 >"$work/upstream.log" 2>&1 &
upstream_pid=$!
"$GATEWAY" --config "$work/gateway.json" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
sleep 1
printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 openssl s_client \
  -connect 127.0.0.1:18443 -tls1_2 -quiet 2>/dev/null | grep -q 'HTTP/1.0 200 ok'
grep -q '"group":"X25519MLKEM768"' "$work/telemetry.jsonl"
printf '%s\n' 'TLS gateway smoke test passed'
