#!/bin/sh
set -eu

work=$(mktemp -d)
server_pid=
cleanup() {
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

openssl version -a
openssl list -providers | grep -q oqsprovider
openssl list -kem-algorithms -provider oqsprovider | grep -qi frodo640aes
openssl list -tls-groups -tls1_3 | grep -qi x25519_frodo640aes

# Exercise a liboqs-backed KEM through the OpenSSL provider API.
openssl genpkey -algorithm frodo640aes -out "$work/frodo.key"
openssl pkey -in "$work/frodo.key" -pubout -out "$work/frodo.pub"
openssl pkeyutl -encap -inkey "$work/frodo.pub" -pubin \
  -out "$work/ciphertext.bin" -secret "$work/encapsulated-secret.bin"
openssl pkeyutl -decap -inkey "$work/frodo.key" -in "$work/ciphertext.bin" \
  -secret "$work/decapsulated-secret.bin"
cmp "$work/encapsulated-secret.bin" "$work/decapsulated-secret.bin"

# Exercise a real TLS 1.3 handshake using an oqs-provider/liboqs hybrid group.
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$work/server.key" -out "$work/server.crt" -days 1 >/dev/null 2>&1
openssl s_server -quiet -www -accept 19446 -cert "$work/server.crt" -key "$work/server.key" \
  -tls1_3 -groups x25519_frodo640aes >"$work/server.log" 2>&1 &
server_pid=$!
sleep 1
printf 'GET / HTTP/1.0\r\n\r\n' | timeout 15 openssl s_client \
  -connect 127.0.0.1:19446 -tls1_3 -groups x25519_frodo640aes \
  -brief >"$work/client.out" 2>"$work/client.log"
grep -q 'HTTP/1.0 200 ok' "$work/client.out"
grep -qi 'x25519_frodo640aes' "$work/client.log"

printf '%s\n' 'oqs-provider/liboqs KEM and TLS interoperability passed.'
