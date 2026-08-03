#!/bin/sh
set -eu

EXPECTED_OPENSSL_VERSION=${EXPECTED_OPENSSL_VERSION:-OpenSSL 3.5}
KEM_ALGORITHM=${PQM_INTEROP_KEM_ALGORITHM:-frodo640aes}
TLS_GROUP=${PQM_INTEROP_TLS_GROUP:-x25519_frodo640aes}

module=${OPENSSL_MODULES:-/opt/oqs-provider/lib/ossl-modules}/oqsprovider.so
work=$(mktemp -d)
server_pid=

print_log() {
  label=$1
  path=$2
  if [ -f "$path" ]; then
    printf '\n--- %s ---\n' "$label" >&2
    cat "$path" >&2
  fi
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    print_log providers "$work/providers.log"
    print_log kems "$work/kems.log"
    print_log server "$work/server.log"
    print_log client-stdout "$work/client.out"
    print_log client-stderr "$work/client.log"
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'oqs smoke failure: %s\n' "$1" >&2
  return 1
}

[ -r "$module" ] || fail "provider module is missing: $module"
export OPENSSL_MODULES

openssl version -a | tee "$work/version.log"
grep -F "$EXPECTED_OPENSSL_VERSION" "$work/version.log" >/dev/null \
  || fail "unexpected OpenSSL version"

openssl list \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -providers -verbose | tee "$work/providers.log"
grep -Eq '^[[:space:]]*oqsprovider[[:space:]]*$' "$work/providers.log" \
  || fail "oqsprovider did not load"

openssl list \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -kem-algorithms | tee "$work/kems.log"
grep -qi "$KEM_ALGORITHM" "$work/kems.log" \
  || fail "KEM algorithm is unavailable: $KEM_ALGORITHM"

# The FrodoKEM algorithm is intentionally selected because it is supplied by
# oqs-provider/liboqs and does not overlap OpenSSL 3.5's built-in ML-KEM.
openssl genpkey \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -algorithm "$KEM_ALGORITHM" \
  -out "$work/kem.key"
openssl pkey \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -in "$work/kem.key" \
  -pubout \
  -out "$work/kem.pub"
openssl pkeyutl \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -encap \
  -inkey "$work/kem.pub" \
  -pubin \
  -out "$work/ciphertext.bin" \
  -secret "$work/encapsulated-secret.bin"
openssl pkeyutl \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -decap \
  -inkey "$work/kem.key" \
  -in "$work/ciphertext.bin" \
  -secret "$work/decapsulated-secret.bin"
cmp "$work/encapsulated-secret.bin" "$work/decapsulated-secret.bin" \
  || fail "encapsulated and decapsulated secrets differ"

openssl req \
  -provider default \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -subj /CN=localhost \
  -keyout "$work/server.key" \
  -out "$work/server.crt" \
  -days 1 >/dev/null 2>&1

openssl s_server \
  -provider-path "$OPENSSL_MODULES" \
  -provider default \
  -provider oqsprovider \
  -www \
  -naccept 1 \
  -accept 19446 \
  -cert "$work/server.crt" \
  -key "$work/server.key" \
  -tls1_3 \
  -groups "$TLS_GROUP" >"$work/server.log" 2>&1 &
server_pid=$!

ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    fail "TLS server exited before accepting connections"
  fi
  if grep -q 'ACCEPT' "$work/server.log"; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
[ "$ready" -eq 1 ] || fail "TLS server did not become ready"

if ! printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
  timeout 20 openssl s_client \
    -provider-path "$OPENSSL_MODULES" \
    -provider default \
    -provider oqsprovider \
    -connect 127.0.0.1:19446 \
    -tls1_3 \
    -groups "$TLS_GROUP" \
    -brief >"$work/client.out" 2>"$work/client.log"; then
  fail "TLS 1.3 client handshake failed"
fi

grep -qi 'HTTP/1.0 200 ok' "$work/client.out" \
  || fail "TLS server did not return its status page"
grep -Eq 'Protocol version: TLSv1\.3|Protocol *: TLSv1\.3' "$work/client.log" \
  || fail "TLS 1.3 was not negotiated"

# OpenSSL 3.5 does not provide `openssl list -tls-groups`. Both peers are
# therefore restricted to TLS_GROUP and the successful TLS 1.3 handshake is
# the authoritative group-availability and interoperability check.
wait "$server_pid" || fail "TLS server exited with an error"
server_pid=

printf 'oqs-provider/liboqs interoperability passed: kem=%s group=%s\n' \
  "$KEM_ALGORITHM" "$TLS_GROUP"
