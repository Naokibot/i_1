#!/usr/bin/env bash
set -euo pipefail

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
PROVIDER="${PROVIDER:-default}"
PROVIDER_PATH="${PROVIDER_PATH:-}"
KEM_ALG="${KEM_ALG:-ML-KEM-768}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${RECRYPT:-}" ]]; then
  RECRYPT_CMD=("$RECRYPT")
else
  RECRYPT_CMD=(go run ./cmd/recrypt-worker)
fi

BACKEND_ARGS=(--openssl "$OPENSSL_BIN" --provider "$PROVIDER")
OPENSSL_PROVIDER_ARGS=(-provider "$PROVIDER")
if [[ -n "$PROVIDER_PATH" ]]; then
  BACKEND_ARGS+=(--provider-path "$PROVIDER_PATH")
  OPENSSL_PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${OPENSSL_PROVIDER_ARGS[@]}")
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

SOURCE="$WORK_DIR/source.bin"
KEY1_PRIVATE="$WORK_DIR/key1-private.pem"
KEY1_PUBLIC="$WORK_DIR/key1-public.pem"
KEY2_PRIVATE="$WORK_DIR/key2-private.pem"
KEY2_PUBLIC="$WORK_DIR/key2-public.pem"
GEN1="$WORK_DIR/source-gen1.pqm"
GEN2="$WORK_DIR/source-gen2.pqm"
RECOVERED1="$WORK_DIR/source-gen1.recovered"
RECOVERED2="$WORK_DIR/source-gen2.recovered"

dd if=/dev/urandom of="$SOURCE" bs=1M count=5 status=none

make_keypair() {
  local private_key="$1"
  local public_key="$2"
  "$OPENSSL_BIN" genpkey -algorithm "$KEM_ALG" -out "$private_key" "${OPENSSL_PROVIDER_ARGS[@]}"
  "$OPENSSL_BIN" pkey -in "$private_key" -pubout -out "$public_key" "${OPENSSL_PROVIDER_ARGS[@]}"
}

make_keypair "$KEY1_PRIVATE" "$KEY1_PUBLIC"
make_keypair "$KEY2_PRIVATE" "$KEY2_PUBLIC"

"${RECRYPT_CMD[@]}" encrypt \
  --input "$SOURCE" \
  --output "$GEN1" \
  --public-key "$KEY1_PUBLIC" \
  --key-id "smoke-key-v1" \
  --kem-algorithm "$KEM_ALG" \
  "${BACKEND_ARGS[@]}"

"${RECRYPT_CMD[@]}" decrypt \
  --input "$GEN1" \
  --output "$RECOVERED1" \
  --private-key "$KEY1_PRIVATE" \
  --minimum-generation 1 \
  --expected-key-id "smoke-key-v1" \
  --reject-legacy-v1 \
  "${BACKEND_ARGS[@]}"
cmp "$SOURCE" "$RECOVERED1"

"${RECRYPT_CMD[@]}" rewrap \
  --input "$GEN1" \
  --output "$GEN2" \
  --old-private-key "$KEY1_PRIVATE" \
  --new-public-key "$KEY2_PUBLIC" \
  --new-key-id "smoke-key-v2" \
  --new-kem-algorithm "$KEM_ALG" \
  "${BACKEND_ARGS[@]}"

python3 - "$GEN1" "$GEN2" <<'PY'
from pathlib import Path
import struct
import sys

def body(path: str) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) < 12:
        raise SystemExit(f"{path}: envelope too short")
    header_length = struct.unpack(">I", raw[8:12])[0]
    body_offset = 12 + header_length
    if body_offset >= len(raw):
        raise SystemExit(f"{path}: missing encrypted body")
    return raw[body_offset:]

if body(sys.argv[1]) != body(sys.argv[2]):
    raise SystemExit("rewrap changed the encrypted payload body")
PY

"${RECRYPT_CMD[@]}" decrypt \
  --input "$GEN2" \
  --output "$RECOVERED2" \
  --private-key "$KEY2_PRIVATE" \
  --minimum-generation 2 \
  --expected-key-id "smoke-key-v2" \
  --reject-legacy-v1 \
  "${BACKEND_ARGS[@]}"
cmp "$SOURCE" "$RECOVERED2"

printf 're-encryption smoke test passed (algorithm=%s, generations=1->2, bytes=%s)\n' \
  "$KEM_ALG" "$(wc -c < "$SOURCE")"
