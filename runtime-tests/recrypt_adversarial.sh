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
WRONG_PRIVATE="$WORK_DIR/wrong-private.pem"
WRONG_PUBLIC="$WORK_DIR/wrong-public.pem"
GEN1="$WORK_DIR/source-gen1.pqm"
GEN2="$WORK_DIR/source-gen2.pqm"
SENTINEL="$WORK_DIR/sentinel.bin"

dd if=/dev/urandom of="$SOURCE" bs=1M count=2 status=none
printf 'existing-output-must-survive\n' > "$SENTINEL"

make_keypair() {
  local private_key="$1"
  local public_key="$2"
  "$OPENSSL_BIN" genpkey -algorithm "$KEM_ALG" -out "$private_key" "${OPENSSL_PROVIDER_ARGS[@]}"
  "$OPENSSL_BIN" pkey -in "$private_key" -pubout -out "$public_key" "${OPENSSL_PROVIDER_ARGS[@]}"
}

make_keypair "$KEY1_PRIVATE" "$KEY1_PUBLIC"
make_keypair "$KEY2_PRIVATE" "$KEY2_PUBLIC"
make_keypair "$WRONG_PRIVATE" "$WRONG_PUBLIC"

"${RECRYPT_CMD[@]}" encrypt \
  --input "$SOURCE" --output "$GEN1" \
  --public-key "$KEY1_PUBLIC" --key-id "adversarial-key-v1" \
  --kem-algorithm "$KEM_ALG" "${BACKEND_ARGS[@]}"

"${RECRYPT_CMD[@]}" rewrap \
  --input "$GEN1" --output "$GEN2" \
  --old-private-key "$KEY1_PRIVATE" \
  --new-public-key "$KEY2_PUBLIC" \
  --new-key-id "adversarial-key-v2" \
  --new-kem-algorithm "$KEM_ALG" "${BACKEND_ARGS[@]}"

expect_rejection_preserving_output() {
  local label="$1"
  local output="$2"
  shift 2
  cp "$SENTINEL" "$output"
  if "$@" >"$WORK_DIR/${label}.stdout" 2>"$WORK_DIR/${label}.stderr"; then
    printf 'expected rejection but command succeeded: %s\n' "$label" >&2
    return 1
  fi
  if ! cmp -s "$SENTINEL" "$output"; then
    printf 'failed operation replaced the pre-existing output: %s\n' "$label" >&2
    return 1
  fi
}

expect_rejection_preserving_output wrong-key "$WORK_DIR/wrong-key.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$GEN1" --output "$WORK_DIR/wrong-key.out" \
  --private-key "$WRONG_PRIVATE" "${BACKEND_ARGS[@]}"

python3 - "$GEN1" "$WORK_DIR/header-tampered.pqm" "$WORK_DIR/body-tampered.pqm" "$WORK_DIR/downgraded.pqm" "$WORK_DIR/unknown-field.pqm" <<'PY'
from pathlib import Path
import json
import struct
import sys

source, header_out, body_out, downgrade_out, unknown_out = sys.argv[1:]
raw = bytearray(Path(source).read_bytes())
header_length = struct.unpack(">I", raw[8:12])[0]
header_start = 12
body_start = header_start + header_length
header = json.loads(raw[header_start:body_start])


def rebuild(target: str, magic: bytes, value: dict) -> None:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    Path(target).write_bytes(magic + struct.pack(">I", len(encoded)) + encoded + raw[body_start:])

changed = dict(header)
changed["keyId"] = "attacker-controlled-key-id"
rebuild(header_out, bytes(raw[:8]), changed)

body = bytearray(raw)
if body_start + 8 >= len(body):
    raise SystemExit("encrypted body unexpectedly short")
body[body_start + 8] ^= 0x80
Path(body_out).write_bytes(body)

downgraded = dict(header)
downgraded["version"] = 1
downgraded.pop("generation", None)
downgraded.pop("headerMac", None)
downgraded.pop("lineage", None)
rebuild(downgrade_out, b"PQMENC01", downgraded)

unknown = dict(header)
unknown["unrecognizedSecurityField"] = True
rebuild(unknown_out, bytes(raw[:8]), unknown)
PY

expect_rejection_preserving_output header-tamper "$WORK_DIR/header-tamper.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$WORK_DIR/header-tampered.pqm" --output "$WORK_DIR/header-tamper.out" \
  --private-key "$KEY1_PRIVATE" --expected-key-id "attacker-controlled-key-id" \
  "${BACKEND_ARGS[@]}"

expect_rejection_preserving_output body-tamper "$WORK_DIR/body-tamper.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$WORK_DIR/body-tampered.pqm" --output "$WORK_DIR/body-tamper.out" \
  --private-key "$KEY1_PRIVATE" "${BACKEND_ARGS[@]}"

expect_rejection_preserving_output downgrade "$WORK_DIR/downgrade.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$WORK_DIR/downgraded.pqm" --output "$WORK_DIR/downgrade.out" \
  --private-key "$KEY1_PRIVATE" "${BACKEND_ARGS[@]}"

expect_rejection_preserving_output unknown-field "$WORK_DIR/unknown-field.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$WORK_DIR/unknown-field.pqm" --output "$WORK_DIR/unknown-field.out" \
  --private-key "$KEY1_PRIVATE" "${BACKEND_ARGS[@]}"

mapfile -t CUTS < <(python3 - "$GEN1" <<'PY'
from pathlib import Path
import struct
import sys
raw = Path(sys.argv[1]).read_bytes()
header_end = 12 + struct.unpack(">I", raw[8:12])[0]
for value in sorted({1, 8, 10, header_end - 1, header_end, len(raw) // 2, len(raw) - 1}):
    if 0 < value < len(raw):
        print(value)
PY
)
for cut in "${CUTS[@]}"; do
  truncated="$WORK_DIR/truncated-${cut}.pqm"
  head -c "$cut" "$GEN1" > "$truncated"
  expect_rejection_preserving_output "truncated-${cut}" "$WORK_DIR/truncated-${cut}.out" \
    "${RECRYPT_CMD[@]}" decrypt \
    --input "$truncated" --output "$WORK_DIR/truncated-${cut}.out" \
    --private-key "$KEY1_PRIVATE" "${BACKEND_ARGS[@]}"
done

expect_rejection_preserving_output rollback "$WORK_DIR/rollback.out" \
  "${RECRYPT_CMD[@]}" decrypt \
  --input "$GEN1" --output "$WORK_DIR/rollback.out" \
  --private-key "$KEY1_PRIVATE" \
  --minimum-generation 2 --expected-key-id "adversarial-key-v1" \
  --reject-legacy-v1 "${BACKEND_ARGS[@]}"

"${RECRYPT_CMD[@]}" decrypt \
  --input "$GEN2" --output "$WORK_DIR/gen2.recovered" \
  --private-key "$KEY2_PRIVATE" \
  --minimum-generation 2 --expected-key-id "adversarial-key-v2" \
  --reject-legacy-v1 "${BACKEND_ARGS[@]}"
cmp "$SOURCE" "$WORK_DIR/gen2.recovered"

if find "$WORK_DIR" -maxdepth 1 \( -name '*.pqm-journal' -o -name '.*.stage-*' -o -name '.*.backup-*' \) -print -quit | grep -q .; then
  printf 'transaction residue found after adversarial tests\n' >&2
  find "$WORK_DIR" -maxdepth 1 \( -name '*.pqm-journal' -o -name '.*.stage-*' -o -name '.*.backup-*' \) -print >&2
  exit 1
fi

printf 'adversarial re-encryption tests passed (tamper, truncation, wrong-key, rollback, downgrade)\n'
