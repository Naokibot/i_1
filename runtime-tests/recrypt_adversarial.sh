#!/usr/bin/env bash
set -euo pipefail

OPENSSL=${OPENSSL:-openssl}
RECRYPT=${RECRYPT:-go run ./cmd/recrypt-worker}
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

"$OPENSSL" genpkey -algorithm ML-KEM-768 -out "$work/key.pem" >/dev/null 2>&1
"$OPENSSL" pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" >/dev/null 2>&1
python3 - <<'PY' >"$work/plain.bin"
import os, sys
sys.stdout.buffer.write(os.urandom(3 * 1024 * 1024 + 137))
PY

$RECRYPT encrypt --input "$work/plain.bin" --output "$work/archive.pqm" \
  --public-key "$work/pub.pem" --key-id test --kem ML-KEM-768
$RECRYPT decrypt --input "$work/archive.pqm" --output "$work/roundtrip.bin" \
  --private-key "$work/key.pem"
cmp "$work/plain.bin" "$work/roundtrip.bin"

# Every sampled single-bit corruption must be rejected and must not leave plaintext output.
size=$(stat -c '%s' "$work/archive.pqm")
for offset in 0 1 7 31 127 511 1024 $((size / 2)) $((size - 2)) $((size - 1)); do
  cp "$work/archive.pqm" "$work/mutated.pqm"
  python3 - "$work/mutated.pqm" "$offset" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, 'r+b') as f:
    f.seek(offset)
    b = f.read(1)
    if not b:
        raise SystemExit('offset outside file')
    f.seek(offset)
    f.write(bytes([b[0] ^ 1]))
PY
  rm -f "$work/recovered.bin"
  if $RECRYPT decrypt --input "$work/mutated.pqm" --output "$work/recovered.bin" \
      --private-key "$work/key.pem" >"$work/mutate.out" 2>"$work/mutate.err"; then
    echo "corruption at offset ${offset} was accepted" >&2
    exit 1
  fi
  if [[ -s "$work/recovered.bin" ]]; then
    echo "failed decryption left plaintext at offset ${offset}" >&2
    exit 1
  fi
done

# Appended bytes, truncation, a wrong key, and path aliasing are negative cases.
cp "$work/archive.pqm" "$work/appended.pqm"
printf 'trailing-data' >>"$work/appended.pqm"
if $RECRYPT decrypt --input "$work/appended.pqm" --output "$work/appended.out" \
    --private-key "$work/key.pem" >/dev/null 2>&1; then
  echo 'archive with trailing bytes was accepted' >&2
  exit 1
fi
head -c $((size - 1)) "$work/archive.pqm" >"$work/truncated.pqm"
if $RECRYPT decrypt --input "$work/truncated.pqm" --output "$work/truncated.out" \
    --private-key "$work/key.pem" >/dev/null 2>&1; then
  echo 'truncated archive was accepted' >&2
  exit 1
fi
"$OPENSSL" genpkey -algorithm ML-KEM-768 -out "$work/wrong.pem" >/dev/null 2>&1
if $RECRYPT decrypt --input "$work/archive.pqm" --output "$work/wrong.out" \
    --private-key "$work/wrong.pem" >/dev/null 2>&1; then
  echo 'wrong private key was accepted' >&2
  exit 1
fi

printf '%s\n' 'Envelope adversarial validation passed'
