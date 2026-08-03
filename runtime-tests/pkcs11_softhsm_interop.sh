#!/usr/bin/env bash
set -euo pipefail

PROXY=${PROXY:-./build/pkcs11/libpqm-pkcs11.so}
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

backend=
for candidate in \
  /usr/lib/softhsm/libsofthsm2.so \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
  if [[ -f "$candidate" ]]; then
    backend=$candidate
    break
  fi
done
if [[ -z "$backend" ]]; then
  echo 'SoftHSM2 module was not found' >&2
  exit 1
fi

mkdir -p "$work/tokens"
cat >"$work/softhsm2.conf" <<EOF
log.level = ERROR
objectstore.backend = file
directories.tokendir = $work/tokens
slots.removable = false
EOF
export SOFTHSM2_CONF="$work/softhsm2.conf"
softhsm2-util --init-token --free --label pqm-test --so-pin 12345678 --pin 1234 >/dev/null

export PQM_PKCS11_BACKEND="$backend"
export PQM_PKCS11_AUDIT="$work/audit.jsonl"
export PQM_PKCS11_ALLOWED_MECHANISMS='CKM_RSA_PKCS_PSS,CKM_SHA256_RSA_PKCS_PSS,CKM_ECDSA,CKM_AES_GCM'

pkcs11-tool --module "$PROXY" --list-slots | grep -q 'pqm-test'
pkcs11-tool --module "$PROXY" --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label signing-key --id 01 >/dev/null
printf 'post-quantum migration proxy interop\n' >"$work/message.bin"
pkcs11-tool --module "$PROXY" --login --pin 1234 --id 01 \
  --sign --mechanism RSA-PKCS-PSS --hash-algorithm SHA256 \
  --input-file "$work/message.bin" --output-file "$work/signature.bin" >/dev/null
[[ -s "$work/signature.bin" ]]
grep -q '"operation":"C_GenerateKeyPair"' "$work/audit.jsonl"
grep -q '"operation":"C_SignInit"' "$work/audit.jsonl"
grep -q '"operation":"C_Sign"' "$work/audit.jsonl"

# The default deny policy must prevent legacy SHA-1/RSA signing.
unset PQM_PKCS11_ALLOWED_MECHANISMS
export PQM_PKCS11_DENIED_MECHANISMS='CKM_RSA_PKCS,CKM_SHA1_RSA_PKCS,CKM_AES_ECB,CKM_DES3_CBC'
if pkcs11-tool --module "$PROXY" --login --pin 1234 --id 01 \
  --sign --mechanism SHA1-RSA-PKCS \
  --input-file "$work/message.bin" --output-file "$work/legacy-signature.bin" \
  >"$work/legacy.out" 2>"$work/legacy.err"; then
  echo 'legacy SHA-1/RSA signing was not blocked' >&2
  exit 1
fi
grep -q '"operation":"C_SignInit"' "$work/audit.jsonl"
grep -q '"result":112' "$work/audit.jsonl" || grep -q '"result":112}' "$work/audit.jsonl"

printf '%s\n' 'PKCS#11 SoftHSM2 interoperability validation passed'
