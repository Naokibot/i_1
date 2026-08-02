#!/bin/sh
set -eu
RECRYPT=${RECRYPT:-go run ./cmd/recrypt-worker}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
printf '%s\n' 'long-lived archive record' > "$work/plain"
openssl genpkey -algorithm ML-KEM-768 -out "$work/private.pem"
openssl pkey -in "$work/private.pem" -pubout -out "$work/public.pem"
$RECRYPT -mode encrypt -source "$work/plain" -destination "$work/encrypted" \
  -public-key "$work/public.pem" -key-id smoke
$RECRYPT -mode decrypt -source "$work/encrypted" -destination "$work/restored" \
  -private-key "$work/private.pem"
cmp "$work/plain" "$work/restored"
printf '%s\n' 'ML-KEM re-encryption smoke test passed'
