#!/bin/sh
set -eu
openssl version -a
openssl list -providers
openssl list -kem-algorithms -provider default
openssl list -kem-algorithms -provider oqsprovider
printf '%s\n' 'oqs-provider lab is ready; do not use this image for production secrets.'
