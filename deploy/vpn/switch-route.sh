#!/bin/sh
set -eu
mode=${1:-}
case "$mode" in
  pqc)
    swanctl --initiate --child pqc-out
    ip route replace 10.30.0.0/16 dev ipsec0 metric 10
    ;;
  legacy)
    ip route replace 10.30.0.0/16 dev ipsec1 metric 10
    ;;
  *) echo "usage: $0 pqc|legacy" >&2; exit 2 ;;
esac
