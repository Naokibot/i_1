#!/usr/bin/env bash
set -euo pipefail

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

sh -n deploy/ssh/pqm-ssh-relay
sh -n deploy/vpn/pqm-vpn-apply
sh -n deploy/vpn/switch-route.sh

# Validate that the installed OpenSSH client recognizes the configured PQ KEX.
ssh -G -F deploy/ssh/ssh_upstream_config relay.example >"$work/ssh-effective.conf"
grep -qi '^kexalgorithms .*mlkem768x25519-sha256' "$work/ssh-effective.conf"
grep -qi '^stricthostkeychecking yes' "$work/ssh-effective.conf"
grep -qi '^clearallforwardings yes' "$work/ssh-effective.conf"

# Validate the inbound sshd policy with an ephemeral host key.
ssh-keygen -q -t ed25519 -N '' -f "$work/host_key"
cat deploy/ssh/sshd_config >"$work/sshd_config"
printf '\nHostKey %s\nPidFile %s\nAuthorizedKeysFile none\nUsePAM no\n' \
  "$work/host_key" "$work/sshd.pid" >>"$work/sshd_config"
/usr/sbin/sshd -t -f "$work/sshd_config"
/usr/sbin/sshd -T -f "$work/sshd_config" >"$work/sshd-effective.conf"
grep -qi '^passwordauthentication no$' "$work/sshd-effective.conf"
grep -qi '^permitrootlogin no$' "$work/sshd-effective.conf"
grep -qi '^allowtcpforwarding no$' "$work/sshd-effective.conf"
grep -qi '^forcecommand /usr/local/libexec/pqm-ssh-relay$' "$work/sshd-effective.conf"

# Run the relay with only fixed path substitutions. The policy logic itself is unchanged.
mkdir -p "$work/etc/targets" "$work/etc/allowed-commands"
printf '%s\n' 'upstream@example.test' >"$work/etc/targets/tester"
printf '%s\n' 'echo approved' >"$work/etc/allowed-commands/tester"
cat >"$work/mock-ssh" <<'SH'
#!/bin/sh
printf '%s\n' "$@" >"${PQM_TEST_SSH_LOG:?}"
SH
chmod 0755 "$work/mock-ssh"
sed \
  -e "s#/etc/pqm/ssh#$work/etc#g" \
  -e "s#/usr/bin/ssh#$work/mock-ssh#g" \
  deploy/ssh/pqm-ssh-relay >"$work/relay"
chmod 0755 "$work/relay"
PQM_TEST_SSH_LOG="$work/ssh.log" USER=tester SSH_ORIGINAL_COMMAND='echo approved' "$work/relay"
grep -Fxq -- 'upstream@example.test' "$work/ssh.log"
grep -Fxq -- 'echo approved' "$work/ssh.log"
if PQM_TEST_SSH_LOG="$work/ssh.log" USER=tester SSH_ORIGINAL_COMMAND='echo' "$work/relay" >/dev/null 2>&1; then
  echo 'SSH relay accepted a partial allowlist match' >&2
  exit 1
fi
if PQM_TEST_SSH_LOG="$work/ssh.log" USER=tester SSH_ORIGINAL_COMMAND=$'echo approved\nwhoami' "$work/relay" >/dev/null 2>&1; then
  echo 'SSH relay accepted a command containing a control character' >&2
  exit 1
fi
printf '%s\n' $'upstream@example.test\nattacker@example.test' >"$work/etc/targets/tester"
if PQM_TEST_SSH_LOG="$work/ssh.log" USER=tester SSH_ORIGINAL_COMMAND='echo approved' "$work/relay" >/dev/null 2>&1; then
  echo 'SSH relay accepted a multiline upstream mapping' >&2
  exit 1
fi

# Exercise VPN validation and route switching with deterministic command adapters.
mkdir -p "$work/bin"
cat >"$work/bin/swanctl" <<'SH'
#!/bin/sh
printf 'swanctl' >>"${PQM_TEST_VPN_LOG:?}"
printf ' <%s>' "$@" >>"$PQM_TEST_VPN_LOG"
printf '\n' >>"$PQM_TEST_VPN_LOG"
SH
cat >"$work/bin/ip" <<'SH'
#!/bin/sh
printf 'ip' >>"${PQM_TEST_VPN_LOG:?}"
printf ' <%s>' "$@" >>"$PQM_TEST_VPN_LOG"
printf '\n' >>"$PQM_TEST_VPN_LOG"
SH
chmod 0755 "$work/bin/swanctl" "$work/bin/ip"
: >"$work/vpn.log"
PATH="$work/bin:$PATH" PQM_TEST_VPN_LOG="$work/vpn.log" \
  deploy/vpn/pqm-vpn-apply --check-config deploy/vpn/swanctl.conf
grep -Fxq 'swanctl <--load-conns> <--file> <deploy/vpn/swanctl.conf> <--noprompt>' "$work/vpn.log"
PATH="$work/bin:$PATH" PQM_TEST_VPN_LOG="$work/vpn.log" deploy/vpn/switch-route.sh pqc
PATH="$work/bin:$PATH" PQM_TEST_VPN_LOG="$work/vpn.log" deploy/vpn/switch-route.sh legacy
grep -Fxq 'swanctl <--initiate> <--child> <pqc-out>' "$work/vpn.log"
grep -Fxq 'ip <route> <replace> <10.30.0.0/16> <dev> <ipsec0> <metric> <10>' "$work/vpn.log"
grep -Fxq 'ip <route> <replace> <10.30.0.0/16> <dev> <ipsec1> <metric> <10>' "$work/vpn.log"
if PATH="$work/bin:$PATH" PQM_TEST_VPN_LOG="$work/vpn.log" deploy/vpn/switch-route.sh invalid >/dev/null 2>&1; then
  echo 'VPN route switch accepted an invalid mode' >&2
  exit 1
fi

printf '%s\n' 'SSH and VPN policy validation passed'
