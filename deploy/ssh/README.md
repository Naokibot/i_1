# SSH translation gateway

The inbound `sshd` authenticates the legacy administrator and terminates that SSH session. `pqm-ssh-relay` then opens a separate upstream SSH session whose key exchange is restricted to `mlkem768x25519-sha256`. Per-user target mappings and known-hosts pinning are mandatory. Commands are denied unless a per-user allow file exists.

This is not a transparent TCP proxy. A transparent proxy would preserve the original end-to-end SSH handshake and could not translate the key exchange algorithm.
