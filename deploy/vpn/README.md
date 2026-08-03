# VPN translation gateway

The sample terminates a legacy IKEv2 tunnel and establishes a separate outbound strongSwan tunnel using additional ML-KEM key exchange. Keep both children available during migration. Route only a canary subnet or marked flow over the PQC child, verify health, then move the remaining routes. A rollback replaces the route and does not destroy the old security association.
