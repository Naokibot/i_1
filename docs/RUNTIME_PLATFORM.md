# Post-Quantum Migration Runtime Platform

This directory extends the Observatory with traffic-changing runtime components. It is deliberately split into a control plane and independently deployable data-plane processes.

## What is implemented

- OpenSSL 3.5 TLS termination gateway with a classical client leg and TLS 1.3 ML-KEM or hybrid upstream leg
- Runtime controller with versioned desired state, deterministic canary assignment, metric gates, rollback state, and signed emergency directives
- Gateway agent that validates a candidate, replaces the process, performs a health check, and restores the previous revision on failure
- JSONL telemetry reporter that advances or rolls back a deployment from observed handshakes
- OpenSSL Provider boundary that works with the OpenSSL 3.5 default provider or an explicitly selected provider such as `oqsprovider`
- ML-KEM envelope encryption and DEK-only rewrapping for long-lived data
- AWS KMS and Google Cloud KMS signing adapters
- PKCS#11 proxy that forwards to a real vendor module, filters mechanisms, and writes an audit trail without exporting private keys
- Java JCA/JCE provider for explicit parallel classical and post-quantum signatures
- OpenSSH and strongSwan termination-gateway deployment profiles

## Trust boundaries

The TLS, SSH, and VPN gateways terminate one protected channel and establish a second protected channel. Plaintext exists inside the gateway process. Place gateways on dedicated hosts or isolated workloads, prevent core dumps, restrict debugging, mount private keys read-only where possible, and keep management traffic on a separate authenticated network.

A gateway does not make a classical endpoint-to-gateway segment quantum resistant. Every connection record keeps the two legs separate and reports the end-to-end result as partial PQC unless both endpoints are independently verified.

## Build

```bash
# Go services
go test -race ./...
go build ./cmd/runtime-controller
go build ./cmd/gateway-agent
go build ./cmd/telemetry-reporter
go build ./cmd/recrypt-worker
go build ./cmd/emergency-sign

# OpenSSL 3.5 gateway
cmake -S native/tls-gateway -B build/tls -DCMAKE_BUILD_TYPE=Release
cmake --build build/tls

# PKCS#11 proxy
cmake -S native/pkcs11-proxy -B build/pkcs11 -DCMAKE_BUILD_TYPE=Release
cmake --build build/pkcs11

# Java provider
cd java/migration-provider
./gradlew test
```

The Java module intentionally exposes `PQM-DUAL`; it never changes the meaning of `RSA`, `ECDSA`, or another standard JCA algorithm name.

## TLS data path

```text
legacy client
  | TLS 1.2/1.3, classical certificate
  v
pqm-tls-gateway
  | TLS 1.3, X25519MLKEM768 or an explicitly configured group
  v
managed upstream service
```

The gateway configuration is a `GatewayConfig` JSON document. Start with `config/tls-gateway.example.json`.

```bash
pqm-tls-gateway --check-config config/tls-gateway.example.json
pqm-tls-gateway --config config/tls-gateway.example.json
```

The native gateway loads the OpenSSL default provider and optionally a second provider. Standardized ML-KEM should use OpenSSL 3.5's default provider. `oqsprovider` is isolated in `deploy/oqs-lab` for interoperability experiments and non-standard algorithms.

## Runtime controller and agent

Start the controller with an API token and an emergency root key:

```bash
runtime-controller \
  -listen :8090 \
  -data data/runtime.json \
  -root /srv/pqm-data \
  -token "$PQM_RUNTIME_TOKEN" \
  -emergency-public-key "$PQM_EMERGENCY_PUBLIC_KEY" \
  -emergency-approvers /etc/pqm/approvers.json
```

A gateway host watches one deployment:

```bash
gateway-agent watch \
  -controller https://control.example.internal \
  -deployment deployment-... \
  -client-id gateway-tokyo-01 \
  -token "$PQM_RUNTIME_TOKEN"
```

The controller returns the stable or candidate revision using a stable hash of the service and client identity. When a candidate fails syntax validation, process startup, or the TCP health check, the agent starts the previous revision again and leaves the `current` symlink unchanged.

The telemetry reporter consumes the gateway JSONL file and posts a metric window. The controller automatically rolls back when the success, fallback, or p99 latency threshold is violated.

```bash
telemetry-reporter \
  -file /var/log/pqm/gateway.jsonl \
  -controller https://control.example.internal \
  -deployment deployment-... \
  -stable-p99 8.5 \
  -minimum-samples 500
```

## Re-encryption

The file format uses chunked AES-256-GCM for data and ML-KEM to establish a key-encryption key that wraps the 256-bit DEK. `rewrap` changes only the KEM ciphertext and wrapped DEK; it copies the authenticated encrypted payload without exposing the plaintext.

```bash
openssl genpkey -algorithm ML-KEM-768 -out keys/archive.pem
openssl pkey -in keys/archive.pem -pubout -out keys/archive.pub.pem

recrypt-worker \
  -mode encrypt \
  -source archive.tar \
  -destination archive.pqm \
  -public-key keys/archive.pub.pem \
  -key-id archive-2026

recrypt-worker \
  -mode decrypt \
  -source archive.pqm \
  -destination restored.tar \
  -private-key keys/archive.pem
```

Writes use a temporary file and atomic rename. Decryption verifies every GCM chunk, plaintext size, and the full SHA-256 digest before committing the output.

## Emergency algorithm exchange

Emergency execution requires:

1. an Ed25519 root signature over the directive;
2. two valid signatures from distinct, pre-registered approvers;
3. a current validity window;
4. a matching deployment that actually uses an affected group.

Generate the root and two approver keys separately:

```bash
emergency-sign -private-key root.key -public-key root.pub keygen
emergency-sign -private-key alice.key -public-key alice.pub keygen
emergency-sign -private-key bob.key -public-key bob.pub keygen
```

Sign and approve a directive without sharing private keys:

```bash
emergency-sign -private-key root.key \
  -input config/emergency-directive.example.json \
  -output /tmp/directive.root.json sign-root

emergency-sign -private-key alice.key -approver alice \
  -input /tmp/directive.root.json -output /tmp/directive.alice.json approve

emergency-sign -private-key bob.key -approver bob \
  -input /tmp/directive.alice.json -output /tmp/directive.ready.json approve
```

POST the final document to `/api/v1/emergencies/execute`. The controller prepares candidate revisions; normal validation, canary, telemetry, and rollback remain in force. Emergency mode does not bypass safety gates.

## HSM and KMS

For an HSM, set `PQM_PKCS11_BACKEND` to the vendor's module and load `libpqm-pkcs11.so` in the application. The proxy does not emulate unsupported mechanisms and does not export private keys. Build it against a PKCS#11 3.2 header when KEM entry points are required; older system headers provide the 2.40-compatible function list only.

AWS and Google Cloud adapters invoke their official CLIs without putting message bytes on the command line. They use private temporary files with mode `0600`, parse the returned signature, and propagate provider errors. Production deployments should normally replace the CLI runner with an SDK implementation and workload identity while retaining the same backend interface.

## Deliberate limits

- This repository is not a FIPS-validated cryptographic module.
- `oqsprovider` and liboqs are kept in a lab image, not the production gateway image.
- The TLS gateway currently forwards byte streams and does not rewrite HTTP headers or application protocols.
- OpenSSH and strongSwan deployments require host-level identity, routing, firewall, certificate, and account mapping owned by the operator.
- JSON state is suitable for a single control-plane node. A production clustered deployment should use PostgreSQL, authenticated agents, RBAC, and an append-only external audit sink.
- HSM and cloud feature availability must be discovered per device, firmware, region, and account rather than inferred from a vendor name.
