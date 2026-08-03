# Post-Quantum Migration Observatory

A runnable MVP for the first stage of a crypto-agile migration platform. It discovers cryptographic dependencies without changing production traffic, generates a CycloneDX 1.7 CBOM, calculates quantum-migration risk, records endpoint capability, detects capability regression, and recommends a reversible migration stage.

> This is **MVP 1: Observatory**. It is not a certified PQC implementation, a production TLS termination gateway, or a claim that legacy endpoint-to-gateway traffic is quantum resistant.

## Implemented

- Active TLS discovery: negotiated TLS version, cipher suite, certificate chain, key type/size, signature algorithm, expiry, and validation findings
- Active SSH discovery: server banner and KEXINIT algorithm lists without authenticating
- Source discovery for Java, .NET, OpenSSL-style APIs, configuration files, and common weak primitives
- Persistent cryptographic asset inventory in an atomic local JSON state file
- Risk score based on confidentiality, retention period, exposure, classical dependency, criticality, update difficulty, and alternatives
- Migration recommendation from Observe through Legacy Removal
- Explicit path truth: classical sections, hybrid PQC, or an end-to-end PQC candidate
- CycloneDX 1.7 CBOM export with cryptographic assets and dependency relationships
- Capability registry with downgrade-suspect detection
- JSON crypto-policy compiler
- SHA-256 hash-chained audit events and verification endpoint
- Responsive embedded dashboard and REST API
- Loopback-only default listener, optional bearer authentication, bounded HTTP requests, and bounded scan concurrency
- Docker image, Compose file, race-enabled tests, vet/build CI, and reachable Go vulnerability scanning

## Run

```bash
make run
```

Open `http://127.0.0.1:8080`.

The source scanner only accepts paths under `-source-root`. The default is the current directory. The observer binds to loopback by default so a local development run does not require an API token.

```bash
go run ./cmd/observer -listen=127.0.0.1:8080 -data=data/observatory.json -source-root=.
```

A non-loopback listener requires a bearer token containing at least 32 characters. Put TLS in front of the service before allowing access from another host; bearer tokens must not be sent over an unencrypted network.

```bash
PQM_API_TOKEN="$(openssl rand -hex 32)" \
  go run ./cmd/observer -listen=0.0.0.0:8080 -data=data/observatory.json -source-root=.
```

Try the included legacy sample from the dashboard with:

```text
kind: source
target: samples/legacy-java
```

Or use the local API:

```bash
curl -sS http://127.0.0.1:8080/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{
    "kind":"tls",
    "target":"example.com",
    "port":443,
    "dataClassification":"confidential",
    "retentionDays":3650,
    "internetExposed":true,
    "businessCriticality":4,
    "updateability":"moderate",
    "hasAlternative":false,
    "harvestNowRisk":"high"
  }'
```

For a token-protected deployment, add `-H "Authorization: Bearer $PQM_API_TOKEN"` to API requests. The dashboard requests the token and retains it only in browser session storage.

The scan is asynchronous. Poll `/api/v1/scans/{scanId}` and read the resulting `assetId`.

## Important endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/scans` | Start TLS, SSH, or source discovery |
| `GET` | `/api/v1/assets` | Risk-sorted cryptographic inventory |
| `POST` | `/api/v1/assets/{id}/context` | Update business/data context and recalculate risk |
| `GET` | `/api/v1/findings` | Discovery findings |
| `GET` | `/api/v1/cbom` | Download CycloneDX CBOM |
| `POST` | `/api/v1/capabilities/report` | Record algorithms supported by a subject |
| `POST` | `/api/v1/policy/compile` | Compile organization policy into an executable profile |
| `GET` | `/api/v1/audit/verify` | Verify the audit hash chain |

## Capability regression example

```bash
curl -sS http://127.0.0.1:8080/api/v1/capabilities/report \
  -H 'content-type: application/json' \
  -d '{"subject":"payments.example","algorithms":{"RSA":true,"X25519":true,"ML-KEM":true}}'

curl -sS http://127.0.0.1:8080/api/v1/capabilities/report \
  -H 'content-type: application/json' \
  -d '{"subject":"payments.example","algorithms":{"RSA":true}}'
```

The second report is marked `downgradeSuspect: true`.

## Policy compiler

```bash
curl -sS http://127.0.0.1:8080/api/v1/policy/compile \
  -H 'content-type: application/json' \
  --data-binary @config/example-policy.json
```

The compiler always emits an explicit warning when a temporary gateway is allowed: the legacy endpoint-to-gateway segment remains classical.

## Docker

Generate a token, then start the service:

```bash
export PQM_API_TOKEN="$(openssl rand -hex 32)"
docker compose up --build
```

Compose publishes the service only on host loopback at `127.0.0.1:8080`, drops Linux capabilities, enables `no-new-privileges`, and uses a read-only root filesystem. The repository is mounted read-only at `/workspace`, so source targets are paths relative to the repository root.

## Architecture

```text
Browser / REST client
        |
Embedded Go control plane
        |-- TLS discovery
        |-- SSH KEX discovery
        |-- source scanner
        |-- risk and migration engine
        |-- capability registry
        |-- policy compiler
        |-- CycloneDX CBOM generator
        `-- atomic state + hash-chained audit log
```

## Deliberate limits

- Go's standard TLS client records the negotiated protocol/cipher and certificate state, but this MVP does not inject a custom OpenSSL provider or negotiate experimental ML-KEM groups.
- The SSH scanner observes server proposals only; it does not authenticate or alter the server.
- Pattern-based source discovery produces leads, not proof that a code path is reachable.
- JSON persistence is intended for a single-node MVP. The next deployment step should replace it with PostgreSQL plus a graph store and authenticated multi-tenant APIs.
- The SHA-256 audit chain can detect accidental or unsophisticated edits, but it is not a keyed or externally anchored tamper-proof ledger.
- CBOM export uses CycloneDX 1.7 cryptographic asset objects. Validate generated output as part of a production release process.
- Runtime gateway, PKCS#11, re-encryption, SSH, and VPN components remain experimental and require the separate runtime validation workflows and production hardening review.

## Recommended next milestones

1. Add authenticated tenants, PostgreSQL, RBAC, and signed scan-agent enrollment.
2. Add passive ClientHello and SSH telemetry ingestion with privacy controls.
3. Add repository/CI scanning and binary/OID extraction.
4. Validate every CBOM with the official CycloneDX JSON schema in CI.
5. Require signed desired state, pinned gateway binaries, mTLS controller enrollment, and replay protection for gateway agents.
6. Add strict upstream identity checks, connection quotas, health thresholds, and rollback orchestration before any production traffic change.
