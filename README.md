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
- Docker image, Compose file, tests, vet/build CI

## Run

```bash
make run
```

Open `http://localhost:8080`.

The source scanner only accepts paths under `-source-root`. The default is the current directory.

```bash
go run ./cmd/observer -listen=:8080 -data=data/observatory.json -source-root=.
```

Try the included legacy sample from the dashboard with:

```text
kind: source
target: samples/legacy-java
```

Or use the API:

```bash
curl -sS http://localhost:8080/api/v1/scans \
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
curl -sS http://localhost:8080/api/v1/capabilities/report \
  -H 'content-type: application/json' \
  -d '{"subject":"payments.example","algorithms":{"RSA":true,"X25519":true,"ML-KEM":true}}'

curl -sS http://localhost:8080/api/v1/capabilities/report \
  -H 'content-type: application/json' \
  -d '{"subject":"payments.example","algorithms":{"RSA":true}}'
```

The second report is marked `downgradeSuspect: true`.

## Policy compiler

```bash
curl -sS http://localhost:8080/api/v1/policy/compile \
  -H 'content-type: application/json' \
  --data-binary @config/example-policy.json
```

The compiler always emits an explicit warning when a temporary gateway is allowed: the legacy endpoint-to-gateway segment remains classical.

## Docker

```bash
docker compose up --build
```

The repository is mounted read-only at `/workspace`, so source targets are paths relative to the repository root.

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
- CBOM export uses CycloneDX 1.7 cryptographic asset objects. Validate generated output as part of a production release process.
- No runtime hook, HSM, PKCS#11 proxy, data re-encryption worker, TLS gateway, or automatic rollback actuator is included yet.

## Recommended next milestones

1. Add authenticated tenants, PostgreSQL, RBAC, and signed scan-agent enrollment.
2. Add passive ClientHello and SSH telemetry ingestion with privacy controls.
3. Add repository/CI scanning and binary/OID extraction.
4. Validate every CBOM with the official CycloneDX JSON schema in CI.
5. Build a separate OpenSSL 3.5 gateway experiment using a provider boundary; keep experimental algorithms outside this control-plane binary.
6. Add canary policy, health thresholds, and rollback orchestration before any traffic-changing feature.
