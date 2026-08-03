# Native OpenSSL 3.5 TLS gateway

`pqm-tls-gateway` terminates an inbound TLS connection and creates a separate TLS 1.3 connection to the upstream service. The upstream named-group list is mandatory and is applied with `SSL_CTX_set1_groups_list`.

The listener accepts TLS 1.2 or later so that legacy clients can be migrated without an application rewrite. This means the client leg may remain classical. Telemetry always records client and upstream legs separately.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

OpenSSL 3.5 or later is required. The container build pins an OpenSSL release and verifies the published SHA-256 file before compilation.

## Process contract

The executable supports the Gateway Agent contract:

```bash
pqm-tls-gateway --check-config gateway.json
pqm-tls-gateway --config gateway.json
```

The process exits on provider, certificate, private-key, trust-store, or group configuration errors. On shutdown it stops accepting new clients, waits for active connection threads, then releases SSL contexts and providers.
