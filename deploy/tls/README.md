# TLS gateway deployment

Build the native gateway with OpenSSL 3.5 or build the provided container image. Mount listener certificates, the upstream trust store, and a writable telemetry directory. The production image uses the OpenSSL default provider. Select `oqsprovider` only in the isolated lab image.

The gateway is a TLS terminator. Route only explicitly approved services through it and record both legs in the inventory. Run `runtime-tests/tls_gateway_smoke.sh` before deploying a new OpenSSL patch or group policy.
