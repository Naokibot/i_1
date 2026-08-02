# HSM and cloud KMS integration

`internal/runtime/openssl.go` contains adapters for OpenSSL Provider operations, AWS KMS signing, and Google Cloud KMS signing. Message bytes are written to mode-0600 temporary files rather than command-line arguments. Use workload identity and replace the CLI runner with the vendor SDK for a long-running production service.

For on-premises HSMs, load `native/pkcs11-proxy/libpqm-pkcs11.so` and set:

```bash
export PQM_PKCS11_BACKEND=/opt/vendor/lib/libCryptoki.so
export PQM_PKCS11_ALLOWED_MECHANISMS=CKM_ML_DSA,CKM_ML_KEM,CKM_AES_GCM
export PQM_PKCS11_AUDIT=/var/log/pqm/pkcs11.jsonl
```

The proxy forwards object and session operations to the vendor library. It filters mechanism discovery and rejects disallowed signing, verification, key generation, wrapping, and unwrapping requests. There is no software-key fallback.
