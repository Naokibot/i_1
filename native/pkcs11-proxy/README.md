# PKCS#11 policy proxy

The proxy loads a vendor PKCS#11 module and returns a copied function table with policy checks around mechanism enumeration, key generation, signing, verification, wrapping, and unwrapping.

Required environment:

```text
PQM_PKCS11_BACKEND=/opt/vendor/lib/libCryptoki2.so
```

Optional policy:

```text
PQM_PKCS11_ALLOWED_MECHANISMS=CKM_ML_DSA,CKM_ML_KEM,CKM_AES_GCM
PQM_PKCS11_DENIED_MECHANISMS=CKM_RSA_PKCS,CKM_SHA1_RSA_PKCS,CKM_AES_ECB,CKM_DES3_CBC
PQM_PKCS11_AUDIT=/var/log/pqm/pkcs11-audit.jsonl
```

No software fallback is implemented. An unavailable or disallowed HSM operation returns a PKCS#11 error.
