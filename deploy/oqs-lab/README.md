# oqs-provider interoperability lab

This image compiles pinned OpenSSL, liboqs, and oqs-provider versions and loads both providers. It is for algorithm sandboxing, test vectors, and interoperability tests. It is intentionally separate from the production TLS gateway image. Do not mount production keys or sensitive customer traffic into this container.
