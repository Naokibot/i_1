# Security

This repository is an observability MVP, not a certified cryptographic module or production TLS/PQC gateway.

Do not expose the API directly to an untrusted network. Put authentication, authorization, TLS, network policy, and rate limiting in front of it. Source scans are restricted to the configured source root, but that root may still contain sensitive code.

Report vulnerabilities privately through GitHub Security Advisories. Do not include real keys, certificates, customer source code, or production scan data in an issue.
