# Runtime security requirements

## Never deploy with defaults

- Require HTTPS or mTLS in front of the runtime controller.
- Set a high-entropy API token and rotate it.
- Keep the emergency root private key offline.
- Store each approver private key separately.
- Run gateway and proxy processes as dedicated non-root users.
- Disable core dumps and ptrace for processes that terminate TLS or unwrap a DEK.
- Restrict egress from a gateway to declared upstream endpoints.
- Mount certificate and key directories read-only.
- Forward audit and telemetry files to an append-only external system.

## Failure behavior

- Unsupported PQC or HSM operations fail closed.
- Provider loading failures stop startup.
- Upstream certificate verification is enabled unless explicitly disabled in a lab configuration.
- A candidate is activated only after configuration validation and a health check.
- A failed candidate causes the previous revision to be started again.
- A metric threshold violation clears the candidate and returns desired state to stable.
- Re-encryption never deletes the source or old key. Revocation is a separate, reviewed operation after read verification and backup validation.

## Secrets

The control plane stores key references and file paths, not secret key bytes. The re-encryption worker necessarily holds a DEK and KEM shared secret in process memory for a short period; buffers are overwritten after use. This does not protect against a compromised process, kernel, hypervisor, debugger, or physical host.
