# Security Policy

## Supported releases

Only the latest published `blindmachine` release receives security fixes. The CLI
handles private data and cryptographic keys, so users should not remain on an older
release after a security update is published.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/blindmachine/blind/security/advisories/new).
Do not open a public issue for an unpatched vulnerability and do not include real
credentials, private keys, genomic data, or other sensitive records in a report.

Useful reports include the affected version, operating system, container runtime,
reproduction steps using synthetic data, impact, and any proposed mitigation. We
will acknowledge a report through the private advisory and coordinate disclosure
after a fix is available.

## Security boundaries

- Application bundles must pass digest and pinned Ed25519 verification before use.
- Dependency installation occurs in a data-free container build phase.
- Every data-bearing application stage runs in a digest-pinned container with no
  network, a read-only root, a non-root UID, dropped capabilities,
  `no-new-privileges`, bounded memory/CPU/PIDs/files, a read-only output directory,
  and only the predeclared, size-bounded output files mounted writable.
- Private keys use the operating-system keychain by default. Plaintext file storage
  requires the explicit `BLIND_SECRET_BACKEND=file` escape hatch and is reported as
  insecure by `blind doctor`.
- PyPI releases are built from clean tags and published through GitHub OIDC Trusted
  Publishing with attestations. No long-lived PyPI token is used.

These controls reduce risk but do not make arbitrary third-party application code
trustworthy. Install only applications signed by a publisher you intend to trust.
