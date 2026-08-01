# Contributing to supek8smcp

Thank you for improving supek8smcp. Contributions should preserve the project's caller-identity, least-privilege, and bounded-resource guarantees.

## Before you start

- Read the [deployment guide](docs/deployment.md) and [security model](docs/security.md).
- For a security vulnerability, do not open a public issue; follow [SECURITY.md](SECURITY.md).
- Open an issue first for large behavior changes, new public tools, or changes to CRD semantics.

## Development

The repository targets Go 1.25. Install the usual Go and Kubernetes tooling, then use the Make targets:

```bash
make fmt
make vet
make test
make build
```

When API types change, run `make manifests` and review generated YAML. Do not hand-edit generated CRDs or RBAC. Keep changes focused, add a behavior-boundary test for real regressions, and avoid tests that only assert constants or implementation details.

## Pull requests

1. Create a focused branch from the current default branch.
2. Explain the user-visible behavior and the security/trust boundary it affects.
3. Include documentation and migration notes for CRD, mode, policy, endpoint, or compatibility changes.
4. Run the relevant checks and report the exact commands and results. Do not include tokens, Secret data, private keys, or raw exec output.
5. Keep generated files, examples, and English/Chinese documentation in sync.

Reviewers will look for least-privilege RBAC, caller-token propagation, bounded input/output/time/concurrency, safe failure behavior, and backwards-compatible operational changes. Maintainers may request changes before merge.
