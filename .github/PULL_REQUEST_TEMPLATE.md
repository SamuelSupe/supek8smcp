## Summary

<!-- What behavior changes, and why? -->

## Validation

- [ ] I ran the relevant checks and listed exact commands/results below.
- [ ] I added or updated a behavior-boundary test when the change fixes a regression.
- [ ] I updated English and Simplified Chinese documentation when behavior or operations changed.
- [ ] I regenerated and reviewed manifests when API types changed.

Commands/results:

## Security and operations

- [ ] Caller Bearer-token propagation and Kubernetes RBAC boundaries remain explicit.
- [ ] Input/output/time/concurrency limits and failure behavior are bounded.
- [ ] No tokens, Secret data, private keys, Authorization headers, or raw exec output are included.
- [ ] Deployment, TLS, NetworkPolicy, observability, and upgrade impact are documented.
