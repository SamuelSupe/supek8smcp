# Security policy

supek8smcp handles Kubernetes credentials and can invoke read or controlled write operations. Please keep vulnerability reports private until a fix and disclosure plan are agreed.

## Reporting a vulnerability

Do not open a public GitHub issue, pull request, or discussion for an unpatched vulnerability. Prefer a private GitHub Security Advisory for this repository. If that channel is unavailable, contact the maintainers privately through the contact method listed on the repository or organization profile and include “supek8smcp security” in the subject.

Include, when safe:

- affected version, commit, image digest, and deployment mode;
- a concise impact statement and reproducible steps or proof of concept;
- required Kubernetes permissions, namespace placement, network assumptions, and whether a client token or Operator identity is involved;
- logs or traces after removing tokens, Secret data, private keys, Authorization headers, resource bodies, commands, and exec output.

Do not test against a cluster or account you do not own. Do not send live credentials in a report.

## Scope and response

Reports about caller-token confusion, RBAC bypass, namespace/TLS trust-boundary escape, Secret disclosure, unsafe write validation, unbounded resource use, or authentication/authorization failures are in scope. Denial-of-service reports should explain realistic resource impact and required privileges. Missing hardening that does not create an exploitable boundary may be treated as a feature request.

Maintainers will acknowledge a private report when practical, investigate with the reporter, and coordinate a fix, affected-version guidance, and disclosure timing. Please allow time for validation and release; do not publish details while users remain exposed.

## Operational guidance

Use a dedicated endpoint namespace, least-privilege client ServiceAccounts, short-lived tokens, TLS verification, Secret redaction, and the limits documented in the [security model](docs/security.md). Rotate any credential that may have appeared in diagnostics and report the exposure privately.
