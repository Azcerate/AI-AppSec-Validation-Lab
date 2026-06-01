# Security Policy

## Purpose & Status

This repository is a **security research / portfolio project**. It demonstrates
security engineering concepts and is **not production-hardened**. Do not deploy
it as-is to handle real production data, secrets, or traffic without an
independent security review.

## Supported Versions

Only the latest commit on the default branch is maintained.

| Version          | Supported          |
| ---------------- | ------------------ |
| `main` (latest)  | :white_check_mark: |
| older commits    | :x:                |

## Reporting a Vulnerability

If you discover a security issue in this project, please report it privately.

- **Preferred:** Open a [GitHub Security Advisory](../../security/advisories/new)
  (Security tab → "Report a vulnerability"). This keeps the report private until
  a fix is ready.
- **Email:** asaunders@dmcslabs.com

Please include:

1. A description of the issue and its impact.
2. Steps to reproduce (proof-of-concept where possible).
3. Affected files, endpoints, or components.
4. Any suggested remediation.

**Please do not** open a public issue for security-sensitive reports.

## Response Targets

| Stage                 | Target            |
| --------------------- | ----------------- |
| Acknowledge report    | 3 business days   |
| Triage & severity     | 7 business days   |
| Fix or mitigation plan| 30 days (severity-dependent) |

Severity is assessed using CVSS v3.1. Critical/High issues are prioritized.

## Scope

In scope: source code in this repository.
Out of scope: third-party dependencies (report upstream), social engineering,
and any deployment a user stands up themselves.

## Safe Harbor

Good-faith security research conducted in accordance with this policy is
welcome. Do not access data that is not yours, degrade service for others, or
violate any law. Acting in good faith under this policy, you will not be pursued
for the research.
