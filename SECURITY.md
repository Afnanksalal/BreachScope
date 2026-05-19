# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.3.x | Current |
| < 0.3.0 | Unsupported |

## Reporting a Vulnerability

Do not report vulnerabilities through public GitHub issues.

Email: itsafnanksalal@gmail.com
PGP: available on request

Please include:

- affected component: CLI, dashboard, API, release pipeline, or package distribution
- reproduction steps
- impact assessment
- logs, payloads, or screenshots when safe to share
- suggested mitigation if known

## Response Targets

| Step | Target |
| --- | --- |
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Patch timeline | 14 days |
| Coordinated disclosure | 90 days unless risk requires faster action |

## Scope

In scope:

- `breachscope` CLI package
- dashboard application and API routes
- authentication, API key, SCIM, SAML, scan ingestion, and triage flows
- release, npm package, and GitHub Actions workflows

Out of scope:

- vulnerabilities in third-party projects that BreachScope scans
- denial of service through intentional resource exhaustion
- social engineering
- findings that require access to another user's dashboard account without an underlying vulnerability

## Current Security Practices

- dependency audits run in CI
- CLI and web builds are typechecked, linted, tested, and audited
- API keys are hashed before storage
- dashboard secrets are encrypted with AES-256-GCM
- scan ingestion validates payload size, fields, dates, finding count, and embedded JSON
- API key scopes are enforced for scan upload and CLI config access
- CLI auth polling is replay-safe
- sandbox secrets are excluded by default and require `--include-secrets`
- SAML ACS fails closed until assertion validation and IdP certificate pinning are configured
