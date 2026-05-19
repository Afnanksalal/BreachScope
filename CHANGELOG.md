# Changelog

All notable changes to BreachScope are documented here.

## Unreleased

### Added

- Dashboard control surfaces: projects, policies, integrations, audit logs, and finding triage.
- Scoped dashboard API keys with `scan:write`, `config:read`, `secrets:read`, and `settings:write`.
- Distributed rate-limit abstraction with in-memory fallback and optional Upstash Redis REST backend.
- Policy-as-code evaluation with severity gates, finding budgets, blocked packages, denied categories, and expiring suppressions.
- Baseline creation and new-findings-only scanning.
- SARIF reporter for code scanning platforms.
- CycloneDX and SPDX SBOM exporters.
- OpenVEX exporter from saved JSON scan results.
- Markdown fix-suggestion exporter.
- Deterministic supply-chain risk scoring from OSV, OpenSSF, deps.dev, registry metadata, lifecycle/source findings, deprecation, and license signals.
- Multi-ecosystem dependency scanning for Maven, Packagist, NuGet, Hex, and Pub in addition to existing ecosystems.
- CI workflow generator with PR, scheduled, sandbox, and Dependabot workflow templates.
- Runtime monitoring command for Tracee/eBPF JSONL collection on Linux hosts.
- SCIM user endpoints and SAML metadata endpoint.
- Integration executors for Slack, Teams, PagerDuty, Jira, and Linear.
- Documentation covering CI gates, policies, baselines, SBOM, OpenVEX, runtime monitoring, identity, integrations, and deployment.

### Changed

- Landing page repositioned around the connected security workflow.
- Dashboard shell and primary pages received a premium command-center visual treatment.
- Registration now normalizes email, validates stronger passwords, rate-limits requests, and avoids account enumeration.
- Scan ingestion now validates payload size, scan mode, dates, embedded JSON fields, finding count, and finding fields.
- CLI auth polling is replay-safe.
- Sandbox defaults are secret-safe: `.env` files are excluded from model context, Docker context, and container environment unless `--include-secrets` is passed.
- Docker sandbox runtime adds stronger security flags and safer temporary environment handling.
- CLI config endpoints enforce API key scopes.
- Dependency and web package versions were upgraded and audited.

### Fixed

- API key scopes were previously stored but not enforced on scan upload and CLI config endpoints.
- Web lint baseline now runs cleanly.
- Stale docs and visible copy were updated to match the implemented dashboard and control features.

## 0.3.0

### Added

- Multi-agent AI scan pipeline.
- Docker sandbox attack command.
- Dependency, code, toolchain, blackbox, and smoke scanners.
- Dashboard scan history, settings, API keys, and scan detail pages.
- Multi-language detection for core ecosystems.

### Notes

This release established the local-first scanner and dashboard foundation that the current controls build on.
