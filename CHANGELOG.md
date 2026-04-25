# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**CLI**
- Sub-toolchain scan engine with three depth modes: `basic`, `major`, `deep`
- `--scan-mode breach|bug|all` flag — scope scan to supply chain, code audit, or both
- Tool classifier: GPT-4o classifies every detected dependency as OSS, SaaS, or hybrid
- OSS pipeline: OpenSSF Scorecard + OSV.dev + deps.dev + npm registry analysis per tool
- SaaS pipeline: AI-powered web research for hosted services
- Risk dashboard: color-coded terminal output with per-tool risk scores (0–100), scorecard highlights, OSV vuln counts, and attack findings
- 80+ tools in the static tool map (`toolmap.ts`) — zero GPT calls for known packages
- Multi-signal tool detection: package.json, import statements, env files, config files
- Dependency graph builder for visualization and cycle detection
- `breachscope toolchain` command — dedicated sub-chain scan
- `breachscope login` command — device flow authentication with breachscoope.vercel.app
- AI multi-agent pipeline: Orchestrator → Dependency / Code / Toolchain / Blackbox / Report agents
- Firecrawl integration for live advisory/changelog crawling
- OpenSSF Scorecard API integration
- OSV.dev API integration (single + batch query)
- deps.dev API integration
- npm registry metadata analysis (maintainer count, download velocity, publish recency)
- Flagged supply chain packages: `flatmap-stream` (event-stream 2018), `coa`, `rc` (2021 hijack batch)

**Web Dashboard**
- Next.js 15 dashboard at breachscoope.vercel.app with full scan history and findings browser
- Authentication: email/password (bcrypt), GitHub OAuth, Google OAuth via NextAuth v5 (JWT strategy)
- Scan overview: 30-day stats (total scans, critical/high counts, tools audited), finding trends chart, category breakdown
- Scan history page with search, mode filter, depth filter, clickable rows
- Scan detail page: per-finding cards with severity, category, description, remediation, file/line, references
- API key management: create, revoke, prefix display — keys hashed with SHA-256, shown once
- Settings: encrypted OpenAI and Firecrawl API key storage (AES-256-GCM), scan depth/mode defaults
- Neon PostgreSQL database with Drizzle ORM — `db:push` for dev, `db:migrate` for production
- `db:seed` script — inserts dev user (with optional password), API key, sample scan with 3 findings
- CLI device flow: `breachscope login` opens browser → user authenticates → CLI receives token

### Changed
- `breachscope scan` now runs the sub-toolchain engine automatically (mode=basic by default)
- CLI banner updated with mode/scan-mode display

---

## [0.1.0] — 2026-04-25

### Added
- Initial release
- Static dependency scanner: flagged packages, lockfile integrity, registry sources
- Static code auditor: 13 patterns covering secrets, eval, SQL injection, weak crypto, CORS, prototype pollution, path traversal
- Toolchain scanners: Supabase RLS, Vercel preview secrets, GitHub branch protection
- Blackbox prober: security headers, CORS misconfiguration, exposed paths, HTTP TRACE
- Smoke tester: reachability, error leakage, auth bypass probes, payload limits
- Console and JSON reporters
- `breachscope.yaml` config file support
- `--ci` flag for CI/CD pipeline integration
- `breachscope init` to scaffold config

[Unreleased]: https://github.com/breachscope/breachscope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/breachscope/breachscope/releases/tag/v0.1.0
