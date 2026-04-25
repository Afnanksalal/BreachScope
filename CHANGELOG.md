# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Changed
- **Smart project detection** — when running `breachscope scan --url <url>` from a directory with no project manifest (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `Gemfile`, `pyproject.toml`), the dependency, code, toolchain, and sub-toolchain scanners are automatically skipped. URL-targeted scans go straight to blackbox + smoke. Scanners still run in full when a codebase is present alongside a URL.

---

## [0.1.0] — 2026-04-25

### Added

**Multi-language dependency scanning**
- Python: `requirements.txt`, `requirements-dev.txt`, `requirements/base.txt`, `pyproject.toml` (PEP 621, Poetry, uv/rye), `Pipfile`, `setup.py`
- Go: `go.mod` (single-line and block `require` syntax)
- Rust: `Cargo.toml` + `Cargo.lock` (`[[package]]` block parsing; lockfile preferred for exact versions)
- Ruby: `Gemfile.lock` (GEM section) and `Gemfile`
- All ecosystems query OSV.dev with correct tags: `PyPI`, `Go`, `crates.io`, `RubyGems`
- Auto-detection runs all applicable language scanners in parallel
- PyPI metadata API: GitHub repo, weekly downloads, maintainer count, `requires_dist` dependencies
- `PYTHON_KNOWN`, `GO_KNOWN`, `RUST_KNOWN` maps (30+ packages each with GitHub slugs)
- Cross-ecosystem collision prevention: detection map keyed as `${ecosystem}:${name}`
- Lockfile-exact version resolution: reads `package-lock.json` (v1/v2/v3) so OSV gets exact installed versions, not range specifiers

**Scan modes**
- `--breach`: 36 credential/infra patterns + aggressive supply chain CVE hunting
- `--bug`: 43 code vulnerability patterns + deep code AI agent
- `--breach --bug` (full): 66 total patterns, all scanners, both AI personalities
- Mode label in CLI banner: BREACH (red), BUG (yellow), FULL (purple)

**Static code patterns (66 total in full mode)**
- Base (13): hardcoded secrets, `eval()`, SQL concat, weak crypto, CORS wildcard, prototype pollution, path traversal, SSL verify disabled, error stack exposure
- Bug (+30): Python `pickle.loads`, `yaml.load` without SafeLoader, `subprocess shell=True`, `os.system` with variable; Go `fmt.Sprintf` SQL, `unsafe.Pointer`; Rust unsafe blocks; SSRF, open redirect, mass assignment, NoSQL injection, `dangerouslySetInnerHTML`, JWT `alg:none`, ReDoS, template injection, zip-slip, timing attack, XXE, LDAP injection
- Breach (+23): GitHub PAT, Stripe/OpenAI/Anthropic/Slack/Supabase/SendGrid/Twilio/AWS keys, Firebase private key, DB connection strings with credentials, debug endpoints, admin routes, DigitalOcean/Cloudflare/Heroku/Vercel tokens, npm token, base64 SSH key

**Active penetration testing (`--browser`)**
- Playwright-powered authenticated browser pentest agent
- SQLi (union, blind, time-based, error-based), XSS with DOM reflection, JWT `alg:none` + admin claim injection + kid SQLi, IDOR enumeration, CORS evil.com reflection, rate limit bypass, 30+ sensitive path enumeration
- Session cookie auto-tracking; results stored and shown in dashboard Probe Activity tab

**Live service probing (`--ai`)**
- Discovers SaaS services from codebase and prompts for credentials interactively
- Step-by-step action logging: HTTP, search, crawl operations with method badges

**AI agents**
- Mode-aware orchestrator: breach favors dependency+toolchain, bug favors code, full runs all
- Code agent: three system prompts (`SYSTEM_ALL`, `SYSTEM_BUG`, `SYSTEM_BREACH`) selected at runtime; uses `read_file` tool to strategically audit actual source files
- Dependency agent: three system prompts with mode-appropriate CVE/advisory research
- Shared dependency deduplication: packages required by multiple parents are audited once; `sharedPackages` map shows which parents share each dep
- Report agent: compact finding summaries sent to GPT (not full objects), returns executive summary + attack chains only — no token truncation

**Scorecard improvements**
- CI/CD practice checks (`Pinned-Dependencies`, `Token-Permissions`, `Code-Review`, `SAST`) reclassified as `[Maintainer Practice]` with `low`/`info` severity — these describe the package dev team's workflow, not vulnerabilities in the package itself
- `Vulnerabilities` check cross-referenced with OSV: downgraded to `info` when OSV confirms 0 CVEs for the installed version (historical repo count, not version-specific)

**Web dashboard**
- AI synthesis section: executive summary, top priority, attack chains rendered at top of Overview tab
- Tool cards: per-tool findings inline, GitHub link, installed version display, CVE version label
- `aiReport` column in scans table stores executive summary/attack chains as JSON
- Probe Activity tab: `ServiceProbeCard` (step log with HTTP/search/crawl badges) + `AttackProbeCard` (attack grid with result icons)
- Real PDF export: jsPDF + jspdf-autotable — dark header, severity boxes, full findings table, dependency risk table (top 40), probe log, page numbers
- Findings: `detail` column in DB stores matched code snippet; shown as "Matched Code" block in FindingCard
- Scan mode badge in list: red (breach), yellow (bug), purple (full)

**CLI**
- `push-scan.ts` sends `aiReport`, `github`, `version` per-tool, and `detail` per-finding
- Sub-toolchain scan returns `sharedPackages` record; shared deps shown in CLI dashboard

### Changed
- OSS pipeline is fully ecosystem-aware: PyPI uses `fetchPypiMeta`, Go infers GitHub from module path
- Sub-toolchain `fetchSubDependencies` caps PyPI sub-deps at 20; Go/Rust/Ruby return `[]`
- `mergedFindings` built from raw static findings + net-new AI findings — GPT's curated subset never truncates the count sent to the dashboard
- Dashboard main metrics: removed "Bugs Found" and "Breach Issues" stat cards (always showed 0)

---

[0.1.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.1.0
