# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**Docker Attack Arena (`breachscope sandbox`)**
- New `sandbox` command spins up a Docker container, deploys your app inside it, and runs an AI agent as root
- AI agent uses PentestGPT / HackingBuddyGPT architecture — evolving attack strategy per iteration via Pentest Task Tree and persistent `AttackMemory`
- Agent installs any tool it needs freely (nmap, sqlmap, nikto, etc.) — no permission prompts
- `attackMode` container config: NET_RAW, NET_ADMIN capabilities, 2 GB RAM, no `no-new-privileges`
- 60 attack iterations per session; `--deep` doubles the sequences
- Auto-detects and extracts credentials from `env` output; flags sensitive API keys
- `attackChains` returned and displayed as colored attack path summary in console
- `exec_cmd` tool accepts `timeout_seconds` parameter (up to 300s) for long-running installs
- Language-specific attack hints injected into system prompt per project type

**10-language sandbox support**
- Node.js / Bun, Python, Go, Rust, Ruby — existing
- Java (Maven/Gradle → Spring Boot, Quarkus), PHP (Laravel/Symfony/plain), .NET (ASP.NET Core), Elixir (Phoenix), Dart (Shelf/Dart Frog) — new

**Sandbox Terminal in dashboard**
- Full terminal replay component (`SandboxTerminal`) showing every step the agent took
- 11 event types with color coding: `finding_critical/high/medium/low`, `chain`, `credential`, `attempt_success/partial/failed`, `exec`, `http`, `info`
- Traffic light dots, monospace `#0a0a0a` background, attack chain highlight, line numbers, blinking cursor

**Free threat intelligence (no API key required)**
- `webSearch()` falls back to free public APIs when `FIRECRAWL_API_KEY` is not set
- OSV.dev POST API — comprehensive open vulnerability database
- npm advisory bulk API — security advisories with affected version ranges
- NVD CVE keyword search — NIST national vulnerability database
- Firecrawl used as enhancement when available, not a hard requirement

**AI always-on**
- AI analysis runs automatically when `OPENAI_API_KEY` is set — no `--ai` flag needed
- Remote API keys pulled from dashboard settings unconditionally (no flag gate)
- `--ai` flag removed; `--browser` flag removed

### Changed
- **Active pentest** moved from Playwright `--browser` agent into Docker sandbox — all active exploitation now inside an isolated container
- **Smart project detection** — when running `breachscope scan --url <url>` with no local project manifest, static scanners are automatically skipped
- `ProbeActivity.attack` → `ProbeActivity.sandbox` in dashboard type contract
- `deduplicatedFindings` removed from `ReportSynthesis` interface (was declared but never populated; fallback always executed)
- Orphaned files deleted: `agents/attack-probe.ts`, `agents/browser-probe.ts`

### Fixed
- `TS2532` in `sandbox-agent.ts`: `toolMatch[1]` optional chaining added
- `opts.ai` gate in `scan.ts` removed — remote API keys now always applied when available

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

**Live service probing**
- Discovers SaaS services from codebase and prompts for credentials interactively when `OPENAI_API_KEY` is set
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
- Probe Activity tab: `ServiceProbeCard` (step log with HTTP/search/crawl badges)
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
