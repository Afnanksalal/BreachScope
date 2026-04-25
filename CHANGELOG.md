# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**Multi-language dependency scanning**
- Python scanner: `requirements.txt`, `requirements-dev.txt`, `requirements/base.txt`, `requirements/prod.txt`, `pyproject.toml` (PEP 621, Poetry, uv/rye), `Pipfile`, `setup.py`
- Go scanner: `go.mod` (single-line and block `require` syntax)
- Rust scanner: `Cargo.toml` + `Cargo.lock` (`[[package]]` block parsing, prefers lockfile for precise versions)
- Ruby scanner: `Gemfile.lock` (GEM section) and `Gemfile` (`gem 'name'` declarations)
- All ecosystems query OSV.dev with correct ecosystem tags: `PyPI`, `Go`, `crates.io`, `RubyGems`
- Auto-detection: scans for manifest presence and runs all applicable language scanners in parallel
- PyPI metadata API integration (`fetchPypiMeta`): extracts GitHub repo, weekly downloads, maintainer count, `requires_dist` dependencies
- `pypiMetaToFindings`: no-maintainer (critical) and recently-published (medium) risk signals
- Detector updated to detect Python/Go/Rust packages from manifests and source imports (`.py` files)
- Import-to-package normalization: `cv2` → `opencv-python`, `PIL` → `pillow`, `sklearn` → `scikit-learn`, `yaml` → `pyyaml`, etc.
- `PYTHON_KNOWN`, `GO_KNOWN`, `RUST_KNOWN` maps in detector (30+ packages each with GitHub slugs)
- Cross-ecosystem collision prevention: detection map keyed as `${ecosystem}:${name}`

**Scan modes: `--breach`, `--bug`, `--breach --bug` (full)**
- `--breach` flag: activates breach mode — 36 credential/infra patterns + aggressive supply chain CVE hunting
- `--bug` flag: activates bug mode — 43 code vulnerability patterns + deep code AI agent
- `--breach --bug` combined: full mode — 66 total patterns, all scanners run, both AI personalities
- Mode label displayed in CLI banner: colored BREACH (red), BUG (yellow), FULL (purple)
- Each mode gates different scanners: bug mode skips toolchain + subchain; breach mode skips nothing

**Expanded code audit patterns (66 total)**
- Base set (13): existing patterns — secrets, eval, SQL concat, weak crypto, CORS, prototype pollution, path traversal, SSL verify disabled, error stack exposed
- Bug set (+30): Python `pickle.loads`, `yaml.load` without SafeLoader, `subprocess` with `shell=True`, `os.system` with variable, Go SQL via `fmt.Sprintf`, `unsafe.Pointer`, Rust unsafe blocks, `unwrap()` chains; SSRF, open redirect, mass assignment (`...req.body`), NoSQL injection, `dangerouslySetInnerHTML`, JWT none algorithm, insecure cookie, ReDoS, template injection, zip-slip, timing attack (`===` for secrets), weak JWT secret, XXE, LDAP injection, hardcoded JWT key
- Breach set (+23): GitHub PAT (`ghp_`/`gho_`/`ghs_`/`ghr_`), Stripe `sk_live_` + `whsec_`, OpenAI `sk-`, Anthropic `sk-ant-`, Google `AIza`, Slack `xoxb-`, SendGrid `SG.`, Twilio auth token, Supabase service role JWT, npm token `npm_`, Firebase private key, DB connection strings with creds, debug endpoints, admin routes, DigitalOcean `dop_v1_`, Cloudflare token, Heroku UUID-format key, Vercel token, dotenv at system path, Sentry DSN with private key, base64-encoded SSH key
- Code scanner extended to also scan `.rs` (Rust) files; `target/` and `vendor/` added to ignore list

**Active penetration testing (`--browser`)**
- `attack-probe.ts`: Playwright-powered authenticated browser pentest agent
- Attacks: SQL injection (URL params + forms: union, blind, time-based, error-based), XSS with DOM reflection + `alert()` detection, JWT `alg:none` + admin claim injection + ID tampering + kid SQLi, IDOR via ID enumeration, CORS evil.com reflection, rate limit bypass via concurrent requests, 30+ sensitive path enumeration
- Session cookie auto-tracking via `page.on("response")` listener
- Results stored in `probeData.attack` and displayed in dashboard Probe Activity tab

**Live service probing (interactive `--ai`)**
- Discovers SaaS services from codebase and prompts for credentials interactively
- Step-by-step action logging: HTTP calls, web searches, crawl operations stored in `probeData.services`
- `LiveProbeResult.steps` array sent to dashboard and shown with HTTP method badges (GET/POST/SRCH/CRAWL)

**AI agent mode awareness**
- `AgentContext.scanMode` field — all agents receive current mode
- Orchestrator: mode-aware planning — breach favors dependency+toolchain, bug favors code, full runs everything
- Code agent: three distinct system prompts (`SYSTEM_ALL`, `SYSTEM_BUG`, `SYSTEM_BREACH`) selected at runtime
- Dependency agent: three distinct system prompts — breach investigates 20+ packages aggressively, bug cross-references reachable CVEs
- Fallback planning (on AI parse failure) is also mode-aware — deterministic, no AI needed

**Dashboard: Probe Activity tab**
- `ServiceProbeCard`: collapsible per-service probe with step log (HTTP method badges, search/crawl labels), finding count, token count
- `AttackProbeCard`: attack grid with icons (💉 SQLi, ⚡ XSS, 🔑 JWT, 🌐 CORS, 🔄 Rate limit, 🗂️ Paths), pages visited
- Empty state with hint to use `--ai`/`--browser`

**Dashboard: Real PDF export**
- Replaced `window.print()` with `jspdf` + `jspdf-autotable` loaded lazily on click
- PDF contents: dark header bar, colored severity summary boxes (Critical/High/Medium/Low), full findings table with severity color coding, dependency risk table (top 40 by score), probe activity log, page numbers + footer on every page
- Download triggers directly as `project-name-date.pdf` — no browser print dialog
- "Generating…" spinner while PDF is being built

**Dashboard: Findings improvements**
- `detail` column added to `findings` DB table — stores matched code line (e.g. `eval(req.body.cmd)`)
- FindingCard now shows "Matched Code" block in dark red monospace when `detail` is present
- Scan mode label colored in Overview tab: red for breach, yellow for bug, purple for full
- Bug mode badge fixed: was using invalid Tailwind opacity classes (`/8`, `/12`) — now valid (`/[0.08]`)
- Full mode (`--breach --bug`) gets purple badge in scan list

**CLI sync**
- `npm link` makes `breachscope` and `bs` available globally after `npm run build`
- `push-scan.ts` now sends `detail` field on every finding

### Changed
- `breachscope scan` banner now shows: `Mode: DEEP | Target: ALL | Scan: BREACH (CVE · supply chain · credential hunt)`
- OSS pipeline is fully ecosystem-aware: PyPI uses `fetchPypiMeta`, Go infers GitHub from module path
- Sub-toolchain `fetchSubDependencies` is ecosystem-aware: PyPI sub-deps capped at 20, Go/Rust/Ruby return `[]`
- `ScanOptions.scanMode` typed in `types.ts`; `AgentContext.scanMode` added

---

## [0.1.0] — 2026-04-25

### Added
- Initial release
- Sub-toolchain scan engine with three depth modes: `basic`, `major`, `deep`
- Tool classifier: GPT-4o classifies every detected dependency as OSS, SaaS, or hybrid
- OSS pipeline: OpenSSF Scorecard + OSV.dev + deps.dev + npm registry analysis per tool
- SaaS pipeline: AI-powered web research for hosted services
- Risk dashboard: per-tool risk scores (0–100), scorecard highlights, OSV vuln counts
- 80+ tools in the static tool map — zero GPT calls for known packages
- Multi-signal tool detection: package.json, import statements, env files, config files
- Dependency graph builder
- Static code auditor: 13 patterns (secrets, eval, SQL injection, weak crypto, CORS, prototype pollution, path traversal, SSL verify disabled)
- Toolchain scanners: Supabase RLS, Vercel preview secrets, GitHub branch protection
- Blackbox prober: security headers, CORS misconfiguration, exposed paths, HTTP TRACE
- Smoke tester: reachability, error leakage, auth bypass probes, payload limits
- AI multi-agent pipeline: Orchestrator → Dependency / Code / Toolchain / Blackbox / Report
- Firecrawl integration for advisory/changelog crawling
- Console and JSON reporters
- `breachscope login` — device flow authentication with breachscoope.vercel.app
- Web dashboard: scan history, findings browser, API key management, settings, 30-day stats
- `breachscope.yaml` config support, `breachscope init` to scaffold
- `--ci` flag for CI/CD pipeline exit code integration

[Unreleased]: https://github.com/breachscope/breachscope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/breachscope/breachscope/releases/tag/v0.1.0
