# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-04-26

### Added

**AI-first sandbox flow**
- Phase 0 codebase understanding: before any Docker work, an AI agent reads every source file, `.env`, config, and secret to build a full security picture — real credentials, auth mechanism, database, all endpoints
- AI-generated Dockerfile: no templates — the AI writes a purpose-built Dockerfile from what it learned about the app (correct base image, start command, port, all deps)
- `.env` and all secrets are guaranteed to land in the container: `.dockerignore` is temporarily neutralized (backed up and restored after build) so no secret file is excluded from the image
- `projectContext` string (full security summary from Phase 0) passed to the attack agent — it attacks known targets with precision instead of blind fuzzing
- Phase 1 initial message now includes: test suite execution, env file discovery, route mapping, and credential extraction before attacking

**Aggressive Firecrawl / web research in all agents**
- `web_search` and `crawl_url` tools added to sandbox agent — looks up HackTricks, PayloadsAllTheThings, Exploit-DB, NVD CVE pages, and GitHub PoC repos before every attack
- `crawl_url` tool added to code agent, dependency agent, and blackbox agent
- `web_search` description changed from "use sparingly" to aggressive usage across all agents
- All agents instructed to research every identified framework version, library, and CVE immediately
- `webSearch` default result limit raised from 5 → 10
- `web_search` limits: sandbox 10, code 8, dependency 10, blackbox 8

**Sandbox reliability**
- Remote config (`fetchRemoteConfig`) now called at sandbox startup — API keys stored in dashboard settings are applied automatically, same as `scan` command
- Unknown project type no longer exits — generates a full Ubuntu 22.04 container with `nmap`, `sqlmap`, `nikto`, `curl`, `python3`, `nodejs`, `postgresql-client`, `redis-tools` pre-installed, auto-detects and starts whatever app it finds
- `detectProjectType` now scans one level of subdirectories — running from a monorepo root correctly identifies the project type

### Changed
- Sandbox startup timeout raised from 60 → 90 seconds (max 180s) to accommodate slower builds
- AI attack agent log display raised from 10 → 15 entries in verbose mode

---

## [0.1.0] — 2026-04-25

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

**10-language dependency scanning**
- Python: `requirements.txt`, `requirements-dev.txt`, `requirements/base.txt`, `pyproject.toml` (PEP 621, Poetry, uv/rye), `Pipfile`, `setup.py`
- Go: `go.mod` (single-line and block `require` syntax)
- Rust: `Cargo.toml` + `Cargo.lock` (`[[package]]` block parsing; lockfile preferred for exact versions)
- Ruby: `Gemfile.lock` (GEM section) and `Gemfile`
- Java, PHP, .NET, Elixir, Dart — added
- All ecosystems query OSV.dev with correct ecosystem tags

**Scan modes**
- `--breach`: 36 credential/infra patterns + aggressive supply chain CVE hunting
- `--bug`: 43 code vulnerability patterns + deep code AI agent
- `--breach --bug` (full): 66 total patterns, all scanners, both AI personalities

**Static code patterns (66 total in full mode)**
- Base (13): hardcoded secrets, `eval()`, SQL concat, weak crypto, CORS wildcard, prototype pollution, path traversal, SSL verify disabled, error stack exposure
- Bug (+30): Python `pickle.loads`, `yaml.load`, `subprocess shell=True`; Go `fmt.Sprintf` SQL, `unsafe.Pointer`; Rust unsafe blocks; SSRF, open redirect, mass assignment, NoSQL injection, `dangerouslySetInnerHTML`, JWT `alg:none`, ReDoS, template injection, zip-slip, timing attack, XXE, LDAP injection
- Breach (+23): GitHub PAT, Stripe/OpenAI/Anthropic/Slack/Supabase/SendGrid/Twilio/AWS keys, Firebase private key, DB connection strings, debug endpoints, admin routes, cloud tokens

**Free threat intelligence (no API key required)**
- OSV.dev POST API — comprehensive open vulnerability database
- npm advisory bulk API — security advisories with affected version ranges
- NVD CVE keyword search — NIST national vulnerability database

**AI always-on**
- AI analysis runs automatically when `OPENAI_API_KEY` is set — no `--ai` flag
- Remote API keys pulled from dashboard settings unconditionally
- `--ai` and `--browser` flags removed

**Web dashboard**
- AI synthesis section: executive summary, top priority, attack chains
- Sandbox Terminal: full terminal replay — every command, HTTP request, credential found, attack chain
- Real PDF export: jsPDF + jspdf-autotable
- AES-256-GCM encrypted stored API keys

### Fixed
- `opts.ai` gate in `scan.ts` removed — remote API keys always applied
- `deduplicatedFindings` removed from `ReportSynthesis` (was declared, never populated)
- Orphaned files deleted: `agents/attack-probe.ts`, `agents/browser-probe.ts`

---

[0.2.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.2.0
[0.1.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.1.0
