# Changelog

All notable changes to BreachScope are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
BreachScope follows [Semantic Versioning](https://semver.org/).

---

## [0.3.1] — 2026-04-27

### Added

**Sandbox CLI flags**
- `--breach` — companion AI agents (code, dep, blackbox) run in breach mode (supply chain & credential focus)
- `--bug` — companion agents run in bug mode (exploitable code vulnerabilities)
- `--scan-mode <all|breach|bug>` — explicit override, wins over `--breach`/`--bug`
- `--deep` now wired up end-to-end: 120 attack iterations instead of 80 (was previously accepted but not passed to the agent)
- Output flags `-o/--output` and `-f/--file` documented and accessible from sandbox command
- Flag priority: `--scan-mode` → `--breach`/`--bug` → dashboard settings → `"all"` fallback

**Dashboard Sandbox Defaults (Settings page)**
- New "Sandbox Defaults" section with two configurable options:
  - **Attack Depth**: Normal (80 iterations) / Deep (120 iterations)
  - **Companion Agent Mode**: All / Breach / Bug
- Settings stored as `sandbox_scan_mode` and `sandbox_deep` in `user_settings` table
- Synced to CLI at runtime via `/api/cli/config` — CLI flags always take priority

**Multi-language AI dependency agent**
- Dependency agent now covers all 10 ecosystems instead of npm-only
- `fetch_osv_data(name, ecosystem)` queries OSV.dev directly with the correct ecosystem tag (npm, PyPI, Go, crates.io, RubyGems, Packagist, Maven, NuGet, Hex, pub)
- `fetch_github_advisory(name, ecosystem)` uses the correct GitHub advisory ecosystem filter per language
- `fetchPackageAdvisories(name, ecosystem)` replaces `fetchNpmAdvisories` — includes ecosystem in search query
- `buildUserMessage` now groups all detected packages by ecosystem and sends them to the agent; agent receives explicit instructions on which ecosystem parameter to pass per lookup
- Tool handlers in `runDependencyAgent` pass `args["ecosystem"]` to all crawler functions

**Dashboard — dependency tree ordering**
- `buildDepTree()` performs DFS traversal of `ToolRiskEntry[]` — roots sorted by risk score, each node's children inserted immediately after it (also sorted by risk)
- Proper `parent → child` indentation in the Supply Chain grid: `20px` margin per depth level with tree-line prefix (`│  └─`) so the hierarchy is visually clear

**Dashboard — dedicated Sandbox Probe findings section**
- New `"sandbox"` group in Smart Groups — highest priority, breach-purple color
- New `SandboxFindingsView` component: confirmed exploits with evidence, attack chains, secret key names (no values), matched remediations from the full findings list
- "Sandbox Probe" tab added to the view toggle — only shown when sandbox data is present

**Dashboard — PTT expand/collapse**
- PTT nodes are now individually clickable to expand/collapse
- "Expand all / Collapse all" toggle above the tree
- Grandchildren supported — full multi-level nesting rendered

**Dashboard — Roadmap page** (`/roadmap`)
- Three phases: v0.1–v0.3 Shipped (7 items), v0.4 Near Term (6 items), v0.5+ Long Term (7 items)
- Status badges: `shipped` / `in-progress` / `planned` / `idea`
- Stats bar: shipped/planned/ideas count
- "Have an idea?" CTA linking to GitHub issues
- Footer Roadmap link updated from dead anchor to `/roadmap`

**Dashboard — "Delete All Scans"**
- Two-step confirmation flow in Settings → Danger Zone
- `DELETE /api/scans` endpoint deletes all findings (FK) then all scans for the authenticated user, then redirects to `/dashboard`

### Changed

- `RemoteConfig` interface gains `sandboxScanMode: string` and `sandboxDeep: boolean`
- `SandboxOptions` gains `breach?`, `bug?`, `scanMode?` fields
- `runSandboxAgent` signature gains `deep?: boolean` parameter
- `buildAgentContext` in sandbox gains `scanMode` parameter — passed through to all companion agents
- `SettingsResponse` and `/api/settings` GET/PUT include sandbox fields
- `/api/cli/config` GET/PATCH include sandbox fields
- Sidebar: removed CLI login banner from the bottom (no longer shown)
- Scan rows in dashboard Overview "Recent Scans" are now clickable — navigate to the full scan detail page
- Discovered secrets in the Sandbox tab display key names only — values are never shown in the UI

### Fixed

- `sandbox --deep` flag was accepted by the CLI but never forwarded to the sandbox agent's `maxIterations` — now correctly sets 120 iterations
- **Critical CLI bug**: `target` was being overwritten with `remote.defaultScanMode` (`"breach"/"bug"/"all"`) — a completely different enum. When the dashboard scan mode was `"breach"`, no scanners ran at all. Fixed by removing the bad assignment and adding `remote?.defaultScanMode` as a fallback to `scanMode` only
- PDF report showed `0,0,0,0` severity counts — null guard added on `f.severity` before `.toLowerCase()` (was crashing silently and skipping all rows)
- PDF report listed only ~20 findings — table styling tightened (`fontSize: 6.5`, `cellPadding: 2`, `minCellHeight: 6`) so far more rows fit per page; full sandbox section added (AI narrative, attack chains, confirmed findings, redacted secret key names, ports, frameworks)
- Raw list showed "Clean Scan" with 5000+ findings — added check: if `findings.length === 0 && total > 0`, shows an orange "Findings not loaded" warning instead
- Settings save corrupted all settings state — `handleSave` was calling `setSettings({ok: true})` (the PUT response body). Fixed by re-fetching settings from the API after a successful save
- Footer Contributing link used `/main/` branch — corrected to `/master/`

---

## [0.3.0] — 2026-04-27

### Added

**Sandbox supervisor agent** (`src/agents/sandbox-supervisor.ts`)
- New `runSupervisor()` agent analyzes all recon data (credentials, endpoints, open ports) and produces a prioritized `SpecialistTask[]` attack plan before the main exploit loop
- Supervisor performs targeted web searches for known CVEs against detected framework versions before assigning tasks
- Plans include: exact endpoint paths, credential values to use, rationale, estimated impact, and chained attack hypotheses
- Early-exit guard: supervisor skips if no recon data is present (avoids wasted tokens on empty sessions)
- 11 specialist attack types: `sql_injection`, `jwt_attack`, `auth_bypass`, `ssrf`, `xss`, `file_traversal`, `redis_exploit`, `prototype_pollution`, `race_condition`, `business_logic`, `ai_llm_attacks`

**Sandbox validator agent** (`src/agents/sandbox-validator.ts`)
- New `validateFinding()` and `validateFindings()` independently re-verify critical and high findings after the main attack loop
- Validator is skeptical-by-default: re-runs replication steps from scratch and must reproduce the same evidence to confirm
- Confidence levels: `confirmed` (≥90), `likely` (60–89), `uncertain` (30–59), `false_positive` (<30)
- Validation results annotated onto findings in the dashboard — confidence badge + score displayed next to each sandbox finding
- Medium/low findings skipped (score 70 / confidence `likely`) to avoid burning tokens on low-impact issues
- Max 5 critical/high validations per session

**CVE intelligence module** (`src/core/cve-intel.ts`)
- `getCVEIntel(cveId)` fetches EPSS exploitation probability, NVD CVSS score/vector/severity, Nuclei template availability, and Exploit-DB presence — all concurrently
- `batchCVEIntel(ids[])` sequences up to 10 CVEs with 700ms delay between NVD requests (respects 5 req/30s rate limit without an API key)
- `formatCVEShort(intel)` returns one-line summary with exploitation risk signal for inline agent use
- EPSS score displayed as `🔴 HIGH` / `🟡 MEDIUM` / `🟢 LOW` exploitation risk in batch output
- In-process cache prevents duplicate API calls within a session
- Nuclei template check tries 3 URL patterns to handle repository structure variations

**3 new specialist agents in sandbox**
- `race_condition` — targets concurrent state operations (financial transfers, inventory, order placement) with parallel request storms
- `business_logic` — exploits pricing manipulation, permission escalation through valid API flows, workflow bypass
- `ai_llm_attacks` — prompt injection, jailbreak, system prompt extraction, indirect injection via user-controlled content for AI-powered endpoints

**Rabbit hole prevention**
- In-memory `Map<string, number>` tracks exact command execution frequency per session
- Commands attempted ≥3 times trigger automatic abandonment with a `[RABBIT HOLE]` log entry and hypothesis reassignment
- No disk I/O — avoids TOCTOU races during concurrent memory updates

**Pentest Task Tree (PTT)**
- `PTTNode` interface with hierarchical structure: root → category → specific attack nodes
- Keyword-based categorization: findings routed by title/description keywords (not severity) to `ptt-creds`, `ptt-auth`, `ptt-inject`, `ptt-services`, or `ptt-web`
- Node statuses: `unexplored` → `in_progress` → `confirmed_vuln` / `not_vulnerable` / `needs_more_info`
- PTT tree visualized in dashboard with color-coded status dots and labels

**Attack chain linking**
- `ConfirmedFinding.parent_finding_id` links a finding to its prerequisite (e.g. "JWT secret found → admin token forged")
- Chain relationships displayed in dashboard findings

**OWASP ZAP integration (inside container)**
- `zap_scan` tool runs entirely via `execFn` (inside the Docker container) — no host-side fetch
- Actions: `install` (finds JAR dynamically with `find /opt/zap`), `spider`, `active_scan`, `alerts`
- ZAP daemon started with `-host 0.0.0.0` for container-internal access via `curl` REST calls
- ZAP invoked after initial recon; active scan results feed into the finding pipeline

**Chain-of-thought (CoT) prompting**
- Every tool call preceded by mandatory `[WHAT I KNOW] → [HYPOTHESIS] → [EXPECTED] → [ATTACK] → [IF IT WORKS] → [IF IT FAILS]` reasoning block
- System prompt enforces CoT as a hard requirement — agent cannot skip straight to tool use

**Monorepo Docker support** (self-healing build pipeline)
- `UNDERSTANDING_SYSTEM` RULE 14: explicit monorepo pattern — `COPY . .` from root, then `WORKDIR /app/<service>` — never `COPY package*.json ./` from a subdirectory root
- `runCodebaseUnderstandingAgent` accepts `isMonorepoProject` flag; activates monorepo context when ≥2 services detected regardless of whether paths differ
- `serviceSubpath` threaded through `buildWithSelfHealing` → `runDockerfileFixAgent` — fix agent receives monorepo note with exact forbidden patterns when repairing a failed build
- `serviceSubpath` threaded through `fixStartupCrash` → `runDockerfileFixAgent` for the same guarantee on runtime crash recovery
- `aiChosenSubpath` passed from `runSandbox` to both heal functions so every repair attempt is monorepo-aware

**`SandboxMemorySnapshot` — rich memory export**
- New `SandboxMemorySnapshot` type captures: worldview, credentials, discovered endpoints (up to 80), discovered services, open ports, framework versions, PTT tree, confirmed findings with CVSS and validation scores
- Snapshot included in `SandboxAgentResult` and pushed to dashboard as part of `ProbeData.sandbox`

### Changed

- `SandboxAgentResult` gains `memorySnapshot: SandboxMemorySnapshot` field
- `ProbeData.sandbox` in `push-scan.ts` gains `memorySnapshot?` field
- Sandbox push in `sandbox.ts` includes full memory snapshot

### Fixed

- `attackLog` typed as `string[]` in web dashboard — corrected to `AttackLogEntry[]` (was the root cause of the `e.startsWith is not a function` crash)
- `f.severity.toUpperCase()` called on potentially non-string values — wrapped with `typeof` guard at all 6 call sites in `ScanDetail.tsx`
- `svc.steps.map()` calling `.startsWith()` on non-string items — pre-filtered with type guard
- `sandbox.attackLog.filter()` using string `.startsWith()` on `AttackLogEntry` objects — replaced with structured entry parsing

### Dashboard — Sandbox tab redesign

- Replaced raw terminal-only view with a full-featured attack intelligence panel:
  - **Stats grid** (6 tiles): Findings, Chains, Secrets, Endpoints, Actions, Tokens — each color-coded
  - **AI Attack Narrative** — agent's running worldview summarizing what it discovered
  - **Confirmed Attack Chains** — orange panel with numbered multi-step exploit chains
  - **Discovered Secrets** — yellow panel listing extracted credential key names (values never shown in the UI)
  - **Sandbox Findings** — red panel with severity badge, CVSS score, validator confidence + score per finding
  - **Open Ports** — detected internal services as port badges
  - **Framework Versions** — detected tech stack from recon
  - **PTT Tree** — visual hierarchy with color-coded node status
  - **Discovered Endpoints** — collapsible grid of mapped routes
  - **Structured Attack Log** — per-entry type badges (`exec`/`http`/`finding`/`chain`/`credential`/`search`/`crawl`/`info`) replacing raw string display; collapsible

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
- `--breach`: 35 credential/infra patterns + aggressive supply chain CVE hunting
- `--bug`: 40 code vulnerability patterns + deep code AI agent
- `--breach --bug` (full): 62 total patterns, all scanners, both AI personalities

**Static code patterns (62 total in full mode)**
- Base (13): hardcoded secrets, `eval()`, SQL concat, weak crypto, CORS wildcard, prototype pollution, path traversal, SSL verify disabled, error stack exposure
- Bug (+27): Python `pickle.loads`, `yaml.load`, `subprocess shell=True`; Go `fmt.Sprintf` SQL, `unsafe.Pointer`; Rust unsafe blocks; SSRF, open redirect, mass assignment, NoSQL injection, `dangerouslySetInnerHTML`, JWT `alg:none`, ReDoS, template injection, zip-slip, timing attack, XXE, LDAP injection
- Breach (+22): GitHub PAT, Stripe/OpenAI/Anthropic/Slack/Supabase/SendGrid/Twilio/AWS keys, Firebase private key, DB connection strings, debug endpoints, admin routes, cloud tokens

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

[0.3.1]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.3.1
[0.3.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.3.0
[0.2.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.2.0
[0.1.0]: https://github.com/Afnanksalal/BreachScope/releases/tag/v0.1.0
