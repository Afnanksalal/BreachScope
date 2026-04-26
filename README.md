<div align="center">

# BreachScope

**Full-stack security scanner — supply chain, code, Docker attack arena, AI agents.**  
Catches what linters and conventional scanners miss, across every language.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

</div>

---

## What is BreachScope?

BreachScope is an open-source CLI that audits the full depth of your stack — not just your code, but every package you depend on across **10 languages**, every tool *those tools* depend on, your live SaaS services, and your running application. An AI agent runs autonomously inside a Docker container, installs whatever tools it needs, and actively exploits your app to find vulnerabilities.

It was built because incidents like the [ua-parser-js hijack](https://github.com/advisories/GHSA-pjwm-rvh2-c424), [node-ipc sabotage](https://github.com/advisories/GHSA-97m3-w2cp-4xx6), and countless credential-leak breaches aren't caught by linters or conventional scanners. They require understanding the *entire supply chain* — the GitHub security posture of your libraries, the configuration of your hosted services, and the transitive dependencies you've never thought about.

---

## Scan Depth

| Mode | What it scans | Speed |
|------|--------------|-------|
| `basic` | Direct tools detected in your codebase | Fast |
| `major` | Direct tools + their direct dependencies | Medium |
| `deep` | Full transitive dependency tree (up to 6 levels) | Thorough |

## Scan Focus

| Flag(s) | Mode | Focus | Patterns |
|---------|------|-------|----------|
| *(none)* | `all` | Balanced — CVE + code + supply chain | 13 base |
| `--breach` | `breach` | CVEs, hijacked packages, leaked credentials, infra exposure | 35 patterns |
| `--bug` | `bug` | Injection flaws, auth bypasses, deserialization, logic bugs | 40 patterns |
| `--breach --bug` | `full` | Everything — maximum coverage | **62 patterns** |

---

## Quick Start

```bash
npm install -g breachscope

# Scan a local project — auto-detects language, runs everything
breachscope scan

# Launch Docker attack arena — AI agent attacks your running app
breachscope sandbox

# Full coverage — deep mode, all scan patterns
breachscope scan --mode deep --breach --bug --url https://yourapp.com
```

Both `breachscope` and `bs` (shorthand) are available after install.

---

## Languages Supported

BreachScope auto-detects your stack and scans the correct manifests for each language:

| Language | Files Scanned | OSV Ecosystem |
|----------|--------------|---------------|
| JavaScript / TypeScript | `package.json`, lockfiles | `npm` |
| Python | `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | `PyPI` |
| Go | `go.mod` | `Go` |
| Rust | `Cargo.toml`, `Cargo.lock` | `crates.io` |
| Ruby | `Gemfile`, `Gemfile.lock` | `RubyGems` |
| Java | `pom.xml`, `build.gradle` | Maven Central |
| PHP | `composer.json`, `composer.lock` | Packagist |
| .NET | `*.csproj`, `packages.lock.json` | NuGet |
| Elixir | `mix.exs`, `mix.lock` | Hex.pm |
| Dart | `pubspec.yaml`, `pubspec.lock` | pub.dev |

All ecosystems query [OSV.dev](https://osv.dev) with the correct ecosystem tag for accurate CVE data.

---

## How It Works

```
Your Codebase (any of 10 languages)
          │
          ▼
  [Multi-Signal Detector]
  package.json · go.mod · Cargo.toml · requirements.txt
  pyproject.toml · Gemfile · pom.xml · composer.json
  *.csproj · mix.exs · pubspec.yaml
          │
          ▼
  [Static Scanners]
  62 code patterns · Toolchain probe · Blackbox · Smoke tests
  Free threat intel: OSV.dev · NVD CVE · npm advisories
          │
          ▼
  [AI Multi-Agent Layer]  ← auto when OPENAI_API_KEY is set
  Orchestrator → Dependency → Code → Toolchain → Blackbox → Report
  (mode-aware: breach/bug/full agents get different system prompts)
          │
          ▼
  [Docker Attack Arena]  ← breachscope sandbox
  Phase 0: AI reads codebase + .env → generates Dockerfile (monorepo-aware)
  Self-healing build (4 attempts, web-search fix agent)
  Supervisor → prioritized SpecialistTask[] plan
  Swarm: sandbox agent + code agent + dep agent + blackbox agent (parallel)
  11 specialists: SQL · JWT · auth bypass · SSRF · XSS · traversal
                  Redis · prototype pollution · race conditions
                  business logic · LLM prompt injection · ZAP
  Validator → independent re-verification of critical/high findings
  CVE intel: EPSS · NVD · Nuclei templates · Exploit-DB (per CVE)
          │
          ▼
  [Web Dashboard]  breachscoope.vercel.app
  Scan history · Findings · Sandbox terminal replay · PDF export
```

---

## Installation

```bash
# npm (global)
npm install -g breachscope

# pnpm
pnpm add -g breachscope

# bun
bun add -g breachscope

# No install
npx breachscope scan
```

Requires **Node.js 18+**. Docker is required for `breachscope sandbox`.

---

## Commands

```
breachscope scan [options]     Full scan — all engines
breachscope sandbox [options]  Docker attack arena — AI agent as root
breachscope audit              Static code audit only
breachscope probe <url>        Blackbox HTTP probe
breachscope smoke <url>        Smoke tests against live URL
breachscope deps               Dependency + lockfile scan (all languages)
breachscope toolchain          Sub-toolchain risk dashboard
breachscope login              Authenticate CLI with dashboard
breachscope init               Create breachscope.yaml config

Shorthand: bs scan, bs sandbox, bs login, bs deps, etc.
```

### `scan` options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode` | `basic` | Scan depth: `basic` \| `major` \| `deep` |
| `--breach` | — | Breach mode: CVE hunting, credential leaks, supply chain |
| `--bug` | — | Bug mode: deep code audit, injection, deserialization, auth |
| `--breach --bug` | — | Full mode: both combined — 62 patterns, all scanners |
| `-t, --target` | `all` | Scope: `all` \| `dependency` \| `toolchain` \| `code` \| `blackbox` \| `smoke` |
| `-u, --url` | — | Target URL for blackbox and smoke probing |
| `-o, --output` | `console` | Output: `console` \| `json` \| `sarif` |
| `-f, --file` | — | Write output to file |
| `--ci` | — | Exit 1 if findings exceed severity threshold |
| `-v, --verbose` | — | Debug output |

### `sandbox` options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | auto | App port inside the container |
| `-i, --image` | auto | Custom base Docker image |
| `-t, --timeout` | `60` | Seconds to wait for app start |
| `--deep` | — | Extended attack sequences |
| `--no-cleanup` | — | Keep container running after scan |
| `-u, --url` | — | Target URL context for dashboard reporting |

---

## Docker Attack Arena (`sandbox`)

The most complete part of BreachScope. Reads your entire codebase, generates a purpose-built Dockerfile, deploys your app with all secrets intact, then runs a multi-agent swarm to actively exploit it.

```bash
# From your project root
breachscope sandbox

# Keep container alive after scan for manual inspection
breachscope sandbox --no-cleanup
```

**How it runs:**

1. **Phase 0 — AI codebase understanding**: Reads every source file, `.env`, config, and secret before touching Docker. Builds a full security picture: tech stack, real credentials, auth mechanisms, database, all endpoints. Handles monorepos — detects services, picks the most interesting one to attack.
2. **Dockerfile generation**: AI writes a purpose-built Dockerfile from what it learned — not a template. Correct base image, start command, port, all deps. Monorepo-aware: uses `COPY . .` + `WORKDIR /app/<service>` pattern.
3. **Self-healing build**: Up to 4 build attempts. On failure, AI searches Stack Overflow/docs, applies the fix, rebuilds. Startup crash? Same heal loop on container logs.
4. **Phase 1 — Multi-agent swarm**: 4 agents run in parallel — sandbox attack, static code analysis, dependency CVE scan, blackbox HTTP probe.
5. **Supervisor planning**: Before exploiting, a supervisor agent analyzes all recon (credentials, endpoints, open ports, framework versions) and generates a prioritized attack plan with exact targets and chained hypotheses.
6. **Full attack**: AI agent as root — installs nmap/sqlmap/nikto/ffuf/nuclei/ZAP, extracts DB credentials and connects, forges JWT tokens, exploits SSTI/SSRF/SQLi/path traversal, runs specialist agents for race conditions, business logic, and LLM prompt injection.
7. **Validation**: After the attack loop, a second AI agent independently re-validates every critical and high finding from scratch — assigns a confidence score and evidence to each.

**What the sandbox swarm covers:**

| Specialist | Attack |
|-----------|--------|
| `sql_injection` | SQLi via sqlmap, manual payloads, error-based extraction |
| `jwt_attack` | `alg:none`, weak secret brute force, admin token forge |
| `auth_bypass` | IDOR, mass assignment, privilege escalation, CSRF |
| `ssrf` | AWS/GCP metadata, internal service pivot |
| `xss` | Stored/reflected/DOM XSS in all input vectors |
| `file_traversal` | Path traversal, LFI/RFI, zip-slip |
| `redis_exploit` | Unauthenticated Redis, session hijacking |
| `prototype_pollution` | Deep object merge, `__proto__` / `constructor.prototype` |
| `race_condition` | Parallel request storms on financial/state operations |
| `business_logic` | Pricing manipulation, permission escalation, workflow bypass |
| `ai_llm_attacks` | Prompt injection, jailbreak, system prompt extraction |

**Supported project types:**

| Language | Detection | Base Image |
|----------|-----------|------------|
| Node.js / Bun | `package.json` | node:20 |
| Python | `requirements.txt`, `pyproject.toml` | python:3.11 |
| Go | `go.mod` | golang:1.22 |
| Rust | `Cargo.toml` | rust:1.77 |
| Ruby | `Gemfile` | ruby:3.3 |
| Java | `pom.xml`, `build.gradle` | maven:3.9-eclipse-temurin-21 |
| PHP | `composer.json` | php:8.3-apache |
| .NET | `*.csproj` | mcr.microsoft.com/dotnet/sdk:8.0 |
| Elixir | `mix.exs` | elixir:1.16 |
| Dart | `pubspec.yaml` | dart:stable |

Results appear in the dashboard's **Sandbox tab** — AI narrative, discovered secrets, confirmed findings with CVSS and validator confidence, PTT tree, open ports, framework versions, full structured attack log.

---

## AI Intelligence

AI analysis runs automatically when `OPENAI_API_KEY` is set — no flags required.

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...   # optional — enables full web search

breachscope scan --mode major
```

**Free threat intel (no API key needed):**
- [OSV.dev](https://osv.dev) — comprehensive open vulnerability database (POST API)
- npm advisory bulk API — security advisories with affected version ranges
- NVD CVE search — NIST national vulnerability database

When `FIRECRAWL_API_KEY` is set, all agents use it aggressively — searching HackTricks, PayloadsAllTheThings, Exploit-DB, NVD CVE pages, and GitHub PoC repos to find exact payloads and confirm exploitability before reporting.

| Agent | Role | Mode Awareness |
|-------|------|---------------|
| **Orchestrator** | Plans agent dispatch based on project profile + scan mode | Biases selection by mode |
| **Dependency** | CVE/advisory research with live web tools | Breach: 20+ packages; Bug: reachable CVEs |
| **Code** | Deep source analysis | Breach: credential hunt; Bug: logic bugs; Full: both |
| **Toolchain** | Live changelog/security page crawling | Breach + full only |
| **Blackbox** | Adaptive HTTP probing | When URL provided |
| **Report** | Attack chain synthesis, executive summary | Always |
| **Sandbox Supervisor** | Analyzes recon, builds prioritized specialist attack plan | Sandbox only |
| **Sandbox Validator** | Independently re-verifies critical/high findings | Sandbox only |

**CVE intelligence**: every CVE found triggers an EPSS exploitation probability lookup (FIRST.org), NVD metadata (CVSS, severity, description), Nuclei template availability check, and Exploit-DB presence detection — all in parallel.

Token usage: ~20,000–60,000 tokens per scan (~$0.05–$0.15 at GPT-4o pricing). Sandbox sessions: ~80,000–200,000 tokens.

---

## Live Service Probing

When `OPENAI_API_KEY` is set and running interactively, BreachScope discovers SaaS services in your codebase and probes them for real misconfigurations:

```bash
breachscope scan
# Discovers: Supabase, GitHub, Stripe, Vercel, OpenAI, etc.
# Prompts for credentials per service
# Probes live APIs for misconfigurations and permission issues
```

Every API call is logged step-by-step in the dashboard's Probe Activity tab.

---

## What Gets Scanned

### Sub-Toolchain Engine

Detects every tool your codebase uses, classifies it as OSS/SaaS/hybrid, runs specialized pipelines.

**OSS Pipeline**
- [OpenSSF Scorecard](https://securityscorecards.dev) — 18 security checks: branch protection, pinned CI deps, code review, maintained status, token permissions, and more
- [OSV.dev](https://osv.dev) — CVEs across all ecosystems in a single batch query
- [deps.dev](https://deps.dev) — project health metrics, security score
- Registry metadata — maintainer count, weekly downloads, publish recency

**SaaS Pipeline**
- Firecrawl-powered security page + changelog crawling
- GPT-4o research for known incidents, breach patterns, SDK CVEs

### Static Code Patterns (62 total in full mode)

| Set | Count | Examples |
|-----|-------|---------|
| Base | 13 | Hardcoded secrets, eval(), SQL concat, weak crypto, CORS wildcard, path traversal |
| Bug | +27 | Python pickle/yaml/subprocess, Go fmt.Sprintf SQLi, SSRF, JWT none, XXE, mass assignment, ReDoS |
| Breach | +22 | GitHub PAT, Stripe/OpenAI/Anthropic keys, DB connection strings, Firebase private key, admin routes |

---

## Web Dashboard

Every scan is automatically pushed to **breachscoope.vercel.app**.

```bash
breachscope login  # authenticate once — all future scans auto-upload
```

### Features

- **Scan History** — search, filter by scan mode (all/breach/bug/full) and depth (basic/major/deep)
- **Overview Tab** — severity bars, scan mode label, duration, tools scanned, AI executive summary, attack chains
- **Findings Tab** — Smart Groups view, Supply Chain grid, Raw list with severity/category filters
- **Sandbox Tab** — full attack intelligence panel:
  - AI narrative (agent's running worldview)
  - Discovered secrets with key=value display
  - Confirmed findings with CVSS scores and validator confidence badges
  - PTT (Pentest Task Tree) with color-coded node statuses
  - Open ports and detected framework versions
  - Discovered endpoints
  - Structured attack log with per-entry type badges
- **Report Tab** — export as JSON, Markdown, or real PDF (jsPDF)
- **API Keys** — generate/revoke CLI tokens (SHA-256 hashed)
- **Settings** — AES-256-GCM encrypted API keys, scan defaults

### Self-hosting

```bash
cd web
cp .env.example .env        # DATABASE_URL, NEXTAUTH_SECRET, OAuth credentials
npm install
npm run db:push             # push schema to your Neon/Postgres DB
npm run db:seed             # seed dev user
npm run dev
```

---

## Configuration

```bash
breachscope init
```

```yaml
version: "1"
project: "my-app"
targets:
  - all

subchain:
  maxDepth: 4
  concurrency: 5
  ignore:
    - lodash
    - tslib

toolchain:
  supabase:
    url: ""              # or SUPABASE_URL
    anonKey: ""          # or SUPABASE_ANON_KEY
  vercel:
    token: ""            # or VERCEL_TOKEN
    projectId: ""
  github:
    token: ""            # or GITHUB_TOKEN
    repo: "owner/repo"

ai:
  openaiApiKey: ""       # or OPENAI_API_KEY — AI runs automatically when set
  firecrawlApiKey: ""    # or FIRECRAWL_API_KEY — optional, enables full web search
  model: gpt-4o

output:
  format: console        # console | json | sarif
  verbose: false

thresholds:
  failOn: high           # critical | high | medium | low
```

---

## CI/CD Integration

```yaml
name: BreachScope

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g breachscope

      - name: Breach scan (supply chain + credentials)
        run: breachscope scan --mode major --breach --ci
        env:
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: AI code audit
        run: breachscope scan --mode deep --bug --ci
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          FIRECRAWL_API_KEY: ${{ secrets.FIRECRAWL_API_KEY }}
```

---

## Project Structure

```
breachscope/
├── cli/                         # CLI package (npm: breachscope)
│   └── src/
│       ├── core/
│       │   ├── ai.ts            # agentLoop, token tracking
│       │   ├── cve-intel.ts     # EPSS, NVD, Nuclei template, Exploit-DB lookup
│       │   ├── push-scan.ts     # Dashboard upload with ProbeData + SandboxMemorySnapshot
│       │   └── ...              # Types, config, logger, tool map, docker, crawler
│       ├── detectors/           # Multi-signal, multi-language tool detection
│       ├── classifiers/         # GPT-4o OSS/SaaS/hybrid classifier
│       ├── apis/                # Scorecard, OSV.dev, deps.dev, npm, PyPI APIs
│       ├── pipelines/           # OSS pipeline (multi-ecosystem), SaaS pipeline, router
│       ├── engine/              # Recursive sub-toolchain engine + dependency graph
│       ├── scanners/
│       │   ├── dependency/      # JS, Python, Go, Rust, Ruby, Java, PHP, .NET, Elixir, Dart
│       │   ├── code/            # patterns.ts (62 rules: 13 base + 27 bug + 22 breach), index.ts
│       │   ├── toolchain/       # Supabase, Vercel, GitHub scanners
│       │   ├── blackbox/        # HTTP security header + path probe
│       │   └── smoke/           # Live app behavior tests
│       ├── agents/
│       │   ├── sandbox-agent.ts    # Main Docker attack arena agent (PentestGPT architecture)
│       │   │                       # PTT, AttackMemory, 11 specialists, CoT prompting, ZAP
│       │   ├── sandbox-supervisor.ts # Recon analysis → prioritized SpecialistTask[] plan
│       │   ├── sandbox-validator.ts  # Independent finding re-verification + confidence scoring
│       │   ├── live-probe.ts        # Interactive SaaS service probing
│       │   └── ...                  # Orchestrator, dependency, code, toolchain, blackbox, report
│       ├── commands/
│       │   └── sandbox.ts       # Monorepo detection, self-healing build/runtime loop,
│       │                        #   AI Dockerfile generation, parallel swarm dispatch
│       └── reporters/           # Console, JSON, risk dashboard, AI console
├── web/                         # Next.js 15 dashboard (breachscoope.vercel.app)
│   ├── app/
│   │   ├── dashboard/           # Overview, scans list, scan detail (4 tabs), keys, settings
│   │   └── api/                 # REST: scans POST/GET, findings, keys, settings, remote-config
│   ├── lib/
│   │   ├── schema.ts            # DB: users, scans, findings (with detail col), api_keys, settings
│   │   └── crypto.ts            # AES-256-GCM for stored API keys
│   └── scripts/                 # seed.ts, migrate.ts
├── docs/
│   ├── getting-started.md
│   ├── ai-agents.md
│   └── commands/scan.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, guidelines, and the PR process.

**Most impactful contributions:**
1. New patterns in `cli/src/scanners/code/patterns.ts` (test on 3+ real codebases first)
2. New tools in `cli/src/core/toolmap.ts`
3. New language scanners in `cli/src/scanners/dependency/`
4. False positive reports with reproduction cases

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security bugs.**  
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built for developers who know their biggest risk isn't their own code.</sub>
</div>
