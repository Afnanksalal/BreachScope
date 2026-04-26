<div align="center">

# BreachScope

**Full-stack security scanner — supply chain, code, Docker attack arena, AI agents.**  
Catches what linters and conventional scanners miss, across every language.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Afnanksalal/BreachScope/badge)](https://scorecard.dev/viewer/?uri=github.com/Afnanksalal/BreachScope)

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
| `--breach` | `breach` | CVEs, hijacked packages, leaked credentials, infra exposure | 36 patterns |
| `--bug` | `bug` | Injection flaws, auth bypasses, deserialization, logic bugs | 43 patterns |
| `--breach --bug` | `full` | Everything — maximum coverage | **66 patterns** |

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
  66 code patterns · Toolchain probe · Blackbox · Smoke tests
  Free threat intel: OSV.dev · NVD CVE · npm advisories
          │
          ▼
  [AI Multi-Agent Layer]  ← auto when OPENAI_API_KEY is set
  Orchestrator → Dependency → Code → Toolchain → Blackbox → Report
  (mode-aware: breach/bug/full agents get different system prompts)
          │
          ▼
  [Docker Attack Arena]  ← breachscope sandbox
  AI agent runs as root · installs nmap/sqlmap/nikto freely
  JWT attacks · SSTI · SSRF · path traversal · cmd injection
  Prototype pollution · SQL injection · env secret extraction
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
| `--breach --bug` | — | Full mode: both combined — 66 patterns, all scanners |
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

Spins up an isolated Docker container, deploys your app, and unleashes an AI agent as root to find vulnerabilities through active exploitation — not pattern matching.

```bash
# From your project root — auto-detects language and builds the right Dockerfile
breachscope sandbox

# Extended attack mode
breachscope sandbox --deep

# Keep container alive for manual inspection after scan
breachscope sandbox --no-cleanup
```

**What the AI agent does:**
- Runs as root, installs any tool it needs (nmap, sqlmap, nikto, custom exploits)
- Extracts all environment variables and flags sensitive credentials
- Tests JWT `alg:none` bypass, weak secrets, missing auth on admin routes
- Probes for SSTI in all template engines (Jinja2, Pug, EJS, Handlebars, Twig)
- Tests SSRF via internal metadata endpoints and private IP ranges
- Path traversal, command injection, SQL injection, prototype pollution

**Supported project types:**

| Language | Detection | Base Image |
|----------|-----------|------------|
| Node.js / Bun | `package.json` | node:20-slim |
| Python | `requirements.txt`, `pyproject.toml` | python:3.12-slim |
| Go | `go.mod` | golang:1.22-alpine |
| Rust | `Cargo.toml` | rust:1.78-slim |
| Ruby | `Gemfile` | ruby:3.3-slim |
| Java | `pom.xml`, `build.gradle` | eclipse-temurin:21-jdk |
| PHP | `composer.json` | php:8.3-cli |
| .NET | `*.csproj` | mcr.microsoft.com/dotnet/sdk:8.0 |
| Elixir | `mix.exs` | elixir:1.16-slim |
| Dart | `pubspec.yaml` | dart:3.3 |

Results appear as a **live terminal replay** in the dashboard's Sandbox tab.

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

Firecrawl enhances this with full web search when available, but real CVE data works out of the box.

| Agent | Role | Mode Awareness |
|-------|------|---------------|
| **Orchestrator** | Plans agent dispatch based on project profile + scan mode | Biases selection by mode |
| **Dependency** | CVE/advisory research with live web tools | Breach: 20+ packages; Bug: reachable CVEs |
| **Code** | Deep source analysis | Breach: credential hunt; Bug: logic bugs; Full: both |
| **Toolchain** | Live changelog/security page crawling | Breach + full only |
| **Blackbox** | Adaptive HTTP probing | When URL provided |
| **Report** | Attack chain synthesis, executive summary | Always |

Token usage: ~20,000–60,000 tokens per scan (~$0.05–$0.15 at GPT-4o pricing).

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

### Static Code Patterns (66 total in full mode)

| Set | Count | Examples |
|-----|-------|---------|
| Base | 13 | Hardcoded secrets, eval(), SQL concat, weak crypto, CORS wildcard, path traversal |
| Bug | +30 | Python pickle/yaml/subprocess, Go fmt.Sprintf SQLi, SSRF, JWT none, XXE, mass assignment, ReDoS |
| Breach | +23 | GitHub PAT, Stripe/OpenAI/Anthropic keys, DB connection strings, Firebase private key, admin routes |

---

## Web Dashboard

Every scan is automatically pushed to **breachscoope.vercel.app**.

```bash
breachscope login  # authenticate once — all future scans auto-upload
```

### Features

- **Scan History** — search, filter by scan mode (all/breach/bug/full) and depth (basic/major/deep)
- **Overview Tab** — severity bars, scan mode label, duration, tools scanned, AI executive summary
- **Findings Tab** — collapsible cards: severity badge, category, file:line, matched code snippet, remediation, references
- **Sandbox Tab** — full terminal replay of the Docker AI agent session — every command, HTTP request, credential found, and attack chain
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
│       ├── core/                # Types, config, logger, AI client, tool map, push-scan
│       ├── detectors/           # Multi-signal, multi-language tool detection
│       ├── classifiers/         # GPT-4o OSS/SaaS/hybrid classifier
│       ├── apis/                # Scorecard, OSV.dev, deps.dev, npm, PyPI APIs
│       ├── pipelines/           # OSS pipeline (multi-ecosystem), SaaS pipeline, router
│       ├── engine/              # Recursive sub-toolchain engine + dependency graph
│       ├── scanners/
│       │   ├── dependency/      # JS, Python, Go, Rust, Ruby, Java, PHP, .NET, Elixir, Dart
│       │   ├── code/            # patterns.ts (66 rules: base + bug + breach), index.ts
│       │   ├── toolchain/       # Supabase, Vercel, GitHub scanners
│       │   ├── blackbox/        # HTTP security header + path probe
│       │   └── smoke/           # Live app behavior tests
│       ├── agents/              # Orchestrator, dependency, code, toolchain, blackbox, report
│       │   ├── sandbox-agent.ts # Docker attack arena AI agent (PentestGPT architecture)
│       │   └── live-probe.ts    # Interactive SaaS service probing
│       └── reporters/           # Console, JSON, risk dashboard, AI console
├── web/                         # Next.js 15 dashboard (breachscoope.vercel.app)
│   ├── app/
│   │   ├── dashboard/           # Overview, scans list, scan detail (4 tabs), keys, settings
│   │   └── api/                 # REST: scans POST/GET, findings, keys, settings, remote-config
│   ├── lib/
│   │   ├── schema.ts            # DB: users, scans, findings (with detail col), api_keys, settings
│   │   └── crypto.ts            # AES-256-GCM for stored API keys
│   └── scripts/                 # seed.ts, migrate.ts
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
