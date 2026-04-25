<div align="center">

# BreachScope

**Full-stack security scanner — supply chain, code, active pentest, AI agents.**  
Catches what linters and conventional scanners miss, across every language.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/breachscope/breachscope/badge)](https://scorecard.dev/viewer/?uri=github.com/breachscope/breachscope)

</div>

---

## What is BreachScope?

BreachScope is an open-source CLI that audits the full depth of your stack — not just your code, but every package you depend on across **every language**, every tool *those tools* depend on, your live SaaS services, and your running application.

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

# Basic scan — auto-detects language, runs everything
breachscope scan

# Maximum coverage — deep, all modes, AI agents, active pentest
breachscope scan --mode deep --breach --bug --ai --browser --url https://yourapp.com -v
```

Both `breachscope` and `bs` (shorthand) are available after install.

---

## Languages Supported

BreachScope auto-detects your stack and scans the correct manifests for each language:

| Language | Files Scanned | OSV Ecosystem |
|----------|--------------|---------------|
| JavaScript / TypeScript | `package.json`, lockfiles | `npm` |
| Python | `requirements.txt`, `requirements-dev.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 + Poetry + uv/rye), `Pipfile`, `setup.py` | `PyPI` |
| Go | `go.mod` | `Go` |
| Rust | `Cargo.toml`, `Cargo.lock` | `crates.io` |
| Ruby | `Gemfile`, `Gemfile.lock` | `RubyGems` |

All ecosystems query [OSV.dev](https://osv.dev) with the correct ecosystem tag for accurate CVE data.

---

## How It Works

```
Your Codebase (any language)
          │
          ▼
  [Multi-Signal Detector]
  package.json · go.mod · Cargo.toml · requirements.txt
  pyproject.toml · Gemfile · imports · .env · config files
          │
          ▼
  [Tool Classifier]  ← static toolmap (150+ known packages) or GPT-4o
          │
     ┌────┴────┐
    OSS       SaaS
     │         │
  Scorecard  Firecrawl
  OSV.dev    GPT-4o research
  deps.dev   Changelog crawling
  Registry
          │
          ▼
  [Static Scanners]
  66 code patterns (base + bug + breach) · Toolchain probe · Blackbox · Smoke tests
          │
          ▼
  [AI Multi-Agent Layer]  ← --ai
  Orchestrator → Dependency → Code → Toolchain → Blackbox → Report
  (mode-aware: breach/bug/full agents get different system prompts + focus)
          │
          ▼
  [Active Pentest]  ← --browser
  Playwright · SQLi · XSS · JWT attacks · CORS · Rate limit · Sensitive paths
          │
          ▼
  [Web Dashboard]  breachscoope.vercel.app
  Scan history · Findings · Probe activity tab · PDF export
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

Requires **Node.js 18+**.

---

## Commands

```
breachscope scan [options]     Full scan — all engines
breachscope audit              Static code audit only
breachscope probe <url>        Blackbox HTTP probe
breachscope smoke <url>        Smoke tests against live URL
breachscope deps               Dependency + lockfile scan (all languages)
breachscope toolchain          Sub-toolchain risk dashboard
breachscope login              Authenticate CLI with breachscoope.vercel.app
breachscope init               Create breachscope.yaml config

Shorthand: bs scan, bs login, bs deps, etc.
```

### `scan` options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode` | `basic` | Scan depth: `basic` \| `major` \| `deep` |
| `--breach` | — | Breach mode: CVE hunting, credential leaks, supply chain |
| `--bug` | — | Bug mode: deep code audit, injection, deserialization, auth |
| `--breach --bug` | — | Full mode: both combined — 66 patterns, all scanners |
| `-t, --target` | `all` | Scope: `all` \| `dependency` \| `toolchain` \| `code` \| `blackbox` \| `smoke` |
| `-u, --url` | — | Target URL for blackbox, smoke, and browser pentest |
| `-o, --output` | `console` | Output: `console` \| `json` \| `sarif` |
| `-f, --file` | — | Write output to file |
| `--ci` | — | Exit 1 if findings exceed severity threshold |
| `--ai` | — | Enable AI multi-agent analysis + live service probing |
| `--browser` | — | Launch authenticated Playwright pentest (requires `--url`) |
| `-v, --verbose` | — | Debug output |

---

## Scan Modes

### `--breach` — Credential & Supply Chain Mode

Focused on finding what an attacker could exploit right now.

- Runs: dependency scan (all languages), supply chain graph, toolchain misconfig probe, code audit with **36 breach patterns**
- Breach patterns target: GitHub PATs, Stripe/OpenAI/Anthropic/Slack/Supabase JWTs, AWS keys, DB connection strings with creds, Firebase service accounts, DigitalOcean/Cloudflare/Vercel tokens, npm tokens, debug endpoints, admin routes without auth
- AI agents: aggressive CVE/hijack hunting across 20+ packages, credential-focused code review, supply chain incident research

### `--bug` — Code Vulnerability Mode

Focused on exploitable bugs in the code itself.

- Runs: deep code audit with **43 patterns**, dependency scan for known-vulnerable versions
- Skips: toolchain scan, sub-toolchain graph (not relevant to code bugs)
- Bug patterns target: Python `pickle.loads`, `yaml.load` without SafeLoader, `subprocess` with `shell=True`, `os.system` with f-strings; Go SQL via `fmt.Sprintf`, `unsafe.Pointer`; Rust unsafe blocks; SSRF, open redirect, mass assignment (`...req.body`), NoSQL injection, `dangerouslySetInnerHTML`, JWT none algorithm, XXE, LDAP injection, zip-slip, timing attacks, ReDoS, template injection
- AI agents: deep logic bug hunting — race conditions, second-order vulns, IDOR, auth bypass, insecure deserialization

### `--breach --bug` — Full Mode

No scanner is skipped. All 66 patterns run. Both AI agent personalities activate.

```bash
breachscope scan --mode deep --breach --bug --ai --browser --url https://yourapp.com -v
```

---

## Active Penetration Testing (`--browser`)

Launches an authenticated Playwright browser that actively attacks your running application:

```bash
breachscope scan --browser --url https://yourapp.com --ai
# Prompts for: login URL, username, password
```

**Attacks executed:**
- SQL injection — URL params and forms (union, blind, time-based, error-based)
- XSS — payload injection with DOM reflection + `alert()` detection
- JWT attacks — `alg:none`, admin claim injection, ID tampering, kid parameter SQLi
- IDOR — ID enumeration on REST endpoints
- CORS — evil.com origin reflection testing
- Rate limiting — concurrent request flooding to detect missing limits
- Sensitive path enumeration — 30+ paths (`.env`, `/.git`, `/admin`, `/graphql`, `/metrics`, etc.)
- Cookie security flag inspection
- Security header analysis

Results appear in the **Probe Activity** tab of the dashboard.

---

## Live Service Probing (`--ai`)

With `--ai`, BreachScope discovers SaaS services in your codebase and probes them interactively:

```bash
breachscope scan --ai
# Discovers: Supabase, GitHub, Stripe, Vercel, OpenAI, etc.
# Prompts for credentials per service
# Probes live APIs for misconfigurations and permission issues
```

Every API call is logged step-by-step in the dashboard's Probe Activity tab, with HTTP method badges, search queries, and crawl steps.

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
- **Overview Tab** — severity bars, scan mode label (colored: red=breach, yellow=bug, purple=full), duration, tools scanned
- **Findings Tab** — collapsible cards: severity badge, category, file:line, **matched code snippet**, remediation, references
- **Probe Activity Tab** — service probe step logs (HTTP/search/crawl badges) + attack probe grid
- **Report Tab** — export as JSON, Markdown, or **real PDF** (jsPDF — structured, not a print screenshot)
- **API Keys** — generate/revoke CLI tokens (SHA-256 hashed)
- **Settings** — AES-256-GCM encrypted API keys, scan defaults

### PDF Report

The generated PDF includes:
- Dark header bar with project name and generation date
- Color-coded severity summary boxes
- Full findings table with severity color coding
- Dependency risk table (top 40 by risk score with color-coded scores)
- Probe activity log
- Page numbers on every page

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
  openaiApiKey: ""       # or OPENAI_API_KEY
  firecrawlApiKey: ""    # or FIRECRAWL_API_KEY
  model: gpt-4o

output:
  format: console        # console | json | sarif
  verbose: false

thresholds:
  failOn: high           # critical | high | medium | low
```

---

## AI Mode

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...

breachscope scan --ai --mode major --url https://yourapp.com
```

| Agent | Role | Mode Awareness |
|-------|------|---------------|
| **Orchestrator** | Plans agent dispatch based on project profile + scan mode | Biases selection by mode |
| **Dependency** | CVE/advisory research with live web tools | Breach: 20+ packages; Bug: reachable CVEs |
| **Code** | Deep source analysis | Breach: credential hunt; Bug: logic bugs; Full: both |
| **Toolchain** | Live changelog/security page crawling | Breach + full only |
| **Blackbox** | Adaptive HTTP probing | When URL provided |
| **Report** | Deduplication, attack chain synthesis, executive summary | Always |

Token usage: ~20,000–60,000 tokens per scan (~$0.05–$0.15 at GPT-4o pricing).

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

      - name: Bug scan (AI-powered code audit)
        run: breachscope scan --mode deep --bug --ai --ci
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
│       │   ├── dependency/      # index.ts + python.ts, go.ts, rust.ts, ruby.ts
│       │   ├── code/            # patterns.ts (66 rules: base + bug + breach), index.ts
│       │   ├── toolchain/       # Supabase, Vercel, GitHub scanners
│       │   ├── blackbox/        # HTTP security header + path probe
│       │   └── smoke/           # Live app behavior tests
│       ├── agents/              # Orchestrator, dependency, code, toolchain, blackbox, report
│       │   └── attack-probe.ts  # Playwright active pentest (SQLi, XSS, JWT, CORS, rate limit)
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
│   ├── commands/scan.md
│   └── integrations/            # supabase.md, vercel.md
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
