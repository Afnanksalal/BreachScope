<div align="center">

# BreachScope

**Supply chain & toolchain breach scanner.**  
Detect vulnerabilities across your entire stack — before attackers do.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/breachscope/breachscope/badge)](https://scorecard.dev/viewer/?uri=github.com/breachscope/breachscope)

</div>

---

## What is BreachScope?

BreachScope is an open-source CLI that audits the full depth of your stack — not just your code, but every tool you depend on and every tool *those tools* depend on.

It was built because incidents like the [Vercel breach](https://vercel.com/blog/vercel-breach-analysis), the [ua-parser-js hijack](https://github.com/advisories/GHSA-pjwm-rvh2-c424), and the [node-ipc sabotage](https://github.com/advisories/GHSA-97m3-w2cp-4xx6) aren't caught by linters or conventional dependency scanners. They require understanding the *entire supply chain* — the GitHub security posture of your libraries, the configuration of your hosted services, and the transitive dependencies you've never thought about.

---

## Scan Depth

| Mode | What it scans | Speed |
|------|--------------|-------|
| `basic` | Direct tools in your codebase | Fast |
| `major` | Direct tools + their direct dependencies | Medium |
| `deep` | Full transitive dependency tree (up to 6 levels) | Thorough |

## Scan Type

| Mode | Focus |
|------|-------|
| `all` | CVE + code audit + supply chain + blackbox |
| `breach` | Supply chain, dependency hijacks, CVEs |
| `bug` | Code audit, dangerous patterns, misconfigs |

```bash
breachscope scan --mode basic --scan-mode all      # default
breachscope scan --mode major --scan-mode breach   # supply chain focus
breachscope scan --mode deep  --scan-mode bug      # deep code audit
```

---

## How It Works

```
Your Codebase
     │
     ▼
[Multi-Signal Detector]
package.json · import statements · .env files · config files
     │
     ▼
[Tool Classifier]  ← GPT-4o (or static toolmap for 80+ known packages)
     │
     ├── OSS ──────────────────────────────────────────────────┐
     │                                                          │
     │   ┌─ OpenSSF Scorecard API ──────────────────────────┐  │
     │   ├─ OSV.dev vulnerability database ─────────────────┤  │
     │   ├─ deps.dev project metadata ─────────────────────┤  │
     │   └─ npm registry (maintainers, download velocity) ──┘  │
     │                                                          │
     ├── SaaS ─────────────────────────────────────────────────┤
     │                                                          │
     │   ┌─ Firecrawl: security pages & changelogs ──────────┐ │
     │   └─ GPT-4o: incident research & misconfiguration ────┘ │
     │                                                          │
     └── Hybrid ────────────────────────────────────────────── both pipelines
                                                                │
                                                                ▼
                                                       [Risk Dashboard]
                                                    Per-tool risk scores (0–100)
                                                    Scorecard + OSV + npm signals
                                                    AI summaries + attack chains
                                                                │
                                                                ▼
                                                     [Web Dashboard]
                                                  breachscoope.vercel.app — scan history,
                                                  findings, API key management
```

**In `major` / `deep` mode**, each discovered tool's own npm dependencies are fetched and recursively scanned, building a full dependency graph.

---

## Installation

```bash
# npm
npm install -g breachscope

# pnpm
pnpm add -g breachscope

# bun
bun add -g breachscope

# Or run without installing
npx breachscope scan
```

Requires **Node.js 18+**.

---

## Quick Start

```bash
# Initialize config
breachscope init

# Scan your project (basic mode — direct tools only)
breachscope scan

# Scan with a live URL for blackbox + smoke testing
breachscope scan --url https://myapp.com

# Go deeper — audit sub-dependencies too
breachscope scan --mode major

# Supply chain focus only
breachscope scan --mode major --scan-mode breach

# Full transitive tree, all scan types
breachscope scan --mode deep --url https://myapp.com
```

---

## Commands

```
breachscope scan [options]     Full scan — all engines
breachscope audit              Static code audit only
breachscope probe <url>        Blackbox HTTP probe
breachscope smoke <url>        Smoke tests against live URL
breachscope deps               Dependency + lockfile scan
breachscope toolchain          Sub-toolchain risk dashboard
breachscope login              Authenticate CLI with breachscoope.vercel.app
breachscope init               Create breachscope.yaml config
```

### `scan` options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode` | `basic` | Scan depth: `basic` \| `major` \| `deep` |
| `-s, --scan-mode` | `all` | Scan type: `all` \| `breach` \| `bug` |
| `-u, --url` | — | Target URL for blackbox + smoke |
| `-o, --output` | `console` | Output: `console` \| `json` \| `sarif` |
| `-f, --file` | — | Write output to file |
| `--ci` | — | Exit 1 if findings exceed threshold |
| `--ai` | — | Enable AI multi-agent analysis |
| `-v, --verbose` | — | Debug output |

---

## Web Dashboard

BreachScope includes a hosted dashboard at **breachscoope.vercel.app** for viewing scan history, browsing findings, and managing CLI authentication.

### Connect the CLI

```bash
breachscope login
# Opens a browser — sign in once, all future scans push results to your dashboard
```

### Dashboard Features

- **Scan History** — every scan result stored with full findings breakdown
- **Findings View** — per-finding severity, category, remediation, file/line reference
- **API Keys** — generate and revoke CLI authentication tokens
- **Settings** — store encrypted OpenAI and Firecrawl keys (AES-256-GCM), set scan defaults
- **Overview** — 30-day stats: critical/high counts, findings by category, trend chart

### Self-hosting

The dashboard lives in `web/` and runs on Next.js 15 + Neon (PostgreSQL) + Drizzle ORM.

```bash
cd web
cp .env.example .env        # fill in DATABASE_URL, NEXTAUTH_SECRET, OAuth credentials
npm install
npm run db:push             # push schema to your database
npm run db:seed             # seed a dev user (set SEED_EMAIL env var)
npm run dev
```

---

## What Gets Scanned

### Sub-Toolchain Engine

Detects every tool your codebase uses, classifies it as OSS, SaaS, or hybrid, then runs specialized pipelines:

**OSS Pipeline**
- [OpenSSF Scorecard](https://securityscorecards.dev) — 18 security checks: branch protection, pinned CI deps, code review, maintained status, binary artifacts, token permissions, and more
- [OSV.dev](https://osv.dev) — comprehensive vulnerability database (CVEs, GitHub Advisories, OSV records)
- [deps.dev](https://deps.dev) — project health metrics, security score
- npm registry — maintainer count, weekly downloads, publish recency

**SaaS Pipeline**
- Firecrawl-powered security page + changelog crawling
- GPT-4o research for known incidents, breach patterns, SDK CVEs

### Static Scanners

| Scanner | What it finds |
|---------|--------------|
| **Dependency** | Hijacked packages, insecure registries, missing integrity hashes, wildcard versions |
| **Code Audit** | Hardcoded secrets, AWS keys, `eval()`, SQL injection, path traversal, weak crypto, CORS wildcards, prototype pollution, SSL verification disabled |
| **Toolchain** | Supabase RLS misconfig, service role key exposure, Vercel preview secrets, GitHub branch protection gaps, overprivileged tokens |
| **Blackbox** | Security headers (HSTS, CSP, X-Frame-Options), CORS origin reflection, exposed `.env`/`.git` paths, HTTP TRACE |
| **Smoke Tests** | Error stack trace leakage, unauthenticated admin routes, missing payload limits, reachability |

---

## Configuration

```bash
breachscope init  # generates breachscope.yaml
```

```yaml
version: "1"
project: "my-app"

targets:
  - all

# Sub-toolchain scan settings
subchain:
  maxDepth: 4        # override for deep mode
  concurrency: 5     # parallel tool scans
  ignore:            # skip specific packages
    - lodash
    - tslib

toolchain:
  supabase:
    url: ""            # or SUPABASE_URL env var
    anonKey: ""        # or SUPABASE_ANON_KEY env var
  vercel:
    token: ""          # or VERCEL_TOKEN env var
    projectId: ""
  github:
    token: ""          # or GITHUB_TOKEN env var
    repo: "owner/repo"

# AI multi-agent mode
ai:
  openaiApiKey: ""     # or OPENAI_API_KEY env var
  firecrawlApiKey: ""  # or FIRECRAWL_API_KEY env var
  model: gpt-4o

output:
  format: console      # console | json | sarif
  verbose: false

thresholds:
  failOn: high         # critical | high | medium | low
```

All secrets can be supplied as environment variables — the config file never needs to contain credentials.

---

## AI Mode

Add `--ai` to activate the multi-agent pipeline (GPT-4o + Firecrawl):

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...

breachscope scan --ai --mode major --url https://yourapp.com
```

**Agents:**

| Agent | Role |
|-------|------|
| **Orchestrator** | Plans dispatch based on project profile |
| **Dependency** | Researches packages against live CVE/advisory databases |
| **Code** | Deep source reasoning — second-order vulns, race conditions, ReDoS |
| **Toolchain** | Fetches live changelogs, finds cross-tool attack chains |
| **Blackbox** | Adaptive HTTP probing with targeted follow-up requests |
| **Report** | Deduplication, attack chain synthesis, executive summary |

A full `--ai` scan typically uses 20,000–60,000 tokens (~$0.05–$0.15 at GPT-4o pricing).

---

## CI/CD Integration

### GitHub Actions

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
      - name: Run breach scan
        run: breachscope scan --mode major --scan-mode all --ci
        env:
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Exits with code `1` if any finding meets or exceeds the `thresholds.failOn` severity (default: `high`).

---

## Project Structure

```
breachscope/
├── cli/                         # CLI package (npm: breachscope)
│   └── src/
│       ├── core/                # Types, config, logger, AI client, Firecrawl, tool map
│       ├── detectors/           # Multi-signal tool detection
│       ├── classifiers/         # GPT-4o tool classifier
│       ├── apis/                # Scorecard, OSV.dev, deps.dev, npm registry
│       ├── pipelines/           # OSS pipeline, SaaS pipeline, router
│       ├── engine/              # Recursive sub-toolchain scan engine
│       ├── scanners/            # Static scanners (dep, code, toolchain, blackbox, smoke)
│       ├── agents/              # AI multi-agent system
│       └── reporters/           # Console, JSON, risk dashboard, AI console
├── web/                         # Next.js 15 dashboard (breachscoope.vercel.app)
│   ├── app/
│   │   ├── dashboard/           # Overview, scans, scan detail, API keys, settings
│   │   ├── api/                 # REST endpoints (scans, findings, keys, settings, auth)
│   │   ├── login/               # Email/password + GitHub/Google OAuth
│   │   └── docs/                # Documentation page
│   ├── components/
│   │   ├── dashboard/           # Sidebar, TopBar, StatsCard, ScanRow, charts
│   │   └── ...                  # Landing page components
│   ├── lib/
│   │   ├── auth.ts              # NextAuth v5 — JWT strategy, Credentials + OAuth
│   │   ├── db.ts                # Drizzle ORM + Neon PostgreSQL
│   │   ├── schema.ts            # Full DB schema (users, scans, findings, api_keys, settings)
│   │   └── crypto.ts            # AES-256-GCM encryption for user API keys
│   └── scripts/
│       ├── seed.ts              # Dev database seeder
│       └── migrate.ts           # Production migration runner
├── docs/                        # Markdown documentation
│   ├── getting-started.md
│   ├── ai-agents.md
│   ├── commands/scan.md
│   └── integrations/
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## Contributing

We welcome contributions — new detection rules, tool integrations, bug fixes, and documentation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding guidelines, and the PR process.

**Good first issues** are tagged in GitHub. The most impactful contributions right now:
1. Adding tools to `cli/src/core/toolmap.ts`
2. Adding detection rules to `cli/src/scanners/code/patterns.ts`
3. Reporting false positives with reproduction cases

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security bugs.**  
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built for the developers who know their biggest risk isn't their own code.</sub>
</div>
