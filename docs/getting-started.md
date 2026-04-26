# Getting Started

## Prerequisites

- Node.js 18 or higher
- npm, pnpm, yarn, or bun
- Docker (required for `breachscope sandbox`)

## Installation

```bash
npm install -g breachscope
```

Or run without installing:

```bash
npx breachscope scan
```

Both `breachscope` and `bs` (shorthand) are available after install.

---

## First Scan

```bash
# Navigate to your project
cd my-project

# Initialize a config (optional but recommended)
breachscope init

# Run a full scan — auto-detects language, runs everything
breachscope scan

# Include a live URL for blackbox + smoke testing
breachscope scan --url https://myapp.com

# Launch Docker attack arena — AI agent attacks your running app
breachscope sandbox
```

---

## Scan Depth

| Flag | Description |
|------|-------------|
| `--mode basic` | Direct tools only — fast (default) |
| `--mode major` | Direct tools + their direct dependencies |
| `--mode deep` | Full transitive dependency tree (up to 6 levels) |

---

## Scan Focus

| Flag(s) | What it focuses on |
|---------|-------------------|
| *(none)* | Balanced — CVE lookup + code audit + supply chain (13 base patterns) |
| `--breach` | Supply chain attacks, CVEs, leaked credentials and API keys (35 patterns) |
| `--bug` | Code vulnerabilities — injection, auth bypass, deserialization, logic bugs (40 patterns) |
| `--breach --bug` | Everything combined — maximum coverage (62 patterns, all scanners) |

---

## Languages

BreachScope auto-detects your stack. No config needed — just run it:

| Language | Manifest files detected |
|----------|------------------------|
| JavaScript / TypeScript | `package.json`, lockfiles |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` |
| Go | `go.mod` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| Java | `pom.xml`, `build.gradle` |
| PHP | `composer.json`, `composer.lock` |
| .NET | `*.csproj`, `packages.lock.json` |
| Elixir | `mix.exs`, `mix.lock` |
| Dart | `pubspec.yaml`, `pubspec.lock` |

CVEs are looked up against OSV.dev with the correct ecosystem per language.

---

## What Gets Scanned

| Target | What it does |
|--------|-------------|
| `dependency` | Audits all package manifests across all languages for CVEs and supply chain risks |
| `code` | Scans source files with 13–62 regex patterns depending on mode |
| `toolchain` | Probes Supabase, Vercel, GitHub APIs for misconfigurations |
| `blackbox` | Hits a live URL for header, CORS, and path exposure issues |
| `smoke` | Tests live app behavior — error leakage, auth bypass, payload limits |
| `all` | All of the above (default) |

---

## AI Mode

AI analysis runs automatically when `OPENAI_API_KEY` is set:

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...   # optional

breachscope scan --mode major --url https://myapp.com
```

BreachScope also discovers SaaS services in your codebase and interactively probes them live — Supabase, GitHub, Stripe, Vercel, OpenAI, and more.

Free threat intel (OSV.dev, NVD, npm advisories) works with no API key.

---

## Docker Attack Arena

The `sandbox` command spins up a Docker container, deploys your app, and runs a multi-agent swarm to actively exploit it:

```bash
breachscope sandbox

# Keep container running after scan for manual inspection
breachscope sandbox --no-cleanup
```

**What happens:**
1. AI reads your entire codebase (including `.env` and secrets) and writes a purpose-built Dockerfile — monorepo-aware
2. Self-healing build loop: up to 4 attempts with AI-powered Dockerfile fixes on failure
3. Supervisor agent analyzes all recon data and creates a prioritized attack plan
4. 4 agents run in parallel: dynamic sandbox attack, static code analysis, dependency CVE scan, blackbox HTTP probe
5. 11 specialist attackers: SQLi, JWT forge, auth bypass, SSRF, XSS, path traversal, Redis exploit, prototype pollution, race conditions, business logic, LLM prompt injection
6. OWASP ZAP active scan runs inside the container
7. Validator agent independently re-confirms every critical/high finding with a confidence score

Results appear in the dashboard Sandbox tab: AI narrative, discovered secrets, confirmed findings with CVSS + validator confidence, Pentest Task Tree, framework versions, full structured attack log.

---

## Maximum Coverage

```bash
# Full static scan — all patterns, deep mode
breachscope scan --mode deep --breach --bug

# Docker attack arena — active exploitation
breachscope sandbox --deep
```

---

## Connect to the Web Dashboard

```bash
breachscope login
```

Opens a browser to authenticate with [breachscoope.vercel.app](https://breachscoope.vercel.app). Once connected, every scan result is pushed automatically — scan history, findings, sandbox terminal replay, PDF reports.

Sign up free with GitHub, Google OAuth, or email/password.

---

## Next Steps

- [Full scan command reference](./commands/scan.md)
- [AI multi-agent mode](./ai-agents.md)
- [Supabase integration](./integrations/supabase.md)
- [CI/CD setup](./commands/scan.md#cicd)
