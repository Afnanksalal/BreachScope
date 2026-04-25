# Getting Started

## Prerequisites

- Node.js 18 or higher
- npm, pnpm, yarn, or bun

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

# Run a full scan — auto-detects JS, Python, Go, Rust, Ruby
breachscope scan

# Include a live URL for blackbox + smoke testing
breachscope scan --url https://myapp.com
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
| `--breach` | Supply chain attacks, CVEs, leaked credentials and API keys (36 patterns) |
| `--bug` | Code vulnerabilities — injection, auth bypass, deserialization, logic bugs (43 patterns) |
| `--breach --bug` | Everything combined — maximum coverage (66 patterns, all scanners) |

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

CVEs are looked up against OSV.dev with the correct ecosystem per language.

---

## What Gets Scanned

| Target | What it does |
|--------|-------------|
| `dependency` | Audits all package manifests across all languages for CVEs and supply chain risks |
| `code` | Scans source files with 13–66 regex patterns depending on mode |
| `toolchain` | Probes Supabase, Vercel, GitHub APIs for misconfigurations |
| `blackbox` | Hits a live URL for header, CORS, and path exposure issues |
| `smoke` | Tests live app behavior — error leakage, auth bypass, payload limits |
| `all` | All of the above (default) |

---

## AI Mode

Add `--ai` to enable the multi-agent pipeline:

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...

breachscope scan --ai --mode major --url https://myapp.com
```

With `--ai`, BreachScope also discovers SaaS services in your codebase and interactively probes them live — Supabase, GitHub, Stripe, Vercel, OpenAI, and more.

---

## Active Penetration Test

Add `--browser --url` to launch an authenticated Playwright pentest:

```bash
breachscope scan --browser --url https://myapp.com --ai
# Prompts for login URL, username, password
# Runs: SQLi, XSS, JWT attacks, CORS, rate limiting, sensitive path scan
```

---

## Maximum Coverage Command

```bash
breachscope scan --mode deep --breach --bug --ai --browser --url https://yourapp.com -v
```

This runs:
- All 66 code patterns (base + bug + breach)
- Full 6-level transitive dependency graph
- All AI agents with mode-appropriate focus
- Live service probing (interactive)
- Authenticated browser pentest

---

## Connect to the Web Dashboard

```bash
breachscope login
```

Opens a browser to authenticate with [breachscoope.vercel.app](https://breachscoope.vercel.app). Once connected, every scan result is pushed automatically — scan history, findings, probe activity logs, PDF reports.

Sign up free with GitHub, Google OAuth, or email/password.

---

## Next Steps

- [Full scan command reference](./commands/scan.md)
- [AI multi-agent mode](./ai-agents.md)
- [Supabase integration](./integrations/supabase.md)
- [CI/CD setup](./commands/scan.md#cicd)
