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
| `code` | Scans source files with 13–66 regex patterns depending on mode |
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

The `sandbox` command spins up a Docker container and runs an AI agent as root to actively exploit your app:

```bash
breachscope sandbox

# Extended attack mode
breachscope sandbox --deep
```

The agent installs any tool it needs (nmap, sqlmap, nikto), extracts env credentials, and tests JWT bypass, SSTI, SSRF, path traversal, command injection, and more. Results appear as a terminal replay in the dashboard.

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
