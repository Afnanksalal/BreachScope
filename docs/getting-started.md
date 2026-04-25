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

## First scan

```bash
# Navigate to your project
cd my-project

# Initialize a config (optional but recommended)
breachscope init

# Run a full scan
breachscope scan

# Include a live URL for blackbox + smoke testing
breachscope scan --url https://myapp.com
```

## Scan depth

| Flag | Description |
|------|-------------|
| `--mode basic` | Direct tools only — fast (default) |
| `--mode major` | Direct tools + their direct dependencies |
| `--mode deep` | Full transitive dependency tree |

## Scan type

| Flag | Description |
|------|-------------|
| `--scan-mode all` | Everything — CVE + code audit + supply chain + blackbox (default) |
| `--scan-mode breach` | Supply chain, dependency hijacks, CVEs |
| `--scan-mode bug` | Code audit, dangerous patterns, misconfigs |

## What gets scanned

| Target       | What it does |
|--------------|-------------|
| `dependency` | Audits package.json, lockfiles for supply chain risks |
| `code`       | Scans source files for hardcoded secrets, dangerous patterns |
| `toolchain`  | Probes Supabase, Vercel, GitHub APIs for misconfigs |
| `blackbox`   | Hits a live URL for header, CORS, and path exposure issues |
| `smoke`      | Tests live app behavior — error leakage, auth bypass, payload limits |
| `all`        | All of the above |

## Connect to the web dashboard

```bash
breachscope login
```

Opens a browser to authenticate with breachscoope.vercel.app. Once connected, every scan result is pushed to your dashboard automatically — scan history, per-finding details, severity trends, and more.

Sign up at breachscoope.vercel.app — free, with GitHub or Google OAuth, or email and password.

## Next steps

- [Full scan command reference](./commands/scan.md)
- [AI multi-agent mode](./ai-agents.md)
- [Supabase integration](./integrations/supabase.md)
- [CI/CD setup](./commands/scan.md#cicd)
