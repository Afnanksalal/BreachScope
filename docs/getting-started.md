# Getting Started

This guide gets BreachScope running locally, connected to the dashboard, and ready for CI.

## Prerequisites

- Node.js 20.19 or higher
- npm, pnpm, yarn, or bun
- Docker Desktop for `breachscope sandbox`
- Optional: customer-owned OpenAI and Firecrawl keys for model-assisted analysis and web research

## Install

```bash
npm install -g breachscope

# or run without installing
npx breachscope scan
```

Both `breachscope` and `bs` are available after installation.

## First Local Scan

```bash
cd my-project
breachscope scan
```

BreachScope auto-detects manifests, source files, lockfiles, and supported services. It runs dependency, code, toolchain, blackbox, and smoke scanners when the relevant inputs are present.

## Connect the Dashboard

```bash
breachscope login
```

The login command opens the dashboard in a browser and stores a local API token under `~/.config/breachscope/credentials.json`. Dashboard-connected scans can push results, use encrypted customer-supplied provider keys, and participate in project-level controls. Use `--no-upload` on `scan` or `sandbox` when authenticated runs should stay local.

## Connect A Repository

Open `Dashboard -> Controls`, create a project, and add a GitHub integration with a customer-owned token. After the connection test passes, run a repository audit or enter a pull request number to save a PR-focused audit as a dashboard scan.

For CLI toolchain scans, add the repository to `breachscope.yaml` or set environment variables:

```yaml
toolchain:
  github:
    token: "" # or GITHUB_TOKEN
    repo: "owner/repo" # or GITHUB_REPO
```

## Configure Defaults

```bash
breachscope init
```

Example policy and threshold block:

```yaml
thresholds:
  failOn: high

policy:
  failOn: high
  maxFindings:
    critical: 0
    high: 3
  blockedPackages:
    - event-stream
  deniedCategories:
    - compliance
```

## Scan Modes

| Flag | Purpose |
| --- | --- |
| `--mode basic` | Direct tools and manifests only |
| `--mode major` | Direct tools plus first-level dependencies |
| `--mode deep` | Recursive dependency graph |
| `--breach` | CVEs, supply-chain risk, credentials, infrastructure exposure |
| `--bug` | Code vulnerabilities, injection, auth bypass, deserialization, SSRF, XSS |
| `--breach --bug` | Full coverage |

## Release Evidence

```bash
breachscope scan --output sarif --file breachscope.sarif
breachscope sbom --output cyclonedx --file bom.cdx.json
breachscope scan --output json --file scan.json
breachscope vex --from scan.json --file openvex.json
breachscope suggest-fixes --from scan.json --file fixes.md
```

## Docker Attack Arena

```bash
breachscope sandbox
breachscope sandbox --deep --breach --bug
breachscope sandbox --include-secrets
```

Sandbox secret handling is safe by default: `.env` files are excluded from model context, Docker context, and container environment unless `--include-secrets` is explicitly passed.

## CI Setup

```bash
breachscope init-ci
```

This generates GitHub Actions workflows for pull-request scans, scheduled scans, sandbox scans, and safe Dependabot automation. Set `BREACHSCOPE_API_KEY` in repository secrets, and set `BREACHSCOPE_DASHBOARD_URL` if your dashboard is self-hosted.

## Next Steps

- [Controls and evidence](enterprise.md)
- [Architecture](architecture.md)
- [Scan command reference](commands/scan.md)
- [Sandbox command reference](commands/sandbox.md)
- [Model-assisted analysis](ai-agents.md)
- [GitHub integration](integrations/github.md)
