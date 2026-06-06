# BreachScope CLI

BreachScope is a local-first security scanner for dependencies, source code, SaaS/toolchain posture, live URLs, sandbox attack evidence, and release artifacts.

## Install

```bash
npm install -g breachscope
```

Requires Node.js 20.19 or newer.

## Quick Start

```bash
breachscope scan
breachscope scan --mode deep --breach --bug --ci
breachscope scan --target dependency --all-cves --output json --file breachscope-full.json
breachscope sandbox --deep
```

Use `breachscope login` to connect the CLI to a BreachScope dashboard, or set `BREACHSCOPE_API_KEY` and optionally `BREACHSCOPE_DASHBOARD_URL` in CI.

## Noise Triage

BreachScope groups CVE advisories by package/fix path and hides low-signal noise from the default report. Use `--all-cves` for hidden CVE detail, `--show-noise` for every review/hidden item, and `--llm-triage` to add LLM reasoning to borderline findings.

## Privacy

Authenticated scans upload dashboard evidence by default. Add `--no-upload` to keep scan or sandbox results local.

## Repository

Full documentation lives at https://github.com/Afnanksalal/BreachScope.
