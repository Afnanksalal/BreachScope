# breachscope scan

Run all enabled scan types against the current project directory.

## Usage

```bash
breachscope scan [options]
# Shorthand:
bs scan [options]
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode` | `basic` | Scan depth: `basic \| major \| deep` |
| `--breach` | — | Breach mode: CVE hunting, credential leaks, supply chain attacks |
| `--bug` | — | Bug mode: deep code audit, injection flaws, deserialization, auth bypasses |
| `--breach --bug` | — | Full mode: both combined — 66 patterns, all scanners |
| `-t, --target` | `all` | Scanner scope: `all \| dependency \| toolchain \| code \| blackbox \| smoke` |
| `-u, --url` | — | Target URL for blackbox and smoke probing |
| `-o, --output` | `console` | Output format: `console \| json \| sarif` |
| `-f, --file` | — | Write output to this file path |
| `-c, --config` | auto-detect | Path to `breachscope.yaml` |
| `--ci` | — | Exit 1 if findings exceed threshold |
| `-v, --verbose` | — | Enable debug logging |

AI analysis runs automatically when `OPENAI_API_KEY` is set — no flag needed.

---

## Scan Depth (`--mode`)

| Value | What it scans |
|-------|--------------|
| `basic` | Direct tools detected in your codebase |
| `major` | Direct tools + their direct npm/PyPI dependencies |
| `deep` | Full transitive dependency tree (up to 6 levels) |

---

## Scan Focus (`--breach` / `--bug`)

| Flag(s) | Mode | Patterns | Scanners active |
|---------|------|----------|----------------|
| *(none)* | `all` | 13 base | Deps, code, toolchain, subchain |
| `--breach` | `breach` | 36 (13 + 23) | Deps, code (credential focus), toolchain, subchain |
| `--bug` | `bug` | 43 (13 + 30) | Deps, code (deep vulns) — skips toolchain, subchain |
| `--breach --bug` | `full` | 66 (13 + 30 + 23) | Everything — no scanner skipped |

### Breach patterns cover
GitHub PATs, Stripe/OpenAI/Anthropic/Slack/Supabase/npm tokens, AWS keys, DB connection strings with credentials, Firebase service accounts, DigitalOcean/Cloudflare/Vercel tokens, debug endpoints, admin routes without visible auth middleware.

### Bug patterns cover
Python `pickle.loads`, `yaml.load` without SafeLoader, `subprocess` with `shell=True`, `os.system` with f-strings; Go SQL injection via `fmt.Sprintf`; Rust `unsafe` blocks; SSRF, open redirect, mass assignment, NoSQL injection, `dangerouslySetInnerHTML`, JWT none algorithm, XXE, LDAP injection, zip-slip, timing attack, ReDoS, template injection.

---

## Languages Detected

| Language | Manifests | OSV Ecosystem |
|----------|-----------|---------------|
| JavaScript / TypeScript | `package.json`, lockfiles | `npm` |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | `PyPI` |
| Go | `go.mod` | `Go` |
| Rust | `Cargo.toml`, `Cargo.lock` | `crates.io` |
| Ruby | `Gemfile`, `Gemfile.lock` | `RubyGems` |
| Java | `pom.xml`, `build.gradle` | Maven Central |
| PHP | `composer.json`, `composer.lock` | Packagist |
| .NET | `*.csproj`, `packages.lock.json` | NuGet |
| Elixir | `mix.exs`, `mix.lock` | Hex.pm |
| Dart | `pubspec.yaml`, `pubspec.lock` | pub.dev |

---

## Examples

```bash
# Auto-detect language, basic scan
breachscope scan

# Scan with live URL (blackbox + smoke)
breachscope scan --url https://myapp.com

# Breach focus — supply chain, CVEs, credential leaks
breachscope scan --breach

# Deep supply chain breach scan
breachscope scan --mode major --breach

# Bug mode — deep code audit
breachscope scan --bug

# Full mode — everything, maximum coverage
breachscope scan --mode deep --breach --bug

# JSON output
breachscope scan -o json -f results.json

# CI pipeline (fails on HIGH+)
breachscope scan --breach --ci

# Docker attack arena — AI agent as root
breachscope sandbox --deep
```

---

## CI/CD

### GitHub Actions

```yaml
name: BreachScope Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  breach-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g breachscope

      - name: Breach scan (CVE + credentials)
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

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above threshold |
| `1` | Findings at or above `thresholds.failOn` severity |

Default failure threshold is `high`. Override in `breachscope.yaml`:

```yaml
thresholds:
  failOn: critical
```

---

## Output Formats

### Console (default)
Colored terminal output with a per-tool risk dashboard, finding summary, and severity breakdown.

### JSON
```bash
breachscope scan -o json -f results.json
```

Structured JSON report with full findings, scan metadata, tool risk data, and summary counts.

### SARIF
```bash
breachscope scan -o sarif -f results.sarif
```

[SARIF](https://sarifweb.azurewebsites.net/) format for GitHub Advanced Security code scanning integration — findings appear as code annotations on PRs.
