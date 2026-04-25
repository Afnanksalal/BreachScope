# breachscope scan

Run all enabled scan types against the current project directory.

## Usage

```bash
breachscope scan [options]
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode` | `basic` | Scan depth: `basic \| major \| deep` |
| `-s, --scan-mode` | `all` | Scan type: `all \| breach \| bug` |
| `-t, --target` | `all` | Scanner: `all \| dependency \| toolchain \| code \| blackbox \| smoke` |
| `-u, --url` | — | Target URL (required for blackbox/smoke) |
| `-o, --output` | `console` | Output format: `console \| json \| sarif` |
| `-f, --file` | — | Write output to this file path |
| `-c, --config` | auto-detect | Path to `breachscope.yaml` |
| `--ci` | — | Exit 1 if findings exceed threshold |
| `--ai` | — | Enable AI multi-agent pipeline |
| `-v, --verbose` | — | Enable debug logging |

## Scan depth (`--mode`)

| Value | What it scans |
|-------|--------------|
| `basic` | Direct tools detected in your codebase |
| `major` | Direct tools + their direct npm dependencies |
| `deep` | Full transitive dependency tree (up to 6 levels) |

## Scan type (`--scan-mode`)

| Value | Focus |
|-------|-------|
| `all` | CVE + supply chain + code audit + blackbox (default) |
| `breach` | Dependency hijacks, CVEs, supply chain signals |
| `bug` | Code audit, dangerous patterns, misconfigurations |

## Examples

```bash
# Full scan with URL
breachscope scan --url https://myapp.com

# Supply chain focus, deeper scan
breachscope scan --mode major --scan-mode breach

# Code audit only
breachscope scan --scan-mode bug --target code

# Dependency + code only (no URL needed)
breachscope scan --target dependency
breachscope scan --target code

# JSON output for integration
breachscope scan -o json -f results.json

# CI pipeline (fails if any HIGH or above)
breachscope scan --url $APP_URL --ci

# AI mode (requires OPENAI_API_KEY + FIRECRAWL_API_KEY)
breachscope scan --ai --mode major --url https://myapp.com
```

## CI/CD

### GitHub Actions

```yaml
- name: BreachScope
  run: breachscope scan --mode major --scan-mode all --ci
  env:
    SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
    SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
    VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above threshold |
| `1` | Findings at or above `thresholds.failOn` severity |

The default failure threshold is `high`. Change it in `breachscope.yaml`:

```yaml
thresholds:
  failOn: critical  # only fail on critical
```
