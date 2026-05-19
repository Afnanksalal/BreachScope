# `breachscope scan`

Run security scanners against the current project, an optional live URL, or both.

## Usage

```bash
breachscope scan [options]
bs scan [options]
```

## Options

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --mode <mode>` | `basic` | Scan depth: `basic`, `major`, or `deep` |
| `--breach` | off | CVE, supply-chain, credential, and exposure focus |
| `--bug` | off | Code vulnerability focus |
| `-t, --target <target>` | `all` | `all`, `dependency`, `toolchain`, `code`, `blackbox`, or `smoke` |
| `-u, --url <url>` | none | Target URL for blackbox and smoke probing |
| `-o, --output <format>` | `console` | `console`, `json`, or `sarif` |
| `-f, --file <path>` | none | Write output to a file |
| `-c, --config <path>` | auto | Path to `breachscope.yaml` |
| `--ci` | off | Exit non-zero when threshold or policy fails |
| `--fail-on <severity>` | config | Override severity threshold |
| `--baseline <path>` | none | Ignore findings already present in a baseline |
| `--write-baseline <path>` | none | Write current findings as a baseline |
| `--new-findings-only` | off | Report only findings not in the baseline |
| `--policy <path>` | config | Load policy-as-code from JSON or YAML |
| `-v, --verbose` | off | Enable debug output |

## Examples

```bash
# Balanced local scan
breachscope scan

# Live URL probing
breachscope scan --url https://app.example.com

# Maximum local coverage
breachscope scan --mode deep --breach --bug

# CI gate with policy-as-code
breachscope scan --ci --policy release-gate.yml --output sarif --file breachscope.sarif

# Baseline adoption flow
breachscope scan --write-baseline breachscope-baseline.json
breachscope scan --baseline breachscope-baseline.json --new-findings-only --ci
```

## Output Formats

| Format | Use |
| --- | --- |
| `console` | Human-readable terminal report |
| `json` | Full machine-readable scan result |
| `sarif` | Code scanning platforms such as GitHub Advanced Security |

## Policy and Exit Codes

`--ci` exits with:

| Code | Meaning |
| --- | --- |
| `0` | No threshold or policy failure |
| `1` | A finding, policy violation, or finding budget failed the configured gate |

Policy documents support severity thresholds, finding budgets, blocked packages, denied categories, and expiring suppressions. See [Controls and Evidence](../enterprise.md).

## Generated Finding Metadata

Each finding can include:

- stable fingerprint
- compliance tags
- status
- assignee
- due date
- accepted-risk reason
- suppression expiry
- VEX status

When results are uploaded to the dashboard, this metadata powers triage, audit logs, and project reporting.
