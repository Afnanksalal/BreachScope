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
| `--show-noise` | off | Include review and hidden findings in the report |
| `--all-cves` | off | Include CVE advisories hidden by default |
| `--llm-triage` | off | Use the configured LLM to reason over borderline findings |
| `--no-upload` | off | Keep results local even when dashboard credentials are configured |
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

# Authenticated local-only scan
breachscope scan --no-upload

# Inspect CVE advisories hidden from the default report
breachscope scan --target dependency --all-cves --output json --file breachscope-full.json

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

## Noise Triage

BreachScope does not show every matched CVE or probe observation by default. Findings pass through a deterministic noise gate that considers dependency depth, VEX status, fix path, CISA KEV, EPSS, exploit/reachability signals, probe confidence, and evidence strength.

- `show`: actionable findings included in console, SARIF, dashboard upload, and CI gates.
- `review`: plausible but context-dependent findings kept in JSON metadata and summarized in console.
- `hide`: low-signal CVEs, duplicate advisory noise, and weak hardening/probe observations kept out of the default report.

Use `--all-cves` when you need the full CVE record, `--show-noise` when you need every review/hidden finding, and `--llm-triage` when you want the configured LLM to add reasoning for borderline findings. LLM triage cannot hide confirmed exploit, CISA KEV, high EPSS, direct high/critical dependency, or confirmed sensitive-exposure findings.

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
- confidence and evidence strength
- triage decision and reason
- grouped CVE/GHSA advisory metadata

When results are uploaded to the dashboard, this metadata powers triage, audit logs, and project reporting. Use `--no-upload` to suppress dashboard upload for a specific run.
