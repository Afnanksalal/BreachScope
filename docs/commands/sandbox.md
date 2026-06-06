# `breachscope sandbox`

Build an isolated Docker runtime for the current project and run active security probes against it.

## Usage

```bash
breachscope sandbox [options]
bs sandbox [options]
```

## Options

| Flag | Default | Description |
| --- | --- | --- |
| `-p, --port <port>` | auto | App port inside the container |
| `-i, --image <image>` | auto | Custom base Docker image |
| `-t, --timeout <seconds>` | `60` | Startup wait time |
| `--deep` | off | Extended attack depth |
| `--breach` | off | Companion agents focus on supply chain and credentials |
| `--bug` | off | Companion agents focus on exploitable code vulnerabilities |
| `--scan-mode <mode>` | `all` | Explicit companion mode: `all`, `breach`, `bug`, or `full` |
| `--include-secrets` | off | Include `.env` files and local secrets in the sandbox context |
| `--ci` | off | Exit non-zero on high or critical sandbox findings |
| `--no-cleanup` | off | Keep the container after the scan |
| `--no-upload` | off | Keep sandbox results local even when dashboard credentials are configured |
| `-u, --url <url>` | none | URL context for dashboard reporting |
| `-o, --output <format>` | `console` | `console` or `json` |
| `-f, --file <path>` | none | Write results to file |
| `-v, --verbose` | off | Debug output |

## Security Model

Sandbox mode is intentionally aggressive, but its defaults are built for controlled team use:

- `.env` files are excluded from model context by default.
- `.env` files are excluded from Docker build context by default.
- local secret values are not injected into the container unless `--include-secrets` is set.
- containers run with `no-new-privileges`, dropped capabilities, and process limits.
- network capabilities are added only when attack mode requires them.

Use `--include-secrets` only inside disposable test environments.

## Typical Runs

```bash
# Standard active test
breachscope sandbox

# Deep attack with full companion coverage
breachscope sandbox --deep --breach --bug

# CI run
breachscope sandbox --bug --ci

# Keep the container for manual inspection
breachscope sandbox --no-cleanup

# Authenticated local-only sandbox run
breachscope sandbox --no-upload
```

## What It Produces

Sandbox output can include:

- confirmed exploit findings
- attack-chain evidence
- HTTP probe evidence
- dependency CVE context
- blackbox findings
- static code findings
- sanitized secret key names
- structured attack log

Dashboard uploads preserve the same finding model used by `breachscope scan`, so triage, audit logs, VEX status, and compliance tags remain consistent.
