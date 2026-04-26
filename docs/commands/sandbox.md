# breachscope sandbox

Spin up a Docker container, deploy your app inside it, and run a multi-agent attack swarm to actively exploit it.

## Usage

```bash
breachscope sandbox [options]
# Shorthand:
bs sandbox [options]
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | auto | App port inside the container (auto-detected from project) |
| `-i, --image` | auto | Custom base Docker image |
| `-t, --timeout` | `60` | Seconds to wait for the app to start (max 180) |
| `--deep` | — | Extended attack: 120 iterations instead of 80 |
| `--breach` | — | Companion agents focus on supply chain & credential risk |
| `--bug` | — | Companion agents focus on exploitable code vulnerabilities |
| `--scan-mode <mode>` | `all` | Explicit companion mode: `all \| breach \| bug` (overrides `--breach`/`--bug`) |
| `--no-cleanup` | — | Keep container running after scan for manual inspection |
| `-u, --url` | — | Target URL context for dashboard reporting |
| `-o, --output` | `console` | Output format: `console \| json` |
| `-f, --file` | — | Write results to file |
| `-v, --verbose` | — | Debug output |

### Flag priority

CLI flags take priority over dashboard settings. Resolution order:

1. `--scan-mode <mode>` (explicit, wins everything)
2. `--breach` / `--bug` flags
3. Dashboard Settings → Sandbox Defaults → Companion Agent Mode
4. Default: `all`

Same order applies to `--deep` vs dashboard Settings → Sandbox Defaults → Attack Depth.

---

## What It Does

### Phase 0 — AI Codebase Understanding

Before touching Docker, an AI agent reads every source file, `.env`, config, and secret. It builds a complete security picture:

- Real credentials and API keys in use
- Auth mechanism (JWT, sessions, OAuth)
- Database type and connection details
- All endpoints and route patterns
- Tech stack and framework versions

It also writes a purpose-built Dockerfile — no templates. For monorepos, it detects all services, picks the most interesting one to attack, and applies the `COPY . .` + `WORKDIR /app/<service>` pattern.

### Build + Self-Healing

The container is built with `.dockerignore` temporarily neutralized so `.env` and all secret files land in the image. On build failure:

1. AI extracts the error from build logs
2. Searches Stack Overflow / docs for the fix
3. Applies it and rebuilds — up to 4 attempts

Startup crashes trigger the same loop against container logs.

### Phase 1 — Swarm Attack

Six tasks run in parallel:

| Task | What it does |
|------|-------------|
| **Sandbox attack agent** | AI as root — active exploitation (see below) |
| **Code agent** | Deep source analysis, logic bugs, missing auth, IDOR |
| **Dependency CVE agent** | CVE research across all 10 ecosystems |
| **Blackbox agent** | External HTTP probe — CORS, headers, exposed endpoints |
| **Static code audit** | 62-pattern static scan (same as `breachscope scan --breach --bug`) |
| **Static dep scanner** | OSV.dev batch query across all languages |

The `--breach`, `--bug`, and `--scan-mode` flags control the focus of the code, dependency, and blackbox AI agents. The sandbox attack agent always goes all-out regardless of mode.

### Supervisor Planning

Before the main exploit loop, a supervisor agent:

- Reviews all recon data: discovered credentials, endpoints, open ports, framework versions
- Performs targeted CVE searches for the detected framework/library versions
- Produces a prioritized `SpecialistTask[]` plan with exact targets, parameters, and chained attack hypotheses
- Max 6 tasks — quality over quantity

### Specialist Agents (11 types)

| Specialist | Attack surface |
|-----------|---------------|
| `sql_injection` | SQLi via sqlmap, manual payloads, error-based extraction |
| `jwt_attack` | `alg:none`, weak secret brute force, admin token forge |
| `auth_bypass` | IDOR, mass assignment, privilege escalation, CSRF |
| `ssrf` | AWS/GCP metadata, internal service enumeration and pivot |
| `xss` | Stored, reflected, DOM XSS across all input vectors |
| `file_traversal` | Path traversal, LFI/RFI, zip-slip |
| `redis_exploit` | Unauthenticated Redis, session hijacking |
| `prototype_pollution` | Deep object merge, `__proto__` / `constructor.prototype` |
| `race_condition` | Parallel request storms on financial/state operations |
| `business_logic` | Pricing manipulation, permission escalation, workflow bypass |
| `ai_llm_attacks` | Prompt injection, jailbreak, system prompt extraction |

### Rabbit Hole Prevention

Commands attempted ≥3 times are automatically abandoned. A `[RABBIT HOLE]` log entry is added and the agent is forced to reassign the hypothesis — no token waste on dead ends.

### OWASP ZAP

ZAP runs entirely inside the container (no host-side setup). It:
- Installs via the JAR at `/opt/zap`
- Spiders the app, then runs an active scan
- Results feed into the finding pipeline

### Validator

After the attack loop, a second AI agent independently re-verifies every critical and high finding from scratch:

| Confidence | Score | Meaning |
|-----------|-------|---------|
| `confirmed` | ≥ 90 | Reproduced with same evidence |
| `likely` | 60–89 | Strong but not fully reproduced |
| `uncertain` | 30–59 | Partial evidence only |
| `false_positive` | < 30 | Could not reproduce |

Medium and low findings are auto-assigned `likely` / 70 to avoid burning tokens on low-impact issues. Max 5 validations per session.

---

## Supported Project Types

| Language | Detection | Base Image |
|----------|-----------|------------|
| Node.js / Bun | `package.json` | node:20 |
| Python | `requirements.txt`, `pyproject.toml` | python:3.11 |
| Go | `go.mod` | golang:1.22 |
| Rust | `Cargo.toml` | rust:1.77 |
| Ruby | `Gemfile` | ruby:3.3 |
| Java | `pom.xml`, `build.gradle` | maven:3.9-eclipse-temurin-21 |
| PHP | `composer.json` | php:8.3-apache |
| .NET | `*.csproj` | mcr.microsoft.com/dotnet/sdk:8.0 |
| Elixir | `mix.exs` | elixir:1.16 |
| Dart | `pubspec.yaml` | dart:stable |

Unknown project type? BreachScope generates a full Ubuntu 22.04 container with nmap, sqlmap, nikto, curl, python3, nodejs, postgresql-client, and redis-tools pre-installed, then auto-detects and starts whatever app it finds.

---

## Dashboard Output

Results appear in the **Sandbox tab** of the scan detail page:

- **Stats grid** — Findings, Chains, Secrets, Endpoints, Actions, Tokens
- **AI Attack Narrative** — agent's running worldview summarizing discoveries
- **Confirmed Attack Chains** — multi-step exploit chains (A → B → C)
- **Discovered Secrets** — extracted key=value credentials
- **Sandbox Findings** — severity badge, CVSS score, validator confidence + score per finding
- **Open Ports** — internal services detected during recon
- **Framework Versions** — detected tech stack
- **PTT Tree** — Pentest Task Tree with color-coded node statuses
- **Discovered Endpoints** — collapsible grid of mapped routes
- **Structured Attack Log** — per-entry type badges: `exec` / `http` / `finding` / `chain` / `credential` / `search` / `crawl` / `info`

---

## Settings

Sandbox defaults can be configured in the dashboard **Settings page** under **Sandbox Defaults**:

| Setting | Options | Description |
|---------|---------|-------------|
| Attack Depth | Normal / Deep | Normal = 80 iterations, Deep = 120 |
| Companion Agent Mode | All / Breach / Bug | Focus for code, dep, and blackbox agents |

CLI flags override these settings.

---

## Examples

```bash
# Basic sandbox — auto-detect everything
breachscope sandbox

# Deep mode — more attack iterations
breachscope sandbox --deep

# Focus companion agents on CVE + supply chain
breachscope sandbox --breach

# Focus companion agents on code vulns
breachscope sandbox --bug

# Full — deep attack + all companion agent modes
breachscope sandbox --deep --breach --bug

# Keep container for manual exploration after scan
breachscope sandbox --no-cleanup

# Save results to JSON
breachscope sandbox -o json -f sandbox-results.json

# Verbose — see every agent step live
breachscope sandbox --verbose
```

---

## Requirements

- Docker Desktop running
- Node.js 18+
- `OPENAI_API_KEY` set (AI phase is skipped without it, static scanners still run)

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...  # optional — enables full web research
```

Or store keys once in the dashboard Settings page — they are encrypted with AES-256-GCM and automatically injected at runtime.

---

## Token Usage

| Mode | Typical range | Cost at GPT-4o pricing |
|------|--------------|----------------------|
| Normal (80 iterations) | 80,000–150,000 | ~$0.20–$0.38 |
| Deep (120 iterations) | 130,000–220,000 | ~$0.33–$0.55 |

Tokens cover: codebase understanding, Dockerfile generation, supervisor plan, sandbox attack agent, code/dep/blackbox agents, validator, report synthesis.
