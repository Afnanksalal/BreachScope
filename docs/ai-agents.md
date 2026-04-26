# AI Multi-Agent Mode

BreachScope's AI pipeline activates automatically when `OPENAI_API_KEY` is set. Each agent has a focused role and adapts behavior based on the active scan mode (`--breach`, `--bug`, or `--breach --bug`).

---

## How It Works

```bash
export OPENAI_API_KEY=sk-...
breachscope scan --mode major --url https://yourapp.com
```

1. Static scanners run first (dependency, code, toolchain, blackbox, smoke)
2. **Orchestrator Agent** reviews the project profile + scan mode and plans which AI agents to dispatch
3. Specialist agents run in sequence, each with tool access:
   - `web_search` — Firecrawl or free OSV/NVD/npm API fallback
   - `crawl_url` — scrape specific advisory/changelog pages
   - HTTP tools — live requests to the target or registry APIs
4. **Report Agent** synthesizes all findings, identifies attack chains, writes executive summary

---

## Mode Awareness

| Mode | Orchestrator bias | Code agent focus | Dep agent focus |
|------|------------------|-----------------|----------------|
| `all` | Balanced dispatch | Broad vulnerability classes | Top 15 risky packages |
| `breach` | Dependency + toolchain heavy | Credential hunt — keys, tokens, infra exposure | 20+ packages: hijacks, malware, CVEs, typosquatting |
| `bug` | Code heavy, skip toolchain | Deep logic bugs — race conditions, IDOR, deserialization | Reachable CVEs in auth/parsing/HTTP packages |
| `full` | Everything runs | Both bug + breach combined | Aggressive + reachable CVEs (25+ packages) |

---

## Agents

### Orchestrator

Plans the attack. Reads the project profile (dependencies, file list, toolchain credentials present, URL, scan mode) and returns a JSON dispatch plan. Falls back to a deterministic plan (no AI) if parsing fails.

**Breach mode fallback**: always includes `dependency + code + toolchain (if creds present) + blackbox (if URL)`  
**Bug mode fallback**: always includes `code + dependency`  
**Full mode fallback**: everything

### Dependency Agent

Researches packages using live tools:
- GitHub Security Advisories
- OSV.dev vulnerability database
- Web search for known incidents, supply chain attacks
- npm advisory data

**In breach mode**: Investigates 20+ packages aggressively. Looks for active malware, postinstall script exfiltration, maintainer takeovers, typosquatting, dependency confusion.

**In bug mode**: Cross-references installed versions against known-vulnerable version ranges. Focuses on packages in auth, parsing, and HTTP handling paths.

**In full mode**: Combines both — 25+ packages, breach hunting + CVE cross-reference.

### Code Agent

Deep static analysis with GPT-4o. Sends prioritized source files (auth, routes, DB, config first) and reasons about the full codebase.

**In breach mode** (`SYSTEM_BREACH` prompt): Hunts exclusively for credentials, secrets, and misconfigurations that give attackers immediate access.

**In bug mode** (`SYSTEM_BUG` prompt): Finds real exploitable security bugs — second-order injection, race conditions in auth flows, prototype pollution chains, subtle SSRF patterns, insecure deserialization, business logic flaws.

**In full mode**: Both prompts merged — credential hunt + deep code vulnerability research simultaneously.

### Toolchain Agent

Fetches live changelogs from Supabase, Vercel, and GitHub. Searches for recent breach patterns, OAuth flow risks, webhook abuse vectors, and cross-tool attack chains. Runs in `breach` and `full` modes.

### Blackbox Agent

HTTP-level penetration tester. Makes targeted requests to the live URL, tests specific attack paths flagged by static scanners, identifies tech stack from response headers. Runs when `--url` is provided.

### Report Agent

CISO-grade synthesis — always runs last. Identifies attack chains (A + B + C = account takeover), writes executive summary and prioritized action list.

---

## Sandbox Agents

The `breachscope sandbox` command runs an additional three specialized agents on top of the main attack loop.

### Sandbox Supervisor

Runs before the main exploit loop. Receives all recon data (discovered credentials, endpoints, open ports, framework versions) and produces a prioritized `SpecialistTask[]` attack plan.

- Performs targeted web searches for known CVEs against detected framework/library versions
- Produces tasks with exact context: endpoint paths, parameter names, credential values, chained hypotheses
- Falls back gracefully if recon data is insufficient (skips with a log entry rather than burning tokens)
- Max 6 tasks per session — quality over quantity

### Sandbox Validator

Runs after the main attack loop. Independently re-verifies every critical and high finding by re-running replication steps from scratch.

- Skeptical by default: must reproduce the same evidence to confirm
- Confidence levels: `confirmed` (≥90/100), `likely` (60–89), `uncertain` (30–59), `false_positive` (<30)
- Results annotated onto findings in the dashboard: confidence badge + score
- Caps at 5 validations per session to control token use
- Medium/low findings skipped (auto-assigned `likely` / 70 score)

### CVE Intelligence (`cve-intel.ts`)

Triggered whenever a CVE ID is found during dependency scanning or live attack. Fetches in parallel:

| Signal | Source | What it provides |
|--------|--------|-----------------|
| EPSS score | FIRST.org API | Exploitation probability in 30 days (0–100%) |
| CVSS + severity | NVD API | Base score, vector string, severity label |
| Nuclei template | projectdiscovery/nuclei-templates | Exploit-ready template available? |
| Exploit-DB entry | Reference URL matching | Public PoC / exploit exists? |

EPSS risk classification: 🔴 >50% (HIGH) · 🟡 10–50% (MEDIUM) · 🟢 <10% (LOW). Displayed inline in agent output and batch CVE reports.

---

## Live Service Probing

With an interactive terminal (`stdin.isTTY`), BreachScope discovers SaaS services in your codebase and prompts for credentials to probe them live:

```bash
breachscope scan
```

```
Detected 3 service(s) in your codebase:
● Supabase (database)
● GitHub (vcs)
● Stripe (payments)

Probe live Supabase environment? [y/N]
  Project URL: ...
  Anon Key: ...
```

Every API call made by the probe agent is logged step-by-step and sent to the dashboard with HTTP method badges (GET/POST/PATCH), search labels (SRCH), and crawl labels (CRAWL).

In CI (`stdin.isTTY === false`), the interactive live service probe is skipped automatically.

---

## Free Threat Intelligence

When `FIRECRAWL_API_KEY` is not set, BreachScope falls back to free public APIs automatically:

- **OSV.dev** — comprehensive open vulnerability database (POST API, no key required)
- **npm advisory bulk API** — security advisories with affected version ranges
- **NVD CVE search** — NIST national vulnerability database keyword search

Firecrawl enables full web search when available but is never required.

---

## Requirements

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...  # optional — free APIs used as fallback
```

Or add to `breachscope.yaml`:

```yaml
ai:
  openaiApiKey: ""    # or OPENAI_API_KEY
  firecrawlApiKey: "" # optional
  model: gpt-4o
```

Keys stored on the dashboard (Settings page) are encrypted with AES-256-GCM and auto-injected into CLI sessions.

---

## Token Usage

| Scan type | Typical token range | Cost at GPT-4o pricing |
|-----------|--------------------|-----------------------|
| Basic scan | 15,000–25,000 | ~$0.04–$0.06 |
| `--mode major` | 25,000–45,000 | ~$0.06–$0.11 |
| `--mode deep --breach --bug` | 40,000–80,000 | ~$0.10–$0.20 |

---

## CI Integration

```yaml
- name: AI Security Scan
  run: breachscope scan --breach --ci
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    FIRECRAWL_API_KEY: ${{ secrets.FIRECRAWL_API_KEY }}
    SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
    SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
```
