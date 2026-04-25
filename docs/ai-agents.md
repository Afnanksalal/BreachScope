# AI Multi-Agent Mode

BreachScope's `--ai` flag activates a multi-agent pipeline powered by GPT-4o and Firecrawl. Each agent has a focused role and its behavior adapts based on the active scan mode (`--breach`, `--bug`, or `--breach --bug`).

---

## How It Works

```bash
breachscope scan --ai --mode major --url https://yourapp.com
```

1. Static scanners run first (dependency, code, toolchain, blackbox, smoke)
2. **Orchestrator Agent** reviews the project profile + scan mode and plans which AI agents to dispatch
3. Specialist agents run in sequence, each with tool access:
   - `web_search` — Firecrawl or DuckDuckGo-powered web search
   - `crawl_url` — scrape specific advisory/changelog pages
   - HTTP tools — live requests to the target or registry APIs
4. **Report Agent** synthesizes all findings, deduplicates, identifies attack chains, writes executive summary

---

## Mode Awareness

The orchestrator and every specialist agent receive the current scan mode and behave differently:

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

**In breach mode**: Investigates 20+ packages aggressively. Looks for active malware, postinstall script exfiltration, maintainer takeovers, typosquatting (`lodahs`, `reqest`), dependency confusion (internal-looking names on public registry), recently published packages with access to sensitive APIs.

**In bug mode**: Cross-references installed versions against known-vulnerable version ranges. Focuses on packages in auth, parsing, and HTTP handling paths.

**In full mode**: Combines both — 25+ packages, breach hunting + CVE cross-reference.

### Code Agent

Deep static analysis with GPT-4o. Sends prioritized source files (auth, routes, DB, config first) and reasons about the full codebase.

**In breach mode** (`SYSTEM_BREACH` prompt): Hunts exclusively for credentials, secrets, and misconfigurations that give attackers immediate access. Looks for GitHub PATs, cloud tokens, DB connection strings, hardcoded JWT secrets, debug/admin routes, env file paths.

**In bug mode** (`SYSTEM_BUG` prompt): Finds real exploitable security bugs — second-order injection (data stored safely, used dangerously later), race conditions in auth flows, prototype pollution chains, subtle SSRF patterns, insecure deserialization, business logic flaws (integer overflow in pricing, negative quantities, state transition gaps).

**In full mode**: Both prompts merged — credential hunt + deep code vulnerability research simultaneously.

Uses `web_search` to verify CVEs for specific library versions and look up prior art for suspicious patterns.

### Toolchain Agent

Fetches live changelogs from Supabase, Vercel, and GitHub. Searches for:
- Recent breach patterns specific to the tools in use
- OAuth flow risks
- Webhook abuse vectors
- Third-party integration risks (e.g., GitHub Actions → Vercel token leak pattern)
- Cross-tool attack chains

Runs in `breach` and `full` modes. Skipped in `bug` mode (not relevant to code-level bugs).

### Blackbox Agent

HTTP-level penetration tester. Makes targeted requests to the live URL:
- Tests specific attack paths flagged by static scanners
- Identifies tech stack from response headers and searches for version-specific CVEs
- Builds chained attack paths from individual findings

Runs when `--url` is provided.

### Report Agent

CISO-grade synthesis — always runs last:
- Deduplicates findings from all agents and static scanners
- Identifies attack chains (A + B + C = account takeover)
- Writes executive summary and prioritized action list

---

## Live Service Probing (interactive `--ai`)

With `--ai` and an interactive terminal (`stdin.isTTY`), BreachScope also discovers and probes live SaaS services:

```bash
breachscope scan --ai
```

BreachScope detects services from your codebase (Supabase, GitHub, Stripe, Vercel, OpenAI, Anthropic, Pinecone, Resend, etc.) and prompts:

```
Detected 3 service(s) in your codebase:
● Supabase (database)
● GitHub (vcs)
● Stripe (payments)

Probe live Supabase environment? [y/N]
  Project URL: ...
  Anon Key: ...
```

Every API call made by the probe agent is logged step-by-step and sent to the dashboard Probe Activity tab with HTTP method badges (GET/POST/PATCH), search labels (SRCH), and crawl labels (CRAWL).

---

## Requirements

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...  # optional — DuckDuckGo used as fallback
```

Or add to `breachscope.yaml`:

```yaml
ai:
  openaiApiKey: ""
  firecrawlApiKey: ""
  model: gpt-4o
```

Keys stored on the dashboard (Settings page) are encrypted with AES-256-GCM and auto-injected into CLI sessions.

---

## Token Usage

A full `--ai` scan of a medium-sized project typically uses 20,000–60,000 tokens across all agents.

| Scan type | Typical token range | Cost at GPT-4o pricing |
|-----------|--------------------|-----------------------|
| Basic `--ai` | 15,000–25,000 | ~$0.04–$0.06 |
| `--ai --mode major` | 25,000–45,000 | ~$0.06–$0.11 |
| `--ai --mode deep --breach --bug` | 40,000–80,000 | ~$0.10–$0.20 |

---

## CI Integration

```yaml
- name: AI Security Scan
  run: breachscope scan --ai --breach --ci
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    FIRECRAWL_API_KEY: ${{ secrets.FIRECRAWL_API_KEY }}
    SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
    SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
```

In CI (`stdin.isTTY === false`), the interactive live service probe is skipped automatically. Static scanners, sub-toolchain engine, and all AI agents run normally.
