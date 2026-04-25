# AI Multi-Agent Mode

BreachScope's `--ai` flag activates a multi-agent pipeline powered by GPT-4o and Firecrawl.

## How it works

```
breachscope scan --ai --url https://yourapp.com
```

1. Static scanners run first (dependency, code, toolchain, blackbox, smoke)
2. **Orchestrator Agent** (GPT-4o) reviews the project profile and plans which AI agents to dispatch
3. Specialist agents run in sequence, each with access to tools:
   - `web_search` — Firecrawl-powered web search
   - `crawl_url` — scrape specific advisory/changelog pages
   - `http_probe` — live HTTP requests to the target
4. **Report Agent** synthesizes all findings, deduplicates, identifies attack chains, and writes an executive summary

## Agents

### Orchestrator
Plans the attack. Reads the project profile (deps, files, toolchain config, URL presence) and decides which agents are worth running. Returns a dispatch plan with rationale.

### Dependency Agent
Researches packages using:
- GitHub Security Advisories
- OSV.dev vulnerability database
- Web search for known incidents
- npm audit data

Goes beyond known-flagged packages — looks for recently transferred packages, single-maintainer high-download packages, typosquatting candidates.

### Code Agent
Deep static analysis with GPT-4o. Sends prioritized source files (auth, routes, DB, config first) and reasons about:
- Second-order injection (data stored safely, used dangerously elsewhere)
- ReDoS patterns (regex backtracking)
- Race conditions in auth flows
- Prototype pollution chains
- Subtle SSRF patterns

Uses web_search to verify CVEs for specific library versions.

### Toolchain Agent
Fetches live changelogs from Supabase, Vercel, and GitHub. Searches for:
- Recent breach patterns specific to these tools
- OAuth flow risks
- Webhook abuse vectors
- Third-party integration risks (the Vercel/connected-tool breach pattern)
- Cross-tool attack chains (e.g., GitHub Actions → Vercel token leak)

### Blackbox Agent
HTTP-level penetration tester. Makes targeted requests to the live URL:
- Tests specific attack paths the static scanner flagged
- Identifies tech stack from response headers and searches for version-specific CVEs
- Builds chained attack paths from individual findings

### Report Agent
CISO-grade synthesis:
- Deduplicates findings from all agents
- Identifies attack chains (A + B + C = account takeover)
- Writes executive summary and top priority action

## Requirements

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-...
```

Or add to `breachscope.yaml`:

```yaml
ai:
  openaiApiKey: ""
  firecrawlApiKey: ""
  model: gpt-4o
```

## Token usage

A full `--ai` scan of a medium-sized project typically uses 20,000–60,000 tokens across all agents. At GPT-4o pricing (~$2.50/M input), this is $0.05–$0.15 per scan.

## Combining with CI

```yaml
- run: breachscope scan --ai --ci
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    FIRECRAWL_API_KEY: ${{ secrets.FIRECRAWL_API_KEY }}
    SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
    SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
```
