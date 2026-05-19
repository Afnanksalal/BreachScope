# Model-Assisted Analysis

BreachScope can run without model assistance. When a customer supplies `OPENAI_API_KEY`, optional analysis workers add reasoning, prioritization, attack-chain synthesis, and source-aware review.

## Activation

```bash
export OPENAI_API_KEY=sk-...
export FIRECRAWL_API_KEY=fc-... # optional

breachscope scan --mode major --url https://app.example.com
```

The dashboard can store customer-supplied OpenAI and Firecrawl keys. API keys need `secrets:read` to retrieve those encrypted values.

GitHub repository audits also use the configured OpenAI key when available. Without it, BreachScope still creates a deterministic summary from the repository and pull request signals.

## Agent Roles

| Agent | Role |
| --- | --- |
| Orchestrator | Chooses which agents should run based on scan mode, detected stack, URL, and credentials |
| Dependency | Investigates packages across supported ecosystems using OSV, advisory sources, and web research |
| Code | Reviews prioritized source files for credential exposure and exploitable vulnerabilities |
| Toolchain | Probes configured SaaS tools such as Supabase, Vercel, and GitHub |
| Blackbox | Uses live HTTP observations to test external attack paths |
| Report | Produces an executive summary, attack chains, and prioritized remediation |

## Mode Awareness

| Mode | Assisted behavior |
| --- | --- |
| `all` | Balanced analysis across dependency, code, toolchain, and blackbox signals |
| `breach` | Favors supply-chain incidents, CVEs, credentials, exposed infrastructure, and SaaS misconfiguration |
| `bug` | Favors code-level exploitability: auth bypass, injection, deserialization, SSRF, XSS, race conditions |
| `full` | Runs both breach and bug emphasis |

## Sandbox Agents

`breachscope sandbox` adds active runtime agents:

- sandbox attack agent
- code companion
- dependency companion
- blackbox companion
- supervisor planner
- validator for critical and high findings

The sandbox agent can install tools inside the container and run active probes. Critical and high findings are independently rechecked before being presented as confirmed evidence.

## Data Handling

- Source context is local-first.
- Dashboard secret values are encrypted at rest.
- Sandbox excludes local `.env` files by default.
- `--include-secrets` must be explicit when a disposable test requires real secrets inside the sandbox.

## Free Intelligence Fallbacks

When Firecrawl is not configured, BreachScope still uses public sources where available:

- OSV.dev
- npm advisory data
- NVD keyword/CVE search paths
- package registry metadata

Model-assisted synthesis can improve prioritization, but deterministic scanners and policy gates remain useful without it.
