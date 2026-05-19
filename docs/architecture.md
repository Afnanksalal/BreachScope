# Architecture

BreachScope is split into a local CLI, a Next.js dashboard, API routes, PostgreSQL storage, and optional customer-owned integrations.

## Runtime Overview

```mermaid
flowchart LR
  User[Developer or security user] --> CLI[BreachScope CLI]
  CLI --> LocalScan[Local scanners]
  LocalScan --> Evidence[Local evidence files]
  CLI -->|authenticated upload| API[Next.js API routes]
  Dashboard[Next.js dashboard] --> API
  API --> DB[(PostgreSQL)]
  API --> Audit[Audit logs]
  API --> Settings[Encrypted settings]
  Settings --> Integrations[Customer-owned providers]
```

## Scan Pipeline

```mermaid
sequenceDiagram
  participant Dev as Developer
  participant CLI as CLI
  participant Policy as Policy Engine
  participant API as Dashboard API
  participant DB as PostgreSQL
  participant Provider as Customer Provider

  Dev->>CLI: breachscope scan --ci
  CLI->>Policy: evaluate thresholds, budgets, suppressions
  Policy-->>CLI: pass/fail decision and findings
  CLI->>API: upload scan when authenticated
  API->>DB: store scan, findings, triage defaults
  API->>DB: append audit event
  API->>Provider: dispatch only if user configured credentials
```

## Data Boundaries

```mermaid
flowchart TB
  subgraph Public["Public crawlable surface"]
    Home[/Homepage/]
    Docs[/Docs/]
    Legal[/Legal policies/]
    LLM[/llms.txt and llms-full.txt/]
    Sitemap[/sitemap.xml and robots.txt/]
  end

  subgraph Private["Private or operational surface"]
    Dashboard[/Dashboard/]
    API[/API routes/]
    Login[/Login and CLI auth/]
  end

  Robots[robots.txt] --> Public
  Robots -. disallow .-> Private
```

## Credential Model

- BreachScope does not provide third-party provider accounts.
- Users bring provider accounts and tokens.
- Dashboard automation keys are scoped.
- Authentication keys are hashed where they are used for authentication.
- Saved provider keys are encrypted before storage.
- Secret retrieval requires an API key with `secrets:read`.
