# Architecture

BreachScope is split into a local CLI, a Next.js dashboard, API routes, PostgreSQL storage, and optional customer-owned integrations.

## Runtime Overview

```mermaid
flowchart LR
  User["Developer or security user"] --> CLI["BreachScope CLI"]
  CLI --> LocalScan["Local scanners"]
  LocalScan --> Evidence["Local evidence files"]
  CLI --> API["Next.js API routes"]
  Dashboard["Next.js dashboard"] --> API
  API --> DB["PostgreSQL"]
  API --> Audit["Audit logs"]
  API --> Settings["Encrypted settings"]
  Settings --> Integrations["Customer-owned providers"]
  DB --> Delivery["Integration delivery ledger"]
  Delivery --> Integrations
```

## Scan Pipeline

```mermaid
flowchart TD
  Dev["Developer"] --> CLI["breachscope scan --ci"]
  CLI --> Scanners["Static scanners, dependency scans, URL probes"]
  Scanners --> NoiseGate["Noise gate: group CVEs, score evidence, classify show/review/hide"]
  NoiseGate --> Policy["Evaluate thresholds and suppressions on actionable findings"]
  Policy --> Result["Pass or fail decision"]
  CLI --> API["Upload scan when authenticated unless --no-upload is set"]
  API --> DB["Store scan and findings"]
  API --> Audit["Append audit event"]
  API --> Delivery["Create post-scan delivery rows"]
  Delivery --> Provider["Send provider request"]
  Provider --> Retry["Retry failed deliveries"]
  Retry --> Provider
```

The noise gate keeps CI and dashboard totals focused on actionable findings. Review and hidden records remain in local JSON metadata, and can be included with `--show-noise` or `--all-cves`.

## Data Boundaries

```mermaid
flowchart TB
  Home["Homepage"] --> Public["Public crawlable surface"]
  Docs["Docs"] --> Public
  Legal["Legal policies"] --> Public
  LLM["llms.txt and llms-full.txt"] --> Public
  Sitemap["sitemap.xml and robots.txt"] --> Public
  Dashboard["Dashboard"] --> Private["Private operational surface"]
  API["API routes"] --> Private
  Login["Login and CLI auth"] --> Private
  Robots["robots.txt"] --> Public
  Robots -.-> Private
```

## Credential Model

- BreachScope does not provide third-party provider accounts.
- Users bring provider accounts and tokens.
- Dashboard automation keys are scoped.
- Authentication keys are hashed where they are used for authentication.
- Saved provider keys are encrypted before storage.
- Secret retrieval requires an API key with `secrets:read`.
- SCIM is disabled unless `ENABLE_SCIM`, `SCIM_ORGANIZATION_ID`, and `SCIM_BEARER_TOKEN` are configured.
