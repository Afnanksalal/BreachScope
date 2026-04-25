# Contributing to BreachScope

First off — thank you. BreachScope is an open-source security tool and every contribution makes the ecosystem safer.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding Detection Rules](#adding-detection-rules)
- [Adding Tool Integrations](#adding-tool-integrations)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

Be excellent to each other. Security is a collaborative field — treat it that way.

## How to Contribute

### Good first issues

Look for issues tagged `good first issue`. These are scoped and well-defined.

### What we need most

1. **New detection rules** — patterns in `cli/src/scanners/code/patterns.ts`
2. **New tools in the tool map** — entries in `cli/src/core/toolmap.ts`
3. **New integrations** — scanners in `cli/src/scanners/toolchain/`
4. **Bug reports** — specific, reproducible, ideally with a fixture codebase
5. **False positive reports** — we'd rather miss a finding than cry wolf

### What we won't accept

- Detection rules with high false positive rates (test on 3+ real codebases first)
- Offensive capabilities — this is a defensive tool
- Breaking changes to the JSON output schema without a migration path

---

## Development Setup

### Prerequisites

- Node.js 18+
- npm 9+ / pnpm 9+ / bun 1.1+
- (Optional for AI features) OpenAI API key, Firecrawl API key

### Install

```bash
git clone https://github.com/breachscope/breachscope.git
cd breachscope/cli
npm install
npm run build
```

### Run locally

```bash
# Link the CLI globally for local testing
npm link

# Run against a test project
cd /your/test/project
breachscope scan

# Or run directly from source
npx ts-node src/index.ts scan
```

### Tests

```bash
npm test           # run once
npm run test:watch # watch mode
```

### Lint

```bash
npm run lint
```

---

## Project Structure

```
breachscope/
├── cli/src/
│   ├── core/            # Types, config, logger, AI client, Firecrawl wrapper, tool map
│   ├── detectors/       # Detect tools from package.json, imports, env files, config files
│   ├── classifiers/     # GPT-4o tool classifier (OSS / SaaS / hybrid)
│   ├── apis/            # OpenSSF Scorecard, OSV.dev, deps.dev, npm registry
│   ├── pipelines/       # OSS pipeline, SaaS pipeline, router
│   ├── engine/          # Recursive sub-toolchain scan engine + dependency graph
│   ├── scanners/        # Static scanners: dependency, code, toolchain, blackbox, smoke
│   ├── agents/          # AI multi-agent: orchestrator, dependency, code, toolchain, blackbox, report
│   ├── reporters/       # Output formatters: console, JSON, AI console, risk dashboard
│   └── commands/        # CLI command handlers
├── web/                 # Next.js landing page + docs
└── docs/                # Markdown documentation
```

---

## Adding Detection Rules

Detection rules live in `cli/src/scanners/code/patterns.ts`.

Each rule is an `AuditPattern`:

```typescript
{
  id: "unique-kebab-id",
  title: "Short, clear title describing the issue",
  severity: "critical" | "high" | "medium" | "low" | "info",
  pattern: /regex-that-matches-the-vulnerable-pattern/,
  description: "What this pattern indicates and why it's dangerous.",
  remediation: "Specific, actionable fix.",
}
```

**Before submitting a new rule:**
1. Test on at least 3 real codebases — measure your false positive rate
2. The pattern must match the vulnerability, not just related code
3. The remediation must be specific, not "fix the code"
4. Add a comment in the PR describing your test methodology

---

## Adding Tool Integrations

### Adding a known tool to the tool map

Add an entry to `cli/src/core/toolmap.ts`:

```typescript
"@your/package": {
  github: "org/repo",       // required for OSS pipeline
  kind: "oss",              // "oss" | "saas" | "hybrid"
  hasSaas: false,
  displayName: "Your Tool",
  advisoryUrl: "https://github.com/org/repo/security/advisories",
}
```

### Adding a new toolchain scanner (static)

Create `cli/src/scanners/toolchain/<toolname>.ts` with an exported async function:

```typescript
export async function scanYourTool(credentials: YourToolConfig): Promise<Finding[]>
```

Register it in `cli/src/scanners/toolchain/index.ts`.

### Adding a new env var → tool mapping

Add to the `ENV_MAP` in `cli/src/detectors/index.ts`.

---

## Pull Request Process

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feat/your-feature` or `fix/your-fix`
3. **Write tests** for new functionality
4. **Run the full suite**: `npm test && npm run lint`
5. **Scan yourself**: `breachscope audit` should pass on your changes
6. **Submit a PR** with:
   - What the change does
   - Why it's needed
   - How you tested it (include test codebases if relevant)
   - Any trade-offs or known limitations

### Commit style

We follow Conventional Commits:

```
feat: add Resend toolchain scanner
fix: false positive in SQL injection pattern
docs: add deps.dev integration guide
chore: bump axios to 1.7.8
```

### Review process

- At least one maintainer review required
- Security-critical changes require two reviews
- We aim to respond to PRs within 5 business days

---

## Questions?

Open a [GitHub Discussion](https://github.com/breachscope/breachscope/discussions) — not an issue.
