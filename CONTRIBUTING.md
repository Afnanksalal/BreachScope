# Contributing to BreachScope

First off — thank you. BreachScope is an open-source security tool and every contribution makes the ecosystem safer.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding Detection Rules](#adding-detection-rules)
- [Adding Language Scanners](#adding-language-scanners)
- [Adding Tool Integrations](#adding-tool-integrations)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

Be excellent to each other. Security is a collaborative field — treat it that way.

---

## How to Contribute

### Good first issues

Look for issues tagged `good first issue`. These are scoped and well-defined.

### What we need most

1. **New detection patterns** — `cli/src/scanners/code/patterns.ts` (base, bug, or breach set)
2. **New language scanners** — `cli/src/scanners/dependency/<lang>.ts`
3. **New tools in the tool map** — `cli/src/core/toolmap.ts`
4. **New toolchain integrations** — `cli/src/scanners/toolchain/`
5. **Bug reports** — specific, reproducible, ideally with a fixture codebase
6. **False positive reports** — we'd rather miss a finding than cry wolf

### What we won't accept

- Detection patterns with high false positive rates (test on 3+ real codebases first)
- Offensive capabilities — this is a defensive tool
- Breaking changes to the JSON output schema without a migration path

---

## Development Setup

### Prerequisites

- Node.js 18+
- npm 9+ / pnpm 9+
- (Optional) OpenAI API key, Firecrawl API key for AI features

### Install

```bash
git clone https://github.com/Afnanksalal/BreachScope.git
cd breachscope/cli
npm install
npm run build
npm link   # makes 'breachscope' and 'bs' available globally
```

### Run locally

```bash
# Run against a test project
cd /your/test/project
breachscope scan

# Or run directly from source (TypeScript)
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
cli/src/
├── core/
│   ├── types.ts         # All shared TypeScript interfaces
│   ├── toolmap.ts       # Static map of 150+ known packages → kind/github/ecosystem
│   ├── push-scan.ts     # Upload scan results to dashboard API
│   └── ai.ts            # OpenAI client wrapper (complete + agentLoop)
├── detectors/
│   └── index.ts         # Multi-language, multi-signal tool detection
│                        # PYTHON_KNOWN, GO_KNOWN, RUST_KNOWN maps here
├── apis/
│   ├── osv.ts           # OSV.dev (queryOSV, osvToFindings, querybatch)
│   ├── pypi.ts          # PyPI JSON API (fetchPypiMeta, pypiMetaToFindings)
│   └── ...              # scorecard, deps-dev, npm-registry
├── scanners/
│   ├── dependency/
│   │   ├── index.ts     # Auto-detects languages, runs all applicable scanners
│   │   ├── python.ts    # requirements.txt, pyproject.toml, Pipfile, setup.py
│   │   ├── go.ts        # go.mod
│   │   ├── rust.ts      # Cargo.toml + Cargo.lock
│   │   └── ruby.ts      # Gemfile + Gemfile.lock
│   └── code/
│       ├── patterns.ts  # AUDIT_PATTERNS (13) + BUG_PATTERNS (30) + BREACH_PATTERNS (23)
│       └── index.ts     # runCodeAudit(cwd, scanMode?) — selects pattern set by mode
├── agents/
│   ├── orchestrator.ts  # Mode-aware dispatch planner
│   ├── code.ts          # SYSTEM_ALL, SYSTEM_BUG, SYSTEM_BREACH — selected at runtime
│   ├── dependency.ts    # SYSTEM_ALL, SYSTEM_BUG, SYSTEM_BREACH — selected at runtime
│   └── attack-probe.ts  # Playwright pentest (SQLi, XSS, JWT, CORS, rate limit)
└── commands/
    └── scan.ts          # Main scan orchestrator — gates scanners by scanMode
```

---

## Adding Detection Rules

Detection rules live in `cli/src/scanners/code/patterns.ts`.

There are three exported arrays — add to the right one:

| Array | Mode activated by | Purpose |
|-------|-------------------|---------|
| `AUDIT_PATTERNS` | All modes | Universal rules that apply everywhere |
| `BUG_PATTERNS` | `--bug`, `--breach --bug` | Code vulnerability patterns — injection, auth, deserialization |
| `BREACH_PATTERNS` | `--breach`, `--breach --bug` | Credential and infra exposure patterns |

Each rule follows `AuditPattern`:

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

**Before submitting a new pattern:**
1. Test on at least 3 real codebases — measure your false positive rate
2. The pattern must match the vulnerability, not just related code
3. The remediation must be specific, not "fix the code"
4. Describe your test methodology in the PR description

---

## Adding Language Scanners

To add dependency scanning for a new language, create `cli/src/scanners/dependency/<lang>.ts`:

```typescript
import { queryOSV, osvToFindings } from "../../apis/osv.js";
import type { Finding } from "../../core/types.js";

interface MyLangPackage { name: string; version?: string }

function parseManifest(content: string): MyLangPackage[] {
  // parse your manifest format
}

async function osvScanMyLang(pkgs: MyLangPackage[]): Promise<Finding[]> {
  if (pkgs.length === 0) return [];
  const findings: Finding[] = [];
  for (const pkg of pkgs) {
    const vulns = await queryOSV(pkg.name, pkg.version, "MyEcosystem");
    findings.push(...osvToFindings(vulns, pkg.name));
  }
  return findings;
}

export async function scanMyLang(cwd: string): Promise<Finding[]> {
  // detect manifests, parse, call osvScanMyLang
}
```

Then register it in `cli/src/scanners/dependency/index.ts`:
1. Add manifest detection to `hasMyLang`
2. Call `scanMyLang(cwd)` in the parallel scanner block
3. Add imports

And add known packages to the detector in `cli/src/detectors/index.ts`:
- Add a `MYLANG_KNOWN` map with package → `{ github, kind }`
- Call your parser in `detectTools()`
- Key entries as `mylang:packagename` to avoid cross-ecosystem collisions

---

## Adding Tool Integrations

### Adding a known tool to the tool map

Add an entry to `cli/src/core/toolmap.ts`:

```typescript
"@your/package": {
  github: "org/repo",        // required for OSS pipeline
  kind: "oss",               // "oss" | "saas" | "hybrid"
  hasSaas: false,
  displayName: "Your Tool",
  advisoryUrl: "https://github.com/org/repo/security/advisories",
  ecosystem: "npm",          // "npm" | "PyPI" | "Go" | "crates.io" | "RubyGems"
}
```

### Adding a new toolchain scanner (static)

Create `cli/src/scanners/toolchain/<toolname>.ts`:

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
5. **Self-scan**: `breachscope audit` should pass on your changes
6. **Submit a PR** with:
   - What the change does
   - Why it's needed
   - How you tested it (include test codebases if relevant for pattern rules)
   - Any trade-offs or known limitations

### Commit style

We follow Conventional Commits:

```
feat: add Rust dependency scanner (Cargo.toml + Cargo.lock)
feat: add 5 Python deserialization patterns to BUG_PATTERNS
fix: false positive in SQL injection pattern on parameterized queries
docs: update scan command reference for --breach/--bug flags
chore: bump playwright to 1.60
```

### Review process

- At least one maintainer review required
- Security-critical changes (new patterns, new scanner logic) require two reviews
- We aim to respond to PRs within 5 business days

---

## Questions?

Open a [GitHub Discussion](https://github.com/Afnanksalal/BreachScope/discussions) — not an issue.
