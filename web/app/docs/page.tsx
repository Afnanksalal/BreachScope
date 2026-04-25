import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";
import { DocsSidebar } from "./DocsSidebar";
import { CodeBlock, Callout } from "./DocsBlocks";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Documentation — BreachScope",
  description: "BreachScope CLI documentation — installation, commands, configuration, AI scanning, and integrations.",
  alternates: { canonical: "https://breachscoope.vercel.app/docs" },
  openGraph: {
    title: "BreachScope Documentation",
    description: "Full reference for the BreachScope CLI — scan commands, AI mode, toolchain probing, and dashboard integration.",
    url: "https://breachscoope.vercel.app/docs",
  },
};

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-black">
      <Nav />

      <div className="max-w-6xl mx-auto px-6 pt-28 pb-32 flex gap-16">
        <DocsSidebar />

        {/* Main content */}
        <article className="flex-1 min-w-0">

          {/* Page header */}
          <div className="mb-14 pb-10 border-b border-white/[0.06]">
            <div className="inline-flex items-center gap-2 mb-4 px-2.5 py-1 rounded-full border border-white/[0.08] bg-white/[0.03]">
              <span className="w-1.5 h-1.5 rounded-full bg-breach-500 animate-pulse" />
              <span className="text-xs text-white/40 font-mono">v0.1.0</span>
            </div>
            <h1 className="text-4xl font-serif italic text-white mb-3">Documentation</h1>
            <p className="text-white/40 text-base max-w-xl leading-relaxed">
              Everything you need to find and fix security issues across your entire stack — dependencies, code, services, and live endpoints.
            </p>
          </div>

          {/* ── Getting Started ─────────────────────────────── */}
          <Section id="installation" label="Getting Started" title="Installation">
            <p className="text-white/45 mb-5 leading-relaxed">Requires Node.js 18 or higher. Install globally with your package manager of choice.</p>
            <CodeBlock code={`npm install -g breachscope\npnpm add -g breachscope\nbun add -g breachscope`} />
            <Callout type="tip">
              Both <code className="font-mono text-white/65">breachscope</code> and <code className="font-mono text-white/65">bs</code> are registered as CLI aliases after install.
            </Callout>
            <p className="text-white/35 text-sm mt-3">
              Run without installing: <code className="font-mono text-white/55">npx breachscope scan</code>
            </p>
          </Section>

          <Section id="quick-start" title="Quick Start">
            <p className="text-white/45 mb-5 leading-relaxed">
              Run from the root of any project. BreachScope auto-detects your language, manifests, and services.
            </p>
            <div className="space-y-4">
              <Step n={1} label="Authenticate with the dashboard">
                <CodeBlock code="breachscope login" />
              </Step>
              <Step n={2} label="Scan your project">
                <CodeBlock code="breachscope scan" />
              </Step>
              <Step n={3} label="Probe a live URL (no local project needed)">
                <CodeBlock code="breachscope scan --url https://yourapp.com" />
              </Step>
              <Step n={4} label="Full coverage — deep mode, all scanners, AI agents, browser pentest">
                <CodeBlock code="breachscope scan --mode deep --breach --bug --ai --browser --url https://yourapp.com" />
              </Step>
            </div>
            <Callout type="note">
              When <code className="font-mono text-white/65">--url</code> is the only input and no project manifest is found in the current directory, static scanners (deps, code, toolchain) are automatically skipped — the scan goes straight to blackbox and smoke probing.
            </Callout>
          </Section>

          <Section id="configuration" title="Configuration">
            <p className="text-white/45 mb-5 leading-relaxed">
              BreachScope looks for <code className="font-mono text-white/65">breachscope.yaml</code> in the current directory, walking up to the repo root. Generate a starter config with <code className="font-mono text-white/65">breachscope init</code>.
            </p>
            <CodeBlock
              lang="yaml"
              code={`version: "1"
project: "my-project"

targets:
  - all  # dependency | toolchain | code | blackbox | smoke | all

subchain:
  maxDepth: 4        # depth for --mode deep
  concurrency: 5
  ignore:
    - lodash
    - tslib

toolchain:
  supabase:
    url: ""        # or SUPABASE_URL
    anonKey: ""    # or SUPABASE_ANON_KEY
  vercel:
    token: ""      # or VERCEL_TOKEN
    projectId: ""
  github:
    token: ""      # or GITHUB_TOKEN
    repo: "owner/repo"

ai:
  openaiApiKey: ""    # or OPENAI_API_KEY
  firecrawlApiKey: "" # or FIRECRAWL_API_KEY
  model: gpt-4o

output:
  format: console   # console | json | sarif
  verbose: false

thresholds:
  failOn: high      # critical | high | medium | low`}
            />
            <Callout type="tip">
              All credentials can be supplied as environment variables. The config file never needs to contain secrets — store API keys in the dashboard Settings instead.
            </Callout>
          </Section>

          {/* ── Commands ───────────────────────────────────── */}
          <Divider label="Commands" />

          <Section id="scan" title="breachscope scan">
            <p className="text-white/45 mb-5 leading-relaxed">
              The primary command. Runs all enabled scanners against the current project, an optional URL, or both.
            </p>
            <CodeBlock code="breachscope scan [options]" />
            <OptionTable
              options={[
                ["-m, --mode", "basic", "Scan depth: basic | major | deep"],
                ["-t, --target", "all", "Scope: all | dependency | toolchain | code | blackbox | smoke"],
                ["-u, --url", "—", "Target URL for blackbox, smoke, and browser pentest"],
                ["--breach", "—", "Breach mode: CVE hunting, leaked credentials, supply chain"],
                ["--bug", "—", "Bug mode: code audit, injection, deserialization, auth bypasses"],
                ["--breach --bug", "—", "Full mode: 66 patterns, all scanners, both AI personalities"],
                ["-o, --output", "console", "Output format: console | json | sarif"],
                ["-f, --file", "—", "Write output to file"],
                ["-c, --config", "—", "Path to breachscope.yaml"],
                ["--ci", "—", "Exit code 1 if findings exceed severity threshold"],
                ["--ai", "—", "Enable AI multi-agent pipeline + live service probing"],
                ["--browser", "—", "Playwright authenticated pentest (requires --url and --ai)"],
                ["-v, --verbose", "—", "Debug output"],
              ]}
            />

            <div className="mt-8 space-y-6">
              <div>
                <p className="text-xs font-semibold text-white/25 uppercase tracking-widest mb-3">Depth modes</p>
                <OptionTable
                  options={[
                    ["basic", "default", "Direct tools detected in your codebase"],
                    ["major", "—", "Direct tools + their first-level dependencies"],
                    ["deep", "—", "Full transitive tree up to 6 levels deep"],
                  ]}
                />
              </div>
              <div>
                <p className="text-xs font-semibold text-white/25 uppercase tracking-widest mb-3">Scan focus</p>
                <OptionTable
                  options={[
                    ["(none)", "13 patterns", "Balanced: CVE + supply chain + code audit"],
                    ["--breach", "36 patterns", "CVEs, hijacked packages, leaked credentials, infra exposure"],
                    ["--bug", "43 patterns", "Injection, deserialization, auth bypass, logic bugs"],
                    ["--breach --bug", "66 patterns", "Everything — maximum coverage"],
                  ]}
                />
              </div>
            </div>
          </Section>

          <Section id="login" title="breachscope login">
            <p className="text-white/45 mb-5 leading-relaxed">
              Authenticate with your BreachScope dashboard using the device authorization flow. Opens a browser — sign in once and all future scans automatically push results to your dashboard.
            </p>
            <CodeBlock code="breachscope login" />
            <Callout type="note">
              Credentials are stored at <code className="font-mono text-white/65">~/.config/breachscope/credentials.json</code> with <code className="font-mono text-white/65">0600</code> permissions. Run <code className="font-mono text-white/65">breachscope whoami</code> to check your login status.
            </Callout>
          </Section>

          <Section id="audit" title="breachscope audit">
            <p className="text-white/45 mb-5 leading-relaxed">Static code audit only — scans all source files in the current directory for dangerous patterns.</p>
            <CodeBlock code="breachscope audit [-v] [-o format] [-f file]" />
          </Section>

          <Section id="probe" title="breachscope probe">
            <p className="text-white/45 mb-5 leading-relaxed">
              Blackbox HTTP security probe against a live URL. Checks security headers, exposed sensitive paths, CORS misconfiguration, and HTTP method exposure.
            </p>
            <CodeBlock code="breachscope probe https://myapp.com" />
          </Section>

          <Section id="smoke" title="breachscope smoke">
            <p className="text-white/45 mb-5 leading-relaxed">
              Smoke tests against a live URL — verifies reachability, checks for error/stack trace leakage, tests large payload handling, and probes unauthenticated access to admin and internal routes.
            </p>
            <CodeBlock code="breachscope smoke https://myapp.com" />
          </Section>

          <Section id="deps" title="breachscope deps">
            <p className="text-white/45 mb-5 leading-relaxed">
              Dependency and lockfile supply chain scan across all supported languages. Queries OSV.dev with exact installed versions.
            </p>
            <CodeBlock code="breachscope deps [-m mode] [-v] [-o format]" />
            <OptionTable
              options={[
                ["npm / yarn / pnpm", "package.json, lockfiles", "npm ecosystem"],
                ["Python", "requirements.txt, pyproject.toml, Pipfile", "PyPI"],
                ["Go", "go.mod", "Go"],
                ["Rust", "Cargo.toml, Cargo.lock", "crates.io"],
                ["Ruby", "Gemfile, Gemfile.lock", "RubyGems"],
              ]}
            />
          </Section>

          <Section id="init" title="breachscope init">
            <p className="text-white/45 mb-5 leading-relaxed">
              Scaffold a <code className="font-mono text-white/65">breachscope.yaml</code> config file in the current directory. Use <code className="font-mono text-white/65">--force</code> to overwrite an existing config.
            </p>
            <CodeBlock code="breachscope init [--force]" />
          </Section>

          {/* ── Dashboard ───────────────────────────────────── */}
          <Divider label="Dashboard" />

          <Section id="dashboard" title="Web Dashboard">
            <p className="text-white/45 mb-5 leading-relaxed">
              Every scan is automatically pushed to <strong className="text-white/70">breachscoope.vercel.app</strong>. Sign up free with GitHub or Google — no credit card required.
            </p>
            <CodeBlock code="breachscope login  # authenticate once, all scans auto-upload" />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-6">
              {[
                { title: "Scan History", desc: "Filter by mode, depth, and date. Search by project name or URL." },
                { title: "Findings", desc: "Collapsible cards with severity, file:line, matched code, and remediation." },
                { title: "Probe Activity", desc: "Step-by-step logs for live service probes and browser attack probes." },
                { title: "PDF Export", desc: "Structured report with severity breakdown, findings table, and probe log." },
              ].map((f) => (
                <div key={f.title} className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3.5">
                  <p className="text-sm font-medium text-white/70 mb-1">{f.title}</p>
                  <p className="text-xs text-white/35 leading-relaxed">{f.desc}</p>
                </div>
              ))}
            </div>
          </Section>

          <Section id="scan-history" title="Scan History">
            <p className="text-white/45 mb-4 leading-relaxed">
              Every scan is stored with the full findings breakdown. Filter by scan type (all / breach / bug) and depth (basic / major / deep), search by project name or URL, and click into any scan for per-finding detail.
            </p>
            <p className="text-white/45 leading-relaxed">
              Each finding shows: severity badge, category, description, matched code snippet, remediation steps, source file and line number, and reference links to CVE advisories.
            </p>
          </Section>

          <Section id="api-keys" title="API Keys">
            <p className="text-white/45 mb-5 leading-relaxed">
              Generate API keys from the dashboard to authenticate the CLI without going through the browser flow on each machine. Keys are shown once — only a SHA-256 hash is stored server-side.
            </p>
            <CodeBlock code="breachscope login --token bs_live_..." />
            <Callout type="warning">
              Treat API keys like passwords. Revoke them immediately from the dashboard if compromised.
            </Callout>
          </Section>

          <Section id="settings" title="Settings">
            <p className="text-white/45 mb-4 leading-relaxed">
              Store your OpenAI and Firecrawl API keys in the dashboard — they are encrypted at rest with AES-256-GCM and fetched by the CLI at scan time. This means you don&apos;t need to set environment variables on every machine.
            </p>
            <p className="text-white/45 leading-relaxed">
              You can also set default scan depth and scan type, which the CLI uses when no flags are provided.
            </p>
          </Section>

          {/* ── Integrations ────────────────────────────────── */}
          <Divider label="Integrations" />

          <Section id="supabase" title="Supabase">
            <p className="text-white/45 mb-4 leading-relaxed">BreachScope probes your live Supabase project for common misconfigurations.</p>
            <ul className="text-white/40 text-sm space-y-2 mb-5">
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> RLS disabled on tables (anon key can read all rows)</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Public storage buckets with sensitive data</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Service role key used in client-side code</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  supabase:\n    url: \${SUPABASE_URL}\n    anonKey: \${SUPABASE_ANON_KEY}`} />
          </Section>

          <Section id="vercel" title="Vercel">
            <p className="text-white/45 mb-4 leading-relaxed">Checks your Vercel project configuration for security gaps.</p>
            <ul className="text-white/40 text-sm space-y-2 mb-5">
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Secrets exposed in preview deployments</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Preview deployments with no access protection</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Open team invite links</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  vercel:\n    token: \${VERCEL_TOKEN}\n    projectId: "prj_xxx"`} />
          </Section>

          <Section id="github" title="GitHub">
            <p className="text-white/45 mb-4 leading-relaxed">Audits your GitHub repository configuration and token permissions.</p>
            <ul className="text-white/40 text-sm space-y-2 mb-5">
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Branch protection missing on main / master</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Required PR reviews not enforced</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Actions default write permissions</li>
              <li className="flex gap-2"><span className="text-white/20 mt-0.5">›</span> Overprivileged personal access tokens</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  github:\n    token: \${GITHUB_TOKEN}\n    repo: "owner/repo"`} />
          </Section>

          {/* ── CI/CD ───────────────────────────────────────── */}
          <Divider label="CI/CD" />

          <Section id="github-actions" title="GitHub Actions">
            <p className="text-white/45 mb-5 leading-relaxed">
              Add BreachScope to your CI pipeline. Use <code className="font-mono text-white/65">--ci</code> to fail the build when findings exceed your threshold.
            </p>
            <CodeBlock
              lang="yaml"
              code={`name: BreachScope

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g breachscope

      - name: Supply chain + credential scan
        run: breachscope scan --mode major --breach --ci
        env:
          SUPABASE_URL: \${{ secrets.SUPABASE_URL }}
          SUPABASE_ANON_KEY: \${{ secrets.SUPABASE_ANON_KEY }}
          VERCEL_TOKEN: \${{ secrets.VERCEL_TOKEN }}
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}

      - name: AI code audit
        run: breachscope scan --mode deep --bug --ai --ci
        env:
          OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
          FIRECRAWL_API_KEY: \${{ secrets.FIRECRAWL_API_KEY }}`}
            />
          </Section>

          <Section id="exit-codes" title="Exit Codes">
            <p className="text-white/45 mb-5 leading-relaxed">
              When <code className="font-mono text-white/65">--ci</code> is passed, BreachScope exits with a non-zero code if any finding meets or exceeds the configured <code className="font-mono text-white/65">thresholds.failOn</code> severity (default: <code className="font-mono text-white/65">high</code>).
            </p>
            <OptionTable
              options={[
                ["0", "Success", "No findings at or above threshold"],
                ["1", "Failure", "One or more findings at or above failOn severity"],
              ]}
            />
          </Section>

          <Section id="sarif" title="SARIF Output">
            <p className="text-white/45 mb-5 leading-relaxed">
              Export results as SARIF to integrate with GitHub Advanced Security code scanning and view findings inline in pull requests.
            </p>
            <CodeBlock code="breachscope scan -o sarif -f results.sarif" />
            <CodeBlock
              lang="yaml"
              code={`# .github/workflows/breachscope.yml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif`}
            />
          </Section>
        </article>
      </div>

      <Footer />
    </div>
  );
}

// ── Layout helpers ─────────────────────────────────────────────────────────────

function Section({
  id,
  label,
  title,
  children,
}: {
  id: string;
  label?: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="mb-14 scroll-mt-28">
      {label && (
        <p className="text-[10px] font-semibold text-breach-500/60 uppercase tracking-widest mb-2">{label}</p>
      )}
      <h2 className="text-xl font-semibold text-white mb-5 font-mono">{title}</h2>
      {children}
    </section>
  );
}

function Step({ n, label, children }: { n: number; label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <div className="shrink-0 w-6 h-6 rounded-full border border-white/[0.1] flex items-center justify-center mt-0.5">
        <span className="text-[10px] font-mono text-white/30">{n}</span>
      </div>
      <div className="flex-1">
        <p className="text-sm text-white/50 mb-2">{label}</p>
        {children}
      </div>
    </div>
  );
}

function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-4 my-12">
      <div className="flex-1 h-px bg-white/[0.05]" />
      <span className="text-[10px] font-semibold text-white/20 uppercase tracking-widest">{label}</span>
      <div className="flex-1 h-px bg-white/[0.05]" />
    </div>
  );
}

function OptionTable({ options }: { options: [string, string, string][] }) {
  return (
    <div className="rounded-xl border border-white/[0.06] overflow-hidden mt-4">
      <table className="w-full text-sm">
        <tbody>
          {options.map(([col1, col2, col3], i) => (
            <tr
              key={col1}
              className={`border-b border-white/[0.04] last:border-0 ${i % 2 === 0 ? "" : "bg-white/[0.01]"}`}
            >
              <td className="px-4 py-3 font-mono text-white/60 text-xs whitespace-nowrap">{col1}</td>
              <td className="px-4 py-3 font-mono text-white/25 text-xs whitespace-nowrap">{col2 || "—"}</td>
              <td className="px-4 py-3 text-white/40 text-xs">{col3}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
