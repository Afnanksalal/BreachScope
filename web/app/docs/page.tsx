import Link from "next/link";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Docs — BreachScope",
  description: "BreachScope CLI documentation — commands, configuration, integrations.",
};

const SECTIONS = [
  {
    title: "Getting Started",
    items: [
      { label: "Installation", anchor: "#installation" },
      { label: "Quick Start", anchor: "#quick-start" },
      { label: "Configuration", anchor: "#configuration" },
    ],
  },
  {
    title: "Commands",
    items: [
      { label: "breachscope scan", anchor: "#scan" },
      { label: "breachscope login", anchor: "#login" },
      { label: "breachscope audit", anchor: "#audit" },
      { label: "breachscope probe", anchor: "#probe" },
      { label: "breachscope smoke", anchor: "#smoke" },
      { label: "breachscope deps", anchor: "#deps" },
      { label: "breachscope init", anchor: "#init" },
    ],
  },
  {
    title: "Dashboard",
    items: [
      { label: "Overview", anchor: "#dashboard" },
      { label: "Scan history", anchor: "#scan-history" },
      { label: "API keys", anchor: "#api-keys" },
      { label: "Settings", anchor: "#settings" },
    ],
  },
  {
    title: "Integrations",
    items: [
      { label: "Supabase", anchor: "#supabase" },
      { label: "Vercel", anchor: "#vercel" },
      { label: "GitHub", anchor: "#github" },
    ],
  },
  {
    title: "CI/CD",
    items: [
      { label: "GitHub Actions", anchor: "#github-actions" },
      { label: "Exit codes", anchor: "#exit-codes" },
      { label: "SARIF output", anchor: "#sarif" },
    ],
  },
];

export default function DocsPage() {
  return (
    <div className="min-h-screen">
      <Nav />

      <div className="max-w-6xl mx-auto px-6 pt-28 pb-20 flex gap-12">
        {/* Sidebar */}
        <aside className="hidden lg:block w-56 shrink-0">
          <div className="sticky top-24 space-y-8">
            {SECTIONS.map((section) => (
              <div key={section.title}>
                <p className="text-xs font-medium text-white/30 uppercase tracking-widest mb-3">
                  {section.title}
                </p>
                <ul className="space-y-1.5">
                  {section.items.map((item) => (
                    <li key={item.anchor}>
                      <a
                        href={item.anchor}
                        className="text-sm text-white/45 hover:text-white/80 transition-colors block py-0.5"
                      >
                        {item.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </aside>

        {/* Content */}
        <article className="flex-1 min-w-0 prose-invert max-w-none">
          <h1 className="text-5xl font-serif italic text-white mb-2">Documentation</h1>
          <p className="text-white/40 text-lg mb-12">
            Everything you need to find breaches in your stack.
          </p>

          {/* Installation */}
          <section id="installation" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-4">Installation</h2>
            <p className="text-white/50 mb-4">Requires Node.js 18 or higher.</p>
            <CodeBlock code="npm install -g breachscope" />
            <p className="text-white/40 text-sm mt-3">
              Or run without installing: <code className="text-white/65 font-mono">npx breachscope scan</code>
            </p>
          </section>

          {/* Quick Start */}
          <section id="quick-start" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-4">Quick Start</h2>
            <div className="space-y-4">
              <div>
                <p className="text-white/50 text-sm mb-2">Initialize a config file:</p>
                <CodeBlock code="breachscope init" />
              </div>
              <div>
                <p className="text-white/50 text-sm mb-2">Run a full scan:</p>
                <CodeBlock code="breachscope scan --url https://yourapp.com" />
              </div>
              <div>
                <p className="text-white/50 text-sm mb-2">Supply chain focus, deeper analysis:</p>
                <CodeBlock code="breachscope scan --mode major --scan-mode breach" />
              </div>
              <div>
                <p className="text-white/50 text-sm mb-2">Connect to your dashboard:</p>
                <CodeBlock code="breachscope login" />
              </div>
            </div>
          </section>

          {/* Configuration */}
          <section id="configuration" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-4">Configuration</h2>
            <p className="text-white/50 mb-4">
              BreachScope looks for <code className="text-white/65 font-mono">breachscope.yaml</code> in the
              current directory and walks up to the repo root.
            </p>
            <CodeBlock
              lang="yaml"
              code={`version: "1"
project: "my-project"

targets:
  - all  # dependency | toolchain | code | blackbox | smoke | all

subchain:
  maxDepth: 4        # override for deep mode
  concurrency: 5
  ignore:
    - lodash

toolchain:
  supabase:
    url: ""        # or SUPABASE_URL env var
    anonKey: ""    # or SUPABASE_ANON_KEY env var
  vercel:
    token: ""      # or VERCEL_TOKEN env var
    projectId: ""
  github:
    token: ""      # or GITHUB_TOKEN env var
    repo: "owner/repo"

ai:
  openaiApiKey: ""   # or OPENAI_API_KEY env var
  firecrawlApiKey: "" # or FIRECRAWL_API_KEY env var
  model: gpt-4o

output:
  format: console  # console | json | sarif
  verbose: false

thresholds:
  failOn: high     # critical | high | medium | low`}
            />
            <p className="text-white/40 text-sm mt-4">
              All credentials can be supplied as environment variables — the config file never needs to contain secrets.
            </p>
          </section>

          {/* Commands */}
          <section id="scan" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope scan</h2>
            <p className="text-white/50 mb-4">Run all enabled scan types against the current project.</p>
            <CodeBlock code="breachscope scan [options]" />
            <OptionTable
              options={[
                ["-m, --mode", "basic", "Scan depth: basic | major | deep"],
                ["-s, --scan-mode", "all", "Scan type: all | breach | bug"],
                ["-t, --target", "all", "Scanner: all | dependency | toolchain | code | blackbox | smoke"],
                ["-u, --url", "", "Target URL for blackbox and smoke scanning"],
                ["-o, --output", "console", "Output format: console | json | sarif"],
                ["-f, --file", "", "Write output to file"],
                ["-c, --config", "", "Path to config file"],
                ["--ci", "", "Exit code 1 if findings exceed threshold"],
                ["--ai", "", "Enable AI multi-agent pipeline"],
                ["-v, --verbose", "", "Verbose logging"],
              ]}
            />
            <div className="mt-6 space-y-3">
              <p className="text-white/40 text-sm font-semibold uppercase tracking-wider">Depth modes</p>
              <OptionTable
                options={[
                  ["basic", "", "Direct tools detected in your codebase (default)"],
                  ["major", "", "Direct tools + their direct npm dependencies"],
                  ["deep", "", "Full transitive dependency tree up to 6 levels"],
                ]}
              />
              <p className="text-white/40 text-sm font-semibold uppercase tracking-wider mt-4">Scan types</p>
              <OptionTable
                options={[
                  ["all", "", "CVE + supply chain + code audit + blackbox (default)"],
                  ["breach", "", "Dependency hijacks, CVEs, supply chain signals"],
                  ["bug", "", "Code audit, dangerous patterns, misconfigurations"],
                ]}
              />
            </div>
          </section>

          <section id="login" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope login</h2>
            <p className="text-white/50 mb-4">
              Authenticate the CLI with your breachscope.dev account using the device authorization flow.
              Opens a browser — sign in once, and all future scans automatically push results to your dashboard.
            </p>
            <CodeBlock code="breachscope login" />
          </section>

          <section id="audit" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope audit</h2>
            <p className="text-white/50 mb-4">Static code audit only. Scans all source files in the current directory.</p>
            <CodeBlock code="breachscope audit [-v] [-o format] [-f file]" />
          </section>

          <section id="probe" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope probe &lt;url&gt;</h2>
            <p className="text-white/50 mb-4">Blackbox security probe against a live URL.</p>
            <CodeBlock code="breachscope probe https://myapp.com" />
          </section>

          <section id="smoke" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope smoke &lt;url&gt;</h2>
            <p className="text-white/50 mb-4">Smoke tests against a live URL — reachability, error leakage, auth bypass probes.</p>
            <CodeBlock code="breachscope smoke https://myapp.com" />
          </section>

          <section id="deps" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope deps</h2>
            <p className="text-white/50 mb-4">Scan npm/yarn/pnpm dependencies and lockfiles for supply chain risks.</p>
            <CodeBlock code="breachscope deps [-v] [-o format]" />
          </section>

          <section id="init" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-3">breachscope init</h2>
            <p className="text-white/50 mb-4">Scaffold a <code className="text-white/65 font-mono">breachscope.yaml</code> config file in the current directory.</p>
            <CodeBlock code="breachscope init" />
          </section>

          {/* Dashboard */}
          <section id="dashboard" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">Web Dashboard</h2>
            <p className="text-white/50 mb-4">
              breachscope.dev is a hosted dashboard for viewing scan history, browsing findings,
              and managing CLI authentication. Sign up free with GitHub, Google, or email.
            </p>
            <p className="text-white/50 mb-4">
              Connect the CLI to your account:
            </p>
            <CodeBlock code="breachscope login" />
            <p className="text-white/40 text-sm mt-3">
              Once authenticated, every scan automatically pushes results to your dashboard.
            </p>
          </section>

          <section id="scan-history" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">Scan History</h2>
            <p className="text-white/50 mb-2">
              Every scan is stored with the full findings breakdown. The scans page lets you filter by scan type
              (all / breach / bug) and depth mode (basic / major / deep), search by project name or URL,
              and click into any scan for per-finding detail.
            </p>
            <p className="text-white/50">
              Each finding shows: severity, category, description, remediation steps, source file and line number,
              and reference links to CVE advisories.
            </p>
          </section>

          <section id="api-keys" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">API Keys</h2>
            <p className="text-white/50 mb-4">
              Generate API keys from the dashboard to authenticate the CLI without going through the browser flow each time.
              Keys are shown once at creation — only a SHA-256 hash is stored.
            </p>
            <CodeBlock code="breachscope login --token bs_live_..." />
          </section>

          <section id="settings" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-3">Settings</h2>
            <p className="text-white/50 mb-2">
              Store your OpenAI and Firecrawl API keys in the dashboard — they are encrypted at rest with AES-256-GCM
              and fetched by the CLI at scan time. This means you don't need to set environment variables on every machine.
            </p>
            <p className="text-white/50">
              You can also set default scan depth and scan type, which the CLI uses when no flags are provided.
            </p>
          </section>

          {/* Integrations */}
          <section id="supabase" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">Supabase Integration</h2>
            <p className="text-white/50 mb-4">Checks:</p>
            <ul className="text-white/45 text-sm space-y-1 list-disc list-inside mb-4">
              <li>RLS disabled on auth.users (anon key can read user data)</li>
              <li>Public storage buckets</li>
              <li>Service role key used in place of anon key</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  supabase:\n    url: \${SUPABASE_URL}\n    anonKey: \${SUPABASE_ANON_KEY}`} />
          </section>

          <section id="vercel" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">Vercel Integration</h2>
            <p className="text-white/50 mb-4">Checks:</p>
            <ul className="text-white/45 text-sm space-y-1 list-disc list-inside mb-4">
              <li>Secrets exposed in preview deployments</li>
              <li>Preview deployments with no access protection</li>
              <li>Open team invite links</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  vercel:\n    token: \${VERCEL_TOKEN}\n    projectId: "prj_xxx"`} />
          </section>

          <section id="github" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-3">GitHub Integration</h2>
            <p className="text-white/50 mb-4">Checks:</p>
            <ul className="text-white/45 text-sm space-y-1 list-disc list-inside mb-4">
              <li>Branch protection on main/master</li>
              <li>Required PR reviews</li>
              <li>Actions default write permissions</li>
              <li>Overprivileged personal access tokens</li>
            </ul>
            <CodeBlock lang="yaml" code={`toolchain:\n  github:\n    token: \${GITHUB_TOKEN}\n    repo: "owner/repo"`} />
          </section>

          {/* CI */}
          <section id="github-actions" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">GitHub Actions</h2>
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
      - run: breachscope scan --mode major --scan-mode all --ci
        env:
          SUPABASE_URL: \${{ secrets.SUPABASE_URL }}
          SUPABASE_ANON_KEY: \${{ secrets.SUPABASE_ANON_KEY }}
          VERCEL_TOKEN: \${{ secrets.VERCEL_TOKEN }}
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}`}
            />
          </section>

          <section id="exit-codes" className="mb-10">
            <h2 className="text-2xl font-semibold text-white mb-3">Exit Codes</h2>
            <p className="text-white/50 mb-4">
              When <code className="text-white/65 font-mono">--ci</code> is set, BreachScope exits with code 1
              if any finding meets or exceeds the <code className="text-white/65 font-mono">thresholds.failOn</code> severity.
              Default threshold is <code className="text-white/65 font-mono">high</code>.
            </p>
            <OptionTable
              options={[
                ["0", "", "No findings at or above threshold"],
                ["1", "", "Findings at or above failOn severity"],
              ]}
            />
          </section>

          <section id="sarif" className="mb-16">
            <h2 className="text-2xl font-semibold text-white mb-3">SARIF Output</h2>
            <p className="text-white/50 mb-4">
              Output as SARIF to integrate with GitHub Advanced Security code scanning.
            </p>
            <CodeBlock code="breachscope scan -o sarif -f results.sarif" />
          </section>
        </article>
      </div>

      <Footer />
    </div>
  );
}

function CodeBlock({ code, lang = "bash" }: { code: string; lang?: string }) {
  return (
    <div className="relative rounded-xl bg-white/[0.04] overflow-hidden mb-2">
      <div className="flex items-center gap-1.5 px-4 py-2.5 border-b border-white/[0.05]">
        <span className="text-xs text-white/20 font-mono">{lang}</span>
      </div>
      <pre className="px-4 py-4 text-sm font-mono text-white/75 overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function OptionTable({ options }: { options: [string, string, string][] }) {
  return (
    <div className="mt-4 rounded-xl bg-white/[0.04] overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/[0.05]">
            <th className="px-4 py-2.5 text-left text-xs text-white/30 font-medium">Flag</th>
            <th className="px-4 py-2.5 text-left text-xs text-white/30 font-medium">Default</th>
            <th className="px-4 py-2.5 text-left text-xs text-white/30 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>
          {options.map(([flag, def, desc]) => (
            <tr key={flag} className="border-b border-white/[0.04] last:border-0">
              <td className="px-4 py-3 font-mono text-white/65 text-xs">{flag}</td>
              <td className="px-4 py-3 font-mono text-white/30 text-xs">{def || "—"}</td>
              <td className="px-4 py-3 text-white/45 text-xs">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
