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
              <span className="text-xs text-white/40 font-mono">v0.3.1</span>
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
              <Step n={4} label="Launch AI attack arena — Docker sandbox with full autonomy">
                <CodeBlock code="breachscope sandbox --url https://yourapp.com --deep" />
              </Step>
            </div>
            <Callout type="note">
              When <code className="font-mono text-white/65">--url</code> is the only input and no project manifest is found, static scanners are skipped — the scan goes straight to blackbox and smoke probing. For full active exploitation use <code className="font-mono text-white/65">breachscope sandbox</code>.
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
                ["-u, --url", "—", "Target URL for blackbox and smoke probing"],
                ["--breach", "—", "Breach mode: CVE hunting, leaked credentials, supply chain"],
                ["--bug", "—", "Bug mode: code audit, injection, deserialization, auth bypasses"],
                ["--breach --bug", "—", "Full mode: 66 patterns, all scanners, both AI personalities"],
                ["-o, --output", "console", "Output format: console | json | sarif"],
                ["-f, --file", "—", "Write output to file"],
                ["-c, --config", "—", "Path to breachscope.yaml"],
                ["--ci", "—", "Exit code 1 if findings exceed severity threshold"],
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

          <Section id="sandbox" title="breachscope sandbox">
            <p className="text-white/45 mb-5 leading-relaxed">
              Spins up a Docker container, deploys your app inside it, and unleashes an AI agent as root to find vulnerabilities through active exploitation — not pattern matching.
            </p>
            <CodeBlock code="breachscope sandbox [options]" />
            <OptionTable
              options={[
                ["-p, --port", "auto", "App port inside the container (auto-detected from project)"],
                ["-i, --image", "auto", "Custom base Docker image (default: auto-detected by language)"],
                ["-t, --timeout", "60", "Seconds to wait for the app to start"],
                ["--deep", "—", "Extended attack: 120 iterations instead of 80"],
                ["--breach", "—", "Companion agents focus on supply chain & credential risk"],
                ["--bug", "—", "Companion agents focus on exploitable code vulnerabilities"],
                ["--scan-mode", "all", "Explicit companion mode: all | breach | bug"],
                ["--no-cleanup", "—", "Keep container running after scan for manual inspection"],
                ["-u, --url", "—", "Target URL context for dashboard reporting"],
                ["-o, --output", "console", "Output format: console | json"],
                ["-f, --file", "—", "Write results to file"],
                ["-v, --verbose", "—", "Debug output"],
              ]}
            />
            <Callout type="tip">
              Sandbox defaults (attack depth + companion agent mode) can be set permanently in the dashboard <strong>Settings → Sandbox Defaults</strong>. CLI flags always take priority.
            </Callout>
            <Callout type="note">
              Requires Docker to be installed and running. The AI agent runs as root inside the container and installs any tool it needs (nmap, sqlmap, nikto, etc.). Results are pushed to the dashboard and displayed as a live terminal replay.
            </Callout>
            <div className="mt-6">
              <p className="text-xs font-semibold text-white/25 uppercase tracking-widest mb-3">Supported languages</p>
              <OptionTable
                options={[
                  ["Node.js / Bun", "package.json", "Express, Fastify, Hono, NestJS"],
                  ["Python", "requirements.txt, pyproject.toml", "Flask, FastAPI, Django"],
                  ["Go", "go.mod", "net/http, Gin, Fiber"],
                  ["Rust", "Cargo.toml", "Actix, Axum"],
                  ["Ruby", "Gemfile", "Rails, Sinatra"],
                  ["Java", "pom.xml, build.gradle", "Spring Boot, Quarkus"],
                  ["PHP", "composer.json", "Laravel, Symfony, plain PHP"],
                  [".NET", "*.csproj", "ASP.NET Core"],
                  ["Elixir", "mix.exs", "Phoenix"],
                  ["Dart", "pubspec.yaml", "Shelf, Dart Frog"],
                ]}
              />
            </div>
            <div className="mt-6">
              <p className="text-xs font-semibold text-white/25 uppercase tracking-widest mb-3">Attack surface covered</p>
              <OptionTable
                options={[
                  ["Env / secrets", "—", "Extracts all env vars, flags sensitive API keys and credentials"],
                  ["Auth bypass", "—", "JWT alg:none, weak secrets, missing auth on protected routes"],
                  ["SSTI", "—", "Template injection in Jinja2, Pug, EJS, Handlebars, Twig"],
                  ["SSRF", "—", "Probes internal metadata endpoints and private IP ranges"],
                  ["Path traversal", "—", "Directory escape, symlink abuse, arbitrary file read"],
                  ["Command injection", "—", "Shell metacharacter injection in all input vectors"],
                  ["Prototype pollution", "—", "Merge/extend functions, JSON body parsing edge cases"],
                  ["SQL injection", "—", "Raw query construction, ORM misuse, blind injection"],
                ]}
              />
            </div>
          </Section>

          <Section id="deps" title="breachscope deps">
            <p className="text-white/45 mb-5 leading-relaxed">
              Dependency and lockfile supply chain scan across all supported languages. Queries OSV.dev with exact installed versions.
            </p>
            <CodeBlock code="breachscope deps [-m mode] [-v] [-o format]" />
            <OptionTable
              options={[
                ["npm / yarn / pnpm / bun", "package.json, lockfiles", "npm ecosystem"],
                ["Python", "requirements.txt, pyproject.toml, Pipfile", "PyPI"],
                ["Go", "go.mod", "Go"],
                ["Rust", "Cargo.toml, Cargo.lock", "crates.io"],
                ["Ruby", "Gemfile, Gemfile.lock", "RubyGems"],
                ["Java", "pom.xml, build.gradle", "Maven Central"],
                ["PHP", "composer.json, composer.lock", "Packagist"],
                [".NET", "*.csproj, packages.lock.json", "NuGet"],
                ["Elixir", "mix.exs, mix.lock", "Hex.pm"],
                ["Dart", "pubspec.yaml, pubspec.lock", "pub.dev"],
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
                { title: "Sandbox Terminal", desc: "Full terminal replay of the AI agent's Docker attack session — every command, HTTP request, credential found, and attack chain." },
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

          <Section id="integrations-overview" title="How integrations work">
            <p className="text-white/45 mb-5 leading-relaxed">
              BreachScope has two distinct integration modes. They serve different purposes and require different setup.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] px-4 py-4">
                <p className="text-sm font-semibold text-white/70 mb-1">Toolchain Scanners</p>
                <p className="text-xs text-white/35 leading-relaxed mb-3">Static checks against your Supabase, Vercel, and GitHub config. No AI required. Set credentials in <code className="font-mono">breachscope.yaml</code> or env vars.</p>
                <div className="flex flex-wrap gap-1.5">
                  {["Supabase", "Vercel", "GitHub"].map(s => <ServiceBadge key={s} name={s} />)}
                </div>
              </div>
              <div className="rounded-xl border border-breach-500/20 bg-breach-500/[0.03] px-4 py-4">
                <p className="text-sm font-semibold text-white/70 mb-1">Live Service Probes <span className="text-xs font-normal text-white/30 ml-1">runs when OPENAI_API_KEY is set</span></p>
                <p className="text-xs text-white/35 leading-relaxed mb-3">AI agent makes real API calls to your live services using credentials you supply interactively. Finds over-privileged keys, misconfigs, and exposed data.</p>
                <div className="flex flex-wrap gap-1.5">
                  {["Firebase","AWS","Stripe","Clerk","Auth0","Cloudflare","Resend","SendGrid","Twilio","OpenAI","Anthropic","Pinecone","Sentry","Datadog","Neon","Upstash","PlanetScale"].map(s => <ServiceBadge key={s} name={s} />)}
                </div>
              </div>
            </div>
          </Section>

          <Section id="toolchain-scanners" label="Toolchain Scanners" title="Supabase, Vercel &amp; GitHub">
            <p className="text-white/45 mb-5 leading-relaxed">
              These run as part of every scan automatically when credentials are present.
            </p>

            <div className="space-y-6">
              <div className="rounded-xl border border-white/[0.06] overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.05] bg-white/[0.02]">
                  <span className="text-sm font-medium text-white/70">Supabase</span>
                  <span className="text-[10px] text-white/25 font-mono ml-auto">Database / Auth</span>
                </div>
                <div className="px-4 py-4">
                  <ul className="text-white/40 text-sm space-y-1.5 mb-4">
                    <li className="flex gap-2"><span className="text-white/20">›</span> RLS disabled on tables (anon key can read all rows)</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Public storage buckets with sensitive data</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Service role key used in client-side code</li>
                  </ul>
                  <CodeBlock lang="yaml" code={`toolchain:\n  supabase:\n    url: \${SUPABASE_URL}\n    anonKey: \${SUPABASE_ANON_KEY}`} />
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.06] overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.05] bg-white/[0.02]">
                  <span className="text-sm font-medium text-white/70">Vercel</span>
                  <span className="text-[10px] text-white/25 font-mono ml-auto">Hosting</span>
                </div>
                <div className="px-4 py-4">
                  <ul className="text-white/40 text-sm space-y-1.5 mb-4">
                    <li className="flex gap-2"><span className="text-white/20">›</span> Secrets exposed in preview deployments</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Preview deployments with no access protection</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Open team invite links</li>
                  </ul>
                  <CodeBlock lang="yaml" code={`toolchain:\n  vercel:\n    token: \${VERCEL_TOKEN}\n    projectId: "prj_xxx"`} />
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.06] overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.05] bg-white/[0.02]">
                  <span className="text-sm font-medium text-white/70">GitHub</span>
                  <span className="text-[10px] text-white/25 font-mono ml-auto">Source Control / CI</span>
                </div>
                <div className="px-4 py-4">
                  <ul className="text-white/40 text-sm space-y-1.5 mb-4">
                    <li className="flex gap-2"><span className="text-white/20">›</span> Branch protection missing on main / master</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Required PR reviews not enforced</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Actions default write permissions</li>
                    <li className="flex gap-2"><span className="text-white/20">›</span> Overprivileged personal access tokens</li>
                  </ul>
                  <CodeBlock lang="yaml" code={`toolchain:\n  github:\n    token: \${GITHUB_TOKEN}\n    repo: "owner/repo"`} />
                </div>
              </div>
            </div>
          </Section>

          <Section id="live-probes" label="Live Service Probes" title="AI-powered service probing">
            <p className="text-white/45 mb-2 leading-relaxed">
              When <code className="font-mono text-white/65">OPENAI_API_KEY</code> is set, BreachScope automatically detects which services your codebase uses, prompts you for credentials interactively, then dispatches an AI agent to probe the live APIs for real misconfigurations — over-privileged keys, exposed data, insecure defaults.
            </p>
            <p className="text-white/35 text-sm mb-5">No flag needed — AI is on by default. Detection uses package imports, env var prefixes, and config file presence. You only get prompted for services actually found in your project.</p>
            <CodeBlock code="OPENAI_API_KEY=sk-... breachscope scan" />
            <Callout type="note">
              Credentials are used in-memory only and destroyed after the probe. They are never stored or uploaded.
            </Callout>

            <div className="mt-6 grid grid-cols-1 gap-2">
              {[
                { category: "Database / Auth", services: [
                  { name: "Supabase",    fields: "Project URL, anon key",              env: "SUPABASE_URL, SUPABASE_ANON_KEY" },
                  { name: "Firebase",    fields: "Project ID, web API key, service account (optional)", env: "FIREBASE_PROJECT_ID, FIREBASE_API_KEY" },
                  { name: "Neon",        fields: "API key, project ID (both optional)", env: "NEON_API_KEY, NEON_PROJECT_ID" },
                  { name: "PlanetScale", fields: "Service token ID, service token, org", env: "PLANETSCALE_SERVICE_TOKEN_ID" },
                ]},
                { category: "Auth", services: [
                  { name: "Clerk",  fields: "Secret key, publishable key", env: "CLERK_SECRET_KEY" },
                  { name: "Auth0",  fields: "Domain, client ID, client secret, mgmt token (optional)", env: "AUTH0_DOMAIN, AUTH0_CLIENT_ID" },
                ]},
                { category: "Cache", services: [
                  { name: "Upstash Redis", fields: "REST URL, REST token", env: "UPSTASH_REDIS_REST_URL" },
                ]},
                { category: "Cloud / CDN", services: [
                  { name: "AWS",        fields: "Access key ID, secret access key, region", env: "AWS_ACCESS_KEY_ID" },
                  { name: "Cloudflare", fields: "API token, zone ID, account ID (both optional)", env: "CLOUDFLARE_API_TOKEN" },
                ]},
                { category: "Payments", services: [
                  { name: "Stripe", fields: "Secret key, webhook secret (optional)", env: "STRIPE_SECRET_KEY" },
                ]},
                { category: "Email", services: [
                  { name: "Resend",   fields: "API key", env: "RESEND_API_KEY" },
                  { name: "SendGrid", fields: "API key", env: "SENDGRID_API_KEY" },
                ]},
                { category: "SMS / Voice", services: [
                  { name: "Twilio", fields: "Account SID, auth token", env: "TWILIO_ACCOUNT_SID" },
                ]},
                { category: "AI", services: [
                  { name: "OpenAI",    fields: "API key, org ID (optional)", env: "OPENAI_API_KEY" },
                  { name: "Anthropic", fields: "API key",                    env: "ANTHROPIC_API_KEY" },
                ]},
                { category: "Vector DB", services: [
                  { name: "Pinecone", fields: "API key, environment", env: "PINECONE_API_KEY" },
                ]},
                { category: "Observability", services: [
                  { name: "Sentry",   fields: "Auth token, org slug, DSN (optional)", env: "SENTRY_AUTH_TOKEN" },
                  { name: "Datadog",  fields: "API key, app key (optional), site",    env: "DD_API_KEY" },
                ]},
              ].map(({ category, services }) => (
                <div key={category} className="rounded-xl border border-white/[0.06] overflow-hidden">
                  <div className="px-4 py-2.5 bg-white/[0.02] border-b border-white/[0.04]">
                    <span className="text-[10px] font-semibold text-white/25 uppercase tracking-widest">{category}</span>
                  </div>
                  <table className="w-full text-xs">
                    <tbody>
                      {services.map((svc, i) => (
                        <tr key={svc.name} className={`border-b border-white/[0.03] last:border-0 ${i % 2 === 1 ? "bg-white/[0.01]" : ""}`}>
                          <td className="px-4 py-3 font-medium text-white/60 whitespace-nowrap w-28">{svc.name}</td>
                          <td className="px-4 py-3 text-white/35">{svc.fields}</td>
                          <td className="px-4 py-3 font-mono text-white/20 hidden sm:table-cell">{svc.env}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
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

      - name: AI code audit (auto-enabled when key is set)
        run: breachscope scan --mode deep --bug --ci
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

          <Divider label="Release History" />

          {/* ── Changelog ─────────────────────────────────── */}
          <Section id="changelog" label="Changelog" title="v0.3.1 — 2026-04-27">
            <p className="text-white/45 mb-5 leading-relaxed">
              Sandbox CLI flags, dashboard Sandbox Defaults settings, and multi-language AI dependency agent.
            </p>
            <div className="space-y-4">
              <ChangelogEntry tag="Added" color="green">
                <strong>Sandbox flags</strong> — <code className="font-mono text-white/65">--breach</code>, <code className="font-mono text-white/65">--bug</code>, <code className="font-mono text-white/65">--scan-mode</code> control companion agent focus. <code className="font-mono text-white/65">--deep</code> now wired end-to-end: 120 attack iterations.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Sandbox Defaults in Settings</strong> — configure Attack Depth (Normal/Deep) and Companion Agent Mode (All/Breach/Bug) from the dashboard. CLI flags always override.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Multi-language AI dependency agent</strong> — dep agent now covers all 10 ecosystems. <code className="font-mono text-white/65">fetch_osv_data</code>, <code className="font-mono text-white/65">fetch_github_advisory</code>, and <code className="font-mono text-white/65">search_vulnerabilities</code> all accept an <code className="font-mono text-white/65">ecosystem</code> parameter. Packages sent to the agent grouped by ecosystem with correct OSV tags.
              </ChangelogEntry>
              <ChangelogEntry tag="Fixed" color="red">
                <code className="font-mono text-white/65">--deep</code> flag was accepted but never forwarded to the sandbox agent — attack iteration count was always 80 regardless of flag.
              </ChangelogEntry>
            </div>
          </Section>

          <Section id="changelog-030" title="v0.3.0 — 2026-04-27">
            <p className="text-white/45 mb-5 leading-relaxed">
              Major sandbox upgrade: AI supervisor + validator agents, CVE intelligence module, 3 new specialist attackers, rabbit hole prevention, Pentest Task Tree, OWASP ZAP integration, and a full sandbox dashboard redesign.
            </p>
            <div className="space-y-4">
              <ChangelogEntry tag="Added" color="green">
                <strong>Sandbox Supervisor</strong> — pre-attack agent that analyzes all recon data (credentials, endpoints, ports) and builds a prioritized <code className="font-mono text-white/65">SpecialistTask[]</code> attack plan. Performs CVE web searches against detected framework versions. Max 6 tasks per session.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Sandbox Validator</strong> — independently re-verifies every critical/high finding after the attack loop. Confidence levels: <code className="font-mono text-white/65">confirmed</code> (≥90) · <code className="font-mono text-white/65">likely</code> (60–89) · <code className="font-mono text-white/65">uncertain</code> (30–59) · <code className="font-mono text-white/65">false_positive</code> (&lt;30). Max 5 validations per session.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>CVE Intelligence module</strong> (<code className="font-mono text-white/65">cve-intel.ts</code>) — fetches EPSS exploitation probability, NVD CVSS, Nuclei template availability, and Exploit-DB presence concurrently. EPSS risk: 🔴 &gt;50% · 🟡 10–50% · 🟢 &lt;10%. In-process cache, NVD rate-limit compliant.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>3 new specialist attackers</strong>: <code className="font-mono text-white/65">race_condition</code>, <code className="font-mono text-white/65">business_logic</code>, <code className="font-mono text-white/65">ai_llm_attacks</code> — total 11 specialist types.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Rabbit hole prevention</strong> — commands attempted ≥3 times are auto-abandoned with a <code className="font-mono text-white/65">[RABBIT HOLE]</code> log entry. In-memory Map, no disk I/O.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Pentest Task Tree (PTT)</strong> — hierarchical attack nodes with keyword-based categorization and status tracking: <code className="font-mono text-white/65">unexplored → in_progress → confirmed_vuln / not_vulnerable / needs_more_info</code>.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>OWASP ZAP integration</strong> — spider + active scan runs inside the container via execFn; results feed the finding pipeline.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Chain-of-thought prompting</strong> — every tool call preceded by mandatory <code className="font-mono text-white/65">[WHAT I KNOW] → [HYPOTHESIS] → [EXPECTED] → [ATTACK]</code> reasoning block.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Monorepo Docker support</strong> — <code className="font-mono text-white/65">COPY . .</code> from root, then <code className="font-mono text-white/65">WORKDIR /app/service</code>. Self-healing build loop threads <code className="font-mono text-white/65">serviceSubpath</code> through all repair agents.
              </ChangelogEntry>
              <ChangelogEntry tag="Changed" color="yellow">
                <strong>Sandbox dashboard redesign</strong> — stats grid, AI attack narrative, confirmed chains, discovered secrets, sandbox findings with CVSS + validator confidence, PTT tree, structured attack log with per-entry type badges.
              </ChangelogEntry>
              <ChangelogEntry tag="Fixed" color="red">
                <code className="font-mono text-white/65">attackLog</code> typed as <code className="font-mono text-white/65">string[]</code> in dashboard — corrected to <code className="font-mono text-white/65">AttackLogEntry[]</code> (root of <code className="font-mono text-white/65">e.startsWith is not a function</code> crash).
              </ChangelogEntry>
            </div>
          </Section>

          <Section id="changelog-020" title="v0.2.0 — 2026-04-26">
            <p className="text-white/45 mb-5 leading-relaxed">
              AI-first sandbox flow, aggressive web research across all agents, monorepo detection, remote config at sandbox startup.
            </p>
            <div className="space-y-4">
              <ChangelogEntry tag="Added" color="green">
                <strong>Phase 0 codebase understanding</strong> — before any Docker work, an AI agent reads every source file, <code className="font-mono text-white/65">.env</code>, and config to build a full security picture. AI writes a purpose-built Dockerfile from what it learned.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Aggressive web research</strong> — <code className="font-mono text-white/65">web_search</code> and <code className="font-mono text-white/65">crawl_url</code> tools in all agents. Agents research every framework version, CVE, and library immediately. Search limit raised 5 → 10.
              </ChangelogEntry>
              <ChangelogEntry tag="Changed" color="yellow">
                Sandbox startup timeout raised 60 → 90 seconds (max 180s). Unknown project type generates Ubuntu 22.04 toolbox container instead of exiting.
              </ChangelogEntry>
            </div>
          </Section>

          <Section id="changelog-010" title="v0.1.0 — 2026-04-25">
            <p className="text-white/45 mb-5 leading-relaxed">
              Initial release: Docker Attack Arena, 10-language dependency scanning, 62-pattern static analysis, AI scan modes, web dashboard.
            </p>
            <div className="space-y-4">
              <ChangelogEntry tag="Added" color="green">
                <strong>Docker Attack Arena</strong> (<code className="font-mono text-white/65">breachscope sandbox</code>) — PentestGPT / HackingBuddyGPT architecture with evolving attack strategy, persistent AttackMemory, 60 iterations per session.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>10-language dependency scanning</strong> — JavaScript, Python, Go, Rust, Ruby, Java, PHP, .NET, Elixir, Dart. All ecosystems query OSV.dev.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>62-pattern static analysis</strong> in full mode — 13 base + 27 bug + 22 breach patterns. Mode-aware: <code className="font-mono text-white/65">--breach</code>, <code className="font-mono text-white/65">--bug</code>, or combined.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Free threat intelligence</strong> — OSV.dev, npm advisory bulk API, NVD keyword search. No API key required.
              </ChangelogEntry>
              <ChangelogEntry tag="Added" color="green">
                <strong>Web dashboard</strong> — AI synthesis, sandbox terminal replay, PDF export, AES-256-GCM encrypted stored API keys.
              </ChangelogEntry>
            </div>
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

function ServiceBadge({ name }: { name: string }) {
  return (
    <span className="text-[10px] font-mono text-white/35 bg-white/[0.04] border border-white/[0.06] rounded px-1.5 py-0.5">
      {name}
    </span>
  );
}

function ChangelogEntry({
  tag,
  color,
  children,
}: {
  tag: "Added" | "Changed" | "Fixed";
  color: "green" | "yellow" | "red";
  children: React.ReactNode;
}) {
  const colorMap = {
    green:  "text-green-400 bg-green-500/[0.08] border-green-500/20",
    yellow: "text-yellow-400 bg-yellow-500/[0.08] border-yellow-500/20",
    red:    "text-red-400 bg-red-500/[0.08] border-red-500/20",
  };
  return (
    <div className="flex gap-3 items-start">
      <span className={`shrink-0 text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border mt-0.5 ${colorMap[color]}`}>
        {tag}
      </span>
      <p className="text-white/45 text-sm leading-relaxed">{children}</p>
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
