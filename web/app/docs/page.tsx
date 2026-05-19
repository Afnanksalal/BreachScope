import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";
import { DocsSidebar } from "./DocsSidebar";
import { CodeBlock, Callout } from "./DocsBlocks";
import type { Metadata } from "next";

const APP_URL = "https://breachscoope.vercel.app";
const LLM_ALTERNATES = {
  "text/plain": `${APP_URL}/llms.txt`,
  "text/plain; profile=llms-full": `${APP_URL}/llms-full.txt`,
};

export const metadata: Metadata = {
  title: "Documentation - BreachScope",
  description: "BreachScope documentation for CLI scans, policy gates, SBOM, OpenVEX, identity, integrations, legal pages, data handling, and deployment.",
  alternates: {
    canonical: `${APP_URL}/docs`,
    types: LLM_ALTERNATES,
  },
};

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-black">
      <Nav />
      <div className="mx-auto flex max-w-7xl gap-14 px-4 pb-24 pt-24 sm:px-6 sm:pb-28 sm:pt-28">
        <DocsSidebar />
        <article className="min-w-0 flex-1">
          <header className="mb-12 border-b border-white/[0.07] pb-10">
            <div className="mb-4 inline-flex items-center rounded-lg border border-emerald-300/20 bg-emerald-300/[0.055] px-3 py-1.5 text-xs text-emerald-100/75">
              BreachScope guide
            </div>
            <h1 className="text-4xl font-semibold text-white md:text-5xl">BreachScope docs</h1>
            <p className="mt-4 max-w-2xl text-base leading-8 text-white/52">
              Configure the CLI, enforce policy in CI, export release evidence, connect the dashboard, and route findings with credentials your team owns.
            </p>
          </header>

          <Section id="installation" label="Start" title="Installation">
            <p>Requires Node.js 18 or higher. Docker is required only for sandbox attack runs.</p>
            <CodeBlock code={`npm install -g breachscope\npnpm add -g breachscope\nbun add -g breachscope\nnpx breachscope scan`} />
          </Section>

          <Section id="quick-start" title="Quick Start">
            <CodeBlock code={`cd my-project\nbreachscope login\nbreachscope scan\nbreachscope scan --mode deep --breach --bug --ci`} />
            <Callout type="tip">
              The CLI pushes results to the dashboard after login. Local scans still work without a dashboard connection.
            </Callout>
          </Section>

          <Section id="configuration" title="Configuration">
            <CodeBlock
              lang="yaml"
              code={`thresholds:\n  failOn: high\n\npolicy:\n  failOn: high\n  maxFindings:\n    critical: 0\n  blockedPackages:\n    - event-stream\n\noutput:\n  format: console\n  verbose: false`}
            />
            <p>Dashboard settings can store customer-supplied OpenAI and Firecrawl keys when a team chooses to enable those workflows. API keys require `secrets:read` before the CLI can retrieve encrypted secret values.</p>
          </Section>

          <Section id="data-and-keys" title="Data and Keys">
            <p>BreachScope provides the scanning, routing, and evidence layer. Teams bring their own provider accounts, tokens, and credentials for GitHub, Slack, Jira, PagerDuty, Linear, OpenAI, Firecrawl, and other connected systems.</p>
            <OptionTable
              rows={[
                ["Stored", "account data", "users, projects, scan records, findings, audit logs, settings, and integration metadata"],
                ["Optional", "provider keys", "encrypted only when a user saves them for dashboard-connected workflows"],
                ["Never supplied", "third-party accounts", "BreachScope does not provide Slack, GitHub, OpenAI, Firecrawl, or incident-management accounts"],
                ["Private routes", "dashboard/API", "robots.txt blocks authenticated and operational routes from crawlers"],
              ]}
            />
          </Section>

          <Divider label="Commands" />

          <Section id="scan" title="breachscope scan">
            <p>The primary scanner for code, dependency, toolchain, blackbox, smoke, policy, baseline, and evidence workflows.</p>
            <OptionTable
              rows={[
                ["--mode", "basic | major | deep", "Dependency traversal depth"],
                ["--breach", "off", "Supply-chain, CVE, credentials, exposure"],
                ["--bug", "off", "Code vulnerability focus"],
                ["--ci", "off", "Fail on configured threshold or policy violation"],
                ["--policy", "none", "External policy file"],
                ["--baseline", "none", "Suppress known legacy findings"],
                ["--output", "console", "console | json | sarif"],
              ]}
            />
            <CodeBlock code={`breachscope scan --ci --policy release-gate.yml --output sarif --file breachscope.sarif`} />
          </Section>

          <Section id="sandbox" title="breachscope sandbox">
            <p>Builds an isolated Docker runtime for active security testing. Secrets are excluded by default.</p>
            <CodeBlock code={`breachscope sandbox --deep --breach --bug\nbreachscope sandbox --bug --ci\nbreachscope sandbox --include-secrets`} />
            <Callout type="warning">
              Use `--include-secrets` only in disposable environments where active exploitation with real credentials is intentional.
            </Callout>
          </Section>

          <Section id="sbom" title="breachscope sbom">
            <p>Generate release evidence in CycloneDX or SPDX JSON.</p>
            <CodeBlock code={`breachscope sbom --output cyclonedx --file bom.cdx.json\nbreachscope sbom --output spdx --file bom.spdx.json`} />
          </Section>

          <Section id="vex" title="OpenVEX and Fix Briefs">
            <p>Export VEX and remediation briefs from a saved JSON scan.</p>
            <CodeBlock code={`breachscope scan --output json --file scan.json\nbreachscope vex --from scan.json --file openvex.json\nbreachscope suggest-fixes --from scan.json --file fixes.md`} />
          </Section>

          <Section id="runtime" title="Runtime Monitoring">
            <p>Collect Tracee/eBPF events on Linux hosts where Tracee is installed.</p>
            <CodeBlock code={`breachscope runtime --container app --duration 120 --file tracee-events.jsonl\nbreachscope runtime --dry-run`} />
          </Section>

          <Divider label="Operations" />

          <Section id="controls" title="Controls Model">
            <p>BreachScope supports policy-as-code, baselines, project-scoped dashboard records, audit logs, scoped API keys, triage fields, and release evidence exports.</p>
            <MetricGrid
              items={[
                ["Policy", "thresholds, budgets, suppressions"],
                ["Evidence", "SARIF, SBOM, OpenVEX, JSON"],
                ["Triage", "status, assignee, due date, risk reason"],
                ["Audit", "project-scoped event history"],
              ]}
            />
          </Section>

          <Section id="policy" title="Policy-as-Code">
            <CodeBlock
              lang="yaml"
              code={`policy:\n  failOn: high\n  maxFindings:\n    critical: 0\n    high: 3\n  blockedPackages:\n    - ua-parser-js\n  suppressions:\n    - fingerprint: "64-character-fingerprint"\n      reason: "Accepted during migration"\n      expiresAt: "2026-12-31T23:59:59Z"\n      approvedBy: "security@example.com"`}
            />
          </Section>

          <Section id="dashboard" title="Dashboard">
            <p>The dashboard adds projects, policies, integrations, audit logs, scoped keys, settings, scan history, and finding triage.</p>
            <OptionTable
              rows={[
                ["Projects", "web", "Group scans, policies, integrations, and audit history"],
                ["API keys", "web", "Least-privilege scopes for automation"],
                ["Triage", "web", "Status, ownership, due dates, VEX status, accepted risk"],
                ["Audit logs", "web", "Immutable project activity stream"],
              ]}
            />
          </Section>

          <Section id="identity" title="Identity">
            <p>SCIM user lifecycle endpoints and SAML metadata are present. SAML ACS fails closed until assertion validation and IdP certificate pinning are configured.</p>
          </Section>

          <Section id="integrations" title="Integrations">
            <p>Project integrations turn completed scans into provider work: Slack and Teams messages, PagerDuty incidents, Jira and Linear issues, GitHub/GitLab/Bitbucket issues, and audit-backed retry records. Each route uses customer-owned credentials and a configurable severity threshold.</p>
          </Section>

          <Divider label="Reference" />

          <Section id="security" title="Security Defaults">
            <ul className="space-y-2 text-white/52">
              <li>API keys are hashed before storage.</li>
              <li>Dashboard secrets are AES-256-GCM encrypted.</li>
              <li>Scan upload payloads are validated and size-limited.</li>
              <li>API key scopes are enforced.</li>
              <li>CLI auth polling is replay-safe.</li>
              <li>Sandbox excludes secrets by default.</li>
            </ul>
          </Section>

          <Section id="ci" title="CI/CD">
            <CodeBlock code={`breachscope init-ci\nbreachscope scan --ci --policy release-gate.yml\nbreachscope scan --baseline breachscope-baseline.json --new-findings-only --ci`} />
          </Section>

          <Section id="deployment" title="Deployment Checklist">
            <ul className="space-y-2 text-white/52">
              <li>Apply the Drizzle migration.</li>
              <li>Configure auth, database, and encryption secrets.</li>
              <li>Set Upstash Redis variables for distributed rate limiting.</li>
              <li>Connect customer-owned provider credentials for integrations.</li>
              <li>Install Tracee on Linux runtime-monitoring hosts.</li>
              <li>Configure SAML validation and IdP certificate pinning before enabling SSO.</li>
            </ul>
          </Section>

          <Section id="legal" title="Legal and Policy Pages">
            <p>Public terms, privacy, acceptable use, and data protection pages are available as normal App Router pages and included in the sitemap for crawler discovery.</p>
            <OptionTable
              rows={[
                ["/terms", "public", "service terms, user responsibilities, customer content, and customer-owned integrations"],
                ["/privacy", "public", "data categories, purposes, retention, rights, subprocessors, and contact paths"],
                ["/acceptable-use", "public", "authorized testing rules and abuse boundaries"],
                ["/data-protection", "public", "controller/processor roles, safeguards, incident process, deletion, and transfer notes"],
                ["/security", "public", "supported versions, vulnerability reporting, response targets, and security practices"],
              ]}
            />
          </Section>

          <Section id="changelog" title="Changelog">
            <p>See the repository `CHANGELOG.md` for release history and verification notes.</p>
          </Section>
        </article>
      </div>
      <Footer />
    </div>
  );
}

function Section({ id, label, title, children }: { id: string; label?: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-28 border-b border-white/[0.07] py-10">
      {label && <p className="mb-3 text-xs font-semibold uppercase text-white/30">{label}</p>}
      <h2 className="mb-4 text-xl font-semibold text-white sm:text-2xl">{title}</h2>
      <div className="space-y-4 text-sm leading-7 text-white/52">{children}</div>
    </section>
  );
}

function Divider({ label }: { label: string }) {
  return (
    <div className="mt-12 border-b border-white/[0.07] pb-3 text-xs font-semibold uppercase text-white/30">
      {label}
    </div>
  );
}

function OptionTable({ rows }: { rows: string[][] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-white/[0.08]">
      <div className="divide-y divide-white/[0.06] sm:hidden">
        {rows.map(([name, value, desc]) => (
          <div key={name} className="space-y-2 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-md bg-white/[0.04] px-2 py-1 font-mono text-xs text-white/62">{name}</span>
              <span className="rounded-md bg-black/35 px-2 py-1 font-mono text-xs text-white/42">{value}</span>
            </div>
            <p className="text-sm leading-6 text-white/52">{desc}</p>
          </div>
        ))}
      </div>
      <table className="hidden w-full text-sm sm:table">
        <tbody>
          {rows.map(([name, value, desc]) => (
            <tr key={name} className="border-b border-white/[0.06] last:border-0">
              <td className="w-44 bg-white/[0.025] px-4 py-3 font-mono text-xs text-white/62">{name}</td>
              <td className="w-40 px-4 py-3 font-mono text-xs text-white/42">{value}</td>
              <td className="px-4 py-3 text-white/52">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MetricGrid({ items }: { items: string[][] }) {
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {items.map(([title, detail]) => (
        <div key={title} className="rounded-lg border border-white/[0.08] bg-white/[0.03] p-4">
          <p className="font-semibold text-white">{title}</p>
          <p className="mt-1 text-xs text-white/42">{detail}</p>
        </div>
      ))}
    </div>
  );
}
