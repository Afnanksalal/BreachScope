import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";

export const metadata: Metadata = {
  title: "Roadmap — BreachScope",
  description: "What's shipped, what's next, and where BreachScope is headed.",
};

interface RoadmapItem {
  title: string;
  description: string;
  status: "shipped" | "in-progress" | "planned" | "idea";
}

interface RoadmapPhase {
  version: string;
  label: string;
  period: string;
  accent: string;
  dotColor: string;
  borderColor: string;
  items: RoadmapItem[];
}

const STATUS_CONFIG = {
  shipped:     { label: "Shipped",      dot: "bg-green-500",   badge: "bg-green-500/15 text-green-300 border-green-500/20" },
  "in-progress":{ label: "In Progress", dot: "bg-yellow-400 animate-pulse", badge: "bg-yellow-500/15 text-yellow-300 border-yellow-500/20" },
  planned:     { label: "Planned",      dot: "bg-white/30",    badge: "bg-white/[0.06] text-white/40 border-white/10" },
  idea:        { label: "Idea",         dot: "bg-purple-500/50",badge: "bg-purple-500/10 text-purple-400/60 border-purple-500/15" },
};

const PHASES: RoadmapPhase[] = [
  {
    version: "v0.1 – v0.3",
    label: "Shipped",
    period: "April 2026",
    accent: "text-green-400",
    dotColor: "bg-green-500",
    borderColor: "border-green-500/20",
    items: [
      { title: "Static code scanner (62 patterns)", description: "Breach + bug mode patterns across SQL injection, hardcoded secrets, weak crypto, prototype pollution, and 50+ more.", status: "shipped" },
      { title: "10-language dependency auditor", description: "OSV.dev + GitHub Advisory queries across npm, PyPI, Go, Rust, Ruby, Java, PHP, .NET, Elixir, Dart — ecosystem-aware CVE lookups.", status: "shipped" },
      { title: "Docker sandbox attack agent", description: "AI-as-root active exploitation inside a container: supervisor planning, 11 specialist agents, ZAP integration, PTT tree, validator.", status: "shipped" },
      { title: "Live service probes (Supabase, Vercel, GitHub, AWS)", description: "Toolchain security checks — misconfigured keys, leaked secrets, exposed endpoints, CORS policies.", status: "shipped" },
      { title: "Web dashboard with AI synthesis", description: "Scan history, smart findings groups, supply chain grid, sandbox terminal replay, PDF/JSON/Markdown export.", status: "shipped" },
      { title: "CI/CD GitHub Actions integration", description: "Exit codes, SARIF output, PR annotations, per-commit scan reports.", status: "shipped" },
      { title: "Sandbox defaults in settings", description: "Configure attack depth and companion agent mode from the dashboard — synced to CLI at runtime.", status: "shipped" },
    ],
  },
  {
    version: "v0.4",
    label: "Near Term",
    period: "Q2–Q3 2026",
    accent: "text-blue-400",
    dotColor: "bg-blue-400",
    borderColor: "border-blue-500/20",
    items: [
      { title: "GitHub OAuth — connect your repos", description: "Link your GitHub account, browse repos from the dashboard, and trigger scans without cloning locally.", status: "in-progress" },
      { title: "Auto PR security gate", description: "BreachScope scans every PR and posts a security summary as a check. Block merge on critical findings.", status: "planned" },
      { title: "Auto-merge safe dependency updates", description: "Automatically merge dependency bumps that pass the full audit — no CVEs, maintainer score healthy, no regressions.", status: "planned" },
      { title: "Scheduled autonomous dep auditing", description: "Set a cron (daily/weekly) — BreachScope re-audits all repos and opens issues when new CVEs drop against your locked deps.", status: "planned" },
      { title: "Sandbox gate before merge", description: "Run the full Docker sandbox attack against feature branches in CI. Block merge if the AI confirms critical exploits.", status: "planned" },
      { title: "Fix suggestions with AI", description: "For each finding, generate a concrete diff suggestion — upgrade this dep, remove this pattern, add this header. One-click apply.", status: "planned" },
    ],
  },
  {
    version: "v0.5",
    label: "Longer Term",
    period: "Q4 2026+",
    accent: "text-purple-400",
    dotColor: "bg-purple-400",
    borderColor: "border-purple-500/20",
    items: [
      { title: "Multi-repo workspace", description: "Manage all your projects from one dashboard. Cross-repo supply chain graph — see shared vulnerable deps across your entire org.", status: "planned" },
      { title: "SBOM generation", description: "Export a full Software Bill of Materials in CycloneDX or SPDX format from any scan. Required for SOC 2 and EU Cyber Resilience Act.", status: "planned" },
      { title: "Compliance mapping", description: "Map findings to OWASP Top 10, NIST SP 800-53, SOC 2 CC6, ISO 27001 A.14 controls. Generate audit-ready compliance reports.", status: "planned" },
      { title: "Team workspaces and roles", description: "Org-level accounts with role-based access: admin, security engineer, read-only auditor. Shared scan history and notifications.", status: "idea" },
      { title: "Slack / Teams / PagerDuty alerts", description: "Push critical findings to your incident channel the moment a scan completes or a new CVE hits your deps.", status: "idea" },
      { title: "Runtime security (eBPF)", description: "Move beyond static — attach to a running process with eBPF and detect actual exploitation attempts in production.", status: "idea" },
      { title: "VEX / EPSS triage assistant", description: "Automatically triage CVEs using EPSS exploitation probability + VEX statements. De-noise findings by real-world exploitability.", status: "idea" },
    ],
  },
];

function StatusBadge({ status }: { status: RoadmapItem["status"] }) {
  const cfg = STATUS_CONFIG[status];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border ${cfg.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

export default function RoadmapPage() {
  const totalShipped  = PHASES[0]!.items.length;
  const totalPlanned  = PHASES.slice(1).flatMap((p) => p.items).filter((i) => i.status === "planned").length;
  const totalIdeas    = PHASES.flatMap((p) => p.items).filter((i) => i.status === "idea").length;

  return (
    <>
      <Nav />
      <main className="min-h-screen pt-28 pb-32">
        <div className="max-w-4xl mx-auto px-6">

          {/* Hero */}
          <div className="mb-16">
            <p className="text-breach-400 text-xs font-semibold uppercase tracking-[0.2em] mb-4">Roadmap</p>
            <h1 className="text-4xl sm:text-5xl font-bold text-white leading-tight mb-4">
              Where BreachScope
              <br />
              <span className="text-white/35">is headed</span>
            </h1>
            <p className="text-white/45 text-base leading-relaxed max-w-xl">
              An honest, public view of what&apos;s been built, what&apos;s actively in progress,
              and what&apos;s coming. This is a living document — priorities shift as the
              security landscape changes.
            </p>

            {/* Stats */}
            <div className="flex items-center gap-6 mt-8">
              {[
                { label: "Shipped",  value: totalShipped,  color: "text-green-400" },
                { label: "Planned",  value: totalPlanned,  color: "text-blue-400"  },
                { label: "Ideas",    value: totalIdeas,    color: "text-purple-400" },
              ].map(({ label, value, color }) => (
                <div key={label}>
                  <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
                  <p className="text-white/30 text-xs mt-0.5">{label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Phases */}
          <div className="space-y-16">
            {PHASES.map((phase) => (
              <section key={phase.version}>
                {/* Phase header */}
                <div className="flex items-center gap-4 mb-8">
                  <div className={`w-3 h-3 rounded-full ${phase.dotColor} shrink-0`} />
                  <div>
                    <div className="flex items-center gap-3">
                      <h2 className={`text-lg font-bold ${phase.accent}`}>{phase.version}</h2>
                      <span className="text-white/25 text-sm">·</span>
                      <span className="text-white/40 text-sm">{phase.label}</span>
                    </div>
                    <p className="text-white/25 text-xs mt-0.5">{phase.period}</p>
                  </div>
                </div>

                {/* Items */}
                <div className="space-y-3 ml-7">
                  {phase.items.map((item) => (
                    <div
                      key={item.title}
                      className={`p-5 rounded-2xl border bg-white/[0.02] ${phase.borderColor} hover:bg-white/[0.035] transition-colors`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <p className="text-white/85 text-sm font-medium leading-snug mb-1.5">{item.title}</p>
                          <p className="text-white/35 text-xs leading-relaxed">{item.description}</p>
                        </div>
                        <div className="shrink-0 mt-0.5">
                          <StatusBadge status={item.status} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            ))}
          </div>

          {/* Contribute CTA */}
          <div className="mt-20 p-8 rounded-3xl border border-white/[0.08] bg-white/[0.02]">
            <h3 className="text-white font-semibold text-lg mb-2">Have an idea?</h3>
            <p className="text-white/40 text-sm leading-relaxed mb-5">
              BreachScope is open source. If there&apos;s a feature you need or a workflow that&apos;s painful,
              open an issue or a discussion on GitHub. The roadmap is shaped by what developers
              actually need.
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <a
                href="https://github.com/Afnanksalal/BreachScope/issues/new"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/10 border border-white/15 text-white text-sm font-medium hover:bg-white/15 transition-colors"
              >
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                </svg>
                Open an issue
              </a>
              <Link
                href="/docs"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-white/[0.08] text-white/50 text-sm font-medium hover:text-white/70 hover:border-white/15 transition-colors"
              >
                Read the docs →
              </Link>
            </div>
          </div>

        </div>
      </main>
      <Footer />
    </>
  );
}
