import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";

const APP_URL = "https://breachscoope.vercel.app";
const LLM_ALTERNATES = {
  "text/plain": `${APP_URL}/llms.txt`,
  "text/plain; profile=llms-full": `${APP_URL}/llms-full.txt`,
};

export const metadata: Metadata = {
  title: "Roadmap - BreachScope",
  description: "What has shipped, what is being operationalized, and what is next for BreachScope.",
  alternates: {
    canonical: `${APP_URL}/roadmap`,
    types: LLM_ALTERNATES,
  },
};

const PHASES = [
  {
    title: "Shipped",
    period: "Current codebase",
    tone: "emerald",
    items: [
      "Policy-as-code gates, baselines, SARIF, SBOM, OpenVEX, and fix suggestions",
      "Projects, scoped API keys, integrations, audit logs, and finding triage",
      "SCIM user lifecycle endpoints and SAML metadata foundation",
      "Tracee/eBPF runtime command for Linux event capture",
      "Deterministic supply-chain risk scoring across registry and security signals",
      "Secret-safe sandbox defaults and hardened Docker runtime flags",
    ],
  },
  {
    title: "Operationalization",
    period: "Next",
    tone: "cyan",
    items: [
      "Production SAML ACS with assertion validation and IdP certificate pinning",
      "Repository connection flows for GitHub, GitLab, and Bitbucket",
      "Scheduled organization scans from the dashboard",
      "Role-based organization access controls across projects",
      "Provider credential management UI for all integration executors",
    ],
  },
  {
    title: "Scale",
    period: "Later",
    tone: "violet",
    items: [
      "Cross-project dependency blast-radius graph",
      "Central evidence archive for release audits",
      "Risk trend analytics by team, project, ecosystem, and policy",
      "Runtime event correlation with static findings",
      "Automated pull requests for verified safe dependency updates",
    ],
  },
];

const TONES: Record<string, string> = {
  emerald: "border-emerald-300/20 bg-emerald-300/[0.055] text-emerald-100",
  cyan: "border-cyan-300/20 bg-cyan-300/[0.055] text-cyan-100",
  violet: "border-violet-300/20 bg-violet-300/[0.055] text-violet-100",
};

export default function RoadmapPage() {
  return (
    <>
      <Nav />
      <main className="min-h-screen bg-black px-4 pb-24 pt-24 sm:px-6 sm:pb-28 sm:pt-28">
        <div className="mx-auto max-w-5xl">
          <header className="mb-12">
            <p className="mb-4 text-xs font-semibold uppercase text-white/35">Roadmap</p>
            <h1 className="max-w-3xl text-4xl font-semibold leading-tight text-white md:text-6xl">
              Built foundations first. Scaling operations next.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-8 text-white/52">
              The current pass moved BreachScope from a scanner into a connected workflow for policy, evidence, triage, and integrations. The remaining roadmap is focused on production identity, connected repositories, organization workflows, and portfolio-level analytics.
            </p>
          </header>

          <div className="grid gap-3 lg:grid-cols-3">
            {PHASES.map((phase, index) => (
              <section key={phase.title} className="rounded-lg border border-white/[0.08] bg-white/[0.025] p-5">
                <div className="mb-5 flex items-center justify-between">
                  <span className={`rounded-md border px-2.5 py-1 text-xs ${TONES[phase.tone]}`}>
                    {phase.period}
                  </span>
                  <span className="text-xs text-white/25">{String(index + 1).padStart(2, "0")}</span>
                </div>
                <h2 className="text-xl font-semibold text-white">{phase.title}</h2>
                <ul className="mt-5 space-y-3">
                  {phase.items.map((item) => (
                    <li key={item} className="flex gap-3 text-sm leading-6 text-white/52">
                      <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-white/28" />
                      {item}
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>

          <div className="mt-12 rounded-lg border border-white/[0.08] bg-white/[0.03] p-6">
            <h3 className="text-lg font-semibold text-white">Need something specific?</h3>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/48">
              Open a GitHub issue with the workflow, environment, and risk outcome you need. Product requests should include an API contract, audit behavior, and verification plan.
            </p>
            <div className="mt-5 flex flex-col gap-3 sm:flex-row">
              <a
                href="https://github.com/Afnanksalal/BreachScope/issues/new"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-primary"
              >
                Open issue
              </a>
              <Link href="/docs" className="btn-ghost">
                Read docs
              </Link>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
