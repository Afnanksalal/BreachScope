"use client";

import { motion } from "framer-motion";
import {
  Activity,
  Boxes,
  Braces,
  FileJson,
  Fingerprint,
  GitBranch,
  KeyRound,
  ShieldCheck,
  Workflow,
} from "lucide-react";

const FEATURES = [
  {
    title: "Policy-as-code gates",
    description: "Fail pull requests on severity thresholds, finding budgets, blocked packages, denied categories, and expiring suppressions.",
    tags: ["baselines", "budgets", "approvals"],
    icon: ShieldCheck,
    tone: "emerald",
  },
  {
    title: "Supply-chain intelligence",
    description: "OSV matching across ten ecosystems plus OpenSSF, deps.dev, maintainer concentration, deprecation, license, and lifecycle-script risk signals.",
    tags: ["OSV", "OpenSSF", "deps.dev"],
    icon: GitBranch,
    tone: "cyan",
  },
  {
    title: "Evidence exports",
    description: "Export SARIF for code scanning, CycloneDX or SPDX SBOMs, OpenVEX advisories, JSON evidence, and fix-suggestion briefs.",
    tags: ["SARIF", "SBOM", "OpenVEX"],
    icon: FileJson,
    tone: "amber",
  },
  {
    title: "Scoped automation",
    description: "Dashboard API keys support least-privilege scopes for scan upload, config read, secret read, and settings write workflows.",
    tags: ["scopes", "audit", "CI"],
    icon: KeyRound,
    tone: "violet",
  },
  {
    title: "Attack arena",
    description: "The sandbox command builds an isolated container, hardens Docker flags, and runs active exploit probes with CI failure support.",
    tags: ["Docker", "Tracee", "sandbox"],
    icon: Boxes,
    tone: "red",
  },
  {
    title: "Runtime monitoring",
    description: "Linux environments can stream Tracee eBPF events into JSONL for investigation alongside static and dynamic findings.",
    tags: ["eBPF", "Tracee", "JSONL"],
    icon: Activity,
    tone: "cyan",
  },
  {
    title: "Identity and audit",
    description: "SCIM user lifecycle endpoints, SAML metadata, IdP-ready ACS fail-closed behavior, and project-level audit logs are in the platform.",
    tags: ["SCIM", "SAML", "audit logs"],
    icon: Fingerprint,
    tone: "emerald",
  },
  {
    title: "Customer-owned integrations",
    description: "Bring your own Slack, Teams, PagerDuty, Jira, Linear, and webhook credentials. BreachScope supplies routing, testing, and audit history.",
    tags: ["Slack", "Jira", "PagerDuty"],
    icon: Workflow,
    tone: "amber",
  },
  {
    title: "Multi-language context",
    description: "Dependency, code, and project context collection understands JavaScript, Python, Go, Rust, Ruby, Java, PHP, .NET, Elixir, and Dart.",
    tags: ["10 ecosystems", "project context", "lockfiles"],
    icon: Braces,
    tone: "violet",
  },
];

const TONES: Record<string, string> = {
  emerald: "border-emerald-300/20 bg-emerald-300/[0.055] text-emerald-100",
  cyan: "border-cyan-300/20 bg-cyan-300/[0.055] text-cyan-100",
  amber: "border-amber-300/20 bg-amber-300/[0.055] text-amber-100",
  red: "border-red-300/20 bg-red-300/[0.055] text-red-100",
  violet: "border-violet-300/20 bg-violet-300/[0.055] text-violet-100",
};

export function Features() {
  return (
    <section id="features" className="relative border-t border-white/[0.06] bg-[#030404] px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto max-w-7xl">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55 }}
          className="mb-12 grid gap-6 lg:grid-cols-[0.8fr_1.2fr]"
        >
          <div>
            <p className="mb-4 text-xs font-semibold uppercase text-white/35">Platform coverage</p>
            <h2 className="max-w-lg text-4xl font-semibold leading-tight text-white md:text-5xl">
              Built like a security program, not a single scanner.
            </h2>
          </div>
          <p className="max-w-2xl text-base leading-8 text-white/55">
            BreachScope covers prevention, detection, triage, evidence export, identity, runtime monitoring, and CI enforcement. The CLI stays fast for local use, while the dashboard keeps teams aligned around ownership, policy, and audit history.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {FEATURES.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.article
                key={feature.title}
                initial={{ opacity: 0, y: 18 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: index * 0.035 }}
                className="rounded-lg border border-white/[0.075] bg-white/[0.025] p-5 transition-colors hover:border-white/[0.16] hover:bg-white/[0.045]"
              >
                <div className="mb-5 flex items-center justify-between">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${TONES[feature.tone]}`}>
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <span className="text-xs text-white/25">{String(index + 1).padStart(2, "0")}</span>
                </div>
                <h3 className="mb-2 text-base font-semibold text-white">{feature.title}</h3>
                <p className="min-h-[4.5rem] text-sm leading-6 text-white/52">{feature.description}</p>
                <div className="mt-5 flex flex-wrap gap-1.5">
                  {feature.tags.map((tag) => (
                    <span key={tag} className="rounded-md border border-white/[0.08] bg-black/25 px-2 py-1 text-xs text-white/38">
                      {tag}
                    </span>
                  ))}
                </div>
              </motion.article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
