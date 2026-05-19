"use client";

import { motion } from "framer-motion";

const STATS = [
  { value: "10", label: "package ecosystems", sub: "OSV-aware scanning" },
  { value: "4", label: "governance exports", sub: "SARIF, SBOM, VEX, JSON" },
  { value: "5", label: "notification targets", sub: "Slack, Teams, PagerDuty, Jira, Linear" },
  { value: "0", label: "audit vulnerabilities", sub: "npm moderate+" },
];

const WORKFLOWS = [
  {
    title: "Pull request gate",
    owner: "AppSec",
    detail: "Run breachscope scan --ci --policy release-gate.yml and upload SARIF to code scanning.",
    checks: ["severity budget", "new findings only", "baseline diff"],
  },
  {
    title: "Release evidence",
    owner: "Platform",
    detail: "Generate CycloneDX, SPDX, OpenVEX, and a fix-suggestion brief from the same JSON scan artifact.",
    checks: ["SBOM", "OpenVEX", "fix plan"],
  },
  {
    title: "Incident routing",
    owner: "Security operations",
    detail: "Send critical findings to PagerDuty and engineering work queues while preserving audit history per project.",
    checks: ["PagerDuty", "Jira", "audit logs"],
  },
];

export function SocialProof() {
  return (
    <section id="workflow" className="relative border-y border-white/[0.06] bg-black px-4 py-20 sm:px-6 sm:py-24">
      <div className="mx-auto max-w-7xl">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55 }}
          className="mb-14 grid gap-3 rounded-lg border border-white/[0.075] bg-white/[0.025] p-2 md:grid-cols-4"
        >
          {STATS.map((stat) => (
            <div key={stat.label} className="rounded-md bg-black/30 px-5 py-6">
              <p className="text-3xl font-semibold text-white">{stat.value}</p>
              <p className="mt-2 text-sm font-medium text-white/62">{stat.label}</p>
              <p className="mt-1 text-xs text-white/32">{stat.sub}</p>
            </div>
          ))}
        </motion.div>

        <div className="mb-10 flex flex-col justify-between gap-5 md:flex-row md:items-end">
          <div>
            <p className="mb-3 text-xs font-semibold uppercase text-white/35">Operational fit</p>
            <h2 className="max-w-2xl text-4xl font-semibold leading-tight text-white md:text-5xl">
              Designed for the workflows security teams already run.
            </h2>
          </div>
          <p className="max-w-md text-sm leading-6 text-white/50">
            Local developer scans, CI enforcement, release evidence, ticket routing, and audit-ready triage all share the same finding model.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {WORKFLOWS.map((workflow, index) => (
            <motion.article
              key={workflow.title}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45, delay: index * 0.06 }}
              className="rounded-lg border border-white/[0.075] bg-[#050606] p-5"
            >
              <div className="mb-5 flex items-center justify-between">
                <span className="rounded-md border border-white/[0.08] bg-white/[0.035] px-2.5 py-1 text-xs text-white/42">
                  {workflow.owner}
                </span>
                <span className="text-xs text-white/25">{String(index + 1).padStart(2, "0")}</span>
              </div>
              <h3 className="text-lg font-semibold text-white">{workflow.title}</h3>
              <p className="mt-3 min-h-[5.25rem] text-sm leading-6 text-white/50">{workflow.detail}</p>
              <div className="mt-5 flex flex-wrap gap-1.5">
                {workflow.checks.map((check) => (
                  <span key={check} className="rounded-md border border-emerald-300/15 bg-emerald-300/[0.055] px-2 py-1 text-xs text-emerald-100/70">
                    {check}
                  </span>
                ))}
              </div>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
