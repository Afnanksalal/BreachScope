"use client";

import { motion } from "framer-motion";
import { FileCheck2, KeyRound, LockKeyhole, Route, ScanLine, ShieldCheck } from "lucide-react";

const PRINCIPLES = [
  {
    title: "Local-first scans",
    body: "Developers can scan without connecting a dashboard. Login adds scan history, triage, policies, and evidence workflows.",
    icon: ScanLine,
  },
  {
    title: "Bring your own providers",
    body: "Teams connect their own GitHub, Slack, Jira, Linear, PagerDuty, OpenAI, Firecrawl, and cloud accounts when they need them.",
    icon: KeyRound,
  },
  {
    title: "Private by default",
    body: "Robots can read public docs and legal pages. Dashboard, API, login, and CLI auth routes stay private and crawler-blocked.",
    icon: LockKeyhole,
  },
  {
    title: "Evidence you can move",
    body: "SARIF, CycloneDX, SPDX, OpenVEX, JSON, and fix briefs keep release reviews portable across existing systems.",
    icon: FileCheck2,
  },
];

export function TrustModel() {
  return (
    <section className="relative overflow-hidden border-t border-white/[0.06] bg-black px-4 py-20 sm:px-6 sm:py-28">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)] bg-[size:88px_88px] opacity-45" />
      <div className="relative mx-auto max-w-7xl">
        <div className="mb-12 grid gap-6 lg:grid-cols-[0.78fr_1.22fr]">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.55 }}
          >
            <p className="mb-4 text-xs font-semibold uppercase text-white/35">Operating model</p>
            <h2 className="max-w-xl text-4xl font-semibold leading-tight text-white md:text-5xl">
              A security workflow that fits around your stack.
            </h2>
          </motion.div>
          <motion.p
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.55, delay: 0.08 }}
            className="max-w-2xl text-base leading-8 text-white/55"
          >
            BreachScope provides the scan engine, dashboard, policy layer, evidence exports, and routing framework. Your team decides which providers to connect, which keys to save, and which findings leave the platform.
          </motion.p>
        </div>

        <div className="grid gap-3 lg:grid-cols-[1.05fr_0.95fr]">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.55 }}
            className="rounded-lg border border-white/[0.08] bg-white/[0.025] p-5"
          >
            <div className="mb-5 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-300/20 bg-emerald-300/[0.055] text-emerald-100">
                <Route className="h-5 w-5" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-white">From scan to owner</h3>
                <p className="text-xs text-white/35">One finding model across CLI, CI, dashboard, and integrations.</p>
              </div>
            </div>
            <div className="grid gap-2 sm:grid-cols-4">
              {["Scan", "Policy", "Evidence", "Route"].map((step, index) => (
                <div key={step} className="rounded-lg border border-white/[0.07] bg-black/35 p-4">
                  <p className="text-xs text-white/28">{String(index + 1).padStart(2, "0")}</p>
                  <p className="mt-5 text-sm font-semibold text-white">{step}</p>
                  <div className="mt-4 h-1 rounded-full bg-white/[0.08]">
                    <div className="h-full rounded-full bg-emerald-300/70" style={{ width: `${55 + index * 13}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.55, delay: 0.08 }}
            className="rounded-lg border border-white/[0.08] bg-[#050606] p-5"
          >
            <div className="mb-5 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/[0.055] text-cyan-100">
                <ShieldCheck className="h-5 w-5" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-white">Data boundary</h3>
                <p className="text-xs text-white/35">Public pages stay public. Work data stays behind auth.</p>
              </div>
            </div>
            <div className="space-y-2">
              {["Public docs and policies", "Private dashboard routes", "Scoped API keys", "Encrypted provider keys"].map((item) => (
                <div key={item} className="flex items-center justify-between rounded-lg border border-white/[0.07] bg-white/[0.025] px-4 py-3">
                  <span className="text-sm text-white/62">{item}</span>
                  <span className="rounded-md border border-white/[0.08] bg-black/35 px-2 py-1 text-xs text-white/34">defined</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {PRINCIPLES.map((item, index) => {
            const Icon = item.icon;
            return (
              <motion.article
                key={item.title}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: index * 0.05 }}
                className="rounded-lg border border-white/[0.075] bg-white/[0.025] p-5"
              >
                <Icon className="h-5 w-5 text-white/70" />
                <h3 className="mt-5 text-base font-semibold text-white">{item.title}</h3>
                <p className="mt-3 text-sm leading-6 text-white/48">{item.body}</p>
              </motion.article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
