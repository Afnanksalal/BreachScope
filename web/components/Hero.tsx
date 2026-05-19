"use client";

import { motion } from "framer-motion";
import Link from "next/link";

const EVENTS: Array<[string, string, string]> = [
  ["critical", "JWT none algorithm accepted", "auth"],
  ["high", "Public preview secret exposure", "vercel"],
  ["medium", "Package missing integrity hash", "npm"],
  ["critical", "Service role key detected", "supabase"],
  ["low", "Unknown package license", "policy"],
];

const METRICS: Array<[string, string]> = [
  ["10", "ecosystems"],
  ["SARIF", "CI output"],
  ["VEX", "advisories"],
  ["SCIM", "identity"],
];

export function Hero() {
  return (
    <section className="relative min-h-[88vh] overflow-hidden bg-black px-4 pb-14 pt-24 sm:px-6 sm:pt-28">
      <div className="absolute inset-0 opacity-80">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.045)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.045)_1px,transparent_1px)] bg-[size:72px_72px]" />
        <div className="absolute inset-x-0 top-0 h-48 bg-gradient-to-b from-cyan-500/[0.08] to-transparent" />
        <div className="absolute inset-x-0 bottom-0 h-56 bg-gradient-to-t from-black to-transparent" />
      </div>

      <div className="relative mx-auto grid max-w-7xl items-center gap-12 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="max-w-2xl">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-6 inline-flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/[0.06] px-3 py-1.5"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
            <span className="text-xs font-medium text-emerald-100/75">Security workbench for modern teams</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.08, ease: [0.16, 1, 0.3, 1] }}
            className="mb-6 font-serif text-4xl font-semibold italic leading-[0.98] text-white sm:text-5xl md:text-7xl lg:text-8xl"
          >
            BreachScope
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.18 }}
            className="mb-8 max-w-xl text-base leading-7 text-white/62 sm:text-lg sm:leading-8"
          >
            Own security work from the first local scan to the release gate. BreachScope brings code, dependencies, SaaS posture, runtime evidence, triage, policy, and customer-owned integrations into one calm workflow.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.28 }}
            className="mb-10 flex flex-col gap-3 sm:flex-row"
          >
            <a href="#install" className="btn-primary">
              Start scanning
            </a>
            <Link href="/docs" className="btn-ghost">
              Read the guide
            </Link>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.38 }}
            className="grid max-w-xl grid-cols-2 gap-2 sm:grid-cols-4"
          >
            {METRICS.map(([value, label]) => (
              <div key={label} className="rounded-lg border border-white/[0.08] bg-white/[0.035] px-3 py-3">
                <p className="text-sm font-semibold text-white">{value}</p>
                <p className="mt-1 text-xs text-white/40">{label}</p>
              </div>
            ))}
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.18, ease: [0.16, 1, 0.3, 1] }}
          className="relative"
        >
          <div className="relative rounded-lg border border-white/[0.08] bg-[#050607]/92 shadow-2xl shadow-black/70">
            <div className="grid min-h-[540px] grid-cols-1 overflow-hidden rounded-lg md:grid-cols-[1fr_0.86fr]">
              <div className="border-b border-white/[0.07] p-4 sm:p-5 md:border-b-0 md:border-r">
                <div className="mb-5 flex items-center justify-between">
                  <div>
                    <p className="text-xs uppercase text-white/30">Risk operations</p>
                    <p className="mt-1 text-lg font-semibold text-white">Production portfolio</p>
                  </div>
                  <span className="rounded-md border border-cyan-300/20 bg-cyan-300/[0.08] px-2.5 py-1 text-xs text-cyan-100/80">
                    live
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-2 min-[420px]:grid-cols-3">
                  {[
                    ["0", "critical SLA"],
                    ["14", "open highs"],
                    ["98%", "policy pass"],
                  ].map(([value, label]) => (
                    <div key={label} className="rounded-lg border border-white/[0.07] bg-white/[0.035] p-3">
                      <p className="text-2xl font-semibold text-white">{value}</p>
                      <p className="mt-1 text-xs text-white/35">{label}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-5 space-y-2">
                  {EVENTS.map(([severity, title, source]) => (
                    <div key={title} className="grid grid-cols-[68px_minmax(0,1fr)] items-center gap-2 rounded-lg border border-white/[0.07] bg-black/30 px-3 py-2.5 sm:grid-cols-[78px_minmax(0,1fr)_72px] sm:gap-3">
                      <SeverityBadge severity={severity} />
                      <span className="truncate text-sm text-white/72">{title}</span>
                      <span className="hidden text-right text-xs text-white/28 sm:block">{source}</span>
                    </div>
                  ))}
                </div>

                <div className="mt-5 rounded-lg border border-white/[0.07] bg-black/35 p-4">
                  <div className="mb-4 flex items-center justify-between">
                    <p className="text-xs uppercase text-white/30">CI gate</p>
                    <span className="text-xs text-emerald-300">passing</span>
                  </div>
                  <div className="space-y-2">
                    {["SARIF uploaded", "SBOM generated", "OpenVEX exported", "Baseline enforced"].map((item) => (
                      <div key={item} className="flex items-center gap-2 text-sm text-white/55">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
                        {item}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex min-w-0 flex-col p-4 sm:p-5">
                <div className="mb-4 flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-300" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-300" />
                  <span className="ml-auto text-xs text-white/28">breachscope sandbox</span>
                </div>
                <div className="flex-1 overflow-x-auto rounded-lg border border-white/[0.07] bg-[#020303] p-4 font-mono text-xs leading-6">
                  <p className="text-white/65">$ breachscope scan --mode deep --breach --bug</p>
                  <p className="text-cyan-200/70">detecting ecosystems: npm, PyPI, Go, Maven</p>
                  <p className="text-emerald-200/70">policy loaded: release-gate.yml</p>
                  <p className="text-amber-200/70">supply-chain score: 78/100</p>
                  <p className="text-red-300/75">critical: service_role key in client bundle</p>
                  <p className="text-red-300/75">critical: exploitable JWT bypass confirmed</p>
                  <p className="text-white/35">writing results.sarif, bom.cdx.json, openvex.json</p>
                  <p className="mt-5 text-white/20">completed in 42s - 19 findings - 2 critical</p>
                </div>
                <div className="mt-4 grid grid-cols-2 gap-2">
                  {["Projects", "Policies", "Integrations", "Audit logs"].map((item) => (
                    <div key={item} className="rounded-lg border border-white/[0.07] bg-white/[0.03] px-3 py-2 text-xs text-white/45">
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: "border-red-400/25 bg-red-400/[0.08] text-red-200",
    high: "border-orange-300/25 bg-orange-300/[0.08] text-orange-200",
    medium: "border-amber-300/25 bg-amber-300/[0.08] text-amber-100",
    low: "border-cyan-300/25 bg-cyan-300/[0.08] text-cyan-100",
  };
  return (
    <span className={`rounded-md border px-2 py-1 text-center text-[0.65rem] uppercase ${styles[severity] ?? styles.low}`}>
      {severity}
    </span>
  );
}
