"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

type PM = "npm" | "pnpm" | "yarn" | "bun";

const INSTALL: Record<PM, string> = {
  npm:  "npm install -g breachscope",
  pnpm: "pnpm add -g breachscope",
  yarn: "yarn global add breachscope",
  bun:  "bun add -g breachscope",
};

const STEPS = [
  {
    step: "01",
    label: "Install globally",
    cmd: "npm install -g breachscope",
    sub: "or pnpm · yarn · bun",
  },
  {
    step: "02",
    label: "Connect your dashboard (optional)",
    cmd: "breachscope login",
    sub: "opens browser · device-flow OAuth · stores token securely",
  },
  {
    step: "03",
    label: "Run a scan from inside your project",
    cmd: "cd my-project && breachscope scan",
    sub: "reads package.json, imports, env files — nothing is uploaded",
  },
];

export function Install() {
  const [pm, setPm] = useState<PM>("npm");
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(INSTALL[pm]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="install" className="relative py-36 px-6">
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />

      {/* Subtle gradient to distinguish section */}
      <div className="absolute inset-0 bg-[#0a0a0a] pointer-events-none" />

      <div className="max-w-3xl mx-auto relative">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="text-center mb-16"
        >
          <p className="text-xs font-medium text-white/40 tracking-[0.18em] uppercase mb-5">
            Get started
          </p>
          <h2 className="text-4xl md:text-[3.25rem] font-serif italic text-white tracking-tight mb-5 leading-[1.05]">
            Running in thirty seconds.
          </h2>
          <p className="text-white/50 text-base font-light">
            Node.js 18+ · macOS · Linux · Windows
          </p>
        </motion.div>

        {/* PM tabs */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="flex gap-1 p-1 rounded-xl bg-white/[0.04] border border-white/[0.06] w-fit mx-auto mb-4"
        >
          {(Object.keys(INSTALL) as PM[]).map((p) => (
            <button
              key={p}
              onClick={() => setPm(p)}
              className={`px-4 py-2 rounded-lg text-[0.8125rem] font-mono font-medium transition-all duration-200 ${
                pm === p
                  ? "bg-white/10 text-white border border-white/10"
                  : "text-white/40 hover:text-white/70"
              }`}
            >
              {p}
            </button>
          ))}
        </motion.div>

        {/* Install command block */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="relative mb-16"
        >
          <div className="relative flex items-center justify-between p-5 rounded-2xl border border-white/[0.08] bg-[#0d0d0d] font-mono text-[0.9rem]">
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-white/40 shrink-0">$</span>
              <span className="text-white/75 truncate">{INSTALL[pm]}</span>
            </div>
            <button
              onClick={copy}
              className={`ml-4 shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 ${
                copied
                  ? "bg-green-500/15 text-green-400 border border-green-500/20"
                  : "bg-white/5 border border-white/10 text-white/40 hover:text-white/75 hover:border-white/20"
              }`}
            >
              {copied ? (
                <>
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                  </svg>
                  Copied
                </>
              ) : (
                <>
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
                  </svg>
                  Copy
                </>
              )}
            </button>
          </div>
        </motion.div>

        {/* Steps */}
        <div className="space-y-3 mb-16">
          {STEPS.map((step, i) => (
            <motion.div
              key={step.step}
              initial={{ opacity: 0, x: -12 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.09 }}
              className="flex items-start gap-5 p-5 rounded-2xl border border-white/[0.05] bg-surface-50/40 hover:border-white/[0.1] transition-colors"
            >
              <span className="text-white/25 font-mono text-xs font-bold tracking-widest shrink-0 mt-0.5">
                {step.step}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-white/70 text-sm font-medium mb-2">{step.label}</p>
                <code className="block text-xs font-mono text-white/70 bg-black/60 px-3.5 py-2.5 rounded-xl border border-white/[0.06] break-all">
                  {step.cmd}
                </code>
                <p className="text-white/40 text-xs mt-2 font-mono">{step.sub}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Dashboard CTA */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-8 text-center"
        >
          <p className="text-white font-semibold text-lg mb-2">Want a dashboard?</p>
          <p className="text-white/55 text-sm mb-6 max-w-sm mx-auto leading-relaxed">
            Sign in to track scan history, manage API keys, and store encrypted AI credentials.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/dashboard" className="btn-primary text-sm">
              Open Dashboard
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </Link>
            <span className="text-white/40 text-xs">Free · No credit card required</span>
          </div>
        </motion.div>

        {/* npx option */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="text-center text-white/40 text-sm mt-10 font-light"
        >
          Run without installing:{" "}
          <code className="font-mono text-white/35">npx breachscope scan</code>
        </motion.p>
      </div>
    </section>
  );
}
