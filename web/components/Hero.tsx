"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

const TERMINAL_LINES = [
  { delay: 0,    text: "$ cd my-project", type: "cmd" },
  { delay: 500,  text: "$ breachscope scan --mode basic", type: "cmd" },
  { delay: 1100, text: "  Detecting tools from package.json, imports, env files…", type: "muted" },
  { delay: 1700, text: "  ✓  23 tools detected — Supabase, Vercel, Stripe, Clerk, Resend…", type: "ok" },
  { delay: 2200, text: "  ✓  OSV + OpenSSF Scorecard + npm advisories fetched", type: "ok" },
  { delay: 2700, text: "  ✓  Sub-dependency graph built  (depth 2, 847 packages)", type: "ok" },
  { delay: 3200, text: "  ✓  Static code audit complete  (1,204 files scanned)", type: "ok" },
  { delay: 3700, text: "", type: "blank" },
  { delay: 3900, text: "  ── FINDINGS ──────────────────────────────────────", type: "header" },
  { delay: 4100, text: "  CRITICAL  Supabase anon key grants write to users table", type: "critical" },
  { delay: 4300, text: "  CRITICAL  lodash@4.17.15 — CVE-2020-8203 (prototype pollution)", type: "critical" },
  { delay: 4500, text: "  HIGH      Hardcoded OpenAI key in src/lib/ai.ts:14", type: "high" },
  { delay: 4700, text: "  HIGH      Missing HSTS + X-Frame-Options headers", type: "high" },
  { delay: 4900, text: "  MEDIUM    node-ipc 10.1.1 — known supply-chain sabotage", type: "medium" },
  { delay: 5200, text: "  Completed in 6.2s  ·  18 findings  ·  2 critical", type: "summary" },
];

const TYPE_COLORS: Record<string, string> = {
  cmd:      "text-white/85",
  muted:    "text-white/40",
  ok:       "text-emerald-400",
  header:   "text-white/30 tracking-widest",
  critical: "text-red-400 font-medium",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  summary:  "text-white/55 italic",
  blank:    "",
};

export function Hero() {
  const [visibleLines, setVisibleLines] = useState<number[]>([]);

  useEffect(() => {
    const timers = TERMINAL_LINES.map((line, i) =>
      setTimeout(() => setVisibleLines((p) => [...p, i]), line.delay + 400)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-6 pt-28 pb-20 overflow-hidden bg-black">
      {/* Subtle noise grain — very faint */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.025]"
        style={{
          backgroundImage: "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      <div className="relative z-10 max-w-5xl mx-auto w-full text-center">
        {/* Eyebrow */}
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-xs font-medium text-white/40 tracking-[0.18em] uppercase mb-8"
        >
          Supply Chain &amp; Toolchain Security
        </motion.p>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          className="text-[2.75rem] md:text-[5rem] lg:text-[6rem] font-serif italic text-white leading-[0.92] tracking-tight mb-7"
        >
          Find the open doors
          <br />
          <span className="text-white/55 not-italic font-serif">before the breach.</span>
        </motion.h1>

        {/* Subheading */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.25 }}
          className="text-base md:text-lg text-white/55 max-w-xl mx-auto leading-relaxed mb-10 font-light"
        >
          One CLI that audits your stack — dependencies, source code,
          live toolchains, and endpoints. Run it from your project directory.
          No code leaves your machine.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.38 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-20"
        >
          <a href="#install" className="btn-primary">
            Get started free
          </a>
          <Link href="/docs" className="btn-ghost">
            Read the docs
          </Link>
        </motion.div>

        {/* Trust strip */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 mb-16"
        >
          {["Open source · MIT", "Node.js 18+", "No data leaves your machine", "Works in CI/CD"].map((tag) => (
            <span key={tag} className="text-xs text-white/30 flex items-center gap-2">
              <span className="w-[3px] h-[3px] rounded-full bg-white/20" />
              {tag}
            </span>
          ))}
        </motion.div>

        {/* Terminal */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, delay: 0.55, ease: [0.16, 1, 0.3, 1] }}
          className="relative mx-auto max-w-[740px] text-left"
        >
          <div className="rounded-2xl overflow-hidden border border-white/[0.08] bg-[#111]">
            {/* Title bar */}
            <div className="flex items-center gap-2 px-5 py-3 border-b border-white/[0.07] bg-[#0d0d0d]">
              <span className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <span className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <span className="w-3 h-3 rounded-full bg-[#28c840]" />
              <span className="ml-3 text-[0.7rem] text-white/25 font-mono tracking-wide">
                terminal — breachscope
              </span>
            </div>

            {/* Body */}
            <div className="p-5 font-mono text-[0.8rem] leading-[1.75] min-h-[300px]">
              {TERMINAL_LINES.map((line, i) => (
                <div
                  key={i}
                  className={`transition-opacity duration-300 ${
                    visibleLines.includes(i) ? "opacity-100" : "opacity-0"
                  } ${TYPE_COLORS[line.type] ?? "text-white/70"}`}
                >
                  {line.text || " "}
                </div>
              ))}
              {visibleLines.length < TERMINAL_LINES.length && (
                <span className="inline-block w-[6px] h-[13px] bg-white/50 cursor-blink mt-0.5" />
              )}
            </div>
          </div>
          <p className="text-center mt-4 text-[0.7rem] text-white/20 font-mono">
            cd into any project directory and run breachscope scan
          </p>
        </motion.div>
      </div>
    </section>
  );
}
