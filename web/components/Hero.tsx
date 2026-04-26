"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

const TERMINAL_LINES = [
  { delay: 0,    text: "$ cd my-project", type: "cmd" },
  { delay: 500,  text: "$ breachscope sandbox", type: "cmd" },
  { delay: 1000, text: "  Building Docker container (node:20-slim)…", type: "muted" },
  { delay: 1600, text: "  ✓  Container started  · AI agent initializing", type: "ok" },
  { delay: 2100, text: "  [exec]  env && id && cat /etc/passwd", type: "exec" },
  { delay: 2500, text: "  [exec]  apt-get install -y nmap sqlmap nikto 2>/dev/null", type: "exec" },
  { delay: 3000, text: "  [cred]  SECRET_KEY=sk-proj-xxxxxxxxxxx  ← exposed in env", type: "credential" },
  { delay: 3400, text: "  [http]  POST /api/admin  →  200 OK  (auth bypass)", type: "http" },
  { delay: 3800, text: "", type: "blank" },
  { delay: 4000, text: "  ── ATTACK CHAINS ─────────────────────────────────", type: "header" },
  { delay: 4200, text: "  ✗  CRITICAL  JWT alg:none accepted — auth bypass confirmed", type: "critical" },
  { delay: 4400, text: "  ✗  CRITICAL  SSTI via /render?tmpl={{7*7}}=49 (code exec)", type: "critical" },
  { delay: 4600, text: "  ✗  HIGH      SSRF — internal metadata at 169.254.169.254", type: "high" },
  { delay: 4800, text: "  ✗  HIGH      Path traversal /static/../../../etc/passwd", type: "high" },
  { delay: 5000, text: "  ✗  MEDIUM    Prototype pollution in POST /api/merge", type: "medium" },
  { delay: 5300, text: "  Completed in 48s  ·  14 findings  ·  2 critical  ·  3 chains", type: "summary" },
];

const TYPE_COLORS: Record<string, string> = {
  cmd:        "text-white/85",
  muted:      "text-white/40",
  ok:         "text-emerald-400",
  exec:       "text-cyan-400/80",
  credential: "text-amber-300 font-medium",
  http:       "text-sky-400/80",
  header:     "text-white/30 tracking-widest",
  critical:   "text-red-400 font-medium",
  high:       "text-orange-400",
  medium:     "text-yellow-400",
  summary:    "text-white/55 italic",
  blank:      "",
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
          One CLI that spins up a Docker attack arena, runs an AI agent as root,
          audits your stack, and hunts vulnerabilities autonomously.
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
          {["Open source · MIT", "Node.js 18+", "10 languages", "AI by default", "Works in CI/CD"].map((tag) => (
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
            cd into any project directory and run breachscope sandbox
          </p>
        </motion.div>
      </div>
    </section>
  );
}
