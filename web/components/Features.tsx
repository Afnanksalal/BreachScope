"use client";

import { motion } from "framer-motion";

const FEATURES = [
  {
    num: "01",
    title: "Supply Chain Scanner",
    description:
      "Audits your dependency graph and lockfiles against known-compromised packages, insecure registries, wildcard versions, and missing integrity hashes.",
    tags: ["npm", "yarn", "pnpm", "bun"],
    icon: ChainIcon,
    accent: "breach",
  },
  {
    num: "02",
    title: "Toolchain Breach Detector",
    description:
      "Probes live toolchain APIs — Supabase RLS misconfigs, exposed storage, Vercel preview secrets, GitHub unprotected branches, overprivileged tokens.",
    tags: ["Supabase", "Vercel", "GitHub"],
    icon: ToolIcon,
    accent: "breach",
  },
  {
    num: "03",
    title: "Static Code Audit",
    description:
      "Scans source files for hardcoded secrets, eval() abuse, SQL injection, weak crypto, prototype pollution, path traversal, and insecure deserialization.",
    tags: ["TypeScript", "Python", "Go", "Rust"],
    icon: CodeIcon,
    accent: "breach",
  },
  {
    num: "04",
    title: "Blackbox Probing",
    description:
      "Fires adversarial requests at your live URL — checks security headers, CORS misconfigs, exposed paths like /.env and /.git, HTTP method abuse.",
    tags: ["Headers", "CORS", "Exposure"],
    icon: RadarIcon,
    accent: "scope",
  },
  {
    num: "05",
    title: "Smoke Testing",
    description:
      "Verifies app hygiene — error message leakage, payload size abuse, unauthenticated admin route access, and internal state exposure in responses.",
    tags: ["Auth bypass", "Error leakage"],
    icon: SmokeIcon,
    accent: "scope",
  },
  {
    num: "06",
    title: "CI-Ready Reports",
    description:
      "Console tables, JSON, or SARIF output. Fail CI on severity thresholds. Pipe into GitHub Advanced Security, Defect Dojo, or any SAST pipeline.",
    tags: ["SARIF", "JSON", "GitHub Actions"],
    icon: ChartIcon,
    accent: "breach",
  },
];

const ACCENT_STYLES = {
  breach: {
    num: "text-white/25",
    tag: "border-white/[0.08] text-white/45 bg-white/[0.03]",
    icon: "text-white/60",
    iconBg: "bg-white/[0.05]",
  },
  scope: {
    num: "text-white/25",
    tag: "border-white/[0.08] text-white/45 bg-white/[0.03]",
    icon: "text-white/60",
    iconBg: "bg-white/[0.05]",
  },
};

export function Features() {
  return (
    <section id="features" className="relative py-36 px-6">
      {/* Top separator */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />

      <div className="max-w-6xl mx-auto">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="text-center mb-20"
        >
          <p className="text-xs font-medium text-white/40 tracking-[0.18em] uppercase mb-5">
            What BreachScope catches
          </p>
          <h2 className="text-4xl md:text-[3.25rem] font-serif italic text-white tracking-tight mb-5 leading-[1.05]">
            Six scanners, one command.
          </h2>
          <p className="text-white/55 text-lg max-w-lg mx-auto font-light leading-relaxed">
            Every attack surface in your stack — from package.json to production infra.
          </p>
        </motion.div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((feature, i) => {
            const a = ACCENT_STYLES[feature.accent as keyof typeof ACCENT_STYLES];
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.55, delay: i * 0.07 }}
                className="card-hover group relative p-6 rounded-2xl border border-white/[0.07] bg-white/[0.02]"
              >
                <div className="flex items-start justify-between mb-5">
                  <div className={`w-10 h-10 rounded-xl ${a.iconBg} flex items-center justify-center`}>
                    <Icon className={`w-5 h-5 ${a.icon}`} />
                  </div>
                  <span className={`font-mono text-xs font-bold ${a.num} tracking-widest`}>
                    {feature.num}
                  </span>
                </div>

                <h3 className="text-white font-semibold text-[0.9375rem] mb-2 tracking-tight">
                  {feature.title}
                </h3>
                <p className="text-white/55 text-sm leading-relaxed mb-5">
                  {feature.description}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {feature.tags.map((tag) => (
                    <span
                      key={tag}
                      className={`px-2.5 py-0.5 rounded-full text-[0.7rem] border ${a.tag}`}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

// ─── SVG Icons ─────────────────────────────────────────────────────────────────

function ChainIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
    </svg>
  );
}

function ToolIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26m-1.745 1.437l1.745-1.437m6.615 8.206L15.75 15.75M4.867 19.125h.008v.008h-.008v-.008z" />
    </svg>
  );
}

function CodeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  );
}

function RadarIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 6.75V15m6-6v8.25m.503 3.498l4.875-2.437c.381-.19.622-.58.622-1.006V4.82c0-.836-.88-1.38-1.628-1.006l-3.869 1.934c-.317.159-.69.159-1.006 0L9.503 3.252a1.125 1.125 0 00-1.006 0L3.622 5.689C3.24 5.88 3 6.27 3 6.695V19.18c0 .836.88 1.38 1.628 1.006l3.869-1.934c.317-.159.69-.159 1.006 0l4.994 2.497c.317.158.69.158 1.006 0z" />
    </svg>
  );
}

function SmokeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function ChartIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  );
}
