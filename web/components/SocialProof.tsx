"use client";

import { motion } from "framer-motion";

const STATS = [
  { value: "6",     label: "Scan types",         sub: "in one CLI" },
  { value: "80+",   label: "Known tools",         sub: "auto-classified" },
  { value: "3",     label: "Scan depths",         sub: "basic · major · deep" },
  { value: "SARIF", label: "Compatible output",   sub: "GitHub Advanced Security" },
];

const BREACH_CASES = [
  {
    name: "ua-parser-js Hijack",
    year: "2021",
    vector: "Compromised npm maintainer account",
    summary:
      "Attacker stole maintainer credentials and published malicious versions containing a crypto miner and credential stealer. 8M weekly downloads affected. React, Angular, and hundreds of enterprise apps pulled the poisoned build.",
    catch: "breachscope deps — flags ua-parser-js as a known-hijacked package with severity CRITICAL in your transitive dependency tree",
    severity: "CRITICAL",
  },
  {
    name: "node-ipc Sabotage",
    year: "2022",
    vector: "Intentional maintainer sabotage",
    summary:
      "Legitimate maintainer deliberately shipped code that overwrote files on machines with Russian or Belarusian IPs. Used in vue-cli, the payload ran silently in CI pipelines of thousands of projects worldwide.",
    catch: "breachscope deps — flags node-ipc as a critical supply chain risk with documented incident history and remediation steps",
    severity: "HIGH",
  },
  {
    name: "polyfill.io CDN Hijack",
    year: "2024",
    vector: "Domain acquisition → CDN poisoning",
    summary:
      "The polyfill.io domain was sold to a Chinese company who began serving malicious JavaScript from the same CDN URL. 100,000+ websites were silently redirecting mobile users to scam and gambling sites. JSTOR, Intuit, and the World Economic Forum were affected.",
    catch: "breachscope code — detects polyfill.io CDN script references in source and flags the domain as a known supply chain risk",
    severity: "CRITICAL",
  },
  {
    name: "XZ Utils Backdoor",
    year: "2024",
    vector: "Multi-year social engineering + build system compromise",
    summary:
      "A fabricated open-source persona spent 2 years building trust, then injected a backdoor into xz-utils that hooked OpenSSH's RSA decrypt. Would have given silent remote access to any internet-facing Linux server running a systemd-linked sshd. Reached Debian, Fedora, and Kali before discovery.",
    catch: "breachscope scorecard — OpenSSF Scorecard detects compromised maintainer patterns and unusual commit behavior; OSV integration flags CVE-2024-3094",
    severity: "CRITICAL",
  },
];

const SEV_STYLES = {
  CRITICAL: "bg-red-500/8 text-red-400 border-red-500/15",
  HIGH:     "bg-orange-500/8 text-orange-400 border-orange-500/15",
};

export function SocialProof() {
  return (
    <section className="relative py-28 px-6 bg-[#060606]">
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/[0.05] to-transparent" />
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/[0.05] to-transparent" />

      <div className="max-w-6xl mx-auto">
        {/* Stats strip */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-px bg-white/[0.05] rounded-2xl overflow-hidden border border-white/[0.07] mb-28"
        >
          {STATS.map((stat) => (
            <div key={stat.label} className="text-center py-10 px-6 bg-[#060606] hover:bg-white/[0.02] transition-colors">
              <p className="text-4xl md:text-5xl font-serif italic text-white mb-1.5">{stat.value}</p>
              <p className="text-white/60 text-sm font-medium">{stat.label}</p>
              <p className="text-white/35 text-xs mt-0.5">{stat.sub}</p>
            </div>
          ))}
        </motion.div>

        {/* Breach cases */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="text-center mb-14"
        >
          <p className="text-xs font-medium text-white/40 tracking-[0.18em] uppercase mb-5">
            Real-world incidents
          </p>
          <h2 className="text-4xl md:text-[3.25rem] font-serif italic text-white tracking-tight leading-[1.05]">
            Built for the attacks
            <br />
            that already happened.
          </h2>
        </motion.div>

        <div className="space-y-3">
          {BREACH_CASES.map((c, i) => {
            const sevStyle = SEV_STYLES[c.severity as keyof typeof SEV_STYLES] ?? SEV_STYLES.HIGH;
            return (
              <motion.div
                key={c.name}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.55, delay: i * 0.08 }}
                className="card-hover group p-6 rounded-2xl border border-white/[0.07] bg-white/[0.02]"
              >
                <div className="flex flex-col md:flex-row md:items-start gap-6">
                  <div className="md:w-64 shrink-0">
                    <div className="flex items-center gap-2.5 mb-2">
                      <span className={`px-2 py-0.5 rounded-md text-[0.7rem] font-semibold border ${sevStyle}`}>
                        {c.severity}
                      </span>
                      <span className="text-white/35 text-xs">{c.year}</span>
                    </div>
                    <p className="text-white font-semibold text-[0.9375rem] mb-1">{c.name}</p>
                    <p className="text-white/40 text-xs font-mono">{c.vector}</p>
                  </div>

                  <div className="flex-1">
                    <p className="text-white/55 text-sm leading-relaxed mb-4">{c.summary}</p>
                    <div className="inline-flex items-start gap-2 bg-white/[0.03] border border-white/[0.07] rounded-lg px-3.5 py-2.5">
                      <span className="text-white/50 text-xs font-semibold shrink-0 mt-px">CATCHES IT</span>
                      <span className="text-white/45 text-xs font-mono leading-relaxed">{c.catch}</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Scan mode callout */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-3"
        >
          {[
            { flag: "--scan-mode breach", title: "Breach mode", desc: "CVE scanning, supply chain research, SaaS toolchain API checks." },
            { flag: "--scan-mode bug",    title: "Bug mode",    desc: "Static code audit, blackbox probing, pre-deploy hardening." },
            { flag: "(default: all)",     title: "Full mode",   desc: "Every scanner, every surface. The complete picture." },
          ].map(({ flag, title, desc }) => (
            <div key={flag} className="p-5 rounded-2xl border border-white/[0.07] bg-white/[0.02]">
              <code className="text-white/35 text-xs font-mono mb-2 block">{flag}</code>
              <p className="text-white/75 text-sm font-medium mb-1.5">{title}</p>
              <p className="text-white/50 text-xs leading-relaxed">{desc}</p>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
