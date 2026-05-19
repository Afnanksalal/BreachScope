"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { Check, Clipboard, Terminal } from "lucide-react";

type PM = "npm" | "pnpm" | "yarn" | "bun";

const INSTALL: Record<PM, string> = {
  npm: "npm install -g breachscope",
  pnpm: "pnpm add -g breachscope",
  yarn: "yarn global add breachscope",
  bun: "bun add -g breachscope",
};

const STEPS = [
  ["1", "Install the CLI", "npm install -g breachscope"],
  ["2", "Authenticate once", "breachscope login"],
  ["3", "Run a release gate", "breachscope scan --ci --policy release-gate.yml --output sarif --file breachscope.sarif"],
  ["4", "Export release evidence", "breachscope sbom --output cyclonedx --file bom.cdx.json"],
];

export function Install() {
  const [pm, setPm] = useState<PM>("npm");
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(INSTALL[pm]);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <section id="install" className="relative bg-[#030404] px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto grid max-w-7xl gap-10 lg:grid-cols-[0.85fr_1.15fr]">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55 }}
        >
          <p className="mb-4 text-xs font-semibold uppercase text-white/35">Deploy the workflow</p>
          <h2 className="max-w-xl text-4xl font-semibold leading-tight text-white md:text-5xl">
            Ship security checks without changing how developers work.
          </h2>
          <p className="mt-5 max-w-lg text-base leading-8 text-white/55">
            Install the CLI, connect it to the dashboard, and use generated CI workflows to enforce policy, export artifacts, and route findings with your own provider accounts.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Link href="/dashboard" className="btn-primary">
              Open dashboard
            </Link>
            <Link href="/docs" className="btn-ghost">
              Read setup guide
            </Link>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55, delay: 0.08 }}
          className="rounded-lg border border-white/[0.08] bg-black/45 p-5"
        >
          <div className="mb-4 flex flex-wrap gap-1 rounded-lg border border-white/[0.07] bg-white/[0.025] p-1">
            {(Object.keys(INSTALL) as PM[]).map((item) => (
              <button
                key={item}
                onClick={() => setPm(item)}
                className={`rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  pm === item ? "bg-white text-black" : "text-white/45 hover:bg-white/[0.06] hover:text-white"
                }`}
              >
                {item}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-white/[0.08] bg-[#050606] px-4 py-4">
            <Terminal className="h-4 w-4 text-cyan-100/70" aria-hidden="true" />
            <code className="min-w-0 flex-1 truncate font-mono text-sm text-white/78">{INSTALL[pm]}</code>
            <button
              onClick={copy}
              className="inline-flex h-8 items-center gap-2 rounded-md border border-white/[0.1] bg-white/[0.04] px-3 text-xs font-medium text-white/60 hover:bg-white/[0.08] hover:text-white"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Clipboard className="h-3.5 w-3.5" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          <div className="mt-5 space-y-2">
            {STEPS.map(([number, title, command]) => (
              <div key={title} className="grid gap-3 rounded-lg border border-white/[0.07] bg-white/[0.025] p-4 min-[420px]:grid-cols-[34px_1fr]">
                <span className="flex h-7 w-7 items-center justify-center rounded-md border border-white/[0.08] bg-black/30 text-xs text-white/35">
                  {number}
                </span>
                <div className="min-w-0">
                  <p className="mb-2 text-sm font-medium text-white/72">{title}</p>
                  <code className="block break-all rounded-md bg-black/45 px-3 py-2 font-mono text-xs text-white/48">
                    {command}
                  </code>
                </div>
              </div>
            ))}
          </div>

          <p className="mt-5 text-sm text-white/38">
            For zero-install scans, run <code className="font-mono text-white/60">npx breachscope scan</code>. Docker is required only for sandbox attack runs.
          </p>
        </motion.div>
      </div>
    </section>
  );
}
