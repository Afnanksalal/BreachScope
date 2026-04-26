"use client";

import { useState, useEffect } from "react";
import { TopBar } from "@/components/dashboard/TopBar";
import { motion } from "framer-motion";
import { clsx } from "clsx";

import type { SettingsResponse as Settings } from "@/app/api/settings/route";

const MODE_OPTIONS = [
  { value: "basic", label: "Basic", desc: "Direct dependencies only — fastest" },
  { value: "major", label: "Major", desc: "2-level deep sub-dependency graph" },
  { value: "deep",  label: "Deep",  desc: "Full recursive traversal — thorough" },
];

const SCAN_MODE_OPTIONS = [
  { value: "all",    label: "All",    desc: "CVE + code audit + blackbox testing" },
  { value: "breach", label: "Breach", desc: "Supply chain & CVE focus" },
  { value: "bug",    label: "Bug",    desc: "Code audit & vulnerability testing" },
];

const SANDBOX_SCAN_MODE_OPTIONS = [
  { value: "all",    label: "All",    desc: "Full analysis: CVE, code, blackbox" },
  { value: "breach", label: "Breach", desc: "Focus on supply chain & credential risk" },
  { value: "bug",    label: "Bug",    desc: "Focus on exploitable code vulns" },
];

const SANDBOX_DEPTH_OPTIONS = [
  { value: "normal", label: "Normal", desc: "80 attack iterations — balanced coverage" },
  { value: "deep",   label: "Deep",   desc: "120 attack iterations — exhaustive" },
];

function FieldRow({
  label,
  hint,
  type = "text",
  value,
  onChange,
  placeholder,
  isSet,
  saving,
}: {
  label: string;
  hint: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  isSet: boolean;
  saving: boolean;
}) {
  return (
    <div className="py-5 border-b border-white/[0.06] last:border-0">
      <div className="flex items-start justify-between gap-8">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <p className="text-white/80 text-sm font-medium">{label}</p>
            {isSet && (
              <span className="px-2 py-0.5 rounded-full text-xs bg-green-500/10 text-green-400 border border-green-500/20">
                Configured
              </span>
            )}
          </div>
          <p className="text-white/30 text-xs">{hint}</p>
        </div>
        <div className="w-80 shrink-0">
          <input
            type={type}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={isSet ? "••••••••••••••• (leave blank to keep)" : placeholder}
            disabled={saving}
            className="w-full bg-black/40 border border-white/[0.08] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-white/20 focus:outline-none focus:border-white/20 transition-colors font-mono disabled:opacity-50"
          />
        </div>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [openAiKey, setOpenAiKey] = useState("");
  const [firecrawlKey, setFirecrawlKey] = useState("");
  const [defaultMode, setDefaultMode] = useState("basic");
  const [defaultScanMode, setDefaultScanMode] = useState("all");
  const [sandboxScanMode, setSandboxScanMode] = useState("all");
  const [sandboxDeep, setSandboxDeep] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data: Settings) => {
        setSettings(data);
        setDefaultMode(data.defaultMode ?? "basic");
        setDefaultScanMode(data.defaultScanMode ?? "all");
        setSandboxScanMode(data.sandboxScanMode ?? "all");
        setSandboxDeep(data.sandboxDeep ?? false);
      });
  }, []);

  async function handleSave() {
    setSaving(true);
    const body: Record<string, string | boolean> = {
      defaultMode,
      defaultScanMode,
      sandboxScanMode,
      sandboxDeep,
    };
    if (openAiKey) body.openaiKey = openAiKey;
    if (firecrawlKey) body.firecrawlKey = firecrawlKey;

    const res = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      const data = await res.json();
      setSettings(data);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    }
    setSaving(false);
  }

  return (
    <>
      <TopBar title="Settings" subtitle="Configure scan defaults and integrations" />

      <div className="flex-1 p-8 space-y-8 max-w-4xl">
        {/* AI Integrations */}
        <section>
          <div className="mb-4">
            <h2 className="text-white font-semibold text-sm">AI Integrations</h2>
            <p className="text-white/30 text-xs mt-0.5">
              Keys are encrypted with AES-256-GCM before storage and fetched by the CLI at scan time.
            </p>
          </div>
          <div className="rounded-2xl bg-white/[0.04] px-5 divide-y divide-white/[0.05]">
            <FieldRow
              label="OpenAI API Key"
              hint="Used for GPT-4o analysis across all agents. Required for AI-powered scanning."
              type="password"
              value={openAiKey}
              onChange={setOpenAiKey}
              placeholder="sk-..."
              isSet={settings?.hasOpenAI ?? false}
              saving={saving}
            />
            <FieldRow
              label="Firecrawl API Key"
              hint="Used for web intelligence — SaaS incident research, changelog fetching, advisory search."
              type="password"
              value={firecrawlKey}
              onChange={setFirecrawlKey}
              placeholder="fc-..."
              isSet={settings?.hasFirecrawl ?? false}
              saving={saving}
            />
          </div>
        </section>

        {/* Scan defaults */}
        <section>
          <div className="mb-4">
            <h2 className="text-white font-semibold text-sm">Scan Defaults</h2>
            <p className="text-white/30 text-xs mt-0.5">
              These apply when no flags are provided to the CLI.
            </p>
          </div>

          <div className="space-y-4">
            <div className="rounded-2xl bg-white/[0.04] p-5">
              <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Depth Mode</p>
              <div className="grid grid-cols-3 gap-3">
                {MODE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setDefaultMode(opt.value)}
                    className={clsx(
                      "p-4 rounded-xl border text-left transition-all",
                      defaultMode === opt.value
                        ? "bg-white/[0.08] border-white/[0.15] text-white"
                        : "bg-black/20 border-white/[0.06] text-white/40 hover:border-white/[0.12] hover:text-white/60"
                    )}
                  >
                    <p className="font-semibold text-sm mb-1">{opt.label}</p>
                    <p className="text-xs opacity-60">{opt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-2xl bg-white/[0.04] p-5">
              <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Scan Mode</p>
              <div className="grid grid-cols-3 gap-3">
                {SCAN_MODE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setDefaultScanMode(opt.value)}
                    className={clsx(
                      "p-4 rounded-xl border text-left transition-all",
                      defaultScanMode === opt.value
                        ? "bg-white/[0.08] border-white/[0.15] text-white"
                        : "bg-black/20 border-white/[0.06] text-white/40 hover:border-white/[0.12] hover:text-white/60"
                    )}
                  >
                    <p className="font-semibold text-sm mb-1">{opt.label}</p>
                    <p className="text-xs opacity-60">{opt.desc}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Sandbox defaults */}
        <section>
          <div className="mb-4">
            <h2 className="text-white font-semibold text-sm">Sandbox Defaults</h2>
            <p className="text-white/30 text-xs mt-0.5">
              Controls attack depth and companion AI agent focus when running <code className="font-mono text-white/50">breachscope sandbox</code>.
            </p>
          </div>

          <div className="space-y-4">
            <div className="rounded-2xl bg-white/[0.04] p-5">
              <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Attack Depth</p>
              <div className="grid grid-cols-2 gap-3">
                {SANDBOX_DEPTH_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setSandboxDeep(opt.value === "deep")}
                    className={clsx(
                      "p-4 rounded-xl border text-left transition-all",
                      (sandboxDeep ? "deep" : "normal") === opt.value
                        ? "bg-white/[0.08] border-white/[0.15] text-white"
                        : "bg-black/20 border-white/[0.06] text-white/40 hover:border-white/[0.12] hover:text-white/60"
                    )}
                  >
                    <p className="font-semibold text-sm mb-1">{opt.label}</p>
                    <p className="text-xs opacity-60">{opt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-2xl bg-white/[0.04] p-5">
              <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Companion Agent Mode</p>
              <p className="text-white/30 text-xs mb-4">Sets focus for the code, dependency, and blackbox agents that run alongside the attack agent.</p>
              <div className="grid grid-cols-3 gap-3">
                {SANDBOX_SCAN_MODE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setSandboxScanMode(opt.value)}
                    className={clsx(
                      "p-4 rounded-xl border text-left transition-all",
                      sandboxScanMode === opt.value
                        ? "bg-white/[0.08] border-white/[0.15] text-white"
                        : "bg-black/20 border-white/[0.06] text-white/40 hover:border-white/[0.12] hover:text-white/60"
                    )}
                  >
                    <p className="font-semibold text-sm mb-1">{opt.label}</p>
                    <p className="text-xs opacity-60">{opt.desc}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Save */}
        <div className="flex items-center gap-4">
          <motion.button
            onClick={handleSave}
            disabled={saving}
            whileTap={{ scale: 0.98 }}
            className="px-6 py-2.5 rounded-xl bg-white text-black text-sm font-semibold hover:bg-white/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {saving ? "Saving…" : "Save Changes"}
          </motion.button>
          {saved && (
            <motion.span
              initial={{ opacity: 0, x: -4 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              className="text-green-400 text-sm"
            >
              Saved
            </motion.span>
          )}
        </div>

        {/* Danger zone */}
        <section className="rounded-2xl border border-red-500/15 bg-red-500/[0.03] p-5">
          <h3 className="text-white/50 text-xs font-semibold uppercase tracking-wider mb-4">Danger Zone</h3>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white/70 text-sm font-medium">Clear all scan data</p>
              <p className="text-white/30 text-xs mt-0.5">Permanently delete all scans and findings from your account.</p>
            </div>
            <button className="px-4 py-2 rounded-xl border border-red-500/25 text-red-400/70 text-sm hover:bg-red-500/10 hover:text-red-400 transition-all">
              Delete All Scans
            </button>
          </div>
        </section>
      </div>
    </>
  );
}
