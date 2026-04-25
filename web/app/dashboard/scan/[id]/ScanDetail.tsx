"use client";

import { useState, useCallback } from "react";
import { clsx } from "clsx";
import type { Scan, Finding } from "@/lib/schema";

// ─── Shared types ─────────────────────────────────────────────────────────────

interface ToolRiskEntry {
  name: string; kind: string; depth: number; parent?: string;
  riskScore: number; aiSummary?: string;
  osvCount: number; osvIds?: string[];
  scorecardScore?: number; weeklyDownloads?: number; maintainerCount?: number;
  findingsCount: number;
}

interface ServiceProbeActivity {
  id: string; name: string; category: string;
  steps: string[]; findingsCount: number; tokensUsed: number;
}

interface AttackProbeActivity {
  url: string; attacks: string[]; pagesVisited: string[];
  findingsCount: number; tokensUsed: number;
}

interface ProbeActivity {
  services?: ServiceProbeActivity[];
  attack?: AttackProbeActivity;
}

// ─── Severity ─────────────────────────────────────────────────────────────────

const SEV = {
  CRITICAL: { label: "Critical", bar: "bg-red-500",    badge: "bg-red-500/15 border-red-500/30 text-red-300",    dot: "bg-red-500",    text: "text-red-400" },
  HIGH:     { label: "High",     bar: "bg-orange-500", badge: "bg-orange-500/15 border-orange-500/30 text-orange-300", dot: "bg-orange-500", text: "text-orange-400" },
  MEDIUM:   { label: "Medium",   bar: "bg-yellow-500", badge: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300", dot: "bg-yellow-500", text: "text-yellow-400" },
  LOW:      { label: "Low",      bar: "bg-cyan-500",   badge: "bg-cyan-500/15 border-cyan-500/30 text-cyan-300",   dot: "bg-cyan-500",   text: "text-cyan-400" },
};
const getSev = (k: string) => SEV[k.toUpperCase() as keyof typeof SEV] ?? SEV.LOW;

const CAT_LABELS: Record<string, string> = {
  dependency: "Dependency", toolchain: "Toolchain", code: "Code",
  blackbox: "Blackbox", "supply-chain": "Supply Chain",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}
function fmtNum(n?: number): string {
  if (!n) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}K`;
  return String(n);
}

// ─── Small atoms ─────────────────────────────────────────────────────────────

function RiskBar({ score }: { score: number }) {
  const color = score >= 75 ? "bg-red-500" : score >= 50 ? "bg-orange-500" : score >= 25 ? "bg-yellow-500" : "bg-green-500";
  const text  = score >= 75 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 25 ? "text-yellow-400" : "text-green-400";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden max-w-[72px]">
        <div className={clsx("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={clsx("text-xs font-mono font-semibold tabular-nums w-5 text-right", text)}>{score}</span>
    </div>
  );
}

function KindBadge({ kind }: { kind: string }) {
  const cls = kind === "oss" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
    : kind === "saas"   ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
    : kind === "hybrid" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
    : "bg-white/5 text-white/30 border-white/10";
  const label = kind === "oss" ? "OSS" : kind === "saas" ? "SaaS" : kind === "hybrid" ? "Hybrid" : "?";
  return <span className={clsx("px-1.5 py-0.5 rounded text-[10px] border font-medium uppercase tracking-wide shrink-0", cls)}>{label}</span>;
}

function Chip({ label, count, active, onClick }: { label: string; count: number; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
        active
          ? "bg-white/10 border-white/20 text-white"
          : "bg-white/[0.03] border-white/[0.07] text-white/40 hover:text-white/60 hover:border-white/15"
      )}
    >
      {label}
      <span className={clsx("text-[10px] font-mono", active ? "text-white/60" : "text-white/25")}>{count}</span>
    </button>
  );
}

// ─── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const sev = getSev(finding.severity);
  let refs: string[] = [];
  try { refs = finding.references ? (JSON.parse(finding.references) as string[]) : []; } catch {}

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-5 py-4 text-left hover:bg-white/[0.02] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <span className={clsx("mt-0.5 px-2 py-0.5 rounded-full text-xs border font-medium shrink-0", sev.badge)}>
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-white/85 text-sm font-medium leading-snug">{finding.title}</p>
          <p className="text-white/30 text-xs mt-0.5">
            {CAT_LABELS[finding.category] ?? finding.category}
            {finding.tool ? ` · ${finding.tool}` : ""}
            {finding.file ? ` · ${finding.file}${finding.line ? `:${finding.line}` : ""}` : ""}
          </p>
        </div>
        <svg className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 mt-1 transition-transform duration-150", open && "rotate-180")}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-3 border-t border-white/[0.04] pt-4">
          <p className="text-white/55 text-sm leading-relaxed">{finding.description}</p>
          {finding.remediation && (
            <div className="p-3 rounded-lg bg-white/[0.04] border border-white/[0.06]">
              <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-1.5">Fix</p>
              <p className="text-white/55 text-sm leading-relaxed">{finding.remediation}</p>
            </div>
          )}
          {refs.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {refs.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                  className="text-white/35 text-xs hover:text-white/60 underline underline-offset-2 truncate max-w-xs transition-colors">
                  {ref.replace(/^https?:\/\//, "").slice(0, 60)}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Tool risk table ──────────────────────────────────────────────────────────

function ToolRiskTable({ tools }: { tools: ToolRiskEntry[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const sorted = [...tools].sort((a, b) => b.riskScore - a.riskScore);
  return (
    <div className="space-y-1">
      {sorted.map((t) => (
        <div key={t.name} className="rounded-xl border border-white/[0.06] overflow-hidden">
          <button
            className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.03] transition-colors text-left min-w-0"
            onClick={() => setExpanded(expanded === t.name ? null : t.name)}
          >
            {t.depth > 0 && <span className="text-white/20 text-xs shrink-0 font-mono">{"└─".repeat(t.depth)}</span>}
            <span className="flex-1 text-sm text-white/75 font-mono truncate">{t.name}</span>
            <KindBadge kind={t.kind} />
            {t.osvCount > 0 && <span className="text-red-400 text-xs shrink-0">{t.osvCount} CVE{t.osvCount !== 1 ? "s" : ""}</span>}
            {t.findingsCount > 0 && <span className="text-orange-400/70 text-xs shrink-0 hidden sm:inline">{t.findingsCount} finding{t.findingsCount !== 1 ? "s" : ""}</span>}
            <div className="shrink-0 w-28 hidden sm:block"><RiskBar score={t.riskScore} /></div>
            <svg className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 transition-transform duration-150", expanded === t.name && "rotate-180")}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {expanded === t.name && (
            <div className="px-4 pb-4 border-t border-white/[0.04] space-y-3 pt-3">
              {t.aiSummary && !t.aiSummary.includes("unavailable") && (
                <p className="text-white/45 text-sm leading-relaxed">{t.aiSummary}</p>
              )}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {t.scorecardScore !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">OpenSSF</p>
                    <p className={clsx("text-sm font-semibold", t.scorecardScore >= 7 ? "text-green-400" : t.scorecardScore >= 4 ? "text-yellow-400" : "text-red-400")}>
                      {t.scorecardScore.toFixed(1)}/10
                    </p>
                  </div>
                )}
                {t.weeklyDownloads !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Weekly DLs</p>
                    <p className="text-white/60 text-sm font-semibold">{fmtNum(t.weeklyDownloads)}</p>
                  </div>
                )}
                {t.maintainerCount !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Maintainers</p>
                    <p className={clsx("text-sm font-semibold", t.maintainerCount === 0 ? "text-red-400" : t.maintainerCount === 1 ? "text-orange-400" : "text-white/60")}>
                      {t.maintainerCount}
                    </p>
                  </div>
                )}
                <div className="p-2.5 rounded-lg bg-white/[0.04]">
                  <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Risk Score</p>
                  <p className={clsx("text-sm font-semibold", t.riskScore >= 75 ? "text-red-400" : t.riskScore >= 50 ? "text-orange-400" : t.riskScore >= 25 ? "text-yellow-400" : "text-green-400")}>
                    {t.riskScore}/100
                  </p>
                </div>
              </div>
              {t.osvIds && t.osvIds.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {t.osvIds.map((id) => (
                    <a key={id} href={`https://osv.dev/vulnerability/${id}`} target="_blank" rel="noopener noreferrer"
                      className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs hover:bg-red-500/20 transition-colors font-mono">
                      {id}
                    </a>
                  ))}
                </div>
              )}
              {t.parent && <p className="text-white/20 text-xs">Introduced via <span className="font-mono text-white/35">{t.parent}</span></p>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Probe timeline ───────────────────────────────────────────────────────────

const SERVICE_ICONS: Record<string, string> = {
  supabase: "🗄️", firebase: "🔥", neon: "⚡", planetscale: "🪐",
  upstash: "🚀", clerk: "🔑", auth0: "🔐", vercel: "▲", github: "🐙",
  aws: "☁️", cloudflare: "🌐", stripe: "💳", resend: "📧", sendgrid: "📨",
  twilio: "📱", openai: "🤖", anthropic: "🧠", pinecone: "🌲",
  sentry: "🚨", datadog: "🐕",
};

function ServiceProbeCard({ svc }: { svc: ServiceProbeActivity }) {
  const [open, setOpen] = useState(false);
  const icon = SERVICE_ICONS[svc.id] ?? "🔌";
  return (
    <div className="rounded-xl border border-white/[0.06] overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-white/[0.03] transition-colors text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="text-lg shrink-0">{icon}</span>
        <div className="flex-1 min-w-0">
          <p className="text-white/80 text-sm font-medium">{svc.name}</p>
          <p className="text-white/30 text-xs">{svc.category}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {svc.findingsCount > 0
            ? <span className="px-2 py-0.5 rounded-full text-xs bg-orange-500/15 border border-orange-500/25 text-orange-300">{svc.findingsCount} finding{svc.findingsCount !== 1 ? "s" : ""}</span>
            : <span className="px-2 py-0.5 rounded-full text-xs bg-green-500/10 border border-green-500/20 text-green-400">Clean</span>
          }
          <span className="text-white/20 text-xs font-mono hidden sm:inline">{svc.steps.length} calls</span>
          <svg className={clsx("w-3.5 h-3.5 text-white/20 transition-transform duration-150", open && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {open && (
        <div className="border-t border-white/[0.04] px-4 py-3">
          <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-2.5">API Calls & Actions</p>
          <div className="space-y-1">
            {svc.steps.map((step, i) => {
              const isHttp = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS)/.test(step);
              const isSearch = step.startsWith("web search");
              const isCrawl = step.startsWith("crawl");
              return (
                <div key={i} className="flex items-start gap-2.5">
                  <span className={clsx(
                    "mt-0.5 text-[10px] font-mono shrink-0 px-1.5 py-0.5 rounded",
                    isHttp   ? "bg-blue-500/10 text-blue-400" :
                    isSearch ? "bg-purple-500/10 text-purple-400" :
                    isCrawl  ? "bg-cyan-500/10 text-cyan-400" :
                    "bg-white/5 text-white/30"
                  )}>
                    {isHttp ? step.split(" ")[0] : isSearch ? "SRCH" : isCrawl ? "CRAWL" : "SYS"}
                  </span>
                  <span className="text-white/45 text-xs font-mono leading-relaxed break-all">
                    {isHttp ? step.split(" ").slice(1).join(" ") : step.replace(/^web search: "|crawl /g, "").replace(/"$/, "")}
                  </span>
                </div>
              );
            })}
          </div>
          {svc.tokensUsed > 0 && (
            <p className="text-white/20 text-xs mt-3 font-mono">{svc.tokensUsed.toLocaleString()} tokens used</p>
          )}
        </div>
      )}
    </div>
  );
}

const ATTACK_ICONS: Record<string, string> = {
  "SQLi fuzz":      "💉",
  "Form SQLi":      "💉",
  "XSS fuzz":       "⚡",
  "JWT tamper":     "🔑",
  "CORS test":      "🌐",
  "Rate limit":     "🔄",
  "Sensitive path": "🗂️",
};

function getAttackIcon(attack: string): string {
  for (const [key, icon] of Object.entries(ATTACK_ICONS)) {
    if (attack.includes(key)) return icon;
  }
  return "🎯";
}

function AttackProbeCard({ probe }: { probe: AttackProbeActivity }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="rounded-xl border border-purple-500/20 bg-purple-500/[0.03] overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-white/[0.02] transition-colors text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="text-lg shrink-0">🎯</span>
        <div className="flex-1 min-w-0">
          <p className="text-white/80 text-sm font-medium">Active Penetration Test</p>
          <p className="text-purple-400/60 text-xs font-mono truncate">{probe.url}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {probe.findingsCount > 0
            ? <span className="px-2 py-0.5 rounded-full text-xs bg-red-500/15 border border-red-500/25 text-red-300">{probe.findingsCount} finding{probe.findingsCount !== 1 ? "s" : ""}</span>
            : <span className="px-2 py-0.5 rounded-full text-xs bg-green-500/10 border border-green-500/20 text-green-400">Clean</span>
          }
          <span className="text-white/20 text-xs font-mono hidden sm:inline">{probe.attacks.length} attacks</span>
          <svg className={clsx("w-3.5 h-3.5 text-white/20 transition-transform duration-150", open && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {open && (
        <div className="border-t border-purple-500/10 px-4 py-4 space-y-4">
          {probe.attacks.length > 0 && (
            <div>
              <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-2.5">Attacks Executed</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {probe.attacks.map((attack, i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.05]">
                    <span className="text-sm shrink-0">{getAttackIcon(attack)}</span>
                    <span className="text-white/45 text-xs font-mono truncate">{attack}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {probe.pagesVisited.length > 0 && (
            <div>
              <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-2">Pages Visited</p>
              <div className="flex flex-wrap gap-1.5">
                {probe.pagesVisited.slice(0, 12).map((page, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.06] text-white/35 text-xs font-mono truncate max-w-[200px]">
                    {page.replace(/^https?:\/\/[^/]+/, "") || "/"}
                  </span>
                ))}
                {probe.pagesVisited.length > 12 && (
                  <span className="text-white/20 text-xs self-center">+{probe.pagesVisited.length - 12} more</span>
                )}
              </div>
            </div>
          )}
          {probe.tokensUsed > 0 && (
            <p className="text-white/20 text-xs font-mono">{probe.tokensUsed.toLocaleString()} tokens used</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Report download ──────────────────────────────────────────────────────────

function generateMarkdown(
  scan: Scan,
  findings: Finding[],
  toolRiskData: ToolRiskEntry[],
  probeActivity: ProbeActivity | null
): string {
  const date = new Date(scan.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
  const dur  = elapsed(scan.startedAt, scan.completedAt);

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = f.severity.toLowerCase() as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  const grouped: Record<string, Finding[]> = {};
  for (const f of findings) {
    const s = f.severity.toUpperCase();
    (grouped[s] ??= []).push(f);
  }

  let md = `# BreachScope Security Report\n\n`;
  md += `**Project**: ${scan.project ?? "Unknown"}  \n`;
  md += `**Date**: ${date}  \n`;
  md += `**Scan Mode**: ${scan.mode} | ${scan.scanMode}  \n`;
  md += `**Duration**: ${dur}  \n`;
  if (scan.url) md += `**Target URL**: ${scan.url}  \n`;
  md += `\n---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `Found **${findings.length} issue${findings.length !== 1 ? "s" : ""}**`;
  const parts = [];
  if (sevCounts.critical > 0) parts.push(`${sevCounts.critical} critical`);
  if (sevCounts.high > 0)     parts.push(`${sevCounts.high} high`);
  if (sevCounts.medium > 0)   parts.push(`${sevCounts.medium} medium`);
  if (sevCounts.low > 0)      parts.push(`${sevCounts.low} low`);
  md += parts.length > 0 ? `: ${parts.join(", ")}.` : ": none.";
  md += "\n\n";

  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    const list = grouped[sev];
    if (!list || list.length === 0) continue;
    md += `## ${sev[0]! + sev.slice(1).toLowerCase()} Findings\n\n`;
    list.forEach((f, i) => {
      md += `### [${sev[0]}${i + 1}] ${f.title}\n\n`;
      md += `**Severity**: ${f.severity} | **Category**: ${f.category}`;
      if (f.tool) md += ` | **Tool**: ${f.tool}`;
      if (f.file) md += ` | **File**: \`${f.file}${f.line ? `:${f.line}` : ""}\``;
      md += `\n\n**Description**: ${f.description}\n\n`;
      if (f.remediation) md += `**Fix**: ${f.remediation}\n\n`;
      let refs: string[] = [];
      try { refs = f.references ? (JSON.parse(f.references) as string[]) : []; } catch {}
      if (refs.length > 0) md += `**References**:\n${refs.map((r) => `- ${r}`).join("\n")}\n\n`;
    });
  }

  if (toolRiskData.length > 0) {
    md += `## Dependency Risk Overview\n\n`;
    md += `| Package | Risk | CVEs | OpenSSF | Maintainers | Weekly DLs |\n`;
    md += `|---------|------|------|---------|-------------|------------|\n`;
    [...toolRiskData].sort((a, b) => b.riskScore - a.riskScore).slice(0, 30).forEach((t) => {
      md += `| \`${t.name}\` | ${t.riskScore}/100 | ${t.osvCount} | ${t.scorecardScore?.toFixed(1) ?? "—"} | ${t.maintainerCount ?? "—"} | ${fmtNum(t.weeklyDownloads)} |\n`;
    });
    md += "\n";
  }

  if (probeActivity) {
    md += `## Probe Activity\n\n`;
    if (probeActivity.services?.length) {
      md += `### Service Probes\n\n`;
      for (const svc of probeActivity.services) {
        md += `**${svc.name}** (${svc.category}) — ${svc.findingsCount} findings, ${svc.tokensUsed.toLocaleString()} tokens\n\n`;
        if (svc.steps.length > 0) md += svc.steps.map((s) => `- \`${s}\``).join("\n") + "\n\n";
      }
    }
    if (probeActivity.attack) {
      const a = probeActivity.attack;
      md += `### Active Penetration Test\n\n`;
      md += `**Target**: ${a.url} — ${a.findingsCount} findings, ${a.tokensUsed.toLocaleString()} tokens\n\n`;
      if (a.attacks.length > 0) md += `**Attacks run**:\n${a.attacks.map((s) => `- ${s}`).join("\n")}\n\n`;
      if (a.pagesVisited.length > 0) md += `**Pages visited**: ${a.pagesVisited.slice(0, 10).join(", ")}\n\n`;
    }
  }

  md += `---\n*Generated by [BreachScope](https://breachscoope.vercel.app) — ${date}*\n`;
  return md;
}

function downloadFile(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function ReportTab({
  scan, findings, toolRiskData, probeActivity,
}: { scan: Scan; findings: Finding[]; toolRiskData: ToolRiskEntry[]; probeActivity: ProbeActivity | null }) {
  const slug = (scan.project ?? "scan").replace(/\s+/g, "-").toLowerCase();
  const date = new Date(scan.createdAt).toISOString().slice(0, 10);

  const downloadJson = useCallback(() => {
    const payload = {
      scan: { id: scan.id, project: scan.project, mode: scan.mode, scanMode: scan.scanMode, url: scan.url, startedAt: scan.startedAt, completedAt: scan.completedAt },
      summary: { total: findings.length, critical: scan.findingsCritical, high: scan.findingsHigh, medium: scan.findingsMedium, low: scan.findingsLow },
      findings: findings.map((f) => ({ ...f, references: (() => { try { return f.references ? JSON.parse(f.references) : []; } catch { return []; } })() })),
      toolRiskData,
      probeActivity,
    };
    downloadFile(JSON.stringify(payload, null, 2), `${slug}-${date}.json`, "application/json");
  }, [scan, findings, toolRiskData, probeActivity, slug, date]);

  const downloadMarkdown = useCallback(() => {
    const md = generateMarkdown(scan, findings, toolRiskData, probeActivity);
    downloadFile(md, `${slug}-${date}.md`, "text/markdown");
  }, [scan, findings, toolRiskData, probeActivity, slug, date]);

  const printPdf = useCallback(() => {
    window.print();
  }, []);

  const sections = [
    { icon: "{ }", label: "JSON", desc: "Machine-readable export. Includes all findings, risk data, and probe activity. Ideal for CI/CD pipelines and programmatic processing.", action: downloadJson, color: "text-cyan-400", border: "border-cyan-500/20 hover:border-cyan-500/40", bg: "bg-cyan-500/5 hover:bg-cyan-500/10" },
    { icon: "#", label: "Markdown", desc: "Human-readable report with findings grouped by severity, dependency risk table, and probe activity log. Great for GitHub issues or Notion.", action: downloadMarkdown, color: "text-purple-400", border: "border-purple-500/20 hover:border-purple-500/40", bg: "bg-purple-500/5 hover:bg-purple-500/10" },
    { icon: "⎙", label: "PDF / Print", desc: "Opens the browser print dialog. Select 'Save as PDF' to generate a formatted PDF report. Works best in Chrome.", action: printPdf, color: "text-orange-400", border: "border-orange-500/20 hover:border-orange-500/40", bg: "bg-orange-500/5 hover:bg-orange-500/10" },
  ];

  return (
    <div className="space-y-8 max-w-3xl">
      <div>
        <h3 className="text-white/75 text-sm font-semibold mb-1">Export Report</h3>
        <p className="text-white/30 text-xs">Download a full security report in your preferred format.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {sections.map(({ icon, label, desc, action, color, border, bg }) => (
          <button
            key={label}
            onClick={action}
            className={clsx(
              "group text-left p-5 rounded-2xl border transition-all duration-200",
              border, bg
            )}
          >
            <div className={clsx("text-2xl font-mono mb-3", color)}>{icon}</div>
            <p className={clsx("text-sm font-semibold mb-2", color)}>{label}</p>
            <p className="text-white/30 text-xs leading-relaxed">{desc}</p>
            <div className={clsx("mt-4 text-xs font-medium flex items-center gap-1.5 transition-opacity opacity-60 group-hover:opacity-100", color)}>
              Download {label}
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
            </div>
          </button>
        ))}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <div className="px-5 py-4 border-b border-white/[0.04]">
          <p className="text-white/50 text-xs font-semibold uppercase tracking-wider">Report Preview</p>
        </div>
        <div className="px-5 py-4 font-mono text-xs text-white/30 leading-relaxed space-y-1">
          <p className="text-white/60"># BreachScope Security Report</p>
          <p><span className="text-white/40">Project:</span> {scan.project ?? "Unknown"}</p>
          <p><span className="text-white/40">Date:</span> {new Date(scan.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}</p>
          <p><span className="text-white/40">Mode:</span> {scan.mode} | {scan.scanMode}</p>
          {scan.url && <p><span className="text-white/40">URL:</span> {scan.url}</p>}
          <p className="pt-2"><span className="text-white/50">## Findings ({findings.length})</span></p>
          {["critical", "high", "medium", "low"].map((s) => {
            const count = findings.filter((f) => f.severity === s).length;
            if (!count) return null;
            return <p key={s} className="pl-2"><span className="text-white/40">{s}:</span> {count}</p>;
          })}
          {toolRiskData.length > 0 && (
            <p className="pt-2"><span className="text-white/50">## Dependency Risk ({toolRiskData.length} packages)</span></p>
          )}
          {(probeActivity?.services?.length || probeActivity?.attack) && (
            <p className="pt-2"><span className="text-white/50">## Probe Activity</span></p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

type Tab = "overview" | "findings" | "probes" | "report";

export function ScanDetail({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  const [tab, setTab]       = useState<Tab>("overview");
  const [sevFilter, setSev] = useState<string>("ALL");
  const [catFilter, setCat] = useState<string>("ALL");

  const total    = scan.findingsTotal    ?? 0;
  const critical = scan.findingsCritical ?? 0;
  const high     = scan.findingsHigh     ?? 0;
  const medium   = scan.findingsMedium   ?? 0;
  const low      = scan.findingsLow      ?? 0;

  let toolRiskData: ToolRiskEntry[] = [];
  try { if (scan.riskData) toolRiskData = JSON.parse(scan.riskData) as ToolRiskEntry[]; } catch {}

  let probeActivity: ProbeActivity | null = null;
  try { if (scan.probeData) probeActivity = JSON.parse(scan.probeData) as ProbeActivity; } catch {}

  const hasProbes = (probeActivity?.services?.length ?? 0) > 0 || !!probeActivity?.attack;

  // Filtered findings
  const filteredFindings = findings.filter((f) => {
    const sevOk = sevFilter === "ALL" || f.severity.toUpperCase() === sevFilter;
    const catOk = catFilter === "ALL" || f.category === catFilter;
    return sevOk && catOk;
  });

  const categories = [...new Set(findings.map((f) => f.category))];

  const grouped: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of filteredFindings) {
    const s = f.severity.toUpperCase() as keyof typeof grouped;
    (grouped[s] ?? grouped.LOW).push(f);
  }

  const TABS: { id: Tab; label: string; count?: number }[] = [
    { id: "overview",  label: "Overview" },
    { id: "findings",  label: "Findings",       count: total },
    { id: "probes",    label: "Probe Activity",  count: hasProbes ? ((probeActivity?.services?.length ?? 0) + (probeActivity?.attack ? 1 : 0)) : undefined },
    { id: "report",    label: "Report" },
  ];

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Scan summary strip */}
      <div className="flex flex-wrap items-center gap-3">
        {total > 0 && (
          <div className="flex items-center gap-2">
            {critical > 0 && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/15 border border-red-500/25 text-red-300">{critical} Critical</span>}
            {high > 0     && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-500/15 border border-orange-500/25 text-orange-300">{high} High</span>}
            {medium > 0   && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-yellow-500/15 border border-yellow-500/25 text-yellow-300">{medium} Medium</span>}
            {low > 0      && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/15 border border-cyan-500/25 text-cyan-300">{low} Low</span>}
          </div>
        )}
        {total === 0 && (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-green-500/10 border border-green-500/20 text-green-400">✓ Clean</span>
        )}
        {scan.url && (
          <a href={scan.url} target="_blank" rel="noopener noreferrer"
            className="text-white/25 text-xs font-mono hover:text-white/50 transition-colors truncate max-w-xs">
            {scan.url.replace(/^https?:\/\//, "")}
          </a>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-white/[0.06]">
        {TABS.map(({ id, label, count }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              "flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
              tab === id
                ? "border-white/60 text-white"
                : "border-transparent text-white/35 hover:text-white/60"
            )}
          >
            {label}
            {count !== undefined && (
              <span className={clsx("text-[10px] font-mono px-1.5 py-0.5 rounded", tab === id ? "bg-white/10 text-white/70" : "bg-white/5 text-white/25")}>
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Overview tab ── */}
      {tab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Scan Mode", value: scan.scanMode },
              { label: "Depth",     value: scan.mode },
              { label: "Duration",  value: elapsed(scan.startedAt, scan.completedAt) },
              { label: "Tools",     value: `${scan.toolsScanned ?? 0} scanned` },
            ].map(({ label, value }) => (
              <div key={label} className="p-4 rounded-2xl bg-white/[0.04]">
                <p className="text-white/30 text-xs mb-2">{label}</p>
                <p className="text-white/80 text-sm font-mono">{value}</p>
              </div>
            ))}
          </div>

          <div className="rounded-2xl bg-white/[0.04] p-5">
            <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Findings Breakdown</p>
            {total === 0 ? (
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <p className="text-green-400 text-sm">No findings — clean scan</p>
              </div>
            ) : (
              <div className="space-y-3">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                  const count = sev === "CRITICAL" ? critical : sev === "HIGH" ? high : sev === "MEDIUM" ? medium : low;
                  const pct   = total > 0 ? (count / total) * 100 : 0;
                  const cfg   = SEV[sev];
                  return (
                    <div key={sev} className="flex items-center gap-4">
                      <span className={clsx("text-xs font-medium w-16 shrink-0", cfg.text)}>{cfg.label}</span>
                      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className={clsx("h-full rounded-full transition-all", cfg.bar)} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-white/40 text-xs w-6 text-right shrink-0">{count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {toolRiskData.length > 0 && (
            <section>
              <div className="flex items-start justify-between gap-4 mb-4">
                <div>
                  <h3 className="text-white/75 text-sm font-semibold">Dependency Risk Overview</h3>
                  <p className="text-white/30 text-xs mt-0.5">
                    {toolRiskData.length} package{toolRiskData.length !== 1 ? "s" : ""} audited
                    {(() => { const top = [...toolRiskData].sort((a, b) => b.riskScore - a.riskScore)[0]; return top ? ` · highest: ${top.name} (${top.riskScore}/100)` : ""; })()}
                  </p>
                </div>
                <div className="hidden sm:flex items-center gap-4 text-[10px] text-white/25 shrink-0">
                  {[{ c: "bg-red-500", l: "≥75" }, { c: "bg-orange-500", l: "≥50" }, { c: "bg-yellow-500", l: "≥25" }, { c: "bg-green-500", l: "<25" }].map(({ c, l }) => (
                    <span key={l} className="flex items-center gap-1"><span className={clsx("w-2 h-2 rounded-full", c)} />{l}</span>
                  ))}
                </div>
              </div>
              <ToolRiskTable tools={toolRiskData} />
            </section>
          )}
        </div>
      )}

      {/* ── Findings tab ── */}
      {tab === "findings" && (
        <div className="space-y-5">
          {/* Filters */}
          <div className="flex flex-wrap gap-2">
            <Chip label="All" count={findings.length} active={sevFilter === "ALL" && catFilter === "ALL"} onClick={() => { setSev("ALL"); setCat("ALL"); }} />
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => {
              const count = findings.filter((f) => f.severity.toUpperCase() === s).length;
              if (!count) return null;
              return <Chip key={s} label={SEV[s].label} count={count} active={sevFilter === s} onClick={() => { setSev(s); setCat("ALL"); }} />;
            })}
            {categories.map((cat) => (
              <Chip key={cat} label={CAT_LABELS[cat] ?? cat} count={findings.filter((f) => f.category === cat).length} active={catFilter === cat} onClick={() => { setCat(cat); setSev("ALL"); }} />
            ))}
          </div>

          {filteredFindings.length === 0 ? (
            <div className="py-12 text-center text-white/25 text-sm">No findings match the current filter.</div>
          ) : (
            (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
              const list = grouped[sev];
              if (!list || list.length === 0) return null;
              const cfg = SEV[sev];
              return (
                <section key={sev}>
                  <div className="flex items-center gap-3 mb-3">
                    <div className={clsx("w-2 h-2 rounded-full", cfg.bar)} />
                    <h3 className={clsx("text-sm font-semibold", cfg.text)}>
                      {cfg.label} <span className="text-white/30 font-normal">({list.length})</span>
                    </h3>
                  </div>
                  <div className="space-y-2">
                    {list.map((f) => <FindingCard key={f.id} finding={f} />)}
                  </div>
                </section>
              );
            })
          )}

          {findings.length === 0 && (
            <div className="py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-green-400 text-sm font-medium">Clean Scan</p>
              <p className="text-white/25 text-xs mt-1">No findings detected.</p>
            </div>
          )}
        </div>
      )}

      {/* ── Probe Activity tab ── */}
      {tab === "probes" && (
        <div className="space-y-6">
          {!hasProbes ? (
            <div className="py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <p className="text-white/35 text-sm font-medium">No probe activity recorded</p>
              <p className="text-white/20 text-xs mt-1">Run with <code className="font-mono bg-white/[0.06] px-1.5 rounded">--ai</code> and/or <code className="font-mono bg-white/[0.06] px-1.5 rounded">--browser</code> to see probe details.</p>
            </div>
          ) : (
            <>
              {(probeActivity?.services?.length ?? 0) > 0 && (
                <section>
                  <h3 className="text-white/60 text-xs font-semibold uppercase tracking-wider mb-3">Live Service Probes</h3>
                  <div className="space-y-2">
                    {probeActivity!.services!.map((svc) => <ServiceProbeCard key={svc.id} svc={svc} />)}
                  </div>
                </section>
              )}
              {probeActivity?.attack && (
                <section>
                  <h3 className="text-white/60 text-xs font-semibold uppercase tracking-wider mb-3">Active Penetration Test</h3>
                  <AttackProbeCard probe={probeActivity.attack} />
                </section>
              )}
            </>
          )}
        </div>
      )}

      {/* ── Report tab ── */}
      {tab === "report" && (
        <ReportTab scan={scan} findings={findings} toolRiskData={toolRiskData} probeActivity={probeActivity} />
      )}
    </div>
  );
}
