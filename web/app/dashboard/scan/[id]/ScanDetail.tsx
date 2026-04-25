"use client";

import { useState } from "react";
import { clsx } from "clsx";
import type { Scan, Finding } from "@/lib/schema";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToolRiskEntry {
  name: string;
  kind: string;
  depth: number;
  parent?: string;
  riskScore: number;
  aiSummary?: string;
  osvCount: number;
  osvIds?: string[];
  scorecardScore?: number;
  weeklyDownloads?: number;
  maintainerCount?: number;
  findingsCount: number;
}

// ─── Severity config ──────────────────────────────────────────────────────────

const SEV_CONFIG = {
  CRITICAL: { label: "Critical", bar: "bg-red-500",    badge: "bg-red-500/15 border-red-500/25 text-red-300",    text: "text-red-400" },
  HIGH:     { label: "High",     bar: "bg-orange-500", badge: "bg-orange-500/15 border-orange-500/25 text-orange-300", text: "text-orange-400" },
  MEDIUM:   { label: "Medium",   bar: "bg-yellow-500", badge: "bg-yellow-500/15 border-yellow-500/25 text-yellow-300", text: "text-yellow-400" },
  LOW:      { label: "Low",      bar: "bg-cyan-500",   badge: "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",   text: "text-cyan-400" },
};

function getSev(key: string) {
  return SEV_CONFIG[key.toUpperCase() as keyof typeof SEV_CONFIG] ?? SEV_CONFIG.LOW;
}

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function fmtDownloads(n?: number): string {
  if (!n) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

// ─── Risk bar ─────────────────────────────────────────────────────────────────

function RiskBar({ score }: { score: number }) {
  const color =
    score >= 75 ? "bg-red-500" :
    score >= 50 ? "bg-orange-500" :
    score >= 25 ? "bg-yellow-500" :
    "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden max-w-[80px]">
        <div className={clsx("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={clsx(
        "text-xs font-mono font-semibold tabular-nums w-6 text-right",
        score >= 75 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 25 ? "text-yellow-400" : "text-green-400"
      )}>{score}</span>
    </div>
  );
}

function KindBadge({ kind }: { kind: string }) {
  const cls =
    kind === "oss"    ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" :
    kind === "saas"   ? "bg-purple-500/10 text-purple-400 border-purple-500/20" :
    kind === "hybrid" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
    "bg-white/5 text-white/30 border-white/10";
  const label = kind === "oss" ? "OSS" : kind === "saas" ? "SaaS" : kind === "hybrid" ? "Hybrid" : "?";
  return (
    <span className={clsx("px-1.5 py-0.5 rounded text-[10px] border font-medium uppercase tracking-wide shrink-0", cls)}>
      {label}
    </span>
  );
}

// ─── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const sev = getSev(finding.severity);
  let refs: string[] = [];
  try { refs = finding.references ? JSON.parse(finding.references) : []; } catch {}

  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.02] overflow-hidden">
      <div className="flex items-start gap-4 px-5 py-4">
        <span className={clsx("mt-0.5 px-2 py-0.5 rounded-full text-xs border font-medium shrink-0", sev.badge)}>
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-white/85 text-sm font-medium">{finding.title}</p>
          <p className="text-white/35 text-xs mt-0.5">{finding.category}{finding.tool ? ` · ${finding.tool}` : ""}</p>
        </div>
      </div>
      <div className="px-5 pb-4 space-y-3">
        <p className="text-white/50 text-sm leading-relaxed">{finding.description}</p>
        {finding.remediation && (
          <div className="p-3 rounded-lg bg-white/[0.04] border border-white/[0.06]">
            <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-1">Fix</p>
            <p className="text-white/55 text-sm leading-relaxed">{finding.remediation}</p>
          </div>
        )}
        {finding.file && (
          <code className="text-white/40 text-xs font-mono">
            {finding.file}{finding.line ? `:${finding.line}` : ""}
          </code>
        )}
        {refs.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {refs.map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                className="text-white/35 text-xs hover:text-white/65 transition-colors underline underline-offset-2 truncate max-w-xs">
                {ref.replace(/^https?:\/\//, "").slice(0, 60)}
              </a>
            ))}
          </div>
        )}
      </div>
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
            {t.depth > 0 && (
              <span className="text-white/20 text-xs shrink-0 font-mono">{"└─".repeat(t.depth)}</span>
            )}

            <span className="flex-1 text-sm text-white/75 font-mono truncate min-w-0">{t.name}</span>

            <KindBadge kind={t.kind} />

            {t.osvCount > 0 && (
              <span className="text-red-400 text-xs shrink-0">{t.osvCount} CVE{t.osvCount > 1 ? "s" : ""}</span>
            )}

            {t.findingsCount > 0 && (
              <span className="text-orange-400/70 text-xs shrink-0 hidden sm:inline">
                {t.findingsCount} finding{t.findingsCount !== 1 ? "s" : ""}
              </span>
            )}

            <div className="shrink-0 w-32 hidden sm:block">
              <RiskBar score={t.riskScore} />
            </div>
            <div className="shrink-0 sm:hidden">
              <span className={clsx(
                "text-xs font-mono font-semibold",
                t.riskScore >= 75 ? "text-red-400" : t.riskScore >= 50 ? "text-orange-400" : t.riskScore >= 25 ? "text-yellow-400" : "text-green-400"
              )}>{t.riskScore}</span>
            </div>

            <svg
              className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 transition-transform duration-150", expanded === t.name && "rotate-180")}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
            >
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
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">OpenSSF Score</p>
                    <p className={clsx("text-sm font-semibold",
                      t.scorecardScore >= 7 ? "text-green-400" : t.scorecardScore >= 4 ? "text-yellow-400" : "text-red-400"
                    )}>{t.scorecardScore.toFixed(1)}/10</p>
                  </div>
                )}
                {t.weeklyDownloads !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Weekly DLs</p>
                    <p className="text-white/60 text-sm font-semibold">{fmtDownloads(t.weeklyDownloads)}</p>
                  </div>
                )}
                {t.maintainerCount !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Maintainers</p>
                    <p className={clsx("text-sm font-semibold",
                      t.maintainerCount === 0 ? "text-red-400" : t.maintainerCount === 1 ? "text-orange-400" : "text-white/60"
                    )}>{t.maintainerCount}</p>
                  </div>
                )}
                <div className="p-2.5 rounded-lg bg-white/[0.04]">
                  <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Risk Score</p>
                  <p className={clsx("text-sm font-semibold",
                    t.riskScore >= 75 ? "text-red-400" : t.riskScore >= 50 ? "text-orange-400" : t.riskScore >= 25 ? "text-yellow-400" : "text-green-400"
                  )}>{t.riskScore}/100</p>
                </div>
              </div>
              {t.osvIds && t.osvIds.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {t.osvIds.map((id) => (
                    <a
                      key={id}
                      href={`https://osv.dev/vulnerability/${id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs hover:bg-red-500/20 transition-colors font-mono"
                    >
                      {id}
                    </a>
                  ))}
                </div>
              )}
              {t.parent && (
                <p className="text-white/20 text-xs">
                  Introduced via <span className="font-mono text-white/35">{t.parent}</span>
                </p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function ScanDetail({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  const total    = scan.findingsTotal    ?? 0;
  const critical = scan.findingsCritical ?? 0;
  const high     = scan.findingsHigh     ?? 0;
  const medium   = scan.findingsMedium   ?? 0;
  const low      = scan.findingsLow      ?? 0;

  let toolRiskData: ToolRiskEntry[] = [];
  try {
    if (scan.riskData) toolRiskData = JSON.parse(scan.riskData) as ToolRiskEntry[];
  } catch {}

  const grouped: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", Finding[]> = {
    CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
  };
  for (const f of findings) {
    const sev = f.severity.toUpperCase() as keyof typeof grouped;
    (grouped[sev] ?? grouped.LOW).push(f);
  }

  const MODE_BADGE: Record<string, string> = {
    breach: "bg-red-500/15 text-red-300 border-red-500/20",
    bug:    "bg-blue-500/15 text-blue-300 border-blue-500/20",
    all:    "bg-white/8 text-white/50 border-white/10",
  };

  const topRisk = toolRiskData.length > 0
    ? [...toolRiskData].sort((a, b) => b.riskScore - a.riskScore)[0]
    : null;

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Meta */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Scan Mode", value: scan.scanMode, badge: true },
          { label: "Depth",     value: scan.mode },
          { label: "Duration",  value: elapsed(scan.startedAt, scan.completedAt) },
          { label: "Tools",     value: `${scan.toolsScanned ?? 0} scanned` },
        ].map(({ label, value, badge }) => (
          <div key={label} className="p-4 rounded-2xl bg-white/[0.04]">
            <p className="text-white/30 text-xs mb-2">{label}</p>
            {badge ? (
              <span className={clsx("px-2 py-0.5 rounded-full text-xs border", MODE_BADGE[value as string] ?? MODE_BADGE.all)}>
                {value}
              </span>
            ) : (
              <p className="text-white/80 text-sm font-mono">{value}</p>
            )}
          </div>
        ))}
      </div>

      {/* Findings summary */}
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
              const pct = total > 0 ? (count / total) * 100 : 0;
              const cfg = SEV_CONFIG[sev];
              return (
                <div key={sev} className="flex items-center gap-4">
                  <span className={clsx("text-xs font-medium w-16 shrink-0", cfg?.text)}>{cfg?.label}</span>
                  <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div className={clsx("h-full rounded-full", cfg?.bar)} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-white/40 text-xs w-6 text-right shrink-0">{count}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Dependency Risk Overview */}
      {toolRiskData.length > 0 && (
        <section>
          <div className="flex items-start justify-between gap-4 mb-4">
            <div>
              <h3 className="text-white/75 text-sm font-semibold">Dependency Risk Overview</h3>
              <p className="text-white/30 text-xs mt-0.5">
                {toolRiskData.length} package{toolRiskData.length !== 1 ? "s" : ""} audited
                {topRisk ? ` · highest risk: ${topRisk.name} (${topRisk.riskScore}/100)` : ""}
              </p>
            </div>
            <div className="flex items-center gap-4 text-[10px] text-white/25 shrink-0 hidden sm:flex">
              {[
                { color: "bg-red-500", label: "≥75" },
                { color: "bg-orange-500", label: "≥50" },
                { color: "bg-yellow-500", label: "≥25" },
                { color: "bg-green-500", label: "<25" },
              ].map(({ color, label }) => (
                <span key={label} className="flex items-center gap-1">
                  <span className={clsx("w-2 h-2 rounded-full inline-block", color)} />
                  {label}
                </span>
              ))}
            </div>
          </div>
          <ToolRiskTable tools={toolRiskData} />
        </section>
      )}

      {/* Findings by severity */}
      {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
        const list = grouped[sev];
        if (!list || list.length === 0) return null;
        const cfg = SEV_CONFIG[sev];
        return (
          <section key={sev}>
            <div className="flex items-center gap-3 mb-3">
              <div className={clsx("w-2 h-2 rounded-full", cfg?.bar)} />
              <h3 className={clsx("text-sm font-semibold", cfg?.text)}>
                {cfg?.label} <span className="text-white/30 font-normal">({list.length})</span>
              </h3>
            </div>
            <div className="space-y-3">
              {list.map((f) => <FindingCard key={f.id} finding={f} />)}
            </div>
          </section>
        );
      })}

      {findings.length === 0 && toolRiskData.length === 0 && (
        <div className="py-16 text-center">
          <div className="w-12 h-12 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-green-400 text-sm font-medium">Clean Scan</p>
          <p className="text-white/25 text-xs mt-1">No findings detected in this scan.</p>
        </div>
      )}
    </div>
  );
}
