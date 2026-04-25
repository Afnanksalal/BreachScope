"use client";

import { clsx } from "clsx";
import type { Scan, Finding } from "@/lib/schema";

const SEV_CONFIG = {
  CRITICAL: { label: "Critical", bar: "bg-red-500",    badge: "bg-red-500/15 border-red-500/25 text-red-300",    text: "text-red-400" },
  HIGH:     { label: "High",     bar: "bg-orange-500", badge: "bg-orange-500/15 border-orange-500/25 text-orange-300", text: "text-orange-400" },
  MEDIUM:   { label: "Medium",   bar: "bg-yellow-500", badge: "bg-yellow-500/15 border-yellow-500/25 text-yellow-300", text: "text-yellow-400" },
  LOW:      { label: "Low",      bar: "bg-cyan-500",   badge: "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",   text: "text-cyan-400" },
};

function getSev(key: string) {
  return SEV_CONFIG[key as keyof typeof SEV_CONFIG] ?? SEV_CONFIG.LOW;
}

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function FindingCard({ finding }: { finding: Finding }) {
  const sev = getSev(finding.severity);
  let refs: string[] = [];
  try { refs = finding.references ? JSON.parse(finding.references) : []; } catch {}

  return (
    <div className="rounded-xl border border-white/5 bg-surface-0/60 overflow-hidden">
      <div className="flex items-start gap-4 px-5 py-4">
        <span className={clsx("mt-0.5 px-2 py-0.5 rounded-full text-xs border font-medium shrink-0", sev.badge)}>
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-white/85 text-sm font-medium">{finding.title}</p>
          <p className="text-white/40 text-xs mt-0.5">{finding.category}</p>
        </div>
        {finding.tool && (
          <span className="text-white/25 text-xs shrink-0">{finding.tool}</span>
        )}
      </div>
      <div className="px-5 pb-4 space-y-3">
        <p className="text-white/50 text-sm leading-relaxed">{finding.description}</p>
        {finding.remediation && (
          <div className="p-3 rounded-lg bg-white/[0.04] border border-white/[0.07]">
            <p className="text-white/30 text-xs font-semibold uppercase tracking-wider mb-1">Remediation</p>
            <p className="text-white/55 text-sm leading-relaxed">{finding.remediation}</p>
          </div>
        )}
        {finding.file && (
          <div className="flex items-center gap-2">
            <span className="text-white/25 text-xs">File:</span>
            <code className="text-white/55 text-xs font-mono">
              {finding.file}{finding.line ? `:${finding.line}` : ""}
            </code>
          </div>
        )}
        {refs.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {refs.map((ref, i) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="text-white/40 text-xs hover:text-white/70 transition-colors truncate max-w-xs underline underline-offset-2"
              >
                {ref.replace(/^https?:\/\//, "")}
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function ScanDetail({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  const total = scan.findingsTotal ?? 0;
  const critical = scan.findingsCritical ?? 0;
  const high = scan.findingsHigh ?? 0;
  const medium = scan.findingsMedium ?? 0;
  const low = scan.findingsLow ?? 0;

  const grouped = { CRITICAL: [] as Finding[], HIGH: [] as Finding[], MEDIUM: [] as Finding[], LOW: [] as Finding[] };
  for (const f of findings) {
    const bucket = grouped[f.severity as keyof typeof grouped];
    if (bucket) bucket.push(f);
    else grouped.LOW.push(f);
  }

  const MODE_BADGE: Record<string, string> = {
    breach: "bg-red-500/15 text-red-300 border-red-500/20",
    bug:    "bg-blue-500/15 text-blue-300 border-blue-500/20",
    all:    "bg-white/8 text-white/50 border-white/10",
  };

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

      {/* Severity breakdown */}
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

      {findings.length === 0 && (
        <div className="py-16 text-center">
          <div className="w-12 h-12 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-green-400 text-sm font-medium">Clean Scan</p>
          <p className="text-white/25 text-xs mt-1">No findings were detected in this scan.</p>
        </div>
      )}
    </div>
  );
}
