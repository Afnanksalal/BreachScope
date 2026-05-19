"use client";

import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import type { Scan } from "@/lib/schema";

const MODE_BADGE: Record<string, string> = {
  full:   "bg-purple-500/15 text-purple-300 border-purple-500/20",
  breach: "bg-red-500/15 text-red-300 border-red-500/20",
  bug:    "bg-yellow-500/15 text-yellow-300 border-yellow-500/20",
  all:    "bg-white/[0.08] text-white/50 border-white/[0.10]",
};

const DEPTH_BADGE: Record<string, string> = {
  basic: "bg-emerald-500/10 text-emerald-400/80",
  major: "bg-yellow-500/10 text-yellow-400/80",
  deep:  "bg-red-500/10 text-red-400/80",
};

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function fmtDate(date: Date | string): string {
  return new Date(date).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "numeric", minute: "2-digit",
  });
}

export function ScansClient({ scans }: { scans: Scan[] }) {
  const [search, setSearch] = useState("");
  const [modeFilter, setModeFilter] = useState<string>("all");
  const [depthFilter, setDepthFilter] = useState<string>("all");

  const filtered = useMemo(() => {
    return scans.filter((s) => {
      const matchesSearch =
        !search ||
        s.project?.toLowerCase().includes(search.toLowerCase()) ||
        s.url?.toLowerCase().includes(search.toLowerCase());
      const matchesMode = modeFilter === "all" || s.scanMode === modeFilter;
      const matchesDepth = depthFilter === "all" || s.mode === depthFilter;
      return matchesSearch && matchesMode && matchesDepth;
    });
  }, [scans, search, modeFilter, depthFilter]);

  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-center">
        <p className="text-white/30 text-sm mb-3">No scans yet.</p>
        <code className="text-white/50 text-xs bg-white/[0.05] border border-white/[0.08] px-3 py-2 rounded-lg font-mono">
          breachscope scan --mode basic
        </code>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-stretch gap-3 sm:items-center">
        <div className="relative min-w-0 flex-1 basis-full sm:basis-64">
          <input
            type="text"
            placeholder="Search project or URL…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-white/20 transition-colors"
          />
        </div>

        <div className="flex max-w-full items-center gap-1 overflow-x-auto rounded-lg bg-white/[0.04] p-1">
          {["all", "full", "breach", "bug"].map((m) => (
            <button
              key={m}
              onClick={() => setModeFilter(m)}
              className={clsx(
                "shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all",
                modeFilter === m
                  ? "bg-white/10 text-white border border-white/15"
                  : "text-white/35 hover:text-white/60 border border-transparent"
              )}
            >
              {m}
            </button>
          ))}
        </div>

        <div className="flex max-w-full items-center gap-1 overflow-x-auto rounded-lg bg-white/[0.04] p-1">
          {["all", "basic", "major", "deep"].map((d) => (
            <button
              key={d}
              onClick={() => setDepthFilter(d)}
              className={clsx(
                "shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all",
                depthFilter === d
                  ? "bg-white/10 text-white border border-white/15"
                  : "text-white/35 hover:text-white/60 border border-transparent"
              )}
            >
              {d}
            </button>
          ))}
        </div>

        <span className="ml-auto text-xs text-white/25">
          {filtered.length} of {scans.length}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg bg-white/[0.04]">
        {filtered.length === 0 ? (
          <div className="py-16 text-center text-white/25 text-sm">No scans match your filters.</div>
        ) : (
          <>
            <div className="grid gap-3 p-3 md:hidden">
              {filtered.map((scan, i) => {
                const hasIssues = (scan.findingsCritical ?? 0) + (scan.findingsHigh ?? 0) > 0;
                const modeBadge = MODE_BADGE[scan.scanMode] ?? MODE_BADGE.all;
                const depthBadge = DEPTH_BADGE[scan.mode] ?? "bg-white/5 text-white/40";

                return (
                  <motion.button
                    key={scan.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.01 }}
                    className="rounded-lg border border-white/[0.07] bg-black/20 p-4 text-left transition-colors hover:bg-white/[0.04]"
                    onClick={() => window.location.href = `/dashboard/scan/${scan.id}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 items-start gap-3">
                        <div className={clsx(
                          "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                          hasIssues ? "bg-red-500 animate-pulse" : "bg-green-500"
                        )} />
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-white/80">
                            {scan.project ?? "Unnamed project"}
                          </p>
                          {scan.url && (
                            <p className="truncate text-xs text-white/30">{scan.url}</p>
                          )}
                        </div>
                      </div>
                      <span className={clsx("shrink-0 rounded-full border px-2 py-0.5 text-xs", modeBadge)}>
                        {scan.scanMode}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <span className={clsx("rounded px-2 py-0.5 font-mono text-xs", depthBadge)}>{scan.mode}</span>
                        {(scan.findingsCritical ?? 0) > 0 && (
                          <span className="text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">
                            {scan.findingsCritical} crit
                          </span>
                        )}
                        {(scan.findingsHigh ?? 0) > 0 && (
                          <span className="text-xs text-orange-400/80">+{scan.findingsHigh} high</span>
                        )}
                        {(scan.findingsTotal ?? 0) > 0 && (scan.findingsCritical ?? 0) === 0 && (scan.findingsHigh ?? 0) === 0 && (
                          <span className="text-xs text-yellow-400/70">{scan.findingsTotal} total</span>
                        )}
                        {(scan.findingsTotal ?? 0) === 0 && (
                          <span className="text-xs text-green-400/70">Clean</span>
                        )}
                      <span className="text-xs text-white/30">{scan.toolsScanned ?? 0} tools</span>
                      <span className="font-mono text-xs text-white/30">{elapsed(scan.startedAt, scan.completedAt)}</span>
                    </div>
                    <p className="mt-2 text-xs text-white/25">{fmtDate(scan.createdAt)}</p>
                  </motion.button>
                );
              })}
            </div>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[760px]">
                <thead>
                  <tr className="border-b border-white/[0.05]">
                    {["Project", "Mode", "Depth", "Findings", "Tools", "Duration", "Date"].map((h) => (
                      <th key={h} className="px-5 py-3 text-left text-xs text-white/25 font-medium first:px-5">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((scan, i) => {
                    const hasIssues = (scan.findingsCritical ?? 0) + (scan.findingsHigh ?? 0) > 0;
                    const modeBadge = MODE_BADGE[scan.scanMode] ?? MODE_BADGE.all;
                    const depthBadge = DEPTH_BADGE[scan.mode] ?? "bg-white/5 text-white/40";

                    return (
                      <motion.tr
                        key={scan.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: i * 0.01 }}
                        className="cursor-pointer border-b border-white/[0.05] transition-colors last:border-0 hover:bg-white/[0.02]"
                        onClick={() => window.location.href = `/dashboard/scan/${scan.id}`}
                      >
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-3">
                            <div className={clsx(
                              "h-2 w-2 shrink-0 rounded-full",
                              hasIssues ? "animate-pulse bg-red-500" : "bg-green-500"
                            )} />
                            <div className="min-w-0">
                              <p className="max-w-[180px] truncate text-sm font-medium text-white/80">
                                {scan.project ?? "Unnamed project"}
                              </p>
                              {scan.url && (
                                <p className="max-w-[180px] truncate text-xs text-white/30">{scan.url}</p>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <span className={clsx("rounded-full border px-2 py-0.5 text-xs", modeBadge)}>
                            {scan.scanMode}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <span className={clsx("rounded px-2 py-0.5 font-mono text-xs", depthBadge)}>
                            {scan.mode}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2">
                            {(scan.findingsCritical ?? 0) > 0 && (
                              <span className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-400">
                                {scan.findingsCritical} crit
                              </span>
                            )}
                            {(scan.findingsHigh ?? 0) > 0 && (
                              <span className="text-xs text-orange-400/80">+{scan.findingsHigh} high</span>
                            )}
                            {(scan.findingsTotal ?? 0) > 0 && (scan.findingsCritical ?? 0) === 0 && (scan.findingsHigh ?? 0) === 0 && (
                              <span className="text-xs text-yellow-400/70">{scan.findingsTotal} total</span>
                            )}
                            {(scan.findingsTotal ?? 0) === 0 && (
                              <span className="text-xs text-green-400/70">Clean</span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-4 text-xs text-white/30">{scan.toolsScanned ?? 0}</td>
                        <td className="px-5 py-4 font-mono text-xs text-white/30">
                          {elapsed(scan.startedAt, scan.completedAt)}
                        </td>
                        <td className="px-5 py-4 text-xs text-white/25">{fmtDate(scan.createdAt)}</td>
                      </motion.tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
