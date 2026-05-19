"use client";

import { clsx } from "clsx";
import type { Scan } from "@/lib/schema";

const MODE_BADGE: Record<string, string> = {
  breach: "bg-red-500/15 text-red-300 border-red-500/20",
  bug:    "bg-blue-500/15 text-blue-300 border-blue-500/20",
  all:    "bg-white/8 text-white/50 border-white/10",
};

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function timeAgo(date: Date | string): string {
  const diff = (Date.now() - new Date(date).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function ScanRow({ scan }: { scan: Scan }) {
  const hasIssues = (scan.findingsCritical ?? 0) + (scan.findingsHigh ?? 0) > 0;
  const modeBadge = MODE_BADGE[scan.scanMode] ?? MODE_BADGE.all;

  return (
    <tr
      className="border-b border-white/5 hover:bg-white/[0.04] transition-colors group cursor-pointer"
      onClick={() => { window.location.href = `/dashboard/scan/${scan.id}`; }}
    >
      <td className="px-5 py-4">
        <div className="flex items-center gap-3">
          <div className={clsx(
            "w-2 h-2 rounded-full shrink-0",
            hasIssues ? "bg-red-500 animate-pulse" : "bg-green-500"
          )} />
          <div>
            <p className="text-white/80 text-sm font-medium truncate max-w-[180px]">
              {scan.project ?? "Unnamed project"}
            </p>
            {scan.url && (
              <p className="text-white/30 text-xs truncate max-w-[180px]">{scan.url}</p>
            )}
          </div>
        </div>
      </td>
      <td className="px-4 py-4">
        <span className={clsx("px-2 py-0.5 rounded-full text-xs border", modeBadge)}>
          {scan.scanMode}
        </span>
      </td>
      <td className="px-4 py-4">
        <span className="text-white/40 text-xs font-mono bg-white/[0.05] px-2 py-0.5 rounded">
          {scan.mode}
        </span>
      </td>
      <td className="px-4 py-4">
        <div className="flex items-center gap-2">
          {(scan.findingsCritical ?? 0) > 0 && (
            <span className="text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">
              {scan.findingsCritical} crit
            </span>
          )}
          {(scan.findingsHigh ?? 0) > 0 && (
            <span className="text-xs text-orange-400/80">+{scan.findingsHigh} high</span>
          )}
          {(scan.findingsCritical ?? 0) === 0 && (scan.findingsHigh ?? 0) === 0 && (
            <span className="text-xs text-green-400/70">Clean</span>
          )}
        </div>
      </td>
      <td className="px-4 py-4 text-white/30 text-xs">
        {scan.toolsScanned ?? 0} tools
      </td>
      <td className="px-4 py-4 text-white/30 text-xs font-mono">
        {elapsed(scan.startedAt, scan.completedAt)}
      </td>
      <td className="px-4 py-4 text-white/25 text-xs">
        {timeAgo(scan.createdAt)}
      </td>
    </tr>
  );
}
