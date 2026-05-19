"use client";

import { clsx } from "clsx";

interface FindingBreakdownProps {
  categories: Record<string, number>;
  total: number;
}

const CATEGORY_CONFIG: Record<string, { label: string; bar: string; text: string }> = {
  code:           { label: "Code Audit",    bar: "bg-white/50",         text: "text-white/70"   },
  dependency:     { label: "Dependencies",  bar: "bg-red-500/70",       text: "text-red-300"    },
  toolchain:      { label: "Toolchain",     bar: "bg-orange-500/70",    text: "text-orange-300" },
  blackbox:       { label: "Blackbox",      bar: "bg-yellow-500/70",    text: "text-yellow-300" },
  smoke:          { label: "Smoke Tests",   bar: "bg-white/30",         text: "text-white/50"   },
  "supply-chain": { label: "Supply Chain",  bar: "bg-rose-500/70",      text: "text-rose-300"   },
};

const ORDER = ["dependency", "supply-chain", "toolchain", "code", "blackbox", "smoke"];

export function FindingBreakdown({ categories, total }: FindingBreakdownProps) {
  const entries = ORDER
    .filter((k) => (categories[k] ?? 0) > 0)
    .map((k) => ({ key: k, count: categories[k] ?? 0, ...CATEGORY_CONFIG[k] }));

  const unknown = Object.entries(categories)
    .filter(([k]) => !ORDER.includes(k) && (categories[k] ?? 0) > 0)
    .reduce((a, [, v]) => a + v, 0);

  return (
    <div className="rounded-lg bg-white/[0.04] p-6">
      <div className="mb-6">
        <h2 className="text-white font-semibold text-sm">By Category</h2>
        <p className="text-white/30 text-xs">Last 30 days</p>
      </div>

      {total === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 text-center">
          <div className="w-8 h-8 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mb-3">
            <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
          </div>
          <p className="text-green-400/80 text-xs font-medium">No findings</p>
        </div>
      ) : (
        <div className="space-y-3.5">
          {entries.map(({ key, label, count, bar, text }) => {
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            return (
              <div key={key}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className={clsx("text-xs font-medium", text)}>{label}</span>
                  <span className="text-white/35 text-xs tabular-nums">{count}</span>
                </div>
                <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                  <div
                    className={clsx("h-full rounded-full transition-all duration-700", bar)}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
          {unknown > 0 && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-medium text-white/35">Other</span>
                <span className="text-white/25 text-xs">{unknown}</span>
              </div>
              <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-white/20"
                  style={{ width: `${Math.round((unknown / total) * 100)}%` }}
                />
              </div>
            </div>
          )}

          <div className="pt-3 border-t border-white/[0.06] flex items-center justify-between">
            <span className="text-white/25 text-xs">Total</span>
            <span className="text-white/60 text-sm font-semibold tabular-nums">{total}</span>
          </div>
        </div>
      )}
    </div>
  );
}
