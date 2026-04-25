"use client";

import { useState } from "react";

export function CodeBlock({ code, lang = "bash" }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="relative rounded-xl bg-[#0d0d0d] border border-white/[0.06] overflow-hidden mb-2 group">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.05]">
        <span className="text-[11px] text-white/25 font-mono">{lang}</span>
        <button
          onClick={copy}
          className="text-[11px] text-white/25 hover:text-white/60 transition-colors flex items-center gap-1.5 opacity-0 group-hover:opacity-100"
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-green-400">Copied</span>
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <rect x="9" y="9" width="13" height="13" rx="2" />
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
              </svg>
              Copy
            </>
          )}
        </button>
      </div>
      <pre className="px-4 py-4 text-sm font-mono text-white/70 overflow-x-auto leading-relaxed scrollbar-thin">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function Callout({
  type = "note",
  children,
}: {
  type?: "note" | "warning" | "tip";
  children: React.ReactNode;
}) {
  const styles = {
    note:    { border: "border-white/10",  bg: "bg-white/[0.03]",  icon: "ℹ", iconColor: "text-white/40" },
    warning: { border: "border-amber-500/20", bg: "bg-amber-500/[0.05]", icon: "⚠", iconColor: "text-amber-400/70" },
    tip:     { border: "border-emerald-500/20", bg: "bg-emerald-500/[0.05]", icon: "✦", iconColor: "text-emerald-400/70" },
  }[type];

  return (
    <div className={`rounded-xl border ${styles.border} ${styles.bg} px-4 py-3.5 mb-4 flex gap-3`}>
      <span className={`${styles.iconColor} text-sm mt-0.5 shrink-0`}>{styles.icon}</span>
      <div className="text-sm text-white/50 leading-relaxed">{children}</div>
    </div>
  );
}
