"use client";

import { useState } from "react";
import { Check, Clipboard, Info, Lightbulb, TriangleAlert } from "lucide-react";

export function CodeBlock({ code, lang = "bash" }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="group relative mb-2 overflow-hidden rounded-lg border border-white/[0.07] bg-[#080909]">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2">
        <span className="font-mono text-[11px] text-white/28">{lang}</span>
        <button
          onClick={copy}
          className="flex items-center gap-1.5 text-[11px] text-white/34 opacity-0 transition-colors hover:text-white group-hover:opacity-100"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Clipboard className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-4 font-mono text-xs leading-relaxed text-white/70 sm:text-sm">
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
    note: {
      border: "border-white/[0.1]",
      bg: "bg-white/[0.035]",
      icon: Info,
      iconColor: "text-white/45",
    },
    warning: {
      border: "border-amber-300/20",
      bg: "bg-amber-300/[0.055]",
      icon: TriangleAlert,
      iconColor: "text-amber-200/75",
    },
    tip: {
      border: "border-emerald-300/20",
      bg: "bg-emerald-300/[0.055]",
      icon: Lightbulb,
      iconColor: "text-emerald-200/75",
    },
  }[type];
  const Icon = styles.icon;

  return (
    <div className={`mb-4 flex gap-3 rounded-lg border ${styles.border} ${styles.bg} px-4 py-3.5`}>
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${styles.iconColor}`} aria-hidden="true" />
      <div className="text-sm leading-relaxed text-white/55">{children}</div>
    </div>
  );
}
