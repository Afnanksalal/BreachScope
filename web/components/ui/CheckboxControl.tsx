"use client";

import { Check } from "lucide-react";
import { clsx } from "clsx";

interface CheckboxControlProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
  className?: string;
}

export function CheckboxControl({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  className,
}: CheckboxControlProps) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        "flex min-w-0 items-start gap-3 rounded-lg border border-white/[0.08] bg-black/20 px-3 py-2 text-left text-xs text-white/55 transition-colors",
        "hover:border-white/[0.14] hover:bg-white/[0.04] hover:text-white/72 focus:outline-none focus:border-white/20",
        checked && "border-white/[0.18] bg-white/[0.07] text-white/82",
        disabled && "cursor-not-allowed opacity-45",
        className,
      )}
    >
      <span
        className={clsx(
          "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors",
          checked ? "border-white/60 bg-white text-black" : "border-white/[0.14] bg-white/[0.035] text-transparent",
        )}
      >
        <Check className="h-3 w-3" />
      </span>
      <span className="min-w-0">
        <span className="block leading-5">{label}</span>
        {description && <span className="mt-0.5 block text-[11px] leading-4 text-white/32">{description}</span>}
      </span>
    </button>
  );
}
