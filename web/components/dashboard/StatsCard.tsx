"use client";

import { motion } from "framer-motion";
import { clsx } from "clsx";

type Accent = "red" | "yellow" | "blue" | "green" | "default";

interface StatsCardProps {
  title: string;
  value: string | number;
  sub?: string;
  trend?: { value: number; label: string };
  accent?: Accent;
  index?: number;
}

const ACCENT_BORDER: Record<Accent, string> = {
  red:     "bg-red-500/[0.06]",
  yellow:  "bg-yellow-500/[0.06]",
  blue:    "bg-white/[0.04]",
  green:   "bg-green-500/[0.06]",
  default: "bg-white/[0.04]",
};

const VALUE_COLOR: Record<Accent, string> = {
  red:     "text-red-400",
  yellow:  "text-yellow-400",
  blue:    "text-white/90",
  green:   "text-green-400",
  default: "text-white/90",
};

const TREND_ICONS = {
  up: (
    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 19.5l15-15m0 0H8.25m11.25 0v11.25" />
    </svg>
  ),
  down: (
    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 4.5l-15 15m0 0h11.25m-11.25 0V8.25" />
    </svg>
  ),
};

export function StatsCard({ title, value, sub, trend, accent = "default", index = 0 }: StatsCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.04, ease: [0.16, 1, 0.3, 1] }}
      className={clsx("p-5 rounded-2xl transition-colors", ACCENT_BORDER[accent])}
    >
      <p className="text-white/35 text-[0.6875rem] font-semibold uppercase tracking-[0.1em] mb-3">
        {title}
      </p>
      <p className={clsx("text-[2rem] font-bold tabular-nums leading-none mb-1", VALUE_COLOR[accent])}>
        {value}
      </p>
      {sub && (
        <p className="text-white/25 text-xs mt-1.5">{sub}</p>
      )}
      {trend && (
        <div className={clsx(
          "flex items-center gap-1 mt-2.5 text-xs font-medium",
          trend.value > 0 ? "text-red-400" : "text-green-400"
        )}>
          {trend.value > 0 ? TREND_ICONS.up : TREND_ICONS.down}
          {Math.abs(trend.value)} {trend.label}
        </div>
      )}
    </motion.div>
  );
}
