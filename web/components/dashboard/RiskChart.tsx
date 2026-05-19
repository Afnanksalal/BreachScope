"use client";

import { motion } from "framer-motion";
import type { Scan } from "@/lib/schema";

interface RiskChartProps {
  scans: Scan[];
}

export function RiskChart({ scans }: RiskChartProps) {
  const last14 = scans.slice(0, 14).reverse();

  if (last14.length === 0) {
    return (
      <div className="h-32 flex items-center justify-center text-white/20 text-sm">
        No scan data yet
      </div>
    );
  }

  const maxFindings = Math.max(...last14.map((s) => s.findingsTotal ?? 0), 1);

  return (
    <div className="relative h-32 flex items-end gap-1 px-1">
      {last14.map((scan, i) => {
        const critical = ((scan.findingsCritical ?? 0) / maxFindings) * 100;
        const high = ((scan.findingsHigh ?? 0) / maxFindings) * 100;
        const medium = ((scan.findingsMedium ?? 0) / maxFindings) * 100;
        const low = ((scan.findingsLow ?? 0) / maxFindings) * 100;
        const totalH = Math.min(critical + high + medium + low, 100);

        return (
          <motion.div
            key={scan.id}
            initial={{ height: 0 }}
            animate={{ height: `${totalH}%` }}
            transition={{ duration: 0.5, delay: i * 0.03 }}
            className="flex-1 rounded-t-sm flex flex-col-reverse overflow-hidden cursor-pointer group relative"
            title={`${scan.project ?? "Scan"}: ${scan.findingsTotal} findings`}
          >
            {low > 0 && <div style={{ height: `${(low / totalH) * 100}%` }} className="bg-cyan-500/40" />}
            {medium > 0 && <div style={{ height: `${(medium / totalH) * 100}%` }} className="bg-yellow-500/50" />}
            {high > 0 && <div style={{ height: `${(high / totalH) * 100}%` }} className="bg-orange-500/60" />}
            {critical > 0 && <div style={{ height: `${(critical / totalH) * 100}%` }} className="bg-red-500/80" />}
          </motion.div>
        );
      })}
    </div>
  );
}
