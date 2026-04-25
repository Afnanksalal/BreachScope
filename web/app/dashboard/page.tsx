import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans, findings } from "@/lib/schema";
import { eq, desc, and, gte, count, sum } from "drizzle-orm";
import { TopBar } from "@/components/dashboard/TopBar";
import { StatsCard } from "@/components/dashboard/StatsCard";
import { ScanRow } from "@/components/dashboard/ScanRow";
import { RiskChart } from "@/components/dashboard/RiskChart";
import { FindingBreakdown } from "@/components/dashboard/FindingBreakdown";

export default async function DashboardPage() {
  const session = await auth();
  const userId = session!.user!.id!;

  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400 * 1000);

  const [recentScans, monthlyScans, categoryStats] = await Promise.all([
    db
      .select()
      .from(scans)
      .where(eq(scans.userId, userId))
      .orderBy(desc(scans.createdAt))
      .limit(20),

    db
      .select()
      .from(scans)
      .where(and(eq(scans.userId, userId), gte(scans.createdAt, thirtyDaysAgo)))
      .orderBy(desc(scans.createdAt)),

    // Finding counts by category for the last 30 days
    db
      .select({
        category: findings.category,
        total:    count(findings.id),
      })
      .from(findings)
      .innerJoin(scans, eq(findings.scanId, scans.id))
      .where(and(eq(scans.userId, userId), gte(scans.createdAt, thirtyDaysAgo)))
      .groupBy(findings.category),
  ]);

  const totalCritical = monthlyScans.reduce((a, s) => a + (s.findingsCritical ?? 0), 0);
  const totalHigh     = monthlyScans.reduce((a, s) => a + (s.findingsHigh    ?? 0), 0);
  const totalTools    = monthlyScans.reduce((a, s) => a + (s.toolsScanned    ?? 0), 0);
  const totalFindings = monthlyScans.reduce((a, s) => a + (s.findingsTotal   ?? 0), 0);

  const bugScans     = monthlyScans.filter((s) => s.scanMode === "bug");
  const breachScans  = monthlyScans.filter((s) => s.scanMode === "breach");
  const bugsFound    = bugScans.reduce((a, s) => a + (s.findingsTotal ?? 0), 0);
  const breachIssues = breachScans.reduce((a, s) => a + (s.findingsTotal ?? 0), 0);

  const catMap = Object.fromEntries(categoryStats.map((r) => [r.category, r.total]));

  return (
    <>
      <TopBar session={session} title="Overview" subtitle="Last 30 days" />

      <div className="flex-1 p-8 space-y-6">
        {/* Primary stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            title="Total Scans"
            value={monthlyScans.length}
            sub="last 30 days"
            accent="blue"
            index={0}
          />
          <StatsCard
            title="Critical"
            value={totalCritical}
            sub={totalCritical > 0 ? "requires immediate action" : "none found"}
            accent={totalCritical > 0 ? "red" : "green"}
            index={1}
          />
          <StatsCard
            title="High Severity"
            value={totalHigh}
            sub={totalHigh > 0 ? "should be addressed soon" : "none found"}
            accent={totalHigh > 0 ? "yellow" : "green"}
            index={2}
          />
          <StatsCard
            title="Tools Audited"
            value={totalTools}
            sub="across all scans"
            accent="default"
            index={3}
          />
        </div>

        {/* Secondary stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            title="Total Findings"
            value={totalFindings}
            sub="all severities"
            accent="default"
            index={4}
          />
          <StatsCard
            title="Bugs Found"
            value={bugsFound}
            sub={`${bugScans.length} bug scan${bugScans.length !== 1 ? "s" : ""}`}
            accent={bugsFound > 0 ? "yellow" : "green"}
            index={5}
          />
          <StatsCard
            title="Breach Issues"
            value={breachIssues}
            sub={`${breachScans.length} breach scan${breachScans.length !== 1 ? "s" : ""}`}
            accent={breachIssues > 0 ? "red" : "green"}
            index={6}
          />
          <StatsCard
            title="Code Issues"
            value={catMap["code"] ?? 0}
            sub="from static audit"
            accent={(catMap["code"] ?? 0) > 0 ? "yellow" : "green"}
            index={7}
          />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Risk trend chart */}
          <div className="lg:col-span-2 rounded-2xl bg-white/[0.04] p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-white font-semibold text-sm">Finding Trends</h2>
                <p className="text-white/30 text-xs">Last 14 scans</p>
              </div>
              <div className="flex items-center gap-4 text-xs text-white/30">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-red-500/80" />Critical
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-orange-500/60" />High
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-yellow-500/50" />Medium
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm bg-cyan-500/40" />Low
                </span>
              </div>
            </div>
            <RiskChart scans={recentScans} />
          </div>

          {/* Category breakdown */}
          <FindingBreakdown categories={catMap} total={totalFindings} />
        </div>

        {/* Recent scans */}
        <div className="rounded-2xl bg-white/[0.04] overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between">
            <h2 className="text-white font-semibold text-sm">Recent Scans</h2>
            <a href="/dashboard/scans" className="text-white/40 text-xs hover:text-white/70 transition-colors">
              View all →
            </a>
          </div>

          {recentScans.length === 0 ? (
            <div className="px-5 py-16 text-center">
              <p className="text-white/30 text-sm mb-4">No scans yet.</p>
              <code className="text-white/50 text-xs bg-white/[0.05] border border-white/[0.08] px-3 py-2 rounded-lg font-mono">
                breachscope scan --mode basic
              </code>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/[0.05]">
                  {["Project", "Mode", "Depth", "Findings", "Tools", "Duration", "When"].map((h) => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-white/25 font-medium first:px-5">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recentScans.slice(0, 8).map((scan) => (
                  <ScanRow key={scan.id} scan={scan} />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Quick start — only when no scans */}
        {recentScans.length === 0 && (
          <div className="rounded-2xl bg-white/[0.04] p-6">
            <h3 className="text-white font-semibold mb-3">Quick Start</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                { cmd: "breachscope login",             label: "1. Authenticate CLI" },
                { cmd: "breachscope init",              label: "2. Create config" },
                { cmd: "breachscope scan --mode basic", label: "3. Run first scan" },
              ].map(({ cmd, label }) => (
                <div key={cmd} className="p-4 rounded-xl bg-white/[0.03]">
                  <p className="text-white/40 text-xs mb-2">{label}</p>
                  <code className="text-white/65 text-xs font-mono">{cmd}</code>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
