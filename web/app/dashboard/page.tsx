import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans, findings } from "@/lib/schema";
import { eq, desc, and, gte, count } from "drizzle-orm";
import { TopBar } from "@/components/dashboard/TopBar";
import { StatsCard } from "@/components/dashboard/StatsCard";
import { ScanRow } from "@/components/dashboard/ScanRow";
import { RiskChart } from "@/components/dashboard/RiskChart";
import { FindingBreakdown } from "@/components/dashboard/FindingBreakdown";

function timeAgo(date: Date | string): string {
  const diff = (Date.now() - new Date(date).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default async function DashboardPage() {
  const session = await auth();
  const userId = session!.user!.id!;

  // eslint-disable-next-line react-hooks/purity
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

  const catMap = Object.fromEntries(categoryStats.map((r) => [r.category, r.total]));

  return (
    <>
      <TopBar session={session} title="Overview" subtitle="Last 30 days" />

      <div className="flex-1 space-y-6 px-4 py-5 sm:px-6 md:px-8">
        <section className="rounded-lg border border-white/[0.08] bg-white/[0.035] p-5">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase text-white/32">Command center</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">Security posture, last 30 days</h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-white/48">
                Track scan velocity, critical risk, high-priority backlog, and dependency coverage from the same evidence stream used by CI gates and release artifacts.
              </p>
            </div>
            <div className="grid grid-cols-1 gap-2 text-center min-[420px]:grid-cols-3 lg:min-w-[22rem]">
              {[
                ["Policy", totalCritical > 0 || totalHigh > 0 ? "review" : "passing"],
                ["Scans", String(monthlyScans.length)],
                ["Findings", String(totalFindings)],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/[0.08] bg-black/25 px-4 py-3">
                  <p className="text-sm font-semibold text-white">{value}</p>
                  <p className="mt-1 text-xs text-white/32">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Primary stats */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <StatsCard
            title="Total Findings"
            value={totalFindings}
            sub="all severities"
            accent="default"
            index={4}
          />
          <StatsCard
            title="Code Issues"
            value={catMap["code"] ?? 0}
            sub="from static audit"
            accent={(catMap["code"] ?? 0) > 0 ? "yellow" : "green"}
            index={5}
          />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Risk trend chart */}
          <div className="rounded-lg border border-white/[0.08] bg-white/[0.035] p-4 sm:p-6 lg:col-span-2">
            <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-white font-semibold text-sm">Finding Trends</h2>
                <p className="text-white/30 text-xs">Last 14 scans</p>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-xs text-white/30 sm:gap-4">
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
        <div className="rounded-lg border border-white/[0.08] bg-white/[0.035] overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between">
            <h2 className="text-white font-semibold text-sm">Recent Scans</h2>
            <a href="/dashboard/scans" className="text-white/40 text-xs hover:text-white/70 transition-colors">
              View all {"->"}
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
            <>
            <div className="grid gap-3 p-3 md:hidden">
              {recentScans.slice(0, 8).map((scan) => (
                <a
                  key={scan.id}
                  href={`/dashboard/scan/${scan.id}`}
                  className="rounded-lg border border-white/[0.07] bg-black/20 p-4 transition-colors hover:bg-white/[0.04]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-white/80">{scan.project ?? "Unnamed project"}</p>
                      {scan.url && <p className="mt-0.5 truncate text-xs text-white/30">{scan.url}</p>}
                    </div>
                    <span className="shrink-0 rounded-full border border-white/[0.10] bg-white/[0.05] px-2 py-0.5 text-xs text-white/45">
                      {scan.scanMode}
                    </span>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-white/35">
                    <span>{scan.mode}</span>
                    <span>{scan.findingsTotal ?? 0} findings</span>
                    <span>{scan.toolsScanned ?? 0} tools</span>
                    <span>{timeAgo(scan.createdAt)}</span>
                  </div>
                </a>
              ))}
            </div>
            <div className="hidden overflow-x-auto md:block">
            <table className="w-full min-w-[760px]">
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
            </div>
            </>
          )}
        </div>

        {/* Quick start - only when no scans */}
        {recentScans.length === 0 && (
          <div className="rounded-lg border border-white/[0.08] bg-white/[0.035] p-6">
            <h3 className="text-white font-semibold mb-3">Quick Start</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                { cmd: "breachscope login",             label: "1. Authenticate CLI" },
                { cmd: "breachscope init",              label: "2. Create config" },
                { cmd: "breachscope scan --mode basic", label: "3. Run first scan" },
              ].map(({ cmd, label }) => (
                <div key={cmd} className="p-4 rounded-lg bg-white/[0.03]">
                  <p className="text-white/40 text-xs mb-2">{label}</p>
                  <code className="break-words font-mono text-xs text-white/65">{cmd}</code>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
