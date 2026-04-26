"use client";

import { useState, useCallback, useMemo } from "react";
import { clsx } from "clsx";
import type { Scan, Finding } from "@/lib/schema";

// ─── Shared types ─────────────────────────────────────────────────────────────

interface ToolRiskEntry {
  name: string; kind: string; depth: number; parent?: string;
  riskScore: number; aiSummary?: string;
  osvCount: number; osvIds?: string[];
  scorecardScore?: number; weeklyDownloads?: number; maintainerCount?: number;
  findingsCount: number;
  github?: string;
  version?: string;
}

interface AttackChain {
  title: string;
  severity: string;
  steps: string[];
  impact: string;
}

interface AISynthesis {
  executiveSummary: string;
  criticalPath?: string;
  topPriority?: string;
  attackChains?: AttackChain[];
}

interface ServiceProbeActivity {
  id: string; name: string; category: string;
  steps: string[]; findingsCount: number; tokensUsed: number;
}

interface SandboxActivity {
  projectType: string;
  attackLog: string[];
  attackChains: string[];
  findingsCount: number;
  tokensUsed: number;
}

interface ProbeActivity {
  services?: ServiceProbeActivity[];
  sandbox?: SandboxActivity;
}

// ─── Smart group types ────────────────────────────────────────────────────────

type SmartGroupKey = "secrets" | "injection" | "auth" | "supplychain" | "infra" | "code" | "other";

interface SmartGroupMeta {
  key: SmartGroupKey;
  label: string;
  description: string;
  priority: number;
  colorBorder: string;
  colorBg: string;
  colorText: string;
  colorDot: string;
}

const SMART_GROUPS: SmartGroupMeta[] = [
  { key: "secrets",     label: "Secrets & Credentials",   description: "API keys, passwords, tokens, .env exposure", priority: 0, colorBorder: "border-red-500/30",    colorBg: "bg-red-500/[0.05]",    colorText: "text-red-300",    colorDot: "bg-red-500"    },
  { key: "injection",   label: "Injection Attacks",        description: "SQL, command, SSTI, XXE, SSRF, path traversal", priority: 1, colorBorder: "border-orange-500/30", colorBg: "bg-orange-500/[0.05]", colorText: "text-orange-300", colorDot: "bg-orange-500" },
  { key: "auth",        label: "Auth & Authorization",     description: "JWT flaws, IDOR, CSRF, session issues, rate limiting", priority: 2, colorBorder: "border-yellow-500/30", colorBg: "bg-yellow-500/[0.05]", colorText: "text-yellow-300", colorDot: "bg-yellow-500" },
  { key: "supplychain", label: "Supply Chain",             description: "Dependency CVEs, malicious packages, unsafe versions", priority: 3, colorBorder: "border-purple-500/30", colorBg: "bg-purple-500/[0.05]", colorText: "text-purple-300", colorDot: "bg-purple-500" },
  { key: "infra",       label: "Infrastructure & Config",  description: "Toolchain misconfigs, security headers, CORS, TLS", priority: 4, colorBorder: "border-cyan-500/30",   colorBg: "bg-cyan-500/[0.05]",   colorText: "text-cyan-300",   colorDot: "bg-cyan-500"   },
  { key: "code",        label: "Code Security Patterns",   description: "Static analysis findings, dangerous patterns", priority: 5, colorBorder: "border-white/10",      colorBg: "bg-white/[0.02]",      colorText: "text-white/60",   colorDot: "bg-white/40"   },
  { key: "other",       label: "Other Findings",           description: "Miscellaneous security issues", priority: 6, colorBorder: "border-white/[0.06]",  colorBg: "bg-white/[0.01]",      colorText: "text-white/40",   colorDot: "bg-white/30"   },
];

function categorizeFinding(f: Finding): SmartGroupKey {
  const text = `${f.title} ${f.description}`.toLowerCase();
  const isCode = f.category === "code";

  if (isCode && /secret|api[._\s-]?key|password|credential|private[._\s-]?key|\.env|auth[._\s-]?token|bearer|stripe[._\s-]?key|openai|jwt[._\s-]?secret|database[._\s-]?url/.test(text)) return "secrets";
  if (/sql[.\s-]?inject|command[.\s-]?inject|ssti|server[.\s-]?side[.\s-]?template|xxe|ldap[.\s-]?inject|header[.\s-]?inject|ssrf|path[.\s-]?travers|local[.\s-]?file|lfi|rfi|rce|remote[.\s-]?code/.test(text)) return "injection";
  if (/jwt|auth[.\s-]?bypass|idor|bola|session|csrf|cross[.\s-]?site[.\s-]?req|unauthorized|privilege[.\s-]?escal|rate[.\s-]?limit|brute[.\s-]?force|broken[.\s-]?auth/.test(text)) return "auth";
  if (f.category === "dependency" || f.category === "supply-chain") return "supplychain";
  if (f.category === "toolchain" || f.category === "blackbox") return "infra";
  if (isCode) return "code";
  return "other";
}

// ─── Known historically-compromised packages ──────────────────────────────────

const KNOWN_COMPROMISED = new Set([
  "event-stream", "flatmap-stream", "eslint-scope", "getcookies",
  "bootstrap-sass", "rest-client", "ua-parser-js", "coa", "rc",
  "colors", "faker", "node-ipc", "peacenotwar",
  "node-pre-gyp-github", "electron-native-notify",
  "crossenv", "cross-env.js", "d3.js", "fabric-js",
  "ffmepg", "gruntcli", "http-proxy.js", "jquery.js",
  "mongose", "mssql.js", "mssql-node", "mysqljs",
  "nodecaffe", "nodefabric", "node-fabric", "nodeffmpeg",
  "nodesass", "node-sass.js", "nodesqlite", "node-sqlite",
  "nodesqlite3", "node-bunyan", "nodejquery",
  "socket.io.js", "socketio", "sqliter", "sqlserver",
  "tensorflow.js", "web3-util", "1337qq-js", "klow", "klown",
  "lodash-express", "discord.js-updated",
]);

// ─── Severity ─────────────────────────────────────────────────────────────────

const SEV = {
  CRITICAL: { label: "Critical", bar: "bg-red-500",    badge: "bg-red-500/15 border-red-500/30 text-red-300",    dot: "bg-red-500",    text: "text-red-400" },
  HIGH:     { label: "High",     bar: "bg-orange-500", badge: "bg-orange-500/15 border-orange-500/30 text-orange-300", dot: "bg-orange-500", text: "text-orange-400" },
  MEDIUM:   { label: "Medium",   bar: "bg-yellow-500", badge: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300", dot: "bg-yellow-500", text: "text-yellow-400" },
  LOW:      { label: "Low",      bar: "bg-cyan-500",   badge: "bg-cyan-500/15 border-cyan-500/30 text-cyan-300",   dot: "bg-cyan-500",   text: "text-cyan-400" },
};
const getSev = (k: string) => SEV[k.toUpperCase() as keyof typeof SEV] ?? SEV.LOW;

const CAT_LABELS: Record<string, string> = {
  dependency: "Dependency", toolchain: "Toolchain", code: "Code",
  blackbox: "Blackbox", "supply-chain": "Supply Chain",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function elapsed(start: Date | string, end?: Date | string | null): string {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}
function fmtNum(n?: number): string {
  if (!n) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}K`;
  return String(n);
}

// ─── Small atoms ─────────────────────────────────────────────────────────────

function RiskBar({ score }: { score: number }) {
  const color = score >= 75 ? "bg-red-500" : score >= 50 ? "bg-orange-500" : score >= 25 ? "bg-yellow-500" : "bg-green-500";
  const text  = score >= 75 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 25 ? "text-yellow-400" : "text-green-400";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden max-w-[72px]">
        <div className={clsx("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className={clsx("text-xs font-mono font-semibold tabular-nums w-5 text-right", text)}>{score}</span>
    </div>
  );
}

function KindBadge({ kind }: { kind: string }) {
  const cls = kind === "oss" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
    : kind === "saas"   ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
    : kind === "hybrid" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
    : "bg-white/5 text-white/30 border-white/10";
  const label = kind === "oss" ? "OSS" : kind === "saas" ? "SaaS" : kind === "hybrid" ? "Hybrid" : "?";
  return <span className={clsx("px-1.5 py-0.5 rounded text-[10px] border font-medium uppercase tracking-wide shrink-0", cls)}>{label}</span>;
}

function Chip({ label, count, active, onClick }: { label: string; count: number; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
        active
          ? "bg-white/10 border-white/20 text-white"
          : "bg-white/[0.03] border-white/[0.07] text-white/40 hover:text-white/60 hover:border-white/15"
      )}
    >
      {label}
      <span className={clsx("text-[10px] font-mono", active ? "text-white/60" : "text-white/25")}>{count}</span>
    </button>
  );
}

// ─── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const sev = getSev(finding.severity);
  let refs: string[] = [];
  try { refs = finding.references ? (JSON.parse(finding.references) as string[]) : []; } catch {}

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-5 py-4 text-left hover:bg-white/[0.02] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <span className={clsx("mt-0.5 px-2 py-0.5 rounded-full text-xs border font-medium shrink-0", sev.badge)}>
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-white/85 text-sm font-medium leading-snug">{finding.title}</p>
          <p className="text-white/30 text-xs mt-0.5">
            {CAT_LABELS[finding.category] ?? finding.category}
            {finding.tool ? ` · ${finding.tool}` : ""}
            {finding.file ? ` · ${finding.file}${finding.line ? `:${finding.line}` : ""}` : ""}
          </p>
        </div>
        <svg className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 mt-1 transition-transform duration-150", open && "rotate-180")}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-3 border-t border-white/[0.04] pt-4">
          <p className="text-white/55 text-sm leading-relaxed">{finding.description}</p>
          {finding.detail && (
            <div className="p-3 rounded-lg bg-black/30 border border-white/[0.06] overflow-x-auto">
              <p className="text-white/25 text-[10px] font-semibold uppercase tracking-wider mb-1.5">Matched Code</p>
              <pre className="text-red-300/80 text-xs font-mono whitespace-pre-wrap break-all leading-relaxed">{finding.detail}</pre>
            </div>
          )}
          {finding.remediation && (
            <div className="p-3 rounded-lg bg-white/[0.04] border border-white/[0.06]">
              <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-1.5">Fix</p>
              <p className="text-white/55 text-sm leading-relaxed">{finding.remediation}</p>
            </div>
          )}
          {refs.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {refs.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                  className="text-white/35 text-xs hover:text-white/60 underline underline-offset-2 truncate max-w-xs transition-colors">
                  {ref.replace(/^https?:\/\//, "").slice(0, 60)}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── AI synthesis section ─────────────────────────────────────────────────────

function AISynthesisSection({ synthesis }: { synthesis: AISynthesis }) {
  return (
    <div className="space-y-3">
      <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/[0.06]">
        <p className="text-white/35 text-[10px] font-semibold uppercase tracking-wider mb-2">AI Executive Summary</p>
        <p className="text-white/70 text-sm leading-relaxed">{synthesis.executiveSummary}</p>
      </div>

      {synthesis.topPriority && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/[0.07] border border-red-500/20">
          <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/20 text-red-300 border border-red-500/30 mt-0.5">
            Top Priority
          </span>
          <p className="text-red-200/75 text-sm leading-relaxed">{synthesis.topPriority}</p>
        </div>
      )}

      {(synthesis.attackChains?.length ?? 0) > 0 && (
        <div>
          <p className="text-white/35 text-[10px] font-semibold uppercase tracking-wider mb-2">Attack Chains Identified</p>
          <div className="space-y-2">
            {synthesis.attackChains!.map((chain, i) => (
              <div key={i} className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                <div className="flex items-center gap-2 mb-2">
                  <span className={clsx(
                    "shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase border",
                    chain.severity === "critical"
                      ? "bg-red-500/15 border-red-500/30 text-red-300"
                      : "bg-orange-500/15 border-orange-500/30 text-orange-300"
                  )}>{chain.severity}</span>
                  <p className="text-white/70 text-sm font-medium">{chain.title}</p>
                </div>
                {chain.impact && <p className="text-white/35 text-xs mb-2 leading-relaxed">{chain.impact}</p>}
                <ol className="space-y-1">
                  {chain.steps.map((step, j) => (
                    <li key={j} className="flex items-start gap-2 text-white/40 text-xs">
                      <span className="shrink-0 text-white/20 font-mono w-4">{j + 1}.</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Tool risk table ──────────────────────────────────────────────────────────

function ToolRiskTable({ tools, findings }: { tools: ToolRiskEntry[]; findings: Finding[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const sorted = [...tools].sort((a, b) => b.riskScore - a.riskScore);
  return (
    <div className="space-y-1">
      {sorted.map((t) => {
        const toolFindings = findings.filter((f) => f.tool === t.name);
        return (
        <div key={t.name} className="rounded-xl border border-white/[0.06] overflow-hidden">
          <button
            className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.03] transition-colors text-left min-w-0"
            onClick={() => setExpanded(expanded === t.name ? null : t.name)}
          >
            {t.depth > 0 && <span className="text-white/20 text-xs shrink-0 font-mono">{"└─".repeat(t.depth)}</span>}
            <div className="flex-1 min-w-0">
              <span className="text-sm text-white/75 font-mono truncate block">{t.name}</span>
              {t.version && <span className="text-white/25 text-[10px] font-mono">v{t.version}</span>}
            </div>
            <KindBadge kind={t.kind} />
            {t.osvCount > 0 && <span className="text-red-400 text-xs shrink-0">{t.osvCount} CVE{t.osvCount !== 1 ? "s" : ""}</span>}
            {t.findingsCount > 0 && <span className="text-orange-400/70 text-xs shrink-0 hidden sm:inline">{t.findingsCount} finding{t.findingsCount !== 1 ? "s" : ""}</span>}
            <div className="shrink-0 w-28 hidden sm:block"><RiskBar score={t.riskScore} /></div>
            <svg className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 transition-transform duration-150", expanded === t.name && "rotate-180")}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {expanded === t.name && (
            <div className="px-4 pb-4 border-t border-white/[0.04] space-y-3 pt-3">
              {/* Header links */}
              {t.github && (
                <a href={t.github} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-white/35 text-xs hover:text-white/60 transition-colors font-mono">
                  <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                  </svg>
                  {t.github.replace("https://github.com/", "")}
                </a>
              )}

              {t.aiSummary && !t.aiSummary.includes("unavailable") && (
                <p className="text-white/45 text-sm leading-relaxed">{t.aiSummary}</p>
              )}

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {t.scorecardScore !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">OpenSSF</p>
                    <p className={clsx("text-sm font-semibold", t.scorecardScore >= 7 ? "text-green-400" : t.scorecardScore >= 4 ? "text-yellow-400" : "text-red-400")}>
                      {t.scorecardScore.toFixed(1)}/10
                    </p>
                  </div>
                )}
                {t.weeklyDownloads !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Weekly DLs</p>
                    <p className="text-white/60 text-sm font-semibold">{fmtNum(t.weeklyDownloads)}</p>
                  </div>
                )}
                {t.maintainerCount !== undefined && (
                  <div className="p-2.5 rounded-lg bg-white/[0.04]">
                    <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Maintainers</p>
                    <p className={clsx("text-sm font-semibold", t.maintainerCount === 0 ? "text-red-400" : t.maintainerCount === 1 ? "text-orange-400" : "text-white/60")}>
                      {t.maintainerCount}
                    </p>
                  </div>
                )}
                <div className="p-2.5 rounded-lg bg-white/[0.04]">
                  <p className="text-white/30 text-[10px] uppercase tracking-wider mb-1">Risk Score</p>
                  <p className={clsx("text-sm font-semibold", t.riskScore >= 75 ? "text-red-400" : t.riskScore >= 50 ? "text-orange-400" : t.riskScore >= 25 ? "text-yellow-400" : "text-green-400")}>
                    {t.riskScore}/100
                  </p>
                </div>
              </div>

              {/* CVE IDs with OSV links */}
              {t.osvIds && t.osvIds.length > 0 && (
                <div>
                  <p className="text-white/25 text-[10px] uppercase tracking-wider mb-1.5">
                    CVEs {t.version ? <span className="normal-case">affecting v{t.version}</span> : ""}
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {t.osvIds.map((id) => (
                      <a key={id} href={`https://osv.dev/vulnerability/${id}`} target="_blank" rel="noopener noreferrer"
                        className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs hover:bg-red-500/20 transition-colors font-mono">
                        {id}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Tool-specific findings */}
              {toolFindings.length > 0 && (
                <div>
                  <p className="text-white/25 text-[10px] uppercase tracking-wider mb-1.5">Findings ({toolFindings.length})</p>
                  <div className="space-y-1.5">
                    {toolFindings.map((f) => {
                      const sev = getSev(f.severity);
                      return (
                        <div key={f.id} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                          <span className={clsx("shrink-0 px-1.5 py-0.5 rounded text-[10px] border font-medium mt-0.5", sev.badge)}>
                            {sev.label}
                          </span>
                          <div className="min-w-0">
                            <p className="text-white/65 text-xs font-medium leading-snug">{f.title}</p>
                            {f.description && (
                              <p className="text-white/30 text-xs mt-0.5 leading-relaxed line-clamp-2">{f.description}</p>
                            )}
                            {f.remediation && (
                              <p className="text-green-400/60 text-xs mt-1">Fix: {f.remediation.slice(0, 100)}{f.remediation.length > 100 ? "…" : ""}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {t.parent && <p className="text-white/20 text-xs">Introduced via <span className="font-mono text-white/35">{t.parent}</span></p>}
            </div>
          )}
        </div>
        );
      })}
    </div>
  );
}

// ─── Probe timeline ───────────────────────────────────────────────────────────

const SERVICE_ABBR: Record<string, string> = {
  supabase: "SB", firebase: "FB", neon: "NE", planetscale: "PS",
  upstash: "UP", clerk: "CL", auth0: "A0", vercel: "VC", github: "GH",
  aws: "AWS", cloudflare: "CF", stripe: "ST", resend: "RS", sendgrid: "SG",
  twilio: "TW", openai: "OA", anthropic: "AN", pinecone: "PC",
  sentry: "SN", datadog: "DD",
};

function ServiceProbeCard({ svc }: { svc: ServiceProbeActivity }) {
  const [open, setOpen] = useState(false);
  const abbr = SERVICE_ABBR[svc.id] ?? svc.id.slice(0, 2).toUpperCase();
  return (
    <div className="rounded-xl border border-white/[0.06] overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-white/[0.03] transition-colors text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="w-8 h-8 rounded-lg bg-white/[0.06] border border-white/[0.08] flex items-center justify-center text-[10px] font-mono font-bold text-white/50 shrink-0">{abbr}</span>
        <div className="flex-1 min-w-0">
          <p className="text-white/80 text-sm font-medium">{svc.name}</p>
          <p className="text-white/30 text-xs">{svc.category}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {svc.findingsCount > 0
            ? <span className="px-2 py-0.5 rounded-full text-xs bg-orange-500/15 border border-orange-500/25 text-orange-300">{svc.findingsCount} finding{svc.findingsCount !== 1 ? "s" : ""}</span>
            : <span className="px-2 py-0.5 rounded-full text-xs bg-green-500/10 border border-green-500/20 text-green-400">Clean</span>
          }
          <span className="text-white/20 text-xs font-mono hidden sm:inline">{svc.steps.length} calls</span>
          <svg className={clsx("w-3.5 h-3.5 text-white/20 transition-transform duration-150", open && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {open && (
        <div className="border-t border-white/[0.04] px-4 py-3">
          <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-2.5">API Calls & Actions</p>
          <div className="space-y-1">
            {svc.steps.map((step, i) => {
              const isHttp = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS)/.test(step);
              const isSearch = step.startsWith("web search");
              const isCrawl = step.startsWith("crawl");
              return (
                <div key={i} className="flex items-start gap-2.5">
                  <span className={clsx(
                    "mt-0.5 text-[10px] font-mono shrink-0 px-1.5 py-0.5 rounded",
                    isHttp   ? "bg-blue-500/10 text-blue-400" :
                    isSearch ? "bg-purple-500/10 text-purple-400" :
                    isCrawl  ? "bg-cyan-500/10 text-cyan-400" :
                    "bg-white/5 text-white/30"
                  )}>
                    {isHttp ? step.split(" ")[0] : isSearch ? "SRCH" : isCrawl ? "CRAWL" : "SYS"}
                  </span>
                  <span className="text-white/45 text-xs font-mono leading-relaxed break-all">
                    {isHttp ? step.split(" ").slice(1).join(" ") : step.replace(/^web search: "|crawl /g, "").replace(/"$/, "")}
                  </span>
                </div>
              );
            })}
          </div>
          {svc.tokensUsed > 0 && (
            <p className="text-white/20 text-xs mt-3 font-mono">{svc.tokensUsed.toLocaleString()} tokens used</p>
          )}
        </div>
      )}
    </div>
  );
}


// ─── Terminal line renderer ───────────────────────────────────────────────────

interface TermLine {
  type: "finding_critical" | "finding_high" | "finding_medium" | "finding_low"
      | "chain" | "credential" | "attempt_success" | "attempt_partial" | "attempt_failed"
      | "exec" | "http" | "info";
  prefix: string;
  text: string;
}

function parseTermLine(entry: string): TermLine {
  if (/^FINDING \[CRITICAL\]/.test(entry)) return { type: "finding_critical", prefix: "● CRITICAL", text: entry.replace(/^FINDING \[CRITICAL\]:\s*/, "") };
  if (/^FINDING \[HIGH\]/.test(entry))     return { type: "finding_high",     prefix: "● HIGH",     text: entry.replace(/^FINDING \[HIGH\]:\s*/, "") };
  if (/^FINDING \[MEDIUM\]/.test(entry))   return { type: "finding_medium",   prefix: "● MEDIUM",   text: entry.replace(/^FINDING \[MEDIUM\]:\s*/, "") };
  if (/^FINDING \[LOW\]/.test(entry))      return { type: "finding_low",      prefix: "● LOW",      text: entry.replace(/^FINDING \[LOW\]:\s*/, "") };
  if (/^CHAIN:/.test(entry))               return { type: "chain",            prefix: "⛓ CHAIN",    text: entry.replace(/^CHAIN:\s*/, "") };
  if (/^CREDENTIAL:/.test(entry))          return { type: "credential",       prefix: "🔑 CRED",    text: entry.replace(/^CREDENTIAL:\s*/, "") };
  if (/^ATTEMPT \[SUCCESS\]/.test(entry))  return { type: "attempt_success",  prefix: "✓ SUCCESS",  text: entry.replace(/^ATTEMPT \[SUCCESS\]:\s*/, "") };
  if (/^ATTEMPT \[PARTIAL\]/.test(entry))  return { type: "attempt_partial",  prefix: "~ PARTIAL",  text: entry.replace(/^ATTEMPT \[PARTIAL\]:\s*/, "") };
  if (/^ATTEMPT \[FAILED\]/.test(entry))   return { type: "attempt_failed",   prefix: "✗ FAILED",   text: entry.replace(/^ATTEMPT \[FAILED\]:\s*/, "") };
  if (/^exec:/.test(entry))                return { type: "exec",             prefix: "$",           text: entry.replace(/^exec:\s*/, "") };
  if (/^HTTP /.test(entry))                return { type: "http",             prefix: "→",           text: entry };
  return { type: "info", prefix: "·", text: entry };
}

const TERM_LINE_STYLES: Record<TermLine["type"], { prefix: string; text: string }> = {
  finding_critical: { prefix: "text-red-400 font-bold",    text: "text-red-300" },
  finding_high:     { prefix: "text-orange-400 font-bold", text: "text-orange-300" },
  finding_medium:   { prefix: "text-yellow-400 font-bold", text: "text-yellow-300" },
  finding_low:      { prefix: "text-cyan-400 font-bold",   text: "text-cyan-300" },
  chain:            { prefix: "text-orange-500 font-bold", text: "text-orange-200/80" },
  credential:       { prefix: "text-yellow-500 font-bold", text: "text-yellow-200/80" },
  attempt_success:  { prefix: "text-green-400 font-bold",  text: "text-green-300/80" },
  attempt_partial:  { prefix: "text-yellow-600",           text: "text-yellow-500/60" },
  attempt_failed:   { prefix: "text-white/20",             text: "text-white/20" },
  exec:             { prefix: "text-green-500/60",         text: "text-white/50" },
  http:             { prefix: "text-blue-400/70",          text: "text-blue-300/60" },
  info:             { prefix: "text-white/25",             text: "text-white/35" },
};

function SandboxTerminal({ sandbox }: { sandbox: SandboxActivity }) {
  const [expanded, setExpanded] = useState(true);
  const [termExpanded, setTermExpanded] = useState(true);

  const findings = sandbox.attackLog.filter((e) => e.startsWith("FINDING"));
  const chains   = sandbox.attackLog.filter((e) => e.startsWith("CHAIN"));
  const creds    = sandbox.attackLog.filter((e) => e.startsWith("CREDENTIAL"));
  const successes = sandbox.attackLog.filter((e) => e.startsWith("ATTEMPT [SUCCESS]"));

  const stats = [
    { label: "Findings",  value: sandbox.findingsCount, color: sandbox.findingsCount > 0 ? "text-red-400" : "text-green-400" },
    { label: "Chains",    value: chains.length,    color: "text-orange-400" },
    { label: "Creds",     value: creds.length,     color: "text-yellow-400" },
    { label: "Bypasses",  value: successes.length, color: "text-green-400" },
    { label: "Actions",   value: sandbox.attackLog.length, color: "text-white/40" },
    { label: "Tokens",    value: sandbox.tokensUsed > 0 ? `${Math.round(sandbox.tokensUsed / 1000)}K` : "—", color: "text-white/25" },
  ];

  return (
    <div className="rounded-xl border border-white/10 overflow-hidden bg-[#0a0a0a]">
      {/* ── Header bar ── */}
      <div className="flex items-center gap-3 px-4 py-3 bg-[#111] border-b border-white/[0.06]">
        {/* Traffic lights */}
        <div className="flex gap-1.5 shrink-0">
          <span className="w-3 h-3 rounded-full bg-red-500/70" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
          <span className="w-3 h-3 rounded-full bg-green-500/70" />
        </div>
        <span className="text-white/30 text-xs font-mono flex-1 truncate">
          breachscope-sandbox · {sandbox.projectType} · root@container
        </span>
        {/* Stats pills */}
        <div className="flex items-center gap-2 shrink-0">
          {stats.map((s) => (
            <span key={s.label} className="hidden sm:flex items-center gap-1">
              <span className={clsx("text-[10px] font-mono font-bold", s.color)}>{s.value}</span>
              <span className="text-white/15 text-[9px]">{s.label}</span>
            </span>
          ))}
        </div>
        <button onClick={() => setExpanded(!expanded)} className="text-white/20 hover:text-white/50 transition-colors ml-1 shrink-0">
          <svg className={clsx("w-3.5 h-3.5 transition-transform duration-150", expanded && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>

      {expanded && (
        <>
          {/* ── Attack chains highlight ── */}
          {sandbox.attackChains.length > 0 && (
            <div className="px-4 pt-3 pb-2 border-b border-white/[0.04] space-y-1.5">
              <p className="text-white/20 text-[9px] font-semibold uppercase tracking-widest mb-2">Confirmed Attack Chains</p>
              {sandbox.attackChains.map((chain, i) => (
                <div key={i} className="flex items-start gap-2 font-mono">
                  <span className="text-orange-500/70 text-[10px] shrink-0 mt-0.5">⛓</span>
                  <span className="text-orange-200/70 text-[10px] leading-relaxed break-all">{chain}</span>
                </div>
              ))}
            </div>
          )}

          {/* ── Key findings summary ── */}
          {findings.length > 0 && (
            <div className="px-4 pt-3 pb-2 border-b border-white/[0.04] space-y-1">
              <p className="text-white/20 text-[9px] font-semibold uppercase tracking-widest mb-2">Discoveries</p>
              {findings.slice(0, 6).map((f, i) => {
                const line = parseTermLine(f);
                const s = TERM_LINE_STYLES[line.type];
                return (
                  <div key={i} className="flex items-center gap-2 font-mono">
                    <span className={clsx("text-[9px] shrink-0 min-w-[60px]", s.prefix)}>{line.prefix}</span>
                    <span className={clsx("text-[10px] truncate", s.text)}>{line.text}</span>
                  </div>
                );
              })}
              {findings.length > 6 && (
                <p className="text-white/15 text-[9px] font-mono pl-16">+ {findings.length - 6} more findings</p>
              )}
            </div>
          )}

          {/* ── Full attack terminal ── */}
          {sandbox.attackLog.length > 0 && (
            <div className="px-0">
              <button
                onClick={() => setTermExpanded(!termExpanded)}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-white/20 hover:text-white/40 hover:bg-white/[0.02] transition-colors border-b border-white/[0.04]"
              >
                <svg className={clsx("w-3 h-3 transition-transform", termExpanded && "rotate-90")} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                <span className="text-[9px] font-mono font-semibold uppercase tracking-widest">
                  Full Session Log — {sandbox.attackLog.length} operations
                </span>
              </button>

              {termExpanded && (
                <div className="max-h-[480px] overflow-y-auto font-mono text-[10px] leading-[1.65] px-4 py-3 space-y-px select-text">
                  {sandbox.attackLog.map((entry, i) => {
                    const line = parseTermLine(entry);
                    const s = TERM_LINE_STYLES[line.type];
                    const isHighlight = ["finding_critical","finding_high","finding_medium","chain","credential","attempt_success"].includes(line.type);
                    return (
                      <div
                        key={i}
                        className={clsx(
                          "flex items-start gap-2 py-px px-1 rounded-sm -mx-1",
                          isHighlight && "bg-white/[0.025]"
                        )}
                      >
                        <span className="text-white/10 w-6 text-right shrink-0 select-none tabular-nums">{i + 1}</span>
                        <span className={clsx("shrink-0 min-w-[70px] text-right pr-2", s.prefix)}>{line.prefix}</span>
                        <span className={clsx("break-all", s.text)}>{line.text}</span>
                      </div>
                    );
                  })}
                  {/* Blinking cursor at end */}
                  <div className="flex items-center gap-2 pt-1">
                    <span className="w-6 shrink-0" />
                    <span className="text-green-500/50 min-w-[70px] text-right pr-2">$</span>
                    <span className="inline-block w-2 h-3 bg-green-500/40 animate-pulse" />
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── Report download ──────────────────────────────────────────────────────────

function generateMarkdown(
  scan: Scan,
  findings: Finding[],
  toolRiskData: ToolRiskEntry[],
  probeActivity: ProbeActivity | null
): string {
  const date = new Date(scan.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
  const dur  = elapsed(scan.startedAt, scan.completedAt);

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = f.severity.toLowerCase() as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  const grouped: Record<string, Finding[]> = {};
  for (const f of findings) {
    const s = f.severity.toUpperCase();
    (grouped[s] ??= []).push(f);
  }

  let md = `# BreachScope Security Report\n\n`;
  md += `**Project**: ${scan.project ?? "Unknown"}  \n`;
  md += `**Date**: ${date}  \n`;
  md += `**Scan Mode**: ${scan.mode} | ${scan.scanMode}  \n`;
  md += `**Duration**: ${dur}  \n`;
  if (scan.url) md += `**Target URL**: ${scan.url}  \n`;
  md += `\n---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `Found **${findings.length} issue${findings.length !== 1 ? "s" : ""}**`;
  const parts = [];
  if (sevCounts.critical > 0) parts.push(`${sevCounts.critical} critical`);
  if (sevCounts.high > 0)     parts.push(`${sevCounts.high} high`);
  if (sevCounts.medium > 0)   parts.push(`${sevCounts.medium} medium`);
  if (sevCounts.low > 0)      parts.push(`${sevCounts.low} low`);
  md += parts.length > 0 ? `: ${parts.join(", ")}.` : ": none.";
  md += "\n\n";

  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    const list = grouped[sev];
    if (!list || list.length === 0) continue;
    md += `## ${sev[0]! + sev.slice(1).toLowerCase()} Findings\n\n`;
    list.forEach((f, i) => {
      md += `### [${sev[0]}${i + 1}] ${f.title}\n\n`;
      md += `**Severity**: ${f.severity} | **Category**: ${f.category}`;
      if (f.tool) md += ` | **Tool**: ${f.tool}`;
      if (f.file) md += ` | **File**: \`${f.file}${f.line ? `:${f.line}` : ""}\``;
      md += `\n\n**Description**: ${f.description}\n\n`;
      if (f.remediation) md += `**Fix**: ${f.remediation}\n\n`;
      let refs: string[] = [];
      try { refs = f.references ? (JSON.parse(f.references) as string[]) : []; } catch {}
      if (refs.length > 0) md += `**References**:\n${refs.map((r) => `- ${r}`).join("\n")}\n\n`;
    });
  }

  if (toolRiskData.length > 0) {
    md += `## Dependency Risk Overview\n\n`;
    md += `| Package | Risk | CVEs | OpenSSF | Maintainers | Weekly DLs |\n`;
    md += `|---------|------|------|---------|-------------|------------|\n`;
    [...toolRiskData].sort((a, b) => b.riskScore - a.riskScore).slice(0, 30).forEach((t) => {
      md += `| \`${t.name}\` | ${t.riskScore}/100 | ${t.osvCount} | ${t.scorecardScore?.toFixed(1) ?? "—"} | ${t.maintainerCount ?? "—"} | ${fmtNum(t.weeklyDownloads)} |\n`;
    });
    md += "\n";
  }

  if (probeActivity) {
    md += `## Probe Activity\n\n`;
    if (probeActivity.services?.length) {
      md += `### Service Probes\n\n`;
      for (const svc of probeActivity.services) {
        md += `**${svc.name}** (${svc.category}) — ${svc.findingsCount} findings, ${svc.tokensUsed.toLocaleString()} tokens\n\n`;
        if (svc.steps.length > 0) md += svc.steps.map((s) => `- \`${s}\``).join("\n") + "\n\n";
      }
    }
    if (probeActivity.sandbox) {
      const s = probeActivity.sandbox;
      md += `### Sandbox Attack Agent\n\n`;
      md += `**Project type**: ${s.projectType} — ${s.findingsCount} findings, ${s.tokensUsed.toLocaleString()} tokens\n\n`;
      if (s.attackChains.length > 0) md += `**Attack chains**:\n${s.attackChains.map((c) => `- ${c}`).join("\n")}\n\n`;
      if (s.attackLog.length > 0) md += `**Attack log** (last 20):\n${s.attackLog.slice(-20).map((l) => `- \`${l}\``).join("\n")}\n\n`;
    }
  }

  md += `---\n*Generated by [BreachScope](https://breachscoope.vercel.app) — ${date}*\n`;
  return md;
}

function downloadFile(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

async function generatePdf(
  scan: Scan,
  findings: Finding[],
  toolRiskData: ToolRiskEntry[],
  probeActivity: ProbeActivity | null,
  slug: string,
  date: string
) {
  const { jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");

  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  // jspdf-autotable adds lastAutoTable at runtime but TypeScript doesn't know
  const docAny = doc as unknown as { lastAutoTable?: { finalY: number } };
  const W = doc.internal.pageSize.getWidth();
  const MARGIN = 16;
  let y = MARGIN;

  const addPage = () => { doc.addPage(); y = MARGIN; };
  const checkY = (need: number) => { if (y + need > 275) addPage(); };

  // ── Cover / header ─────────────────────────────────────────────────────────
  doc.setFillColor(10, 10, 14);
  doc.rect(0, 0, W, 50, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont("helvetica", "bold");
  doc.text("BreachScope", MARGIN, 22);
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(180, 180, 180);
  doc.text("Security Audit Report", MARGIN, 31);
  doc.setFontSize(9);
  doc.setTextColor(120, 120, 120);
  doc.text(`Generated ${date}`, W - MARGIN, 31, { align: "right" });
  y = 58;

  // ── Metadata block ─────────────────────────────────────────────────────────
  doc.setFontSize(9);
  doc.setTextColor(60, 60, 60);
  const meta = [
    ["Project", scan.project ?? "Unknown"],
    ["Scan Mode", `${(scan.scanMode ?? "all").toUpperCase()} / Depth: ${(scan.mode ?? "basic").toUpperCase()}`],
    ["Duration", elapsed(scan.startedAt, scan.completedAt)],
    ...(scan.url ? [["Target URL", scan.url]] : []),
  ];
  for (const [k, v] of meta) {
    doc.setFont("helvetica", "bold"); doc.text(`${k}:`, MARGIN, y);
    doc.setFont("helvetica", "normal"); doc.text(String(v), MARGIN + 28, y);
    y += 5.5;
  }
  y += 4;

  // ── Summary counts ─────────────────────────────────────────────────────────
  doc.setDrawColor(230, 230, 230);
  doc.line(MARGIN, y, W - MARGIN, y);
  y += 6;
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(30, 30, 30);
  doc.text("Executive Summary", MARGIN, y);
  y += 7;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = f.severity.toLowerCase() as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  const summaryColors: [string, number, [number,number,number]][] = [
    ["Critical", sevCounts.critical, [239,68,68]],
    ["High",     sevCounts.high,     [249,115,22]],
    ["Medium",   sevCounts.medium,   [234,179,8]],
    ["Low",      sevCounts.low,      [6,182,212]],
  ];
  const boxW = (W - MARGIN * 2 - 9) / 4;
  let bx = MARGIN;
  for (const [label, count, [r,g,b]] of summaryColors) {
    doc.setFillColor(r,g,b);
    doc.roundedRect(bx, y, boxW, 18, 2, 2, "F");
    doc.setTextColor(255,255,255);
    doc.setFontSize(16); doc.setFont("helvetica", "bold");
    doc.text(String(count), bx + boxW / 2, y + 10, { align: "center" });
    doc.setFontSize(7); doc.setFont("helvetica", "normal");
    doc.text(label, bx + boxW / 2, y + 15.5, { align: "center" });
    bx += boxW + 3;
  }
  y += 26;

  // ── Findings table ─────────────────────────────────────────────────────────
  if (findings.length > 0) {
    doc.setDrawColor(230,230,230);
    doc.line(MARGIN, y, W - MARGIN, y);
    y += 6;
    doc.setFontSize(12); doc.setFont("helvetica","bold"); doc.setTextColor(30,30,30);
    doc.text(`Findings (${findings.length})`, MARGIN, y);
    y += 4;

    const sevOrder: Record<string,number> = { critical:0, high:1, medium:2, low:3, info:4 };
    const sorted = [...findings].sort((a,b) => (sevOrder[a.severity]??5) - (sevOrder[b.severity]??5));

    const SEV_COLORS: Record<string,[number,number,number]> = {
      critical: [239,68,68], high: [249,115,22], medium: [234,179,8], low: [6,182,212], info: [148,163,184],
    };

    autoTable(doc, {
      startY: y,
      margin: { left: MARGIN, right: MARGIN },
      head: [["Severity","Category","Title","File","Remediation"]],
      body: sorted.map((f) => [
        f.severity.toUpperCase(),
        f.category,
        f.title,
        f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "—",
        f.remediation ? f.remediation.slice(0, 120) + (f.remediation.length > 120 ? "…" : "") : "—",
      ]),
      styles: { fontSize: 7.5, cellPadding: 3, overflow: "linebreak", minCellHeight: 8 },
      headStyles: { fillColor: [30,30,30], textColor: [255,255,255], fontStyle: "bold", fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 18, fontStyle: "bold" },
        1: { cellWidth: 22 },
        2: { cellWidth: 48 },
        3: { cellWidth: 30 },
        4: { cellWidth: "auto" },
      },
      didParseCell: (data) => {
        if (data.column.index === 0 && data.section === "body") {
          const sev = String(data.cell.raw).toLowerCase();
          const [r,g,b] = SEV_COLORS[sev] ?? [148,163,184];
          data.cell.styles.textColor = [r,g,b];
        }
      },
      didDrawPage: () => { y = (docAny.lastAutoTable?.finalY ?? y) + 8; },
    });
    y = (docAny.lastAutoTable?.finalY ?? y) + 8;
  }

  // ── Dependency risk table ──────────────────────────────────────────────────
  if (toolRiskData.length > 0) {
    checkY(20);
    doc.setDrawColor(230,230,230);
    doc.line(MARGIN, y, W - MARGIN, y);
    y += 6;
    doc.setFontSize(12); doc.setFont("helvetica","bold"); doc.setTextColor(30,30,30);
    doc.text(`Dependency Risk (${toolRiskData.length} packages)`, MARGIN, y);
    y += 4;

    const topRisk = [...toolRiskData].sort((a,b) => b.riskScore - a.riskScore).slice(0,40);
    autoTable(doc, {
      startY: y,
      margin: { left: MARGIN, right: MARGIN },
      head: [["Package","Kind","Risk","CVEs","OpenSSF","Maintainers","Weekly DLs"]],
      body: topRisk.map((t) => [
        t.name, t.kind,
        `${t.riskScore}/100`,
        String(t.osvCount),
        t.scorecardScore !== undefined ? t.scorecardScore.toFixed(1) : "—",
        t.maintainerCount !== undefined ? String(t.maintainerCount) : "—",
        fmtNum(t.weeklyDownloads),
      ]),
      styles: { fontSize: 7, cellPadding: 2.5, overflow: "linebreak" },
      headStyles: { fillColor: [30,30,30], textColor: [255,255,255], fontStyle: "bold", fontSize: 7.5 },
      columnStyles: {
        0: { cellWidth: 42, fontStyle: "bold" },
        1: { cellWidth: 16 },
        2: { cellWidth: 18 },
        3: { cellWidth: 14 },
        4: { cellWidth: 18 },
        5: { cellWidth: 22 },
        6: { cellWidth: "auto" },
      },
      didParseCell: (data) => {
        if (data.column.index === 2 && data.section === "body") {
          const score = parseInt(String(data.cell.raw));
          if (score >= 75) data.cell.styles.textColor = [239,68,68];
          else if (score >= 50) data.cell.styles.textColor = [249,115,22];
          else if (score >= 25) data.cell.styles.textColor = [234,179,8];
          else data.cell.styles.textColor = [34,197,94];
        }
      },
      didDrawPage: () => { y = (docAny.lastAutoTable?.finalY ?? y) + 8; },
    });
    y = (docAny.lastAutoTable?.finalY ?? y) + 8;
  }

  // ── Probe activity ─────────────────────────────────────────────────────────
  if (probeActivity?.services?.length || probeActivity?.sandbox) {
    checkY(20);
    doc.setDrawColor(230,230,230);
    doc.line(MARGIN, y, W - MARGIN, y);
    y += 6;
    doc.setFontSize(12); doc.setFont("helvetica","bold"); doc.setTextColor(30,30,30);
    doc.text("Probe Activity", MARGIN, y);
    y += 6;

    if (probeActivity.services?.length) {
      for (const svc of probeActivity.services) {
        checkY(10);
        doc.setFontSize(9); doc.setFont("helvetica","bold"); doc.setTextColor(60,60,60);
        doc.text(`${svc.name} (${svc.category}) — ${svc.findingsCount} finding(s), ${svc.tokensUsed.toLocaleString()} tokens`, MARGIN, y);
        y += 5;
        doc.setFontSize(7.5); doc.setFont("helvetica","normal"); doc.setTextColor(100,100,100);
        for (const step of svc.steps.slice(0, 15)) {
          checkY(5);
          doc.text(`  • ${step}`, MARGIN + 2, y);
          y += 4;
        }
        y += 2;
      }
    }

    if (probeActivity.sandbox) {
      const sb = probeActivity.sandbox;
      checkY(12);
      doc.setFontSize(9); doc.setFont("helvetica","bold"); doc.setTextColor(60,60,60);
      doc.text(`Sandbox Attack Agent — ${sb.projectType}`, MARGIN, y);
      y += 5;
      doc.setFontSize(7.5); doc.setFont("helvetica","normal"); doc.setTextColor(100,100,100);
      doc.text(`${sb.findingsCount} finding(s) · ${sb.tokensUsed.toLocaleString()} tokens · ${sb.attackLog.length} actions`, MARGIN + 2, y);
      y += 4;
      for (const chain of sb.attackChains.slice(0, 8)) {
        checkY(5);
        const truncated = chain.length > 100 ? chain.slice(0, 100) + "…" : chain;
        doc.text(`  → ${truncated}`, MARGIN + 2, y); y += 4;
      }
    }
  }

  // ── Footer on every page ───────────────────────────────────────────────────
  const pageCount = doc.internal.pages.length - 1;
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7); doc.setFont("helvetica","normal"); doc.setTextColor(160,160,160);
    doc.text(`BreachScope Security Report · ${date}`, MARGIN, 292);
    doc.text(`Page ${i} of ${pageCount}`, W - MARGIN, 292, { align: "right" });
  }

  doc.save(`${slug}-${date}.pdf`);
}

function ReportTab({
  scan, findings, toolRiskData, probeActivity,
}: { scan: Scan; findings: Finding[]; toolRiskData: ToolRiskEntry[]; probeActivity: ProbeActivity | null }) {
  const slug = (scan.project ?? "scan").replace(/\s+/g, "-").toLowerCase();
  const date = new Date(scan.createdAt).toISOString().slice(0, 10);
  const [pdfLoading, setPdfLoading] = useState(false);

  const downloadJson = useCallback(() => {
    const payload = {
      scan: { id: scan.id, project: scan.project, mode: scan.mode, scanMode: scan.scanMode, url: scan.url, startedAt: scan.startedAt, completedAt: scan.completedAt },
      summary: { total: findings.length, critical: scan.findingsCritical, high: scan.findingsHigh, medium: scan.findingsMedium, low: scan.findingsLow },
      findings: findings.map((f) => ({ ...f, references: (() => { try { return f.references ? JSON.parse(f.references) : []; } catch { return []; } })() })),
      toolRiskData,
      probeActivity,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${slug}-${date}.json`; a.click();
    URL.revokeObjectURL(url);
  }, [scan, findings, toolRiskData, probeActivity, slug, date]);

  const downloadMarkdown = useCallback(() => {
    const md = generateMarkdown(scan, findings, toolRiskData, probeActivity);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${slug}-${date}.md`; a.click();
    URL.revokeObjectURL(url);
  }, [scan, findings, toolRiskData, probeActivity, slug, date]);

  const downloadPdf = useCallback(async () => {
    setPdfLoading(true);
    try {
      await generatePdf(scan, findings, toolRiskData, probeActivity, slug, date);
    } finally {
      setPdfLoading(false);
    }
  }, [scan, findings, toolRiskData, probeActivity, slug, date]);

  const sections = [
    { icon: "{ }", label: "JSON", desc: "Machine-readable export. Includes all findings, risk data, and probe activity. Ideal for CI/CD pipelines and programmatic processing.", action: downloadJson, color: "text-cyan-400", border: "border-cyan-500/20 hover:border-cyan-500/40", bg: "bg-cyan-500/5 hover:bg-cyan-500/10", loading: false },
    { icon: "#", label: "Markdown", desc: "Human-readable report with findings grouped by severity, dependency risk table, and probe activity log. Great for GitHub issues or Notion.", action: downloadMarkdown, color: "text-purple-400", border: "border-purple-500/20 hover:border-purple-500/40", bg: "bg-purple-500/5 hover:bg-purple-500/10", loading: false },
    { icon: "⎙", label: "PDF", desc: "Generates a structured PDF with summary cards, findings table, dependency risk analysis, and probe activity log. No browser dialog needed.", action: downloadPdf, color: "text-orange-400", border: "border-orange-500/20 hover:border-orange-500/40", bg: "bg-orange-500/5 hover:bg-orange-500/10", loading: pdfLoading },
  ];

  return (
    <div className="space-y-8 max-w-3xl">
      <div>
        <h3 className="text-white/75 text-sm font-semibold mb-1">Export Report</h3>
        <p className="text-white/30 text-xs">Download a full security report in your preferred format.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {sections.map(({ icon, label, desc, action, color, border, bg, loading }) => (
          <button
            key={label}
            onClick={() => void action()}
            disabled={loading}
            className={clsx(
              "group text-left p-5 rounded-2xl border transition-all duration-200 disabled:opacity-60 disabled:cursor-wait",
              border, bg
            )}
          >
            <div className={clsx("text-2xl font-mono mb-3", color)}>{icon}</div>
            <p className={clsx("text-sm font-semibold mb-2", color)}>{label}</p>
            <p className="text-white/30 text-xs leading-relaxed">{desc}</p>
            <div className={clsx("mt-4 text-xs font-medium flex items-center gap-1.5 transition-opacity opacity-60 group-hover:opacity-100", color)}>
              {loading ? "Generating…" : `Download ${label}`}
              {loading ? (
                <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
              ) : (
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
              )}
            </div>
          </button>
        ))}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <div className="px-5 py-4 border-b border-white/[0.04]">
          <p className="text-white/50 text-xs font-semibold uppercase tracking-wider">Report Preview</p>
        </div>
        <div className="px-5 py-4 font-mono text-xs text-white/30 leading-relaxed space-y-1">
          <p className="text-white/60"># BreachScope Security Report</p>
          <p><span className="text-white/40">Project:</span> {scan.project ?? "Unknown"}</p>
          <p><span className="text-white/40">Date:</span> {new Date(scan.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}</p>
          <p><span className="text-white/40">Mode:</span> {scan.mode} | {scan.scanMode}</p>
          {scan.url && <p><span className="text-white/40">URL:</span> {scan.url}</p>}
          <p className="pt-2"><span className="text-white/50">## Findings ({findings.length})</span></p>
          {["critical", "high", "medium", "low"].map((s) => {
            const count = findings.filter((f) => f.severity === s).length;
            if (!count) return null;
            return <p key={s} className="pl-2"><span className="text-white/40">{s}:</span> {count}</p>;
          })}
          {toolRiskData.length > 0 && (
            <p className="pt-2"><span className="text-white/50">## Dependency Risk ({toolRiskData.length} packages)</span></p>
          )}
          {(probeActivity?.services?.length || probeActivity?.sandbox) && (
            <p className="pt-2"><span className="text-white/50">## Probe Activity</span></p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Smart Groups View ────────────────────────────────────────────────────────

function SeverityPills({ findings }: { findings: Finding[] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = f.severity.toLowerCase() as keyof typeof counts;
    if (s in counts) counts[s]++;
  }
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {counts.critical > 0 && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/15 border border-red-500/25 text-red-300">{counts.critical}C</span>}
      {counts.high > 0     && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-orange-500/15 border border-orange-500/25 text-orange-300">{counts.high}H</span>}
      {counts.medium > 0   && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-yellow-500/15 border border-yellow-500/25 text-yellow-300">{counts.medium}M</span>}
      {counts.low > 0      && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 border border-cyan-500/25 text-cyan-300">{counts.low}L</span>}
    </div>
  );
}

function SmartGroupView({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState<Set<SmartGroupKey>>(() => {
    const autoExpand = new Set<SmartGroupKey>();
    for (const f of findings) {
      const key = categorizeFinding(f);
      if (f.severity === "critical" || f.severity === "high") autoExpand.add(key);
    }
    return autoExpand;
  });

  const grouped = useMemo(() => {
    const map = new Map<SmartGroupKey, Finding[]>();
    for (const f of findings) {
      const key = categorizeFinding(f);
      const arr = map.get(key) ?? [];
      arr.push(f);
      map.set(key, arr);
    }
    return map;
  }, [findings]);

  const toggle = (key: SmartGroupKey) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const activeGroups = SMART_GROUPS.filter((g) => (grouped.get(g.key)?.length ?? 0) > 0);

  if (activeGroups.length === 0) {
    return <div className="py-12 text-center text-white/25 text-sm">No findings to display.</div>;
  }

  return (
    <div className="space-y-3">
      {activeGroups.map((meta) => {
        const groupFindings = grouped.get(meta.key) ?? [];
        const isOpen = expanded.has(meta.key);
        const hasCritical = groupFindings.some((f) => f.severity === "critical");
        const hasHigh     = groupFindings.some((f) => f.severity === "high");

        return (
          <div key={meta.key} className={clsx("rounded-2xl border overflow-hidden", meta.colorBorder, meta.colorBg)}>
            <button
              className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-white/[0.02] transition-colors"
              onClick={() => toggle(meta.key)}
            >
              <div className={clsx("w-2 h-2 rounded-full shrink-0", meta.colorDot)} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={clsx("text-sm font-semibold", meta.colorText)}>{meta.label}</span>
                  {(hasCritical || hasHigh) && (
                    <span className={clsx(
                      "px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border",
                      hasCritical ? "bg-red-500/20 border-red-500/30 text-red-300" : "bg-orange-500/20 border-orange-500/30 text-orange-300"
                    )}>
                      {hasCritical ? "Critical" : "High"}
                    </span>
                  )}
                </div>
                <p className="text-white/30 text-xs mt-0.5">{meta.description}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <SeverityPills findings={groupFindings} />
                <span className="text-white/25 text-xs font-mono w-8 text-right">{groupFindings.length}</span>
                <svg className={clsx("w-3.5 h-3.5 text-white/20 transition-transform duration-150", isOpen && "rotate-180")}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </button>

            {isOpen && (
              <div className="border-t border-white/[0.04] px-5 py-4 space-y-2">
                {groupFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Supply Chain Grid ────────────────────────────────────────────────────────

type SortKey = "risk" | "cves" | "maintainers" | "ssf";

function DepCard({ tool, findings }: { tool: ToolRiskEntry; findings: Finding[] }) {
  const [open, setOpen] = useState(false);
  const isBreached = KNOWN_COMPROMISED.has(tool.name.toLowerCase());
  const isSolo     = tool.maintainerCount === 1;
  const isAbandoned = tool.maintainerCount === 0;
  const lowSSF     = tool.scorecardScore !== undefined && tool.scorecardScore < 4;

  const riskColor = tool.riskScore >= 75 ? "text-red-400"
    : tool.riskScore >= 50 ? "text-orange-400"
    : tool.riskScore >= 25 ? "text-yellow-400"
    : "text-green-400";

  const ssfColor = tool.scorecardScore === undefined ? "text-white/30"
    : tool.scorecardScore >= 7 ? "text-green-400"
    : tool.scorecardScore >= 4 ? "text-yellow-400"
    : "text-red-400";

  const maintColor = !tool.maintainerCount ? "text-red-400"
    : tool.maintainerCount === 1 ? "text-orange-400"
    : tool.maintainerCount <= 3 ? "text-yellow-400"
    : "text-green-400";

  const toolFindings = findings.filter((f) => f.tool === tool.name);

  return (
    <div className={clsx(
      "rounded-xl border transition-all",
      isBreached
        ? "border-red-500/40 bg-red-500/[0.04]"
        : tool.riskScore >= 75
        ? "border-red-500/20 bg-white/[0.02]"
        : "border-white/[0.06] bg-white/[0.02]"
    )}>
      <button
        className="w-full text-left p-4 space-y-3"
        onClick={() => setOpen(!open)}
      >
        {/* Header */}
        <div className="flex items-start gap-2 min-w-0">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-white/80 text-sm font-mono font-medium truncate">{tool.name}</span>
              {tool.version && <span className="text-white/25 text-[10px] font-mono">v{tool.version}</span>}
            </div>
            <div className="flex items-center gap-1.5 mt-1 flex-wrap">
              <KindBadge kind={tool.kind} />
              {isBreached && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-red-500/20 border border-red-500/30 text-red-300">
                  BREACH RISK
                </span>
              )}
              {isAbandoned && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-red-500/15 border border-red-500/25 text-red-400">
                  ABANDONED
                </span>
              )}
              {isSolo && !isAbandoned && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase tracking-wider bg-orange-500/10 border border-orange-500/20 text-orange-400">
                  SOLO MAINT.
                </span>
              )}
              {lowSSF && !isBreached && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase tracking-wider bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">
                  LOW SSF
                </span>
              )}
            </div>
          </div>
          <svg className={clsx("w-3.5 h-3.5 text-white/20 shrink-0 mt-1 transition-transform duration-150", open && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Metrics row */}
        <div className="grid grid-cols-4 gap-2">
          <div className="text-center">
            <p className="text-white/25 text-[9px] uppercase tracking-wider mb-0.5">Risk</p>
            <p className={clsx("text-xs font-mono font-bold", riskColor)}>{tool.riskScore}</p>
          </div>
          <div className="text-center">
            <p className="text-white/25 text-[9px] uppercase tracking-wider mb-0.5">CVEs</p>
            <p className={clsx("text-xs font-mono font-bold", tool.osvCount > 0 ? "text-red-400" : "text-white/30")}>{tool.osvCount}</p>
          </div>
          <div className="text-center">
            <p className="text-white/25 text-[9px] uppercase tracking-wider mb-0.5">SSF</p>
            <p className={clsx("text-xs font-mono font-bold", ssfColor)}>
              {tool.scorecardScore !== undefined ? tool.scorecardScore.toFixed(1) : "—"}
            </p>
          </div>
          <div className="text-center">
            <p className="text-white/25 text-[9px] uppercase tracking-wider mb-0.5">Maint.</p>
            <p className={clsx("text-xs font-mono font-bold", maintColor)}>
              {tool.maintainerCount ?? "—"}
            </p>
          </div>
        </div>

        {/* Risk bar */}
        <div className="h-1 bg-white/5 rounded-full overflow-hidden">
          <div
            className={clsx("h-full rounded-full", tool.riskScore >= 75 ? "bg-red-500" : tool.riskScore >= 50 ? "bg-orange-500" : tool.riskScore >= 25 ? "bg-yellow-500" : "bg-green-500")}
            style={{ width: `${tool.riskScore}%` }}
          />
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-white/[0.04] pt-3 space-y-3">
          {tool.github && (
            <a href={tool.github} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-white/35 text-xs hover:text-white/60 transition-colors font-mono">
              <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
              {tool.github.replace("https://github.com/", "")}
            </a>
          )}

          {tool.aiSummary && !tool.aiSummary.includes("unavailable") && (
            <p className="text-white/40 text-xs leading-relaxed">{tool.aiSummary}</p>
          )}

          <div className="grid grid-cols-2 gap-2">
            {tool.weeklyDownloads !== undefined && (
              <div className="p-2 rounded-lg bg-white/[0.03]">
                <p className="text-white/25 text-[9px] uppercase tracking-wider mb-1">Weekly DLs</p>
                <p className="text-white/55 text-xs font-mono">{fmtNum(tool.weeklyDownloads)}</p>
              </div>
            )}
            {tool.parent && (
              <div className="p-2 rounded-lg bg-white/[0.03]">
                <p className="text-white/25 text-[9px] uppercase tracking-wider mb-1">Via</p>
                <p className="text-white/40 text-xs font-mono truncate">{tool.parent}</p>
              </div>
            )}
          </div>

          {tool.osvIds && tool.osvIds.length > 0 && (
            <div>
              <p className="text-white/25 text-[9px] uppercase tracking-wider mb-1.5">CVE IDs</p>
              <div className="flex flex-wrap gap-1">
                {tool.osvIds.map((id) => (
                  <a key={id} href={`https://osv.dev/vulnerability/${id}`} target="_blank" rel="noopener noreferrer"
                    className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-[10px] hover:bg-red-500/20 transition-colors font-mono">
                    {id}
                  </a>
                ))}
              </div>
            </div>
          )}

          {toolFindings.length > 0 && (
            <div>
              <p className="text-white/25 text-[9px] uppercase tracking-wider mb-1.5">Findings ({toolFindings.length})</p>
              <div className="space-y-1">
                {toolFindings.slice(0, 5).map((f) => {
                  const sev = getSev(f.severity);
                  return (
                    <div key={f.id} className="flex items-start gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                      <span className={clsx("shrink-0 px-1.5 py-0.5 rounded text-[9px] border font-medium mt-0.5", sev.badge)}>{sev.label}</span>
                      <p className="text-white/55 text-xs leading-snug">{f.title}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SupplyChainGrid({ tools, findings }: { tools: ToolRiskEntry[]; findings: Finding[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("risk");

  const sorted = useMemo(() => {
    return [...tools].sort((a, b) => {
      switch (sortKey) {
        case "risk":        return b.riskScore - a.riskScore;
        case "cves":        return b.osvCount - a.osvCount;
        case "maintainers": return (a.maintainerCount ?? 999) - (b.maintainerCount ?? 999);
        case "ssf":         return (a.scorecardScore ?? 11) - (b.scorecardScore ?? 11);
      }
    });
  }, [tools, sortKey]);

  const stats = useMemo(() => ({
    total:      tools.length,
    highRisk:   tools.filter((t) => t.riskScore >= 75).length,
    withCves:   tools.filter((t) => t.osvCount > 0).length,
    soloMaint:  tools.filter((t) => t.maintainerCount === 1).length,
    lowSSF:     tools.filter((t) => t.scorecardScore !== undefined && t.scorecardScore < 4).length,
    breached:   tools.filter((t) => KNOWN_COMPROMISED.has(t.name.toLowerCase())).length,
  }), [tools]);

  const groups: Array<{ label: string; color: string; bgColor: string; items: ToolRiskEntry[] }> = [
    { label: "Critical Risk",  color: "text-red-400",    bgColor: "bg-red-500/10 border-red-500/20",    items: sorted.filter((t) => t.riskScore >= 75) },
    { label: "High Risk",      color: "text-orange-400", bgColor: "bg-orange-500/10 border-orange-500/20", items: sorted.filter((t) => t.riskScore >= 50 && t.riskScore < 75) },
    { label: "Medium Risk",    color: "text-yellow-400", bgColor: "bg-yellow-500/10 border-yellow-500/20", items: sorted.filter((t) => t.riskScore >= 25 && t.riskScore < 50) },
    { label: "Healthy",        color: "text-green-400",  bgColor: "bg-green-500/10 border-green-500/20",  items: sorted.filter((t) => t.riskScore < 25) },
  ];

  if (tools.length === 0) {
    return (
      <div className="py-16 text-center">
        <p className="text-white/30 text-sm">No dependency data available.</p>
        <p className="text-white/20 text-xs mt-1">Run with <code className="font-mono bg-white/[0.06] px-1.5 rounded">--mode major</code> or <code className="font-mono bg-white/[0.06] px-1.5 rounded">--mode deep</code> to collect dependency intelligence.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Stats bar */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        {[
          { label: "Total",      value: stats.total,      color: "text-white/60" },
          { label: "High Risk",  value: stats.highRisk,   color: stats.highRisk  > 0 ? "text-red-400"    : "text-white/30" },
          { label: "With CVEs",  value: stats.withCves,   color: stats.withCves  > 0 ? "text-orange-400" : "text-white/30" },
          { label: "Solo Maint", value: stats.soloMaint,  color: stats.soloMaint > 0 ? "text-yellow-400" : "text-white/30" },
          { label: "Low SSF",    value: stats.lowSSF,     color: stats.lowSSF    > 0 ? "text-yellow-400" : "text-white/30" },
          { label: "Breached",   value: stats.breached,   color: stats.breached  > 0 ? "text-red-400"    : "text-green-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.05] text-center">
            <p className="text-white/25 text-[9px] uppercase tracking-wider mb-0.5">{label}</p>
            <p className={clsx("text-sm font-mono font-bold", color)}>{value}</p>
          </div>
        ))}
      </div>

      {/* Sort controls */}
      <div className="flex items-center gap-2">
        <span className="text-white/30 text-xs">Sort by:</span>
        <div className="flex items-center gap-1 bg-white/[0.04] rounded-lg p-0.5">
          {([["risk", "Risk Score"], ["cves", "CVEs"], ["maintainers", "Maintainers"], ["ssf", "OpenSSF"]] as Array<[SortKey, string]>).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setSortKey(key)}
              className={clsx(
                "px-2.5 py-1 rounded text-xs font-medium transition-all",
                sortKey === key ? "bg-white/10 text-white border border-white/15" : "text-white/35 hover:text-white/60"
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Grouped grid */}
      {groups.filter((g) => g.items.length > 0).map((group) => (
        <div key={group.label}>
          <div className={clsx("inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-medium mb-3", group.bgColor, group.color)}>
            {group.label}
            <span className="font-mono">{group.items.length}</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {group.items.map((tool) => (
              <DepCard key={tool.name} tool={tool} findings={findings} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Maintainer Risk Intelligence (Overview tab section) ─────────────────────

function MaintainerRiskSection({ tools }: { tools: ToolRiskEntry[] }) {
  if (tools.length === 0) return null;

  const solo     = tools.filter((t) => t.maintainerCount === 1).length;
  const abandoned = tools.filter((t) => t.maintainerCount === 0).length;
  const lowSSF   = tools.filter((t) => t.scorecardScore !== undefined && t.scorecardScore < 4).length;
  const breached = tools.filter((t) => KNOWN_COMPROMISED.has(t.name.toLowerCase())).length;
  const topRisk  = [...tools].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);

  const statCards = [
    { label: "Solo Maintainer",    value: solo,     sub: "Single point of failure",   color: solo     > 0 ? "text-orange-400" : "text-white/30", border: solo     > 0 ? "border-orange-500/20" : "border-white/[0.06]" },
    { label: "Abandoned",          value: abandoned, sub: "No active maintainers",     color: abandoned > 0 ? "text-red-400"    : "text-white/30", border: abandoned > 0 ? "border-red-500/20"    : "border-white/[0.06]" },
    { label: "Low Security Score", value: lowSSF,   sub: "OpenSSF score below 4/10",  color: lowSSF   > 0 ? "text-yellow-400" : "text-white/30", border: lowSSF   > 0 ? "border-yellow-500/20" : "border-white/[0.06]" },
    { label: "Known Compromised",  value: breached, sub: "Previously supply-chain attacked", color: breached > 0 ? "text-red-400" : "text-green-400", border: breached > 0 ? "border-red-500/25" : "border-green-500/20" },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-white/60 text-xs font-semibold uppercase tracking-wider mb-1">Maintainer Risk Intelligence</h3>
        <p className="text-white/25 text-xs">{tools.length} packages analyzed</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {statCards.map(({ label, value, sub, color, border }) => (
          <div key={label} className={clsx("p-4 rounded-2xl bg-white/[0.03] border", border)}>
            <p className={clsx("text-2xl font-mono font-bold mb-1", color)}>{value}</p>
            <p className="text-white/60 text-xs font-medium">{label}</p>
            <p className="text-white/25 text-[10px] mt-0.5 leading-snug">{sub}</p>
          </div>
        ))}
      </div>

      {topRisk.length > 0 && (
        <div>
          <p className="text-white/30 text-[10px] font-semibold uppercase tracking-wider mb-2">Top Risk Packages</p>
          <div className="flex flex-wrap gap-2">
            {topRisk.map((t) => {
              const isBreached = KNOWN_COMPROMISED.has(t.name.toLowerCase());
              return (
                <div key={t.name} className={clsx(
                  "flex items-center gap-2 px-3 py-2 rounded-xl border",
                  isBreached ? "bg-red-500/[0.06] border-red-500/20" : "bg-white/[0.03] border-white/[0.06]"
                )}>
                  <span className="text-white/60 text-xs font-mono">{t.name}</span>
                  {t.version && <span className="text-white/20 text-[10px] font-mono">v{t.version}</span>}
                  <span className={clsx(
                    "px-1.5 py-0.5 rounded text-[9px] font-mono font-bold",
                    t.riskScore >= 75 ? "text-red-400" : t.riskScore >= 50 ? "text-orange-400" : "text-yellow-400"
                  )}>{t.riskScore}</span>
                  {t.osvCount > 0 && <span className="text-red-300 text-[9px] font-mono">{t.osvCount}CVE</span>}
                  {(t.maintainerCount === 0 || t.maintainerCount === 1) && (
                    <span className="text-orange-400/70 text-[9px]">{t.maintainerCount === 0 ? "no-maint" : "solo"}</span>
                  )}
                  {isBreached && <span className="text-red-400 text-[9px] font-bold">BREACHED</span>}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

type Tab = "overview" | "findings" | "probes" | "report";

type FindingsViewMode = "smart" | "grid" | "raw";

export function ScanDetail({ scan, findings }: { scan: Scan; findings: Finding[] }) {
  const [tab, setTab]             = useState<Tab>("overview");
  const [sevFilter, setSev]       = useState<string>("ALL");
  const [catFilter, setCat]       = useState<string>("ALL");
  const [findingsView, setFindingsView] = useState<FindingsViewMode>("smart");

  const total    = scan.findingsTotal    ?? 0;
  const critical = scan.findingsCritical ?? 0;
  const high     = scan.findingsHigh     ?? 0;
  const medium   = scan.findingsMedium   ?? 0;
  const low      = scan.findingsLow      ?? 0;

  let toolRiskData: ToolRiskEntry[] = [];
  try { if (scan.riskData) toolRiskData = JSON.parse(scan.riskData) as ToolRiskEntry[]; } catch {}

  let probeActivity: ProbeActivity | null = null;
  try { if (scan.probeData) probeActivity = JSON.parse(scan.probeData) as ProbeActivity; } catch {}

  let aiSynthesis: AISynthesis | null = null;
  try { if (scan.aiReport) aiSynthesis = JSON.parse(scan.aiReport) as AISynthesis; } catch {}

  const hasProbes = (probeActivity?.services?.length ?? 0) > 0 || !!probeActivity?.sandbox;

  // Filtered findings
  const filteredFindings = findings.filter((f) => {
    const sevOk = sevFilter === "ALL" || f.severity.toUpperCase() === sevFilter;
    const catOk = catFilter === "ALL" || f.category === catFilter;
    return sevOk && catOk;
  });

  const categories = [...new Set(findings.map((f) => f.category))];

  const grouped: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of filteredFindings) {
    const s = f.severity.toUpperCase() as keyof typeof grouped;
    (grouped[s] ?? grouped.LOW).push(f);
  }

  const TABS: { id: Tab; label: string; count?: number }[] = [
    { id: "overview",  label: "Overview" },
    { id: "findings",  label: "Findings",       count: total },
    { id: "probes",    label: "Probe Activity",  count: hasProbes ? ((probeActivity?.services?.length ?? 0) + (probeActivity?.sandbox ? 1 : 0)) : undefined },
    { id: "report",    label: "Report" },
  ];

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Scan summary strip */}
      <div className="flex flex-wrap items-center gap-3">
        {total > 0 && (
          <div className="flex items-center gap-2">
            {critical > 0 && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/15 border border-red-500/25 text-red-300">{critical} Critical</span>}
            {high > 0     && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-500/15 border border-orange-500/25 text-orange-300">{high} High</span>}
            {medium > 0   && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-yellow-500/15 border border-yellow-500/25 text-yellow-300">{medium} Medium</span>}
            {low > 0      && <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/15 border border-cyan-500/25 text-cyan-300">{low} Low</span>}
          </div>
        )}
        {total === 0 && (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-green-500/10 border border-green-500/20 text-green-400">Clean</span>
        )}
        {scan.url && (
          <a href={scan.url} target="_blank" rel="noopener noreferrer"
            className="text-white/25 text-xs font-mono hover:text-white/50 transition-colors truncate max-w-xs">
            {scan.url.replace(/^https?:\/\//, "")}
          </a>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-white/[0.06]">
        {TABS.map(({ id, label, count }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              "flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
              tab === id
                ? "border-white/60 text-white"
                : "border-transparent text-white/35 hover:text-white/60"
            )}
          >
            {label}
            {count !== undefined && (
              <span className={clsx("text-[10px] font-mono px-1.5 py-0.5 rounded", tab === id ? "bg-white/10 text-white/70" : "bg-white/5 text-white/25")}>
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Overview tab ── */}
      {tab === "overview" && (
        <div className="space-y-6">
          {aiSynthesis && <AISynthesisSection synthesis={aiSynthesis} />}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Scan Mode", value: scan.scanMode },
              { label: "Depth",     value: scan.mode },
              { label: "Duration",  value: elapsed(scan.startedAt, scan.completedAt) },
              { label: "Tools",     value: `${scan.toolsScanned ?? 0} scanned` },
            ].map(({ label, value }) => {
              const scanModeColor = label === "Scan Mode"
                ? value === "full" ? "text-purple-400" : value === "breach" ? "text-red-400" : value === "bug" ? "text-yellow-400" : "text-white/80"
                : "text-white/80";
              return (
              <div key={label} className="p-4 rounded-2xl bg-white/[0.04]">
                <p className="text-white/30 text-xs mb-2">{label}</p>
                <p className={clsx("text-sm font-mono uppercase", scanModeColor)}>{value}</p>
              </div>
              );
            })}
          </div>

          <div className="rounded-2xl bg-white/[0.04] p-5">
            <p className="text-white/40 text-xs font-semibold uppercase tracking-wider mb-4">Findings Breakdown</p>
            {total === 0 ? (
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <p className="text-green-400 text-sm">No findings — clean scan</p>
              </div>
            ) : (
              <div className="space-y-3">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                  const count = sev === "CRITICAL" ? critical : sev === "HIGH" ? high : sev === "MEDIUM" ? medium : low;
                  const pct   = total > 0 ? (count / total) * 100 : 0;
                  const cfg   = SEV[sev];
                  return (
                    <div key={sev} className="flex items-center gap-4">
                      <span className={clsx("text-xs font-medium w-16 shrink-0", cfg.text)}>{cfg.label}</span>
                      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className={clsx("h-full rounded-full transition-all", cfg.bar)} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-white/40 text-xs w-6 text-right shrink-0">{count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {toolRiskData.length > 0 && (
            <section>
              <div className="flex items-start justify-between gap-4 mb-4">
                <div>
                  <h3 className="text-white/75 text-sm font-semibold">Dependency Risk Overview</h3>
                  <p className="text-white/30 text-xs mt-0.5">
                    {toolRiskData.length} package{toolRiskData.length !== 1 ? "s" : ""} audited
                    {(() => { const top = [...toolRiskData].sort((a, b) => b.riskScore - a.riskScore)[0]; return top ? ` · highest: ${top.name} (${top.riskScore}/100)` : ""; })()}
                  </p>
                </div>
                <div className="hidden sm:flex items-center gap-4 text-[10px] text-white/25 shrink-0">
                  {[{ c: "bg-red-500", l: "≥75" }, { c: "bg-orange-500", l: "≥50" }, { c: "bg-yellow-500", l: "≥25" }, { c: "bg-green-500", l: "<25" }].map(({ c, l }) => (
                    <span key={l} className="flex items-center gap-1"><span className={clsx("w-2 h-2 rounded-full", c)} />{l}</span>
                  ))}
                </div>
              </div>
              <ToolRiskTable tools={toolRiskData} findings={findings} />
            </section>
          )}

          <MaintainerRiskSection tools={toolRiskData} />
        </div>
      )}

      {/* ── Findings tab ── */}
      {tab === "findings" && (
        <div className="space-y-5">
          {/* View mode toggle */}
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-1 bg-white/[0.04] rounded-xl p-1">
              {([
                ["smart", "Smart Groups"],
                ["grid",  "Supply Chain"],
                ["raw",   "Raw List"],
              ] as Array<[FindingsViewMode, string]>).map(([mode, label]) => (
                <button
                  key={mode}
                  onClick={() => setFindingsView(mode)}
                  className={clsx(
                    "px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
                    findingsView === mode
                      ? "bg-white/10 text-white border border-white/15"
                      : "text-white/35 hover:text-white/60 border border-transparent"
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Filters — only shown in raw mode */}
            {findingsView === "raw" && (
              <div className="flex flex-wrap gap-2">
                <Chip label="All" count={findings.length} active={sevFilter === "ALL" && catFilter === "ALL"} onClick={() => { setSev("ALL"); setCat("ALL"); }} />
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => {
                  const count = findings.filter((f) => f.severity.toUpperCase() === s).length;
                  if (!count) return null;
                  return <Chip key={s} label={SEV[s].label} count={count} active={sevFilter === s} onClick={() => { setSev(s); setCat("ALL"); }} />;
                })}
                {categories.map((cat) => (
                  <Chip key={cat} label={CAT_LABELS[cat] ?? cat} count={findings.filter((f) => f.category === cat).length} active={catFilter === cat} onClick={() => { setCat(cat); setSev("ALL"); }} />
                ))}
              </div>
            )}
          </div>

          {/* ── Smart Groups view ── */}
          {findingsView === "smart" && <SmartGroupView findings={findings} />}

          {/* ── Supply Chain Grid view ── */}
          {findingsView === "grid" && <SupplyChainGrid tools={toolRiskData} findings={findings} />}

          {/* ── Raw List view ── */}
          {findingsView === "raw" && (
            <>
          {filteredFindings.length === 0 ? (
            <div className="py-12 text-center text-white/25 text-sm">No findings match the current filter.</div>
          ) : (
            (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
              const list = grouped[sev];
              if (!list || list.length === 0) return null;
              const cfg = SEV[sev];
              return (
                <section key={sev}>
                  <div className="flex items-center gap-3 mb-3">
                    <div className={clsx("w-2 h-2 rounded-full", cfg.bar)} />
                    <h3 className={clsx("text-sm font-semibold", cfg.text)}>
                      {cfg.label} <span className="text-white/30 font-normal">({list.length})</span>
                    </h3>
                  </div>
                  <div className="space-y-2">
                    {list.map((f) => <FindingCard key={f.id} finding={f} />)}
                  </div>
                </section>
              );
            })
          )}

          {findings.length === 0 && (
            <div className="py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-green-400 text-sm font-medium">Clean Scan</p>
              <p className="text-white/25 text-xs mt-1">No findings detected.</p>
            </div>
          )}
            </>
          )}
        </div>
      )}

      {/* ── Probe Activity tab ── */}
      {tab === "probes" && (
        <div className="space-y-6">
          {!hasProbes ? (
            <div className="py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <p className="text-white/35 text-sm font-medium">No probe activity recorded</p>
              <p className="text-white/20 text-xs mt-1">Set <code className="font-mono bg-white/[0.06] px-1.5 rounded">OPENAI_API_KEY</code> and run <code className="font-mono bg-white/[0.06] px-1.5 rounded">breachscope sandbox</code> to see AI attack session logs here.</p>
            </div>
          ) : (
            <>
              {(probeActivity?.services?.length ?? 0) > 0 && (
                <section>
                  <h3 className="text-white/60 text-xs font-semibold uppercase tracking-wider mb-3">Live Service Probes</h3>
                  <div className="space-y-2">
                    {probeActivity!.services!.map((svc) => <ServiceProbeCard key={svc.id} svc={svc} />)}
                  </div>
                </section>
              )}
              {probeActivity?.sandbox && (
                <section>
                  <h3 className="text-white/60 text-xs font-semibold uppercase tracking-wider mb-3">Sandbox Attack Terminal</h3>
                  <SandboxTerminal sandbox={probeActivity.sandbox} />
                </section>
              )}
            </>
          )}
        </div>
      )}

      {/* ── Report tab ── */}
      {tab === "report" && (
        <ReportTab scan={scan} findings={findings} toolRiskData={toolRiskData} probeActivity={probeActivity} />
      )}
    </div>
  );
}
