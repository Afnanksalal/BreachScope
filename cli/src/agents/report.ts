import { complete } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";

const SYSTEM = `You are BreachScope's Report Agent — a CISO-level security analyst synthesizing raw findings into an executive-grade assessment.

You will receive a compact summary of findings (title + severity + description). Your job:
1. Write a concise executive summary (3-5 sentences) covering the overall security posture
2. Identify attack chains — sequences of lower-severity issues that combine into a critical path
3. Identify the single most urgent fix
4. Explain the highest-impact path

Return ONLY this JSON (no markdown fences, no extra keys):
{
  "executiveSummary": "string",
  "criticalPath": "string",
  "topPriority": "string",
  "attackChains": [
    {
      "title": "string",
      "severity": "critical|high",
      "steps": ["step 1", "step 2"],
      "impact": "string"
    }
  ]
}

Do NOT include a findings array in your response — findings are managed separately.
Be direct. No security theater.`;

export interface ReportSynthesis {
  executiveSummary: string;
  criticalPath: string;
  topPriority: string;
  attackChains: Array<{
    title: string;
    severity: string;
    steps: string[];
    impact: string;
  }>;
}

export let lastSynthesis: ReportSynthesis | null = null;

export async function runReportAgent(ctx: AgentContext): Promise<AgentResult> {
  if (ctx.existingFindings.length === 0) {
    lastSynthesis = {
      executiveSummary: "No findings detected across all scan types.",
      criticalPath: "None.",
      topPriority: "No immediate action required. Schedule a rescan after the next major dependency update.",
      attackChains: [],
    };
    return {
      agent: "report",
      findings: [],
      reasoning: lastSynthesis.executiveSummary,
      sourcesCrawled: [],
      tokensUsed: 0,
    };
  }

  // Send compact summaries only — full finding objects are too large and cause truncation.
  // GPT returns ONLY the narrative (no findings array echo), so the response stays small.
  const compact = ctx.existingFindings.map((f) => ({
    title:       f.title,
    severity:    f.severity,
    category:    f.category,
    description: f.description.slice(0, 180),
  }));

  // Group by severity so GPT can see the shape at a glance
  const bySev = groupBySeverity(ctx.existingFindings);

  const userMessage = `Synthesize these ${ctx.existingFindings.length} security findings into an executive report.

Severity breakdown: ${JSON.stringify(bySev)}
Categories: ${JSON.stringify(groupByCategory(ctx.existingFindings))}

Findings (compact):
${JSON.stringify(compact, null, 2)}

Identify attack chains — e.g. CORS misconfiguration + exposed endpoint + missing auth → data exfiltration path.`;

  const { content, tokensUsed } = await complete({
    system: SYSTEM,
    messages: [{ role: "user", content: userMessage }],
    temperature: 0.2,
    maxTokens: 2048,
  });

  let synthesis: ReportSynthesis;
  try {
    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed: unknown = JSON.parse(clean);
    if (!isReportSynthesis(parsed)) throw new Error("schema mismatch");
    synthesis = parsed;
  } catch (e) {
    logger.debug(`[report-agent] Parse failed: ${e} — response was: ${content.slice(0, 200)}`);
    synthesis = {
      executiveSummary: buildFallbackSummary(ctx.existingFindings),
      criticalPath: "",
      topPriority: topFinding(ctx.existingFindings),
      attackChains: [],
    };
  }

  lastSynthesis = synthesis;
  logger.debug(`[report-agent] ${synthesis.attackChains.length} attack chain(s) identified`);

  return {
    agent: "report",
    findings: [],  // findings managed by scan.ts, not returned here
    reasoning: synthesis.executiveSummary,
    sourcesCrawled: [],
    tokensUsed,
  };
}

function isReportSynthesis(v: unknown): v is ReportSynthesis {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o["executiveSummary"] === "string" &&
    Array.isArray(o["attackChains"])
  );
}

function groupByCategory(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.category] = (acc[f.category] ?? 0) + 1;
    return acc;
  }, {});
}

function groupBySeverity(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
}

function topFinding(findings: Finding[]): string {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const top = [...findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5))[0];
  if (!top) return "";
  return `Address the ${top.severity}-severity issue: ${top.title}`;
}

function buildFallbackSummary(findings: Finding[]): string {
  const bySev = groupBySeverity(findings);
  const parts: string[] = [];
  if (bySev["critical"]) parts.push(`${bySev["critical"]} critical`);
  if (bySev["high"])     parts.push(`${bySev["high"]} high`);
  if (bySev["medium"])   parts.push(`${bySev["medium"]} medium`);
  if (bySev["low"])      parts.push(`${bySev["low"]} low`);
  const cats = Object.keys(groupByCategory(findings)).join(", ");
  return `Scan identified ${findings.length} finding(s) — ${parts.join(", ")} — across ${cats}. Review the findings list for details.`;
}
