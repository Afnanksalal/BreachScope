import { complete } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";

const SYSTEM = `You are BreachScope's Report Agent — a CISO-level security analyst who synthesizes raw findings into an executive-grade security assessment.

You will receive all findings from multiple specialist agents. Your job:

1. Deduplicate findings that describe the same underlying issue
2. Identify attack chains — sequences of lower-severity issues that combine into a critical path
3. Prioritize by actual business impact, not just CVSS score
4. Write a concise executive summary (3-5 sentences)
5. Identify the single most urgent thing to fix first

Return JSON:
{
  "executiveSummary": "string",
  "criticalPath": "string (the highest-impact attack chain or single finding, explained in one paragraph)",
  "topPriority": "string (one sentence: the #1 thing to fix right now)",
  "deduplicatedFindings": [...findings array, same schema as input],
  "attackChains": [
    {
      "title": "string",
      "severity": "critical|high",
      "steps": ["step 1", "step 2", ...],
      "impact": "string"
    }
  ]
}

Be direct. Security theater wastes time. Only report what matters.`;

export interface ReportSynthesis {
  executiveSummary: string;
  criticalPath: string;
  topPriority: string;
  deduplicatedFindings: Finding[];
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
      deduplicatedFindings: [],
      attackChains: [],
    };
    return {
      agent: "report",
      findings: [],
      reasoning: "No findings to synthesize.",
      sourcesCrawled: [],
      tokensUsed: 0,
    };
  }

  const userMessage = `Synthesize the following security findings into an executive report.

Total raw findings: ${ctx.existingFindings.length}

Findings by category:
${JSON.stringify(groupByCategory(ctx.existingFindings), null, 2)}

All findings:
${JSON.stringify(ctx.existingFindings, null, 2)}

Identify attack chains. For example: if there's a CORS misconfiguration + an exposed API endpoint + missing auth → chain those into a data exfiltration path.`;

  const { content, tokensUsed } = await complete({
    system: SYSTEM,
    messages: [{ role: "user", content: userMessage }],
    temperature: 0.2,
    maxTokens: 4096,
  });

  let synthesis: ReportSynthesis;
  try {
    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed: unknown = JSON.parse(clean);
    if (!isReportSynthesis(parsed)) throw new Error("Response did not match ReportSynthesis schema");
    synthesis = parsed;
  } catch {
    synthesis = {
      executiveSummary: "Report synthesis failed — raw findings available below.",
      criticalPath: "",
      topPriority: "",
      deduplicatedFindings: ctx.existingFindings,
      attackChains: [],
    };
  }

  lastSynthesis = synthesis;
  logger.debug(`[report-agent] ${synthesis.attackChains.length} attack chain(s) identified`);

  return {
    agent: "report",
    findings: synthesis.deduplicatedFindings,
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
    typeof o["criticalPath"] === "string" &&
    typeof o["topPriority"] === "string" &&
    Array.isArray(o["deduplicatedFindings"]) &&
    Array.isArray(o["attackChains"])
  );
}

function groupByCategory(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.category] = (acc[f.category] ?? 0) + 1;
    return acc;
  }, {});
}
