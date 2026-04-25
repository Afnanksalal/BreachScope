import pLimit from "p-limit";
import { logger } from "../core/logger.js";
import type { DetectedTool, ToolPipelineResult, Finding } from "../core/types.js";
import { fetchScorecard, scorecardToFindings } from "../apis/scorecard.js";
import { queryOSV, osvToFindings } from "../apis/osv.js";
import { fetchDepsDevProject, depsDevToFindings } from "../apis/deps-dev.js";
import { fetchNpmMeta, npmMetaToFindings } from "../apis/npm-registry.js";
import { complete } from "../core/ai.js";

const OSS_ANALYSIS_SYSTEM = `You are a senior supply-chain security analyst reviewing an open-source package.
Given structured security data about a package, produce a concise risk assessment.

Return JSON:
{
  "riskScore": 0-100,
  "summary": "2-3 sentence risk assessment",
  "keyRisks": ["risk1", "risk2", ...],
  "recommendation": "use | use-with-caution | replace | urgent-replace"
}

riskScore guide: 0=no risk, 25=minor concerns, 50=notable risks, 75=serious risks, 100=critical/avoid.
No markdown fences.`;

const limit = pLimit(5); // max 5 concurrent API calls

/**
 * Run the full OSS security pipeline for a detected tool.
 */
export async function runOssPipeline(tool: DetectedTool): Promise<ToolPipelineResult> {
  if (!tool.github) {
    return emptyResult(tool, "No GitHub repo — skipping OSS pipeline");
  }

  logger.info(`[oss] Scanning ${tool.name} (${tool.github})`);

  const findings: Finding[] = [];

  // Run all three public APIs in parallel
  const [scorecard, osvVulns, depsDevData, npmMeta] = await Promise.all([
    limit(() => fetchScorecard(tool.github!)),
    limit(() => queryOSV(tool.name, tool.version)),
    limit(() => fetchDepsDevProject(tool.github!)),
    limit(() => fetchNpmMeta(tool.name)),
  ]);

  if (scorecard) {
    findings.push(...scorecardToFindings(scorecard, tool.name));
  }

  if (osvVulns.length > 0) {
    findings.push(...osvToFindings(osvVulns, tool.name));
  }

  if (depsDevData) {
    findings.push(...depsDevToFindings(depsDevData, tool.name, tool.github!));
  }

  if (npmMeta) {
    findings.push(...npmMetaToFindings(npmMeta, tool.name));
  }

  // GPT-4o risk synthesis
  const riskScore = await synthesizeRisk({
    tool: tool.name,
    github: tool.github,
    scorecardScore: scorecard?.score,
    scorecardChecks: scorecard?.checks.filter((c) => c.score < 5),
    osvCount: osvVulns.length,
    osvIds: osvVulns.map((v) => v.id),
    maintainerCount: npmMeta?.maintainers.length,
    weeklyDownloads: npmMeta?.weeklyDownloads,
    depsDevScore: depsDevData?.scorecardV2?.score?.overall ?? depsDevData?.scorecard?.score,
  });

  return {
    tool,
    scorecard: scorecard ?? undefined,
    osvVulnerabilities: osvVulns,
    depsDevData: depsDevData ?? undefined,
    npmMeta: npmMeta ?? undefined,
    findings,
    riskScore: riskScore.score,
    aiSummary: riskScore.summary,
  };
}

async function synthesizeRisk(data: Record<string, unknown>): Promise<{ score: number; summary: string }> {
  try {
    const { content } = await complete({
      system: OSS_ANALYSIS_SYSTEM,
      messages: [{ role: "user", content: JSON.stringify(data, null, 2) }],
      temperature: 0.1,
      maxTokens: 512,
    });

    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed: unknown = JSON.parse(clean);
    if (
      typeof parsed !== "object" || parsed === null ||
      typeof (parsed as Record<string, unknown>)["riskScore"] !== "number" ||
      typeof (parsed as Record<string, unknown>)["summary"] !== "string"
    ) {
      throw new Error("Invalid synthesis response shape");
    }
    const p = parsed as Record<string, unknown>;
    return { score: p["riskScore"] as number, summary: p["summary"] as string };
  } catch {
    const osv = Number(data["osvCount"] ?? 0);
    const sc = Number(data["scorecardScore"] ?? 5);
    const fallbackScore = Math.min(100, osv * 15 + (10 - sc) * 5);
    return { score: fallbackScore, summary: "Automated risk assessment (AI synthesis unavailable)." };
  }
}

function emptyResult(tool: DetectedTool, reason: string): ToolPipelineResult {
  logger.debug(`[oss] Skipping ${tool.name}: ${reason}`);
  return {
    tool,
    osvVulnerabilities: [],
    findings: [],
    riskScore: 0,
    aiSummary: reason,
  };
}
