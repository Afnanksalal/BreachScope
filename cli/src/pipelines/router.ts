import type { DetectedTool, ToolPipelineResult } from "../core/types.js";
import { runOssPipeline } from "./oss.js";
import { runSaasPipeline } from "./saas.js";
import { logger } from "../core/logger.js";

/**
 * Route a detected tool to the appropriate pipeline based on its kind.
 * Hybrid tools run both pipelines and merge results.
 */
export async function routeToPipeline(tool: DetectedTool): Promise<ToolPipelineResult> {
  switch (tool.kind) {
    case "oss":
      return runOssPipeline(tool);

    case "saas":
      return runSaasPipeline(tool);

    case "hybrid": {
      // Run both and merge — OSS pipeline for the SDK, SaaS pipeline for the hosted service
      logger.debug(`[router] Running hybrid pipeline for ${tool.name}`);
      const [ossResult, saasResult] = await Promise.all([
        runOssPipeline(tool),
        runSaasPipeline(tool),
      ]);

      return {
        tool,
        scorecard: ossResult.scorecard,
        osvVulnerabilities: ossResult.osvVulnerabilities,
        depsDevData: ossResult.depsDevData,
        npmMeta: ossResult.npmMeta,
        findings: [...ossResult.findings, ...saasResult.findings],
        riskScore: Math.max(ossResult.riskScore, saasResult.riskScore),
        aiSummary: [ossResult.aiSummary, saasResult.aiSummary].filter(Boolean).join(" | "),
      };
    }

    default:
      logger.debug(`[router] Skipping unknown tool kind for ${tool.name}`);
      return {
        tool,
        osvVulnerabilities: [],
        findings: [],
        riskScore: 0,
        aiSummary: "Tool kind unknown — classification may have failed.",
      };
  }
}
