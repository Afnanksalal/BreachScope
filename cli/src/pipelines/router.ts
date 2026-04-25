import type { DetectedTool, ToolPipelineResult, ScanMode } from "../core/types.js";
import { runOssPipeline } from "./oss.js";
import { runSaasPipeline } from "./saas.js";
import { logger } from "../core/logger.js";

export async function routeToPipeline(
  tool: DetectedTool,
  mode: ScanMode = "basic"
): Promise<ToolPipelineResult> {
  switch (tool.kind) {
    case "oss":
      return runOssPipeline(tool, mode);

    case "saas":
      return runSaasPipeline(tool);

    case "hybrid": {
      logger.debug(`[router] Running hybrid pipeline for ${tool.name}`);
      const [ossResult, saasResult] = await Promise.all([
        runOssPipeline(tool, mode),
        runSaasPipeline(tool),
      ]);

      return {
        tool,
        scorecard:          ossResult.scorecard,
        osvVulnerabilities: ossResult.osvVulnerabilities,
        depsDevData:        ossResult.depsDevData,
        npmMeta:            ossResult.npmMeta,
        findings:           [...ossResult.findings, ...saasResult.findings],
        riskScore:          Math.max(ossResult.riskScore, saasResult.riskScore),
        aiSummary:          [ossResult.aiSummary, saasResult.aiSummary].filter(Boolean).join(" | "),
      };
    }

    default:
      // unknown kind: still run OSV + npm (they work by package name alone)
      logger.debug(`[router] Running minimal OSS pipeline for unknown tool ${tool.name}`);
      return runOssPipeline(tool, mode);
  }
}
