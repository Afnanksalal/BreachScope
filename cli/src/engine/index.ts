import pLimit from "p-limit";
import ora from "ora";
import chalk from "chalk";
import { logger } from "../core/logger.js";
import type {
  DetectedTool,
  ScanMode,
  SubchainScanResult,
  ToolPipelineResult,
  SubchainConfig,
} from "../core/types.js";
import { detectTools } from "../detectors/index.js";
import { classifyTools } from "../classifiers/tool.js";
import { routeToPipeline } from "../pipelines/router.js";
import { fetchNpmMeta } from "../apis/npm-registry.js";
import { fetchPypiMeta } from "../apis/pypi.js";
import { resolveKnownTool } from "../core/toolmap.js";
import { DepGraph, shouldSkipPackage } from "./graph.js";

const MODE_DEPTH: Record<ScanMode, number> = {
  basic: 1,   // direct tools only
  major: 2,   // tools + their direct deps
  deep: 6,    // transitive tree up to 6 levels
};

/**
 * Main sub-toolchain scan engine.
 * Detects, classifies, and recursively audits every tool in the dependency graph.
 */
export async function runSubchainScan(
  cwd: string,
  mode: ScanMode,
  config?: SubchainConfig
): Promise<SubchainScanResult> {
  const maxDepth = config?.maxDepth ?? MODE_DEPTH[mode];
  const concurrency = config?.concurrency ?? 5;
  const ignore = new Set(config?.ignore ?? []);
  const limit = pLimit(concurrency);
  const graph = new DepGraph();

  logger.section(`Sub-Toolchain Scan [${mode.toUpperCase()} mode, depth=${maxDepth}]`);

  // ── Phase 1: Detect & classify direct tools ───────────────────────────────
  const spinner = ora("Detecting tools in codebase...").start();
  const rawDetected = await detectTools(cwd);
  spinner.text = "Classifying tools (OSS / SaaS / hybrid)...";
  const classified = await classifyTools(rawDetected);
  spinner.succeed(`Detected and classified ${classified.length} tool(s)`);

  // Initialize work queue at depth=0
  const queue: DetectedTool[] = classified.filter((t) => !ignore.has(t.name));
  const visited = new Set<string>();
  const allResults: ToolPipelineResult[] = [];
  // requiredBy tracks every parent that depends on a given package (for dedup reporting)
  const requiredBy = new Map<string, Set<string>>();

  // Add all direct tools to graph
  for (const tool of queue) {
    graph.addNode(tool.name, tool.kind, 0, 0);
    visited.add(tool.name);
  }

  // ── Phase 2: Recursive scan loop ─────────────────────────────────────────
  let currentDepth = 0;

  while (queue.length > 0 && currentDepth < maxDepth) {
    const currentBatch = [...queue];
    queue.length = 0;
    currentDepth++;

    logger.info(`Scanning depth ${currentDepth - 1}: ${currentBatch.length} tool(s)`);

    const batchResults = await Promise.all(
      currentBatch.map((tool) =>
        limit(async () => {
          const badge = tool.kind === "oss"
            ? chalk.cyan("[OSS]")
            : tool.kind === "saas"
            ? chalk.magenta("[SaaS]")
            : chalk.yellow("[Hybrid]");
          const ecoLabel = tool.ecosystem && tool.ecosystem !== "npm" ? chalk.gray(`[${tool.ecosystem}] `) : "";
          logger.info(`  ${badge} ${ecoLabel}${tool.name}${tool.depth > 0 ? chalk.gray(` (via ${tool.parent ?? "?"})`) : ""}`);

          const result = await routeToPipeline(tool, mode);
          graph.addNode(tool.name, tool.kind, result.riskScore, tool.depth);

          // Enqueue sub-dependencies for next depth level if mode allows
          if (currentDepth < maxDepth) {
            const subDeps = await fetchSubDependencies(tool);
            for (const sub of subDeps) {
              if (ignore.has(sub.name) || shouldSkipPackage(sub.name)) continue;

              // Always record the parent→child relationship in the graph
              graph.addEdge(tool.name, sub.name);

              // Track which parents require this package (for shared-dep reporting)
              if (!requiredBy.has(sub.name)) requiredBy.set(sub.name, new Set());
              requiredBy.get(sub.name)!.add(tool.name);

              if (!visited.has(sub.name)) {
                visited.add(sub.name);
                graph.addNode(sub.name, sub.kind, 0, sub.depth);
                queue.push(sub);
              } else {
                // Already audited — log the shared relationship, skip re-scan
                const parents = [...requiredBy.get(sub.name)!].join(", ");
                logger.debug(`  [dedup] ${sub.name} already audited — shared by: ${parents}`);
              }
            }
          }

          return result;
        })
      )
    );

    allResults.push(...batchResults);
  }

  const allFindings = allResults.flatMap((r) => r.findings);

  // Build sharedPackages: only packages required by 2+ parents
  const sharedPackages: Record<string, string[]> = {};
  for (const [pkg, parents] of requiredBy) {
    if (parents.size >= 2) sharedPackages[pkg] = [...parents];
  }

  const sharedCount = Object.keys(sharedPackages).length;
  logger.success(
    `Sub-chain scan complete: ${allResults.length} tools scanned, ${allFindings.length} finding(s), ` +
    `depth reached: ${currentDepth}` +
    (sharedCount > 0 ? `, ${sharedCount} shared dep(s) deduped` : "")
  );

  return {
    mode,
    toolsScanned: allResults.length,
    depthReached: currentDepth,
    toolResults: allResults,
    allFindings,
    graph: graph.toJSON(),
    sharedPackages,
  };
}

/**
 * Fetch the direct dependencies of a tool from the appropriate registry,
 * classify them, and return as DetectedTool at depth+1.
 * Supports npm and PyPI; Go/Rust sub-deps are skipped (too noisy).
 */
async function fetchSubDependencies(parent: DetectedTool): Promise<DetectedTool[]> {
  if (parent.kind === "saas") return [];

  const ecosystem = parent.ecosystem ?? "npm";

  try {
    if (ecosystem === "PyPI") {
      const meta = await fetchPypiMeta(parent.name);
      if (!meta || Object.keys(meta.dependencies).length === 0) return [];

      return Object.entries(meta.dependencies)
        .filter(([name]) => !shouldSkipPackage(name))
        .slice(0, 20) // cap Python deps — requirements can be huge
        .map(([name, version]) => ({
          name,
          version: version === "*" ? undefined : version.replace(/^[\^~>=<]+/, ""),
          kind: "unknown" as const,
          detectedFrom: ["sub-dependency"] as const,
          depth: parent.depth + 1,
          parent: parent.name,
          ecosystem: "PyPI",
        }));
    }

    if (ecosystem === "Go" || ecosystem === "crates.io" || ecosystem === "RubyGems") {
      return []; // Sub-dependency recursion for these is handled by lockfile scanners
    }

    // Default: npm
    const meta = await fetchNpmMeta(parent.name);
    if (!meta || !meta.dependencies) return [];

    const subDeps: DetectedTool[] = [];
    for (const [depName, depVersion] of Object.entries(meta.dependencies)) {
      if (shouldSkipPackage(depName)) continue;
      const known = resolveKnownTool(depName);
      subDeps.push({
        name: depName,
        version: depVersion.replace(/^[\^~>=<!]+/, "").split(/[\s,|]/)[0],
        kind: known?.kind ?? "unknown",
        github: known?.github,
        detectedFrom: ["sub-dependency"],
        depth: parent.depth + 1,
        parent: parent.name,
        ecosystem: "npm",
      });
    }
    return subDeps;
  } catch {
    return [];
  }
}
