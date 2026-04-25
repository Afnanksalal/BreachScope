import { complete } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentName, AgentResult, OrchestratorPlan } from "../core/types.js";
import { runDependencyAgent } from "./dependency.js";
import { runCodeAgent } from "./code.js";
import { runToolchainAgent } from "./toolchain.js";
import { runBlackboxAgent } from "./blackbox.js";
import { runReportAgent } from "./report.js";

const SYSTEM = `You are the BreachScope Orchestrator — a senior security architect overseeing a multi-agent breach detection pipeline.

Your job:
1. Receive a project profile (dependencies, tech stack, URL, toolchain config).
2. Decide which specialist agents to run based on what will be most impactful.
3. Return a JSON plan: { "agents": [...], "rationale": "..." }

Available agents:
- "dependency"  — supply chain analysis of npm packages, lockfiles, registries
- "code"        — deep static analysis of source files for secrets, vuln patterns, insecure APIs
- "toolchain"   — live API probing of Supabase, Vercel, GitHub for misconfigs
- "blackbox"    — HTTP probing of a live URL (security headers, CORS, exposed paths)

Rules:
- Always include "dependency" and "code" unless explicitly told to skip.
- Include "toolchain" only if at least one toolchain credential is present.
- Include "blackbox" only if a target URL is provided.
- Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

export async function runOrchestrator(ctx: AgentContext): Promise<AgentResult[]> {
  logger.section("AI Orchestrator");
  logger.info("Planning agent dispatch...");

  // Build a compact project profile for the planner
  const profile = {
    dependencyCount: ctx.dependencies.length,
    sampleDeps: ctx.dependencies.slice(0, 30),
    hasUrl: !!ctx.url,
    hasSupabase: !!(ctx.toolchain.supabase?.url || process.env["SUPABASE_URL"]),
    hasVercel: !!(ctx.toolchain.vercel?.token || process.env["VERCEL_TOKEN"]),
    hasGitHub: !!(ctx.toolchain.github?.token || process.env["GITHUB_TOKEN"]),
    fileCount: Object.keys(ctx.files).length,
    fileSample: Object.keys(ctx.files).slice(0, 20),
  };

  const { content, tokensUsed } = await complete({
    system: SYSTEM,
    messages: [{ role: "user", content: JSON.stringify(profile, null, 2) }],
    temperature: 0.1,
    maxTokens: 512,
  });

  let plan: OrchestratorPlan;
  try {
    plan = JSON.parse(content) as OrchestratorPlan;
  } catch {
    // Fallback: run everything applicable
    const agents: AgentName[] = ["dependency", "code"];
    if (profile.hasSupabase || profile.hasVercel || profile.hasGitHub) agents.push("toolchain");
    if (profile.hasUrl) agents.push("blackbox");
    plan = { agents, rationale: "Fallback plan — JSON parse failed." };
  }

  logger.info(`Plan: [${plan.agents.join(", ")}]`);
  logger.debug(`Rationale: ${plan.rationale}`);

  // Dispatch agents
  const AGENT_RUNNERS: Record<AgentName, (ctx: AgentContext) => Promise<AgentResult>> = {
    dependency: runDependencyAgent,
    code: runCodeAgent,
    toolchain: runToolchainAgent,
    blackbox: runBlackboxAgent,
    report: runReportAgent,
    orchestrator: async () => ({ agent: "orchestrator", findings: [], reasoning: "", sourcesCrawled: [], tokensUsed }),
  };

  const results: AgentResult[] = [];

  for (const agentName of plan.agents) {
    const runner = AGENT_RUNNERS[agentName];
    if (!runner) continue;

    logger.section(`Agent: ${agentName}`);
    try {
      const result = await runner({ ...ctx, existingFindings: results.flatMap((r) => r.findings) });
      results.push(result);
      logger.success(`${agentName} — ${result.findings.length} finding(s), ${result.tokensUsed} tokens`);
    } catch (e) {
      logger.error(`${agentName} agent failed: ${e}`);
    }
  }

  // Always synthesize a report
  logger.section("Agent: report");
  const report = await runReportAgent({ ...ctx, existingFindings: results.flatMap((r) => r.findings) });
  results.push(report);

  return results;
}
