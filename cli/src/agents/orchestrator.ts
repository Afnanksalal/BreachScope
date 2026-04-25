import { complete } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentName, AgentResult, OrchestratorPlan } from "../core/types.js";
import { runDependencyAgent } from "./dependency.js";
import { runCodeAgent } from "./code.js";
import { runToolchainAgent } from "./toolchain.js";
import { runBlackboxAgent } from "./blackbox.js";
import { runReportAgent } from "./report.js";

const SYSTEM_BASE = `You are the BreachScope Orchestrator — a senior security architect overseeing a multi-agent breach detection pipeline.

Your job:
1. Receive a project profile (dependencies, tech stack, URL, toolchain config, and scan mode).
2. Decide which specialist agents to run based on what will be most impactful for the given mode.
3. Return a JSON plan: { "agents": [...], "rationale": "..." }

Available agents:
- "dependency"  — supply chain analysis: CVEs, malicious packages, typosquatting, recently-published, few-maintainer risks
- "code"        — deep static analysis: secrets, injection flaws, auth bypasses, insecure APIs, dangerous patterns
- "toolchain"   — live API probing of Supabase, Vercel, GitHub for misconfigurations and leaked permissions
- "blackbox"    — HTTP probing of a live URL: security headers, CORS, exposed paths, error leakage

Scan mode rules:
- "breach": ALWAYS include "dependency" and "code" (credential/secret focus). Include "toolchain" if any credential is present. Include "blackbox" if URL provided. Focus on CVEs, supply chain incidents, and leaked credentials.
- "bug": ALWAYS include "code" (deep vulnerability analysis). Include "dependency" only to cross-reference known-vulnerable versions. Skip "toolchain" unless explicitly present. Focus on injection, auth flaws, logic bugs.
- "all": Include "dependency" and "code" always. Include "toolchain" if credentials present. Include "blackbox" if URL provided.

Return ONLY valid JSON. No markdown, no explanation outside the JSON.`;

export async function runOrchestrator(ctx: AgentContext): Promise<AgentResult[]> {
  logger.section("AI Orchestrator");
  const scanMode = ctx.scanMode ?? "all";
  logger.info(`Planning agent dispatch [${scanMode.toUpperCase()} mode]...`);

  const effectiveMode = scanMode === "full" ? "full (breach + bug combined — maximum coverage)" : scanMode;
  const profile = {
    scanMode: effectiveMode,
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
    system: SYSTEM_BASE,
    messages: [{ role: "user", content: JSON.stringify(profile, null, 2) }],
    temperature: 0.1,
    maxTokens: 512,
  });

  let plan: OrchestratorPlan;
  try {
    plan = JSON.parse(content) as OrchestratorPlan;
  } catch {
    // Deterministic fallback based on mode — don't trust AI parse failure
    plan = buildFallbackPlan(scanMode, profile);
  }

  logger.info(`Plan: [${plan.agents.join(", ")}]`);
  logger.debug(`Rationale: ${plan.rationale}`);

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

  logger.section("Agent: report");
  const report = await runReportAgent({ ...ctx, existingFindings: results.flatMap((r) => r.findings) });
  results.push(report);

  return results;
}

function buildFallbackPlan(
  scanMode: string,
  profile: { hasUrl: boolean; hasSupabase: boolean; hasVercel: boolean; hasGitHub: boolean }
): OrchestratorPlan {
  const hasToolchain = profile.hasSupabase || profile.hasVercel || profile.hasGitHub;

  if (scanMode === "full") {
    const agents: AgentName[] = ["dependency", "code"];
    if (hasToolchain) agents.push("toolchain");
    if (profile.hasUrl) agents.push("blackbox");
    return { agents, rationale: "Full mode: everything — supply chain CVE + credential hunt + deep code audit + toolchain misconfig." };
  }

  if (scanMode === "breach") {
    const agents: AgentName[] = ["dependency", "code"];
    if (hasToolchain) agents.push("toolchain");
    if (profile.hasUrl) agents.push("blackbox");
    return { agents, rationale: "Breach mode: supply chain CVE + credential hunt + toolchain misconfig." };
  }

  if (scanMode === "bug") {
    const agents: AgentName[] = ["code", "dependency"];
    if (profile.hasUrl) agents.push("blackbox");
    return { agents, rationale: "Bug mode: deep code audit + vulnerable version cross-reference." };
  }

  const agents: AgentName[] = ["dependency", "code"];
  if (hasToolchain) agents.push("toolchain");
  if (profile.hasUrl) agents.push("blackbox");
  return { agents, rationale: "All mode: full spectrum scan." };
}
