import { logger } from "../core/logger.js";
import type { DetectedTool, ToolPipelineResult, Finding } from "../core/types.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
import { agentLoop } from "../core/ai.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

const SAAS_SYSTEM = `You are a SaaS security analyst investigating a hosted service that a codebase depends on.

Given the service name and any crawled content, identify:
1. Known security incidents or breaches
2. Known CVEs or vulnerability classes in their SDKs
3. Security advisory pages
4. Compliance and data residency concerns
5. Common misconfigurations (from their docs or incident reports)

Return JSON:
{
  "riskScore": 0-100,
  "summary": "2-3 sentence risk assessment",
  "incidents": [{"date": "...", "title": "...", "severity": "critical|high|medium|low"}],
  "findings": [
    {
      "id": "saas-...",
      "title": "...",
      "severity": "critical|high|medium|low|info",
      "category": "supply-chain",
      "description": "...",
      "remediation": "...",
      "references": [...]
    }
  ]
}

No markdown fences.`;

const SAAS_TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for security incidents, CVEs, advisories for this SaaS service",
      parameters: {
        type: "object",
        properties: { query: { type: "string" } },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_page",
      description: "Fetch the content of a specific security or changelog page",
      parameters: {
        type: "object",
        properties: { url: { type: "string" } },
        required: ["url"],
      },
    },
  },
];

/**
 * Run the SaaS security pipeline for a detected hosted service.
 */
export async function runSaasPipeline(tool: DetectedTool): Promise<ToolPipelineResult> {
  const displayName = tool.name;
  logger.info(`[saas] Investigating ${displayName}...`);

  const sourcesCrawled: string[] = [];

  const userMessage = `Investigate the security posture of the SaaS service: "${displayName}"

Known info:
- npm package: ${tool.name}
- GitHub: ${tool.github ?? "unknown"}
- Homepage: ${tool.homepage ?? "unknown"}

Research:
1. Search for known security incidents or breaches involving ${displayName}
2. Check their security advisory page if it exists
3. Look for CVEs in their SDK (npm package: ${tool.name})
4. Check for known misconfiguration patterns developers make with this service

Be specific. Reference real incidents with dates if found.`;

  let findings: Finding[] = [];
  let riskScore = 20;
  let aiSummary = "";

  try {
    const { content } = await agentLoop(
      {
        system: SAAS_SYSTEM,
        messages: [{ role: "user", content: userMessage }],
        tools: SAAS_TOOLS,
        temperature: 0.15,
        maxTokens: 3000,
      },
      async (toolName, args) => {
        if (toolName === "web_search") {
          const query = String(args["query"] ?? "");
          sourcesCrawled.push(`web:${query}`);
          return webSearch(query, 4);
        }
        if (toolName === "crawl_page") {
          const url = String(args["url"] ?? "");
          sourcesCrawled.push(url);
          return crawlUrl(url);
        }
        return "Unknown tool";
      }
    );

    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(clean) as {
      riskScore?: number;
      summary?: string;
      findings?: Finding[];
    };

    riskScore = parsed.riskScore ?? 20;
    aiSummary = parsed.summary ?? "";
    findings = (parsed.findings ?? []).map((f, i) => ({
      ...f,
      id: f.id ?? `saas-${tool.name}-${i}`,
      category: "supply-chain" as const,
      tool: tool.name,
    }));
  } catch (e) {
    logger.debug(`[saas] Pipeline failed for ${tool.name}: ${e}`);
    aiSummary = "SaaS analysis unavailable.";
  }

  return {
    tool,
    osvVulnerabilities: [],
    findings,
    riskScore,
    aiSummary,
  };
}
