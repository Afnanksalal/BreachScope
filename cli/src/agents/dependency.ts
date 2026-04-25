import { agentLoop } from "../core/ai.js";
import { webSearch, fetchNpmAdvisories, fetchGitHubAdvisory, fetchOSVData } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

const SYSTEM = `You are BreachScope's Dependency Agent — a specialist in supply chain security.

Your goal: identify supply chain and dependency risks in the project's packages.

You have access to tools to:
- Search for known vulnerabilities and advisories for specific packages
- Fetch GitHub Security Advisories
- Fetch OSV.dev data
- Search for recent security incidents involving npm packages

For each dependency you're concerned about:
1. Search for known issues
2. Check GitHub advisories
3. Reason about the risk

Return your findings as a JSON array of Finding objects. Each finding must have:
{
  "id": "unique-string",
  "title": "short title",
  "severity": "critical|high|medium|low|info",
  "category": "dependency",
  "description": "detailed explanation",
  "remediation": "what to do",
  "references": ["urls"],
  "tool": "npm"
}

Think deeply. Look for:
- Packages with known supply chain attacks
- Packages that were recently transferred to new maintainers (high risk window)
- Packages with very few maintainers controlling high-download packages
- Outdated packages with known CVEs
- Packages resolving from non-registry sources
- Typosquatting candidates near popular packages

After your research, return ONLY the JSON array of findings. No markdown fences.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "search_vulnerabilities",
      description: "Search the web for known vulnerabilities and security incidents for an npm package",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string", description: "The npm package name" },
        },
        required: ["package_name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fetch_github_advisory",
      description: "Fetch GitHub Security Advisories for an npm package",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string" },
        },
        required: ["package_name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fetch_osv_data",
      description: "Fetch OSV.dev vulnerability database entries for an npm package",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string" },
        },
        required: ["package_name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search the web for security-related information",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string" },
        },
        required: ["query"],
      },
    },
  },
];

export async function runDependencyAgent(ctx: AgentContext): Promise<AgentResult> {
  const sourcesCrawled: string[] = [];

  const userMessage = buildUserMessage(ctx);

  const { content, tokensUsed } = await agentLoop(
    {
      system: SYSTEM,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.15,
      maxTokens: 4096,
    },
    async (toolName, args) => {
      const pkg = String(args["package_name"] ?? "");
      const query = String(args["query"] ?? "");

      if (toolName === "search_vulnerabilities") {
        sourcesCrawled.push(`npm-advisories:${pkg}`);
        return fetchNpmAdvisories(pkg);
      }
      if (toolName === "fetch_github_advisory") {
        sourcesCrawled.push(`github-advisory:${pkg}`);
        return fetchGitHubAdvisory(pkg);
      }
      if (toolName === "fetch_osv_data") {
        sourcesCrawled.push(`osv:${pkg}`);
        return fetchOSVData(pkg);
      }
      if (toolName === "web_search") {
        sourcesCrawled.push(`web:${query}`);
        return webSearch(query);
      }
      return "Unknown tool";
    }
  );

  const findings = parseFindings(content, "dependency");
  logger.debug(`[dependency-agent] ${findings.length} findings parsed`);

  return {
    agent: "dependency",
    findings,
    reasoning: content,
    sourcesCrawled,
    tokensUsed,
  };
}

function buildUserMessage(ctx: AgentContext): string {
  const pkgJson = ctx.packageJson ?? {};
  const deps = {
    dependencies: (pkgJson["dependencies"] as Record<string, string>) ?? {},
    devDependencies: (pkgJson["devDependencies"] as Record<string, string>) ?? {},
  };

  return `Analyze the following project dependencies for supply chain risks.

package.json dependencies:
${JSON.stringify(deps, null, 2)}

Total unique packages: ${ctx.dependencies.length}

Focus your investigation on:
1. The 15 most downloaded / highest-risk packages in the list
2. Any packages that look unusual, obscure, or potentially typosquatted
3. Packages you know have had historical supply chain incidents

Use your tools to research the riskiest ones. Be thorough but prioritize impact.`;
}

function parseFindings(content: string, category: Finding["category"]): Finding[] {
  try {
    // Strip any markdown code fences the model might have added
    const clean = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(clean);
    const arr = Array.isArray(parsed) ? parsed : parsed.findings ?? [];
    return arr.map((f: Partial<Finding>, i: number) => ({
      id: f.id ?? `ai-${category}-${i}`,
      title: f.title ?? "Untitled finding",
      severity: f.severity ?? "info",
      category,
      description: f.description ?? "",
      remediation: f.remediation,
      references: f.references,
      tool: f.tool ?? "ai",
      file: f.file,
      line: f.line,
    }));
  } catch {
    logger.debug("[agent] Could not parse findings JSON from model output");
    return [];
  }
}

export { parseFindings };
