import { agentLoop } from "../core/ai.js";
import { webSearch, fetchNpmAdvisories, fetchGitHubAdvisory, fetchOSVData } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

const SYSTEM_ALL = `You are BreachScope's Dependency Agent — a specialist in supply chain security.

Your goal: identify supply chain and dependency risks in the project's packages.

Think deeply. Look for:
- Packages with known supply chain attacks
- Packages recently transferred to new maintainers (high risk window)
- Packages with very few maintainers controlling high-download packages
- Outdated packages with known CVEs
- Packages resolving from non-registry sources
- Typosquatting candidates near popular packages

Return ONLY a JSON array of Finding objects with: id, title, severity, category ("dependency"), description, remediation, references, tool.
No markdown fences.`;

const SYSTEM_BREACH = `You are BreachScope's Supply Chain Breach Intelligence Agent — an elite analyst specializing in active exploitation paths through the dependency tree.

Your mission: find dependencies that represent an IMMEDIATE breach risk or active supply chain threat.

Prioritize and actively investigate:
1. **Active malware / supply chain attacks**: packages known to have been hijacked, contain malicious postinstall scripts, or exfiltrate environment variables
2. **CVE severity critical/high**: packages with unpatched CVEs that have public exploits — focus on RCE, authentication bypass, data exfiltration
3. **Maintainer takeover risk**: packages with single maintainers, recently transferred ownership, or maintainers with compromised npm accounts
4. **Typosquatting**: packages whose names are 1-2 characters off from popular packages (lodahs, reqest, expres, etc.)
5. **Dependency confusion**: internal-looking package names that may be intercepted on the public registry
6. **Recently published with high access**: packages published in the last 30 days that have access to sensitive APIs (crypto, fs, net, child_process)
7. **Known bad packages**: packages flagged by Socket.dev, Snyk, or npm security team

For each finding, explain exactly what breach impact it has: data exfiltration, RCE, credential theft, etc.
Search aggressively — don't stop at 1-2 packages. Cover the 20 riskiest packages in the list.

Return ONLY a JSON array of Finding objects with: id, title, severity, category ("dependency"), description, remediation, references, tool.
No markdown fences.`;

const SYSTEM_BUG = `You are BreachScope's Vulnerable Dependency Agent — a specialist in finding packages with exploitable CVEs relevant to the current codebase.

Your mission: identify dependencies that introduce real, exploitable vulnerabilities into this application.

Focus on:
- Packages with known CVEs that are actually reachable given the project's usage patterns
- Version ranges that include vulnerable releases (check if the installed version is patched)
- Transitive dependency vulnerabilities in critical packages (express middleware, auth libraries, parsers)
- Known prototype pollution vulnerabilities in utility libraries
- ReDoS vulnerabilities in validation/parsing packages
- Path traversal in file-handling packages
- Authentication bypass in auth middleware

Cross-reference the dependency list against known vulnerable versions. Be specific about which version range is affected and what the fix version is.

Return ONLY a JSON array of Finding objects with: id, title, severity, category ("dependency"), description, remediation, references, tool.
No markdown fences.`;

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
  const scanMode = ctx.scanMode ?? "all";
  const sourcesCrawled: string[] = [];

  const system = scanMode === "full" ? SYSTEM_BREACH  // full mode: use aggressive breach hunting for deps
    : scanMode === "breach" ? SYSTEM_BREACH
    : scanMode === "bug" ? SYSTEM_BUG
    : SYSTEM_ALL;

  const userMessage = buildUserMessage(ctx, scanMode);

  const { content, tokensUsed } = await agentLoop(
    {
      system,
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

function buildUserMessage(ctx: AgentContext, scanMode: string): string {
  const pkgJson = ctx.packageJson ?? {};
  const deps = {
    dependencies: (pkgJson["dependencies"] as Record<string, string>) ?? {},
    devDependencies: (pkgJson["devDependencies"] as Record<string, string>) ?? {},
  };

  const modeInstruction = scanMode === "full"
    ? `MAXIMUM COVERAGE MODE: Combine breach + bug analysis. Aggressively hunt packages with known exploits, hijacks, or exfiltration potential AND cross-reference exploitable CVEs in auth/parsing/HTTP packages. Cover at least 25 packages. Every finding must explain attack path and impact.`
    : scanMode === "breach"
    ? `BREACH MODE: This is an active breach investigation. Aggressively hunt for packages with known exploits, recent hijacks, or that could exfiltrate data. Cover at least 20 packages. Every finding should explain immediate breach impact.`
    : scanMode === "bug"
    ? `BUG MODE: Focus on packages with exploitable CVEs that are reachable in this application. Cross-reference known vulnerable version ranges. Prioritize packages used in auth, parsing, and HTTP handling.`
    : `STANDARD MODE: Identify the top supply chain risks across this dependency list.`;

  return `${modeInstruction}

package.json dependencies:
${JSON.stringify(deps, null, 2)}

Total unique packages: ${ctx.dependencies.length}
All package names: ${ctx.dependencies.join(", ")}

Use your tools to research the riskiest packages. Be thorough — prioritize by impact.`;
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
