import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl, fetchPackageAdvisories, fetchGitHubAdvisory, fetchOSVData } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding, LanguageDep } from "../core/types.js";
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

Use web_search and crawl_url aggressively — search every suspicious package for CVEs, hijacks, and malicious activity. Crawl NVD, GitHub advisories, and Socket.dev reports for full details.

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
Use web_search for every package that looks suspicious. Use crawl_url to read full GitHub advisories, NVD CVE pages, and Socket.dev/Snyk reports for complete exploit details and impact assessment.

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
Use web_search and crawl_url to look up exact CVE details, NVD CVSS scores, and PoC exploits for each vulnerable package you identify.

Return ONLY a JSON array of Finding objects with: id, title, severity, category ("dependency"), description, remediation, references, tool.
No markdown fences.`;

interface PendingFinding {
  id: string;
  title: string;
  severity: string;
  description: string;
  evidence: string;
  remediation: string;
  references: string[];
}

function makeFeedbackStore() {
  const findings: PendingFinding[] = [];
  let counter = 0;

  return {
    findings,
    save(title: string, severity: string, description: string, evidence: string, remediation: string, references: string[]): string {
      const id = `dep-${++counter}`;
      findings.push({ id, title, severity, description, evidence, remediation, references });
      return JSON.stringify({ success: true, id, total: findings.length });
    },
    get(): string {
      if (findings.length === 0) return JSON.stringify({ findings: [], note: "No findings saved yet." });
      return JSON.stringify({
        total: findings.length,
        findings: findings.map((f) => ({
          id: f.id, severity: f.severity, title: f.title,
          has_evidence: f.evidence.length > 10,
        })),
        instruction: "Review each finding. Use remove_finding(id) on any finding that is speculative, lacks a confirmed CVE/incident, or where the installed version is actually patched.",
      });
    },
    remove(id: string): string {
      const idx = findings.findIndex((f) => f.id === id);
      if (idx === -1) return JSON.stringify({ success: false, reason: "Not found" });
      const removed = findings.splice(idx, 1)[0]!;
      return JSON.stringify({ success: true, removed: removed.title, remaining: findings.length });
    },
  };
}

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "save_finding",
      description: "Submit a confirmed dependency vulnerability. ONLY call with concrete evidence: a confirmed CVE with matching version range, a confirmed supply chain incident, or a verified malicious package. Do NOT speculate.",
      parameters: {
        type: "object",
        properties: {
          title:       { type: "string" },
          severity:    { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: { type: "string", description: "Exact package name, ecosystem, installed version, vulnerable version range, CVE ID or incident reference, and attack impact." },
          evidence:    { type: "string", description: "CVE ID, advisory URL, or direct quote from the advisory confirming the vulnerability." },
          remediation: { type: "string", description: "Exact fix version or action." },
          references:  { type: "array", items: { type: "string" }, description: "Advisory URLs" },
        },
        required: ["title", "severity", "description", "evidence", "remediation"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_findings",
      description: "Review all findings saved so far. Call periodically to check quality — remove any speculative finding that lacks a real CVE or confirmed incident.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "remove_finding",
      description: "Remove a finding that is speculative, lacks evidence, or where the installed version is not actually in the vulnerable range.",
      parameters: {
        type: "object",
        properties: { id: { type: "string" } },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "search_vulnerabilities",
      description: "Search the web for known CVEs, security advisories, and supply chain incidents for any package regardless of language. Works for npm, PyPI, Go, Rust (crates.io), Ruby (RubyGems), PHP (Packagist), Java (Maven), .NET (NuGet), Elixir (Hex), Dart (pub), and more.",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string", description: "Package name (any ecosystem)" },
          ecosystem:    { type: "string", description: "Ecosystem: npm | PyPI | Go | crates.io | RubyGems | Maven | Packagist | NuGet | Hex | pub" },
        },
        required: ["package_name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fetch_github_advisory",
      description: "Fetch GitHub Security Advisories for a package from any ecosystem (npm, PyPI, Go, Rust, Ruby, Java, PHP, etc.)",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string" },
          ecosystem:    { type: "string", description: "Ecosystem hint for the advisory search" },
        },
        required: ["package_name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fetch_osv_data",
      description: "Query OSV.dev vulnerability database for a package. Covers all ecosystems: npm, PyPI, Go, crates.io, RubyGems, Maven, Packagist, NuGet, Hex, pub, and more.",
      parameters: {
        type: "object",
        properties: {
          package_name: { type: "string" },
          ecosystem:    { type: "string", description: "OSV ecosystem name: npm | PyPI | Go | crates.io | RubyGems | Maven | Packagist | NuGet | Hex | pub" },
        },
        required: ["package_name", "ecosystem"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search the web for supply chain attacks, CVEs, package hijacks, malicious packages, maintainer compromises — for ANY language ecosystem. Examples: 'requests PyPI vulnerability CVE', 'log4j Maven RCE exploit', 'event-stream npm supply chain attack', 'serde crates.io security advisory'.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Include package name, ecosystem, CVE ID, or attack type — be specific" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_url",
      description: "Fetch a specific advisory page, CVE detail, package registry page, GitHub security advisory, or threat intelligence report. Works for any language: NVD, OSV.dev, GHSA, PyPI, crates.io, RubyGems, pkg.go.dev, Packagist, NuGet, Snyk, Socket.dev.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "Full URL to fetch" },
        },
        required: ["url"],
      },
    },
  },
];

export async function runDependencyAgent(ctx: AgentContext): Promise<AgentResult> {
  const scanMode = ctx.scanMode ?? "all";
  const sourcesCrawled: string[] = [];
  const store = makeFeedbackStore();

  const system = scanMode === "full" ? SYSTEM_BREACH
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
      maxTokens: 8192,
      maxIterations: 30,
    },
    async (toolName, args) => {
      const pkg = String(args["package_name"] ?? "");
      const query = String(args["query"] ?? "");

      if (toolName === "save_finding") {
        const a = args as Record<string, unknown>;
        return store.save(
          String(a["title"] ?? ""), String(a["severity"] ?? "low"),
          String(a["description"] ?? ""), String(a["evidence"] ?? ""),
          String(a["remediation"] ?? ""),
          Array.isArray(a["references"]) ? (a["references"] as string[]) : [],
        );
      }
      if (toolName === "get_findings") return store.get();
      if (toolName === "remove_finding") return store.remove(String(args["id"] ?? ""));
      if (toolName === "search_vulnerabilities") {
        const eco = String(args["ecosystem"] ?? "npm");
        sourcesCrawled.push(`${eco}-advisories:${pkg}`);
        return fetchPackageAdvisories(pkg, eco);
      }
      if (toolName === "fetch_github_advisory") {
        const eco = String(args["ecosystem"] ?? "npm");
        sourcesCrawled.push(`github-advisory:${pkg}`);
        return fetchGitHubAdvisory(pkg, eco);
      }
      if (toolName === "fetch_osv_data") {
        const eco = String(args["ecosystem"] ?? "npm");
        sourcesCrawled.push(`osv:${pkg}`);
        return fetchOSVData(pkg, eco);
      }
      if (toolName === "web_search") {
        sourcesCrawled.push(`web:${query}`);
        return webSearch(query, 10);
      }
      if (toolName === "crawl_url") {
        const url = String(args["url"] ?? "");
        sourcesCrawled.push(`crawl:${url}`);
        return crawlUrl(url);
      }
      return "Unknown tool";
    }
  );

  // Primary: tool-submitted findings
  const toolFindings: Finding[] = store.findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity as Finding["severity"],
    category: "dependency" as const,
    description: f.description,
    remediation: f.remediation,
    references: f.references,
    tool: "ai",
    detail: f.evidence.slice(0, 400),
  }));

  // Fallback: JSON from final text (deduped)
  const toolTitles = new Set(toolFindings.map((f) => f.title.toLowerCase()));
  const textFindings = parseFindings(content, "dependency").filter((f) => !toolTitles.has(f.title.toLowerCase()));

  const findings = [...toolFindings, ...textFindings];
  logger.debug(`[dependency-agent] ${findings.length} findings (${toolFindings.length} via tool, ${textFindings.length} from text)`);

  return {
    agent: "dependency",
    findings,
    reasoning: content,
    sourcesCrawled,
    tokensUsed,
  };
}

function buildUserMessage(ctx: AgentContext, scanMode: string): string {
  const allDeps: LanguageDep[] = ctx.allDeps ?? [];

  // Group by ecosystem
  const byEco: Record<string, LanguageDep[]> = {};
  for (const d of allDeps) {
    (byEco[d.ecosystem] ??= []).push(d);
  }
  const ecosystems = Object.keys(byEco);

  // Format each ecosystem block
  const depBlocks = ecosystems.map((eco) => {
    const list = byEco[eco]!;
    const entries = list.map((d) => `  "${d.name}": "${d.version ?? "unknown"}"`).join(",\n");
    return `### ${eco} (${list.length} packages)\n{\n${entries}\n}`;
  }).join("\n\n");

  const modeInstruction = scanMode === "full"
    ? `MAXIMUM COVERAGE MODE: Combine breach + bug analysis. Aggressively hunt packages with known exploits, hijacks, or exfiltration potential AND cross-reference exploitable CVEs in auth/parsing/HTTP packages. Cover at least 25 packages across ALL ecosystems. Every finding must explain attack path and impact.`
    : scanMode === "breach"
    ? `BREACH MODE: This is an active breach investigation. Aggressively hunt for packages with known exploits, recent hijacks, or that could exfiltrate data. Cover at least 20 packages across ALL ecosystems. Every finding should explain immediate breach impact.`
    : scanMode === "bug"
    ? `BUG MODE: Focus on packages with exploitable CVEs that are reachable in this application. Cross-reference known vulnerable version ranges. Prioritize packages used in auth, parsing, and HTTP handling across ALL ecosystems.`
    : `STANDARD MODE: Identify the top supply chain risks across ALL ecosystems in this dependency list.`;

  return `${modeInstruction}

This project uses ${ecosystems.length} ecosystem(s): ${ecosystems.join(", ")}.
Total unique packages: ${allDeps.length}

IMPORTANT: Use the correct ecosystem parameter when calling fetch_osv_data, fetch_github_advisory, and search_vulnerabilities.
- npm packages → ecosystem: "npm"
- Python packages → ecosystem: "PyPI"
- Go modules → ecosystem: "Go"
- Rust crates → ecosystem: "crates.io"
- Ruby gems → ecosystem: "RubyGems"
- PHP packages → ecosystem: "Packagist"
- Java/Maven → ecosystem: "Maven"
- .NET/NuGet → ecosystem: "NuGet"
- Elixir → ecosystem: "Hex"
- Dart → ecosystem: "pub"

WORKFLOW:
1. Research packages using search_vulnerabilities, fetch_osv_data, fetch_github_advisory, web_search, crawl_url — always pass the correct ecosystem
2. For each confirmed vulnerability: call save_finding() with CVE ID or advisory URL as evidence
3. Every 5-6 researched packages: call get_findings() to review quality
4. Use remove_finding() on any finding where the installed version is not in the vulnerable range, or you can't confirm a real CVE/incident
5. Final pass: call get_findings() and remove any speculative findings before finishing

FEEDBACK LOOP: save_finding → get_findings → remove_finding is your quality gate.
Only findings with a confirmed CVE or documented incident should survive.

Dependencies by ecosystem:
${depBlocks || "(no dependencies detected)"}

Research the riskiest packages first across all ecosystems. Prioritize packages used in auth, HTTP handling, parsing, and file operations.
When done, output remaining findings as a JSON array (fallback for anything not submitted via save_finding).`;
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
