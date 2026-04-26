import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import { parseFindings } from "./dependency.js";
import axios from "axios";

const SYSTEM = `You are BreachScope's Blackbox Agent — a penetration tester specializing in HTTP-level security analysis.

You will receive:
- A target URL
- Results from automated HTTP probes already run
- Headers, response bodies, and CORS behavior observed

Your job:
1. Interpret the raw probe data and identify what it means in terms of real exploitability
2. Use your http_probe tool to make additional targeted requests (test specific endpoints, header combinations, etc.)
3. Search for known vulnerabilities in the tech stack you can infer from the responses
4. Identify chained attack paths (e.g., CORS misconfiguration + stored XSS = account takeover)

Look for:
- Information disclosure in headers (X-Powered-By, Server, X-AspNet-Version)
- CORS misconfigurations enabling cross-origin data theft
- Security header weaknesses with concrete exploit scenarios
- Exposed admin interfaces, debug endpoints, API documentation
- Error messages leaking stack traces, file paths, or DB queries
- Authentication weaknesses (JWT without validation, session fixation)
- HTTP request smuggling indicators
- Open redirects
- GraphQL introspection enabled

When you find something, explain the concrete attack scenario — not just the header is missing.

Use web_search aggressively when you identify a framework, server version, or vulnerability indicator — search for known CVEs, exploit techniques, and HackTricks coverage immediately. Use crawl_url to read specific advisory pages, PortSwigger research, or HackTricks articles to get exact attack payloads and verify exploitability.

Return ONLY a JSON array of Finding objects: id, title, severity, category ("blackbox"), description, remediation, references, detail.`;

interface PendingFinding {
  id: string;
  title: string;
  severity: string;
  description: string;
  evidence: string;
  remediation: string;
}

function makeBlackboxFeedbackStore() {
  const findings: PendingFinding[] = [];
  let counter = 0;

  return {
    findings,
    save(title: string, severity: string, description: string, evidence: string, remediation: string): string {
      const id = `bb-${++counter}`;
      findings.push({ id, title, severity, description, evidence, remediation });
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
        instruction: "Review each finding. Use remove_finding(id) on any finding that is speculative, based only on a missing header, or that doesn't have a concrete attack path with HTTP response evidence.",
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
      description: "Submit a confirmed HTTP-level vulnerability. ONLY call when you have an HTTP response proving exploitability — a real CORS bypass, a real auth bypass response, a real info leak in response body. NOT for missing headers alone.",
      parameters: {
        type: "object",
        properties: {
          title:       { type: "string" },
          severity:    { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: { type: "string", description: "Exact HTTP request sent, exact response received, concrete attack scenario with impact." },
          evidence:    { type: "string", description: "The actual HTTP response or header that proves the vulnerability." },
          remediation: { type: "string" },
        },
        required: ["title", "severity", "description", "evidence", "remediation"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_findings",
      description: "Review all findings saved so far. Call after every 4-5 probes to verify quality. Remove findings that lack real HTTP evidence.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "remove_finding",
      description: "Remove a speculative finding or one that only flags a missing header without a proven attack path.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "http_probe",
      description: "Make an HTTP request to the target and return status, headers, and body snippet",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Path to request (e.g. /api/users)" },
          method: { type: "string", enum: ["GET", "POST", "OPTIONS", "HEAD", "DELETE", "PUT"], default: "GET" },
          headers: { type: "object", description: "Additional request headers", additionalProperties: { type: "string" } },
          body: { type: "string", description: "Request body for POST/PUT" },
        },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for CVEs, exploit techniques, and security research related to the observed tech stack, server version, or headers. Use aggressively — when you see 'X-Powered-By: Express 4.18', search for known Express 4.18 CVEs immediately. Examples: 'nginx 1.18 CVE exploit', 'GraphQL introspection attack payloads', 'JWT RS256 to HS256 confusion attack'.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Include version numbers, framework names, CVE IDs — be specific" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_url",
      description: "Fetch a specific security resource — PortSwigger research, HackTricks (book.hacktricks.xyz), NVD CVE pages, vendor security advisories, or OWASP testing guides. Use to get exact attack payloads and step-by-step exploit instructions.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "Full URL: PortSwigger, HackTricks, NVD, OWASP, vendor advisory" },
        },
        required: ["url"],
      },
    },
  },
];

export async function runBlackboxAgent(ctx: AgentContext): Promise<AgentResult> {
  if (!ctx.url) {
    return { agent: "blackbox", findings: [], reasoning: "No URL provided.", sourcesCrawled: [], tokensUsed: 0 };
  }

  const sourcesCrawled: string[] = [];
  const store = makeBlackboxFeedbackStore();
  const baseUrl = ctx.url.replace(/\/$/, "");

  // Pre-collect some basic info for the agent to start with
  const initialProbe = await probeHttp(baseUrl, "/", "GET", {});
  const optionsProbe = await probeHttp(baseUrl, "/", "OPTIONS", {});

  const userMessage = `Analyze this target for HTTP-level security vulnerabilities.

Target URL: ${baseUrl}

Initial probe results:

GET /:
${initialProbe}

OPTIONS /:
${optionsProbe}

Prior static probe findings (for context):
${JSON.stringify(ctx.existingFindings.filter((f) => f.category === "blackbox").slice(0, 10), null, 2)}

WORKFLOW:
1. Use http_probe to test attack paths — don't just read headers, actively probe
2. For every confirmed vulnerability: call save_finding() with the actual HTTP response as evidence
3. Every 4-5 probes: call get_findings() to review quality
4. Use remove_finding() on any finding based only on a missing header without a proven attack path
5. Final pass: call get_findings() and clean up before finishing

FEEDBACK LOOP: save_finding → get_findings → remove_finding is your quality gate.
"Missing X-Frame-Options" is not a finding without a proven clickjacking attack path.
A real CORS bypass with evidence IS a finding. A real auth bypass response IS a finding.

Think like an attacker — what can you chain together? Use web_search for any tech stack version you identify.
When done, output remaining findings as a JSON array (fallback for anything not submitted via save_finding).`;

  const { content, tokensUsed } = await agentLoop(
    {
      system: SYSTEM,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.15,
      maxTokens: 8192,
      maxIterations: 25,
    },
    async (toolName, args) => {
      if (toolName === "save_finding") {
        const a = args as Record<string, unknown>;
        return store.save(
          String(a["title"] ?? ""), String(a["severity"] ?? "low"),
          String(a["description"] ?? ""), String(a["evidence"] ?? ""),
          String(a["remediation"] ?? ""),
        );
      }
      if (toolName === "get_findings") return store.get();
      if (toolName === "remove_finding") return store.remove(String(args["id"] ?? ""));
      if (toolName === "http_probe") {
        const path = String(args["path"] ?? "/");
        const method = String(args["method"] ?? "GET");
        const headers = (args["headers"] as Record<string, string>) ?? {};
        const body = args["body"] as string | undefined;
        sourcesCrawled.push(`${method} ${baseUrl}${path}`);
        return probeHttp(baseUrl, path, method, headers, body);
      }
      if (toolName === "web_search") {
        const query = String(args["query"] ?? "");
        sourcesCrawled.push(`web:${query}`);
        return webSearch(query, 8);
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
    category: "blackbox" as const,
    description: f.description,
    remediation: f.remediation,
    references: [],
    detail: f.evidence.slice(0, 500),
  }));

  // Fallback: JSON from final text (deduped)
  const toolTitles = new Set(toolFindings.map((f) => f.title.toLowerCase()));
  const textFindings = parseFindings(content, "blackbox").filter((f) => !toolTitles.has(f.title.toLowerCase()));

  const findings = [...toolFindings, ...textFindings];
  logger.debug(`[blackbox-agent] ${findings.length} findings (${toolFindings.length} via tool, ${textFindings.length} from text)`);

  return { agent: "blackbox", findings, reasoning: content, sourcesCrawled, tokensUsed };
}

async function probeHttp(
  base: string,
  path: string,
  method: string,
  extraHeaders: Record<string, string>,
  body?: string
): Promise<string> {
  try {
    const res = await axios.request({
      method,
      url: `${base}${path}`,
      headers: { "User-Agent": "BreachScope/0.1 Security Scanner", ...extraHeaders },
      data: body,
      validateStatus: () => true,
      timeout: 8000,
      maxContentLength: 50000,
    });

    const headerLines = Object.entries(res.headers as Record<string, string>)
      .map(([k, v]) => `  ${k}: ${String(v).slice(0, 120)}`)
      .join("\n");

    const bodySnippet = typeof res.data === "string"
      ? res.data.slice(0, 800)
      : JSON.stringify(res.data).slice(0, 800);

    return `HTTP ${res.status} ${res.statusText}\nHeaders:\n${headerLines}\n\nBody (first 800 chars):\n${bodySnippet}`;
  } catch (e) {
    return `Request failed: ${String(e)}`;
  }
}
