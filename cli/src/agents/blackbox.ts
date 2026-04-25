import { agentLoop } from "../core/ai.js";
import { webSearch } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult } from "../core/types.js";
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

Return ONLY a JSON array of Finding objects: id, title, severity, category ("blackbox"), description, remediation, references, detail.`;

const TOOLS: ChatCompletionTool[] = [
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
      description: "Search for vulnerabilities related to the observed tech stack or specific CVEs",
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

export async function runBlackboxAgent(ctx: AgentContext): Promise<AgentResult> {
  if (!ctx.url) {
    return { agent: "blackbox", findings: [], reasoning: "No URL provided.", sourcesCrawled: [], tokensUsed: 0 };
  }

  const sourcesCrawled: string[] = [];
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

Use http_probe to test specific attack paths. Use web_search to research identified tech stack versions.
Think like an attacker — what can you chain together?`;

  const { content, tokensUsed } = await agentLoop(
    {
      system: SYSTEM,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.2,
      maxTokens: 4096,
    },
    async (toolName, args) => {
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
        return webSearch(query, 3);
      }
      return "Unknown tool";
    }
  );

  const findings = parseFindings(content, "blackbox");
  logger.debug(`[blackbox-agent] ${findings.length} findings parsed`);

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
