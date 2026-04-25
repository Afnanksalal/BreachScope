import axios from "axios";
import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { Finding } from "../core/types.js";
import type { ServiceDefinition } from "../core/services.js";
import { parseFindings } from "./dependency.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "http_request",
      description: "Make an HTTP request to any URL — use this to probe the live service APIs",
      parameters: {
        type: "object",
        properties: {
          method:  { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
          url:     { type: "string" },
          headers: { type: "object", additionalProperties: { type: "string" } },
          body:    { type: "string", description: "JSON body string" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "decode_jwt",
      description: "Decode a JWT without verification — reveals role, expiry, issuer, etc.",
      parameters: {
        type: "object",
        properties: {
          token: { type: "string" },
        },
        required: ["token"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for CVEs, known misconfigs, and security issues for this service",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_url",
      description: "Fetch a specific advisory, changelog, or docs page",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string" },
        },
        required: ["url"],
      },
    },
  },
];

async function httpRequest(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string
): Promise<string> {
  try {
    const res = await axios.request({
      method: method as "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
      url,
      headers,
      data: body ? (JSON.parse(body) as unknown) : undefined,
      validateStatus: () => true,
      timeout: 12000,
    });

    const responseHeaders: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(res.headers)) responseHeaders[k] = v;

    let responseBody: unknown = res.data;
    const str = typeof responseBody === "object" ? JSON.stringify(responseBody) : String(responseBody ?? "");
    if (str.length > 8000) {
      responseBody = str.slice(0, 8000) + "...[truncated]";
    }

    return JSON.stringify({ status: res.status, headers: responseHeaders, body: responseBody });
  } catch (e) {
    return JSON.stringify({ error: String(e) });
  }
}

function decodeJwt(token: string): string {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return JSON.stringify({ error: "Not a valid JWT" });
    const header  = JSON.parse(Buffer.from(parts[0]!, "base64url").toString()) as unknown;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString()) as unknown;
    return JSON.stringify({ header, payload });
  } catch {
    return JSON.stringify({ error: "Failed to decode JWT" });
  }
}

function buildSystemPrompt(service: ServiceDefinition): string {
  return `You are BreachScope's live security probe agent for ${service.name} (${service.category}).

You have real credentials for this live ${service.name} instance. Your job is to find genuine security issues by probing the actual API — not theoretical risks.

Methodology:
1. Start by probing the most dangerous potential issues first (over-privileged keys, exposed data, misconfigs)
2. Use what you find to decide what to probe next — adapt based on real responses
3. Decode any JWT tokens to check their role and permissions
4. Search the web for known CVEs or misconfigurations specific to the version/config you observe
5. Look for cross-cutting risks: does the key have more permissions than needed? Can you read data that should be restricted? Are there admin APIs accessible?

Return ONLY a raw JSON array of Finding objects:
[
  {
    "id": "unique-slug",
    "title": "Short title",
    "severity": "critical | high | medium | low",
    "category": "toolchain",
    "tool": "${service.id}",
    "description": "What the issue is and what an attacker could do with it",
    "remediation": "Specific steps to fix",
    "references": ["https://..."]
  }
]

Only include findings confirmed by actual API responses. If a probe returns an error or expected 403, that is not a finding.
Do not wrap in markdown. Output only the JSON array.`;
}

function buildUserMessage(service: ServiceDefinition, credentials: Record<string, string>): string {
  const credLines = Object.entries(credentials)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join("\n");

  return `Credentials for ${service.name}:
${credLines}

Begin probing the live ${service.name} environment. Use http_request to test the actual APIs.
Start with the highest-risk checks, adapt based on what you find.`;
}

export interface LiveProbeResult {
  service: string;
  findings: Finding[];
  tokensUsed: number;
}

export async function runLiveProbe(
  service: ServiceDefinition,
  credentials: Record<string, string>
): Promise<LiveProbeResult> {
  logger.info(`  Probing ${service.name}...`);

  const system = buildSystemPrompt(service);
  const userMessage = buildUserMessage(service, credentials);

  const { content, tokensUsed } = await agentLoop(
    {
      system,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.05,
      maxTokens: 8192,
    },
    async (toolName, args) => {
      switch (toolName) {
        case "http_request": {
          const method  = String(args["method"] ?? "GET");
          const url     = String(args["url"] ?? "");
          const headers = (args["headers"] ?? {}) as Record<string, string>;
          const body    = args["body"] ? String(args["body"]) : undefined;
          logger.debug(`  [${service.id}] ${method} ${url}`);
          return httpRequest(method, url, headers, body);
        }
        case "decode_jwt":
          return decodeJwt(String(args["token"] ?? ""));
        case "web_search":
          return webSearch(String(args["query"] ?? ""));
        case "crawl_url":
          return crawlUrl(String(args["url"] ?? ""));
        default:
          return "Unknown tool";
      }
    }
  );

  const findings = parseFindings(content, "toolchain");
  return { service: service.id, findings, tokensUsed };
}
