import axios from "axios";
import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl, fetchToolChangelog } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, ToolchainConfig } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import { parseFindings } from "./dependency.js";

const SYSTEM = `You are BreachScope's Toolchain Agent — a cloud security specialist who finds real, exploitable misconfigurations in the SaaS tools developers use.

You have LIVE access to the user's actual Supabase, Vercel, and GitHub environments via the http_request tool.
You also have internet access via web_search and crawl_url.

Your job:
1. Use http_request to probe the real APIs with the provided credentials
2. Analyze the responses — look for misconfigurations, exposed data, and dangerous settings
3. Search the web for recent CVEs, breach patterns, and known issues specific to the tool versions/config you observe
4. Identify cross-tool attack chains (e.g., a leaked Vercel preview env var that also grants Supabase service_role access)

For Supabase — probe everything:
- REST API: /rest/v1/{table}?limit=1 for common tables (users, profiles, orders, payments, messages, documents, subscriptions, audit_log, admin_users)
- Auth settings: /auth/v1/settings — check autoconfirm, signup restrictions, MFA enforcement, rate limits
- Storage: /storage/v1/bucket — public buckets, file listing
- Schema endpoint: /rest/v1/ — what tables are exposed to anon key
- JWT role: decode the anon key JWT — is it actually service_role?
- Functions: /functions/v1/ — are edge functions publicly callable?

For Vercel — probe everything:
- /v10/projects/{id}/env — secrets in preview, plain-text secrets
- /v10/projects/{id} — preview protection, framework, build settings
- /v6/deployments?projectId={id}&limit=3 — check recent preview deployments
- Latest deployment logs — scan for leaked secrets
- /v10/projects/{id}/domains — unverified domains, no custom domain
- /v2/teams — open invite links

For GitHub — probe everything:
- Branch protection on main + master
- /repos/{owner}/{repo}/actions/permissions — default_workflow_permissions, can_approve_pull_request_reviews
- /repos/{owner}/{repo} — secret_scanning, push_protection, dependabot enabled, repo visibility
- /repos/{owner}/{repo}/contents/CODEOWNERS — exists?
- /repos/{owner}/{repo}/contents/.github/workflows — fetch each file, check for tag-pinned Actions, dangerous patterns like pull_request_target with checkout + run
- /repos/{owner}/{repo}/environments — production env has required reviewers?
- /user + x-oauth-scopes header — token privilege level
- /repos/{owner}/{repo}/actions/secrets — can we LIST secrets? (should be forbidden)

Look for second-order risks too:
- A Supabase anon key + no RLS + Vercel preview exposure = full database read from a PR link
- GitHub Actions write perms + no branch protection = supply chain injection vector
- Service role key in any env var = bypass of all security controls

Return ONLY a raw JSON array of Finding objects with fields: id, title, severity (critical|high|medium|low), category ("toolchain"), description, remediation, references (array), tool.
Do not wrap in markdown. Just the JSON array.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "http_request",
      description: "Make an authenticated HTTP request to a live API endpoint (Supabase, Vercel, GitHub, or any URL)",
      parameters: {
        type: "object",
        properties: {
          method: { type: "string", enum: ["GET", "POST", "PATCH", "DELETE"], description: "HTTP method" },
          url: { type: "string", description: "Full URL to request" },
          headers: {
            type: "object",
            description: "HTTP headers as key-value pairs",
            additionalProperties: { type: "string" },
          },
          body: { type: "string", description: "JSON body string for POST/PATCH requests" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "decode_jwt",
      description: "Decode a JWT token and return its header and payload (without verification)",
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
      name: "fetch_tool_changelog",
      description: "Fetch the latest security-relevant changelog/release notes for a SaaS tool",
      parameters: {
        type: "object",
        properties: {
          tool: { type: "string", enum: ["supabase", "vercel", "github"] },
        },
        required: ["tool"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for CVEs, security advisories, breach reports, and misconfigurations",
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
      description: "Fetch the content of a specific security advisory, documentation page, or changelog",
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
      method: method as "GET" | "POST" | "PATCH" | "DELETE",
      url,
      headers,
      data: body ? JSON.parse(body) : undefined,
      validateStatus: () => true,
      timeout: 10000,
      // Don't send full response body for large payloads — truncate
    });

    const responseHeaders: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(res.headers)) {
      responseHeaders[k] = v;
    }

    let responseBody: unknown = res.data;
    // Truncate large responses so we don't blow the context window
    if (typeof responseBody === "object") {
      const str = JSON.stringify(responseBody);
      if (str.length > 6000) {
        responseBody = JSON.parse(str.slice(0, 6000) + '"[truncated]"}');
      }
    } else if (typeof responseBody === "string" && responseBody.length > 3000) {
      responseBody = responseBody.slice(0, 3000) + "...[truncated]";
    }

    return JSON.stringify({
      status: res.status,
      headers: responseHeaders,
      body: responseBody,
    });
  } catch (e) {
    return JSON.stringify({ error: String(e) });
  }
}

function decodeJwt(token: string): string {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return JSON.stringify({ error: "Not a valid JWT" });
    const header = JSON.parse(Buffer.from(parts[0]!, "base64").toString()) as unknown;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64").toString()) as unknown;
    return JSON.stringify({ header, payload });
  } catch {
    return JSON.stringify({ error: "Failed to decode JWT" });
  }
}

function buildCredentialContext(toolchain: ToolchainConfig): string {
  const lines: string[] = ["Available credentials for live probing:"];

  const supabaseUrl = toolchain.supabase?.url ?? process.env["SUPABASE_URL"];
  const supabaseKey = toolchain.supabase?.anonKey ?? process.env["SUPABASE_ANON_KEY"];
  if (supabaseUrl && supabaseKey) {
    lines.push(`\nSupabase:`);
    lines.push(`  URL: ${supabaseUrl}`);
    lines.push(`  Anon key: ${supabaseKey}`);
    lines.push(`  REST base: ${supabaseUrl.replace(/\/$/, "")}/rest/v1`);
    lines.push(`  Auth base: ${supabaseUrl.replace(/\/$/, "")}/auth/v1`);
    lines.push(`  Storage base: ${supabaseUrl.replace(/\/$/, "")}/storage/v1`);
    lines.push(`  Standard headers: { apikey: "<anon_key>", Authorization: "Bearer <anon_key>" }`);
  }

  const vercelToken = toolchain.vercel?.token ?? process.env["VERCEL_TOKEN"];
  const vercelProjectId = toolchain.vercel?.projectId ?? process.env["VERCEL_PROJECT_ID"];
  if (vercelToken) {
    lines.push(`\nVercel:`);
    lines.push(`  Token: ${vercelToken}`);
    if (vercelProjectId) lines.push(`  Project ID: ${vercelProjectId}`);
    lines.push(`  API base: https://api.vercel.com`);
    lines.push(`  Standard headers: { Authorization: "Bearer <token>" }`);
  }

  const githubToken = toolchain.github?.token ?? process.env["GITHUB_TOKEN"];
  const githubRepo = toolchain.github?.repo ?? process.env["GITHUB_REPO"];
  if (githubToken) {
    lines.push(`\nGitHub:`);
    lines.push(`  Token: ${githubToken}`);
    if (githubRepo) lines.push(`  Repo: ${githubRepo}`);
    lines.push(`  API base: https://api.github.com`);
    lines.push(`  Standard headers: { Authorization: "Bearer <token>", Accept: "application/vnd.github+json", X-GitHub-Api-Version: "2022-11-28" }`);
  }

  if (lines.length === 1) {
    return "No toolchain credentials configured. Focus on web research for relevant security patterns.";
  }

  return lines.join("\n");
}

export async function runToolchainAgent(ctx: AgentContext): Promise<AgentResult> {
  const sourcesCrawled: string[] = [];

  const credentialContext = buildCredentialContext(ctx.toolchain);

  const priorFindings = ctx.existingFindings
    .filter((f) => f.category === "toolchain")
    .slice(0, 20);

  const userMessage = `${credentialContext}

Static scanner already found these issues (confirmed — don't re-report them, use them as context):
${priorFindings.length > 0 ? JSON.stringify(priorFindings, null, 2) : "None"}

Target URL: ${ctx.url ?? "not provided"}

Now probe the live environments directly. Use http_request to make real API calls.
Start with the most dangerous checks first (RLS, service role exposure, secrets in previews, Actions permissions).
Adapt based on what you find — if you find RLS is off, go deeper into what data is exposed.
Search the web to cross-reference any suspicious configs against known CVEs or breach patterns.

Return only findings that are real issues confirmed by the live probe results.`;

  const { content, tokensUsed } = await agentLoop(
    {
      system: SYSTEM,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.1,
      maxTokens: 8192,
    },
    async (toolName, args) => {
      switch (toolName) {
        case "http_request": {
          const method = String(args["method"] ?? "GET");
          const url = String(args["url"] ?? "");
          const headers = (args["headers"] ?? {}) as Record<string, string>;
          const body = args["body"] ? String(args["body"]) : undefined;
          logger.debug(`[toolchain-agent] ${method} ${url}`);
          sourcesCrawled.push(`${method}:${url}`);
          return httpRequest(method, url, headers, body);
        }
        case "decode_jwt": {
          return decodeJwt(String(args["token"] ?? ""));
        }
        case "fetch_tool_changelog": {
          const tool = String(args["tool"] ?? "") as "supabase" | "vercel" | "github";
          sourcesCrawled.push(`changelog:${tool}`);
          return fetchToolChangelog(tool);
        }
        case "web_search": {
          const query = String(args["query"] ?? "");
          sourcesCrawled.push(`web:${query}`);
          return webSearch(query);
        }
        case "crawl_url": {
          const url = String(args["url"] ?? "");
          sourcesCrawled.push(url);
          return crawlUrl(url);
        }
        default:
          return "Unknown tool";
      }
    }
  );

  const findings = parseFindings(content, "toolchain");
  logger.debug(`[toolchain-agent] ${findings.length} findings from live probing`);

  return { agent: "toolchain", findings, reasoning: content, sourcesCrawled, tokensUsed };
}
