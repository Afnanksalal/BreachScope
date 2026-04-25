import { agentLoop } from "../core/ai.js";
import { webSearch } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import { parseFindings } from "./dependency.js";

const SYSTEM = `You are BreachScope's Code Audit Agent — an elite application security engineer specializing in source code vulnerability analysis.

You will receive file contents from the project. Your job is to identify real, exploitable security vulnerabilities — not style issues.

Focus on:
- Hardcoded secrets, API keys, tokens, credentials
- Injection vulnerabilities (SQL, command, LDAP, XPath, template injection)
- Authentication and authorization flaws (missing auth checks, broken access control)
- Insecure cryptography (MD5/SHA1 for security, Math.random() for tokens, ECB mode)
- Dangerous API usage (eval, Function(), innerHTML without sanitization, dangerouslySetInnerHTML)
- Path traversal and directory listing
- Server-Side Request Forgery (SSRF) patterns
- Prototype pollution
- Regular expression denial of service (ReDoS) — exponential backtracking patterns
- Race conditions in authentication flows
- Insecure deserialization
- Second-order vulnerabilities (data stored in one place, used dangerously elsewhere)

Use your web_search tool to look up:
- Whether a specific API usage pattern is known to be vulnerable
- CVEs related to libraries used in suspicious code patterns
- Security advisories for specific framework versions

Rate severity honestly. Not every pattern match is critical — consider exploitability and impact.

Return ONLY a JSON array of Finding objects with fields: id, title, severity, category ("code"), description, remediation, references, file, line, detail.
No markdown fences. Real findings only — no false positives from overly cautious rules.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for security information about a specific code pattern, library, or CVE",
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

const MAX_FILE_CHARS = 40000; // keep total prompt under context limit

export async function runCodeAgent(ctx: AgentContext): Promise<AgentResult> {
  const sourcesCrawled: string[] = [];

  // Build a focused file snapshot — prioritize auth, api routes, db, config
  const priorityPatterns = [/auth/i, /api\//i, /route/i, /db/i, /database/i, /config/i, /secret/i, /token/i, /middleware/i, /service/i];
  const fileEntries = Object.entries(ctx.files);

  const prioritized = [
    ...fileEntries.filter(([p]) => priorityPatterns.some((rx) => rx.test(p))),
    ...fileEntries.filter(([p]) => !priorityPatterns.some((rx) => rx.test(p))),
  ];

  let fileSnapshot = "";
  for (const [path, content] of prioritized) {
    const chunk = `\n\n=== ${path} ===\n${content}`;
    if (fileSnapshot.length + chunk.length > MAX_FILE_CHARS) break;
    fileSnapshot += chunk;
  }

  const userMessage = `Audit the following source files for security vulnerabilities.

Project files (${fileEntries.length} total, showing highest-priority first):
${fileSnapshot}

Existing rule-based findings to be aware of (don't duplicate these, but use them for context):
${JSON.stringify(ctx.existingFindings.filter((f) => f.category === "code").slice(0, 10), null, 2)}

Go deep. Look for subtle vulnerabilities that static regex rules miss.
Use web_search to verify your suspicions about specific patterns or libraries.`;

  const { content, tokensUsed } = await agentLoop(
    {
      system: SYSTEM,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.1,
      maxTokens: 4096,
    },
    async (toolName, args) => {
      if (toolName === "web_search") {
        const query = String(args["query"] ?? "");
        sourcesCrawled.push(`web:${query}`);
        return webSearch(query, 3);
      }
      return "Unknown tool";
    }
  );

  const findings = parseFindings(content, "code");
  logger.debug(`[code-agent] ${findings.length} findings parsed`);

  return { agent: "code", findings, reasoning: content, sourcesCrawled, tokensUsed };
}
