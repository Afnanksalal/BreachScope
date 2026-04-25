import { agentLoop } from "../core/ai.js";
import { webSearch } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import { parseFindings } from "./dependency.js";

const SYSTEM_ALL = `You are BreachScope's Code Audit Agent — an elite application security engineer specializing in source code vulnerability analysis.

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
- Insecure deserialization
- Second-order vulnerabilities (data stored in one place, used dangerously elsewhere)

Use web_search to look up CVEs related to suspicious code patterns or library versions.

Rate severity honestly. Not every pattern match is critical — consider exploitability and impact.
Return ONLY a JSON array of Finding objects: id, title, severity, category ("code"), description, remediation, references, file, line, detail.
No markdown fences. Real findings only.`;

const SYSTEM_BUG = `You are BreachScope's Bug-Finding Agent — a specialist in deep code vulnerability research, modeled after elite security researchers who find logic bugs and novel attack paths.

Your mission: find real, exploitable security bugs the scanner may have missed.

Go deep on:
- **Injection flaws**: SQL injection (including second-order, blind, ORM bypass), command injection, LDAP injection, XPath injection, SSTI (template injection), log injection
- **Authentication & authorization bugs**: JWT algorithm confusion, privilege escalation via mass assignment, IDOR, missing middleware, broken session management
- **Deserialization attacks**: Python pickle/yaml.load, Node.js serialize/deserialize, Java ObjectInputStream patterns, PHP unserialize
- **Memory safety issues**: Rust unsafe blocks with pointer arithmetic, C-extension Python modules, buffer overflow patterns
- **Race conditions**: TOCTOU in file operations, double-spend logic in payment/credit flows
- **Business logic flaws**: integer overflow in pricing, negative quantities, missing validation on state transitions
- **Cryptographic failures**: predictable nonces, ECB mode, short keys, reused IVs, timing-safe comparison missing
- **Client-side attacks**: dangerouslySetInnerHTML with unsanitized data, DOM clobbering, postMessage origin bypass, prototype pollution
- **SSRF / open redirect**: fetch/axios to user-controlled URLs, redirect without allowlist
- **Path traversal / zip slip**: unvalidated archive extraction, file operations with user paths
- **ReDoS**: catastrophically backtracking regex with user-controlled input

For each bug:
1. Identify the exact file + line number
2. Explain the full attack path (how an attacker would trigger it)
3. Rate exploitability vs. impact to assign severity accurately
4. Use web_search to find related CVEs or prior art for similar patterns

Return ONLY a JSON array of Finding objects: id, title, severity, category ("code"), description, remediation, references, file, line, detail.
No markdown fences. Prioritize novel, high-impact bugs over obvious patterns the scanner already caught.`;

const SYSTEM_BREACH = `You are BreachScope's Credential & Breach Intelligence Agent — a specialist in identifying exposed secrets, credential leaks, and misconfigurations that could lead to immediate breach.

Your mission: find any secret, credential, or configuration that could give an attacker unauthorized access right now.

Hunt for:
- **API keys & tokens**: OpenAI (sk-), Anthropic (sk-ant-), GitHub PAT (ghp_/gho_/ghs_), Stripe (sk_live_), Twilio, Slack (xoxb-), SendGrid (SG.), AWS (AKIA), GCP service accounts
- **Cloud credentials**: DigitalOcean (dop_v1_), Cloudflare tokens, Vercel tokens, Heroku API keys, npm tokens (npm_), Docker registry passwords
- **Database connection strings**: Postgres/MySQL/MongoDB URLs with embedded credentials, Supabase service role JWTs
- **Private keys**: RSA/EC PEM blocks, base64-encoded SSH keys, PKCS#12 files referenced in code
- **Hardcoded passwords**: any variable named password/passwd/pwd with a string literal value
- **JWT secrets**: short or hardcoded signing secrets used with HS256/HS384/HS512
- **Infrastructure exposure**: debug routes (/debug, /phpinfo, /_debug), admin routes without auth middleware, exposed metrics endpoints
- **Environment file leaks**: .env files being read, committed, or logged; sensitive env var values in logs or responses
- **Webhook secrets**: Stripe whsec_, GitHub webhook secrets committed in code
- **SaaS misconfigs**: Supabase anon key used server-side with no RLS, Firebase rules allowing public read/write

For each finding:
1. Quote the exact line or value (truncated if too long)
2. Explain the immediate impact: what can an attacker do with this credential right now?
3. Give precise remediation: which service to revoke on, what to replace it with

Use web_search to verify if a key format matches a known service's token format when uncertain.

Return ONLY a JSON array of Finding objects: id, title, severity, category ("code"), description, remediation, references, file, line, detail.
No markdown fences. Every finding must be actionable.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for security information about a code pattern, library vulnerability, or API key format",
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

const MAX_FILE_CHARS = 40000;

export async function runCodeAgent(ctx: AgentContext): Promise<AgentResult> {
  const scanMode = ctx.scanMode ?? "all";
  const sourcesCrawled: string[] = [];

  const system = scanMode === "full" ? `${SYSTEM_BUG}\n\n---\n\nADDITIONALLY — this is a FULL scan. After finding code bugs, also hunt for:\n${SYSTEM_BREACH}`
    : scanMode === "bug" ? SYSTEM_BUG
    : scanMode === "breach" ? SYSTEM_BREACH
    : SYSTEM_ALL;

  // In breach mode prioritize auth/config/secret files; in bug mode prioritize routes/api/db
  const priorityPatterns = scanMode === "breach"
    ? [/auth/i, /secret|token|key|cred/i, /config|env|setting/i, /\.env/i, /db|database/i]
    : [/auth/i, /api\//i, /route/i, /db|database/i, /config/i, /secret|token/i, /middleware/i, /service/i];

  const fileEntries = Object.entries(ctx.files);
  const prioritized = [
    ...fileEntries.filter(([p]) => priorityPatterns.some((rx) => rx.test(p))),
    ...fileEntries.filter(([p]) => !priorityPatterns.some((rx) => rx.test(p))),
  ];

  let fileSnapshot = "";
  for (const [filePath, content] of prioritized) {
    const chunk = `\n\n=== ${filePath} ===\n${content}`;
    if (fileSnapshot.length + chunk.length > MAX_FILE_CHARS) break;
    fileSnapshot += chunk;
  }

  const modeHint = scanMode === "full"
    ? "MAXIMUM COVERAGE MODE: Find EVERY vulnerability class — logic bugs, injection flaws, race conditions, AND credentials, secrets, API keys, misconfigurations. Leave nothing on the table."
    : scanMode === "bug"
    ? "DEEP BUG MODE: Go beyond surface patterns. Find logic bugs, race conditions, auth bypasses, and novel attack paths."
    : scanMode === "breach"
    ? "BREACH MODE: Hunt specifically for credentials, secrets, API keys, and configurations that give immediate unauthorized access."
    : "FULL MODE: Broad security analysis across all vulnerability classes.";

  const userMessage = `${modeHint}

Audit the following source files for security vulnerabilities.

Project files (${fileEntries.length} total, showing highest-priority first):
${fileSnapshot}

Existing rule-based findings (don't duplicate, use for context):
${JSON.stringify(ctx.existingFindings.filter((f) => f.category === "code").slice(0, 10), null, 2)}

Use web_search to verify suspicious patterns or look up CVEs for specific libraries.`;

  const { content, tokensUsed } = await agentLoop(
    {
      system,
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
