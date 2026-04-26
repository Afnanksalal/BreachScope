import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
import { logger } from "../core/logger.js";
import type { AgentContext, AgentResult, Finding } from "../core/types.js";
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

Use web_search aggressively — when you spot a library version, a dangerous API, or a suspicious pattern, search for its CVE history, PoC exploits, and HackTricks coverage immediately. Use crawl_url to read specific CVE pages, HackTricks articles, or exploit write-ups to get exact attack payloads and confirm exploitability.

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
4. Use web_search to find related CVEs, PoC exploits, and prior art for similar patterns. Use crawl_url to read HackTricks, NVD CVE pages, or GitHub PoC repos for exact payloads and attack steps.

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

Use web_search to verify key formats, look up breach history for identified tokens, and search for known exploits. Use crawl_url to read specific advisory pages, vendor security disclosures, or HaveIBeenPwned-style resources when you identify a credential type.

Return ONLY a JSON array of Finding objects: id, title, severity, category ("code"), description, remediation, references, file, line, detail.
No markdown fences. Every finding must be actionable.`;

interface PendingFinding {
  id: string;
  title: string;
  severity: string;
  description: string;
  evidence: string;
  remediation: string;
  file?: string;
  line?: number;
}

function makeCodeFeedbackStore() {
  const findings: PendingFinding[] = [];
  let counter = 0;

  return {
    findings,
    save(title: string, severity: string, description: string, evidence: string, remediation: string, file?: string, line?: number): string {
      const id = `code-${++counter}`;
      findings.push({ id, title, severity, description, evidence, remediation, file, line });
      return JSON.stringify({ success: true, id, total: findings.length });
    },
    get(): string {
      if (findings.length === 0) return JSON.stringify({ findings: [], note: "No findings saved yet." });
      return JSON.stringify({
        total: findings.length,
        findings: findings.map((f) => ({
          id: f.id,
          severity: f.severity,
          title: f.title,
          file: f.file,
          has_evidence: f.evidence.length > 10,
        })),
        instruction: "Review each finding. Use remove_finding(id) for any finding without concrete evidence or that is a false positive.",
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
      name: "read_file",
      description: "Read the full content of a source file from the project. Use this to audit files you want to inspect for vulnerabilities.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path (e.g. src/auth/login.ts)" },
        },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_finding",
      description: "Submit a confirmed vulnerability finding. ONLY call this when you have read the actual code and have concrete evidence — exact file, exact line, exact vulnerable pattern. Do NOT call for speculative or pattern-matched findings without reading the code.",
      parameters: {
        type: "object",
        properties: {
          title:       { type: "string" },
          severity:    { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: { type: "string", description: "Attack path: how an attacker triggers this, what they gain. Include exact line/pattern from the code." },
          evidence:    { type: "string", description: "The exact vulnerable code snippet or value from the file you read." },
          remediation: { type: "string" },
          file:        { type: "string", description: "Relative file path" },
          line:        { type: "number", description: "Line number" },
        },
        required: ["title", "severity", "description", "evidence", "remediation"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_findings",
      description: "Review all findings you have saved so far. Call this periodically to check your progress and verify quality. Use remove_finding() on any finding that lacks concrete evidence or might be a false positive.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "remove_finding",
      description: "Remove a finding that turns out to be a false positive, speculative, or lacks concrete evidence. Better to remove a weak finding than report it.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Finding ID from get_findings()" },
        },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for CVEs, exploit techniques, PoC code, HackTricks coverage, and security research. Use aggressively — when you see a library, API pattern, or vulnerability class, search for known exploits immediately. Examples: 'express-session CVE exploit', 'JWT none algorithm bypass payload', 'prototype pollution RCE Node.js'.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Specific search: include library names, version numbers, CVE IDs, vulnerability class" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_url",
      description: "Fetch and read the full content of a specific security resource — CVE detail pages (nvd.nist.gov), HackTricks articles (book.hacktricks.xyz), PayloadsAllTheThings raw files, Exploit-DB entries, GitHub security advisories, or vendor security bulletins. Use to get exact payloads and confirm exploit steps.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "Full URL: NVD CVE page, HackTricks, PayloadsAllTheThings raw, Exploit-DB, GitHub advisory" },
        },
        required: ["url"],
      },
    },
  },
];

// Pre-load just enough high-priority content so GPT has immediate context
const PRELOAD_CHARS = 24_000;

export async function runCodeAgent(ctx: AgentContext): Promise<AgentResult> {
  const scanMode = ctx.scanMode ?? "all";
  const sourcesCrawled: string[] = [];
  const store = makeCodeFeedbackStore();

  const system = scanMode === "full"
    ? `${SYSTEM_BUG}\n\n---\n\nADDITIONALLY — this is a FULL scan. After finding code bugs, also hunt for:\n${SYSTEM_BREACH}`
    : scanMode === "bug"    ? SYSTEM_BUG
    : scanMode === "breach" ? SYSTEM_BREACH
    : SYSTEM_ALL;

  const priorityPatterns = scanMode === "breach"
    ? [/auth/i, /secret|token|key|cred/i, /config|env|setting/i, /\.env/i, /db|database/i]
    : [/auth/i, /route|api\//i, /db|database/i, /config/i, /secret|token/i, /middleware/i, /service/i];

  const fileEntries = Object.entries(ctx.files);
  const prioritized = [
    ...fileEntries.filter(([p]) => priorityPatterns.some((rx) => rx.test(p))),
    ...fileEntries.filter(([p]) => !priorityPatterns.some((rx) => rx.test(p))),
  ];

  // Pre-load the highest-priority files so GPT has immediate context
  let preloaded = "";
  const preloadedPaths = new Set<string>();
  for (const [filePath, content] of prioritized) {
    const chunk = `\n\n=== ${filePath} ===\n${content}`;
    if (preloaded.length + chunk.length > PRELOAD_CHARS) break;
    preloaded += chunk;
    preloadedPaths.add(filePath);
  }

  // File tree for the rest — GPT requests what it needs via read_file
  const remaining = fileEntries
    .filter(([p]) => !preloadedPaths.has(p))
    .map(([p]) => p)
    .join("\n");

  const modeHint = scanMode === "full"
    ? "MAXIMUM COVERAGE: find every vulnerability class — injection, logic bugs, race conditions, auth flaws, AND secrets/credentials. Read every suspicious file."
    : scanMode === "bug"
    ? "DEEP BUG HUNT: find real, exploitable logic bugs, injection flaws, auth bypasses. Read the actual code — don't guess, verify."
    : scanMode === "breach"
    ? "BREACH HUNT: find credentials, secrets, API keys, hardcoded tokens. Quote the exact value and line."
    : "SECURITY AUDIT: find real vulnerabilities across all classes.";

  const userMessage = `${modeHint}

WORKFLOW:
1. Read files using read_file — start with pre-loaded files below, then request more
2. For every confirmed vulnerability: call save_finding() with the exact code snippet as evidence
3. Every 5-6 tool calls: call get_findings() to review your progress
4. Use remove_finding() on any finding that is speculative or lacks a real code snippet
5. At the end: call get_findings() one final time and remove any weak findings before finishing

FEEDBACK LOOP: save_finding → get_findings → remove_finding is your quality gate.
Only findings with concrete evidence (exact vulnerable code) should survive to the end.

Pre-loaded files (highest security priority):
${preloaded}

Additional files available (request with read_file):
${remaining || "(none)"}

Already found by static scanner (skip these, use for context only):
${ctx.existingFindings.filter((f) => f.category === "code").slice(0, 8).map((f) => `- [${f.severity}] ${f.title}${f.file ? ` (${f.file})` : ""}`).join("\n") || "(none)"}

Strategy: review pre-loaded files first. Then read_file anything that handles auth, payments, file uploads, DB queries, user input, sessions, or external HTTP calls. Find bugs the static scanner missed.
When done reviewing, output any remaining findings as a JSON array (fallback for anything not submitted via save_finding).`;

  const { content, tokensUsed } = await agentLoop(
    {
      system,
      messages: [{ role: "user", content: userMessage }],
      tools: TOOLS,
      temperature: 0.1,
      maxTokens: 8192,
      maxIterations: 35,
    },
    async (toolName, args) => {
      if (toolName === "read_file") {
        const reqPath = String(args["path"] ?? "").replace(/\\/g, "/");
        if (ctx.files[reqPath]) {
          sourcesCrawled.push(`file:${reqPath}`);
          return `=== ${reqPath} ===\n${ctx.files[reqPath]}`;
        }
        const match = Object.entries(ctx.files).find(
          ([p]) => p.replace(/\\/g, "/").endsWith(reqPath) || reqPath.endsWith(p.replace(/\\/g, "/"))
        );
        if (match) {
          sourcesCrawled.push(`file:${match[0]}`);
          return `=== ${match[0]} ===\n${match[1]}`;
        }
        return `File not found: ${reqPath}\nAvailable:\n${Object.keys(ctx.files).join("\n")}`;
      }
      if (toolName === "save_finding") {
        const a = args as Record<string, unknown>;
        return store.save(
          String(a["title"] ?? ""), String(a["severity"] ?? "low"),
          String(a["description"] ?? ""), String(a["evidence"] ?? ""),
          String(a["remediation"] ?? ""),
          a["file"] ? String(a["file"]) : undefined,
          a["line"] ? Number(a["line"]) : undefined,
        );
      }
      if (toolName === "get_findings") return store.get();
      if (toolName === "remove_finding") return store.remove(String(args["id"] ?? ""));
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

  // Primary: findings submitted via save_finding tool
  const toolFindings: Finding[] = store.findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity as Finding["severity"],
    category: "code" as const,
    description: f.description,
    remediation: f.remediation,
    references: [],
    file: f.file,
    line: f.line,
    detail: f.evidence.slice(0, 500),
  }));

  // Fallback: parse JSON from final text output (deduped)
  const toolTitles = new Set(toolFindings.map((f) => f.title.toLowerCase()));
  const textFindings = parseFindings(content, "code").filter((f) => !toolTitles.has(f.title.toLowerCase()));

  const findings = [...toolFindings, ...textFindings];
  logger.debug(`[code-agent] ${findings.length} findings (${toolFindings.length} via tool, ${textFindings.length} from text), ${sourcesCrawled.length} sources`);

  return { agent: "code", findings, reasoning: content, sourcesCrawled, tokensUsed };
}
