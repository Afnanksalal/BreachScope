import { agentLoop } from "../core/ai.js";
import { logger } from "../core/logger.js";
import { parseFindings } from "./dependency.js";
import type { Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";

const SYSTEM = `You are BreachScope's authenticated browser security probe agent.

You control a real Chromium browser. Your job:
1. Log in to the target web application using the provided credentials
2. Once authenticated, systematically audit security posture

Login strategy:
- navigate() to the login URL
- get_interactive_elements() to see inputs, buttons, links on the page
- fill() and click() to complete the login form
- Verify login succeeded by checking for auth cookies or user-specific content in the HTML
- If there's a 2FA step, report it as a finding note and stop (can't automate 2FA)

Security checks to run after login (passive analysis only — do NOT attempt actual exploits):

1. COOKIE SECURITY: get_cookies() — check every auth cookie for:
   - Missing HttpOnly flag (XSS can steal it)
   - Missing Secure flag (transmitted over HTTP)
   - SameSite=None without Secure (CSRF risk)
   - Very long or no expiry (session fixation risk)

2. SECURITY HEADERS: check_headers() on the main URL — look for:
   - Missing Content-Security-Policy
   - Missing X-Frame-Options or frame-ancestors in CSP (clickjacking)
   - Missing X-Content-Type-Options: nosniff
   - Missing Strict-Transport-Security (HSTS)
   - Missing Permissions-Policy
   - Server header leaking version info

3. CSRF PROTECTION: navigate to pages with forms (account settings, profile, etc.)
   - get_interactive_elements() to find forms
   - get_page_html() to check for CSRF tokens (look for hidden input with name containing "csrf", "_token", "authenticity_token")
   - Missing CSRF tokens on POST forms = CSRF vulnerability

4. AUTH ENFORCEMENT: check_headers() on a known authenticated page URL but without the session cookie
   - If it returns 200 (not 401/403/redirect to login), that URL is publicly accessible

5. SENSITIVE DATA LEAKAGE: get_page_html() on dashboard/profile pages
   - Look for exposed: API keys, tokens, full credit card numbers, SSNs, internal server paths, stack traces, debug info

6. IDOR ANALYSIS: find_links() to discover URLs with numeric IDs or UUIDs
   - Report patterns like /user/123/edit or /invoice/456 as potential IDOR vectors (don't attempt actual exploitation)

7. SESSION MANAGEMENT: from get_cookies()
   - Check session token entropy (length < 32 chars = weak)
   - Multiple active session tokens with no clear purpose

Return ONLY a JSON array of Finding objects with fields: id, title, severity (critical|high|medium|low), category ("blackbox"), description, remediation, references.
Do not wrap in markdown. Output only the JSON array.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "navigate",
      description: "Navigate the browser to a URL. Returns page title, final URL, and first 2000 chars of HTML.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "URL to navigate to" },
        },
        required: ["url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_interactive_elements",
      description: "Get all interactive elements on the current page: inputs (with label/type/name/placeholder), buttons (with text), and links (with text/href). Use this to understand the page structure before filling forms.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "fill",
      description: "Fill an input field. Use the CSS selector you got from get_interactive_elements.",
      parameters: {
        type: "object",
        properties: {
          selector: { type: "string", description: "CSS selector for the input (e.g. 'input[name=email]' or 'input[type=password]')" },
          value:    { type: "string", description: "Value to fill in" },
        },
        required: ["selector", "value"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "click",
      description: "Click an element. Use CSS selector, or text content like 'text=Sign in'.",
      parameters: {
        type: "object",
        properties: {
          selector: { type: "string", description: "CSS selector or 'text=Button Text'" },
        },
        required: ["selector"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_page_html",
      description: "Get the current page's full HTML (up to 15000 chars). Use to inspect content, find forms, check for sensitive data leakage.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "get_cookies",
      description: "Get all cookies for the current origin, including their security attributes (httpOnly, secure, sameSite, expires, size).",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "find_links",
      description: "Get all unique hrefs found on the current page. Useful for discovering URL patterns with IDs (IDOR analysis).",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "check_headers",
      description: "Fetch a URL and return its HTTP response headers. Use this to check security headers and auth enforcement.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string" },
        },
        required: ["url"],
      },
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
];

export interface BrowserProbeResult {
  url: string;
  findings: Finding[];
  tokensUsed: number;
  pagesVisited: string[];
}

export async function runBrowserProbe(
  url: string,
  credentials: { username: string; password: string; loginUrl?: string }
): Promise<BrowserProbeResult> {
  // Dynamic import — playwright is optional. If not installed, give clear error.
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

  // Capture network requests for header checks
  const networkLog: Array<{ url: string; status: number; headers: Record<string, string> }> = [];
  page.on("response", (resp) => {
    try {
      networkLog.push({
        url: resp.url(),
        status: resp.status(),
        headers: Object.fromEntries(Object.entries(resp.headers())),
      });
    } catch { /* ignore */ }
  });

  const pagesVisited: string[] = [];

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
        const inputs = Array.from(document.querySelectorAll("input:not([type=hidden])")).map((el) => {
          const input = el as HTMLInputElement;
          // Find associated label
          let label = "";
          if (input.id) {
            const labelEl = document.querySelector(`label[for="${input.id}"]`);
            if (labelEl) label = labelEl.textContent?.trim() ?? "";
          }
          if (!label) label = input.placeholder ?? "";
          return {
            selector: input.name ? `input[name="${input.name}"]` : `input[type="${input.type}"]`,
            type: input.type,
            name: input.name,
            placeholder: input.placeholder,
            label,
          };
        });

        const buttons = Array.from(document.querySelectorAll("button, input[type=submit]")).map((el) => ({
          selector: el.tagName.toLowerCase() === "button" ? `button` : `input[type=submit]`,
          text: (el as HTMLElement).textContent?.trim().slice(0, 80) ?? "",
          type: (el as HTMLInputElement).type ?? "button",
        }));

        const links = Array.from(document.querySelectorAll("a[href]"))
          .slice(0, 30)
          .map((el) => ({
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
      return (await page.content()).slice(0, 15000);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function getCookies(): Promise<string> {
    try {
      const cookies = await context.cookies();
      return JSON.stringify(cookies.map((c) => ({
        name:     c.name,
        domain:   c.domain,
        path:     c.path,
        httpOnly: c.httpOnly,
        secure:   c.secure,
        sameSite: c.sameSite,
        expires:  c.expires,
        size:     (c.name + c.value).length,
      })));
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function findLinks(): Promise<string> {
    try {
      const links = await page.evaluate(() =>
        [...new Set(Array.from(document.querySelectorAll("a[href]"))
          .map((a) => (a as HTMLAnchorElement).href)
          .filter((h) => h.startsWith("http")))]
          .slice(0, 60)
      );
      return JSON.stringify(links);
    } catch (e) {
      return JSON.stringify({ error: String(e) });
    }
  }

  async function checkHeaders(targetUrl: string): Promise<string> {
    // Use the network log first if we have a cached entry
    const cached = networkLog.find((r) => r.url === targetUrl || r.url.startsWith(targetUrl));
    if (cached) return JSON.stringify({ status: cached.status, headers: cached.headers });

    try {
      const resp = await page.request.get(targetUrl, { timeout: 10000 });
      return JSON.stringify({
        status: resp.status(),
        headers: Object.fromEntries(Object.entries(resp.headers())),
      });
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

  const loginUrl = credentials.loginUrl ?? url;

  const userMessage = `Target URL: ${url}
Login URL: ${loginUrl}
Username / email: ${credentials.username}
Password: (provided — use the fill() tool, I will not display it here)

IMPORTANT: The password is: ${credentials.password}

Steps:
1. navigate("${loginUrl}") to open the login page
2. get_interactive_elements() to see the form fields
3. fill() each field and click the submit button
4. Verify you are logged in
5. Run all security checks

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
        maxTokens: 16384,
      },
      async (toolName, args) => {
        logger.debug(`  [browser] ${toolName}(${JSON.stringify(args).slice(0, 80)})`);
        switch (toolName) {
          case "navigate":            return navigate(String(args["url"] ?? ""));
          case "get_interactive_elements": return getInteractiveElements();
          case "fill":                return fill(String(args["selector"] ?? ""), String(args["value"] ?? ""));
          case "click":               return click(String(args["selector"] ?? ""));
          case "get_page_html":       return getPageHtml();
          case "get_cookies":         return getCookies();
          case "find_links":          return findLinks();
          case "check_headers":       return checkHeaders(String(args["url"] ?? url));
          case "go_back":             return goBack();
          default:                    return "Unknown tool";
        }
      }
    );
    content = result.content;
    tokensUsed = result.tokensUsed;
  } finally {
    await browser.close();
  }

  const findings = parseFindings(content, "blackbox");
  return { url, findings, tokensUsed, pagesVisited: [...new Set(pagesVisited)] };
}
