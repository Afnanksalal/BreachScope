import axios from "axios";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

interface BlackboxOptions {
  url: string;
  verbose?: boolean;
}

export async function runBlackboxProbe(opts: BlackboxOptions): Promise<Finding[]> {
  logger.section("Blackbox Security Probing");
  const findings: Finding[] = [];
  const { url } = opts;
  const base = url.replace(/\/$/, "");

  logger.info(`Target: ${base}`);

  findings.push(...await checkSecurityHeaders(base));
  findings.push(...await checkCommonExposedPaths(base));
  findings.push(...await checkCORSMisconfiguration(base));
  findings.push(...await checkMethodOverride(base));

  logger.info(`Found ${findings.length} blackbox issue(s)`);
  return findings;
}

async function checkSecurityHeaders(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await axios.get(base, { validateStatus: () => true, timeout: 8000 });
    const h = res.headers;

    const required: Array<{ header: string; description: string; remediation: string; severity: Finding["severity"] }> = [
      {
        header: "strict-transport-security",
        severity: "medium",
        description: "Missing HSTS header — browsers may downgrade to HTTP, enabling MITM attacks.",
        remediation: "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
      },
      {
        header: "x-frame-options",
        severity: "low",
        description: "Missing X-Frame-Options — the application may be embeddable in iframes, enabling clickjacking.",
        remediation: "Add: X-Frame-Options: DENY or use CSP frame-ancestors directive.",
      },
      {
        header: "x-content-type-options",
        severity: "low",
        description: "Missing X-Content-Type-Options — browsers may MIME-sniff responses, enabling content injection.",
        remediation: "Add: X-Content-Type-Options: nosniff",
      },
      {
        header: "content-security-policy",
        severity: "medium",
        description: "No Content-Security-Policy header — the application has no defense against XSS via policy.",
        remediation: "Define a strict CSP. Start with default-src 'self' and expand as needed.",
      },
      {
        header: "permissions-policy",
        severity: "info",
        description: "Missing Permissions-Policy — browser features like camera/microphone are unrestricted.",
        remediation: "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
      },
    ];

    for (const { header, description, remediation, severity } of required) {
      if (!h[header]) {
        findings.push({
          id: `header-missing-${header}`,
          title: `Missing security header: ${header}`,
          severity,
          category: "blackbox",
          description,
          remediation,
          confidence: "high",
          evidenceStrength: "weak",
          signals: ["browser-hardening-header"],
        });
      }
    }
    } catch {
    logger.warn(`Could not reach ${base} for header check`);
  }
  return findings;
}

async function checkCommonExposedPaths(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const SENSITIVE_PATHS = [
    { path: "/.env", label: ".env file" },
    { path: "/.git/config", label: "Git config" },
    { path: "/api/debug", label: "Debug endpoint" },
    { path: "/api/__health", label: "Health endpoint (internal)" },
    { path: "/graphql", label: "GraphQL endpoint" },
    { path: "/swagger.json", label: "Swagger spec" },
    { path: "/openapi.json", label: "OpenAPI spec" },
    { path: "/api-docs", label: "API docs" },
    { path: "/.well-known/security.txt", label: "Security policy" },
    { path: "/robots.txt", label: "Robots.txt (check for hidden paths)" },
  ];

  await Promise.allSettled(
    SENSITIVE_PATHS.map(async ({ path: p, label }) => {
      try {
        const res = await axios.get(`${base}${p}`, { validateStatus: () => true, timeout: 5000 });
        if (res.status === 200) {
          const isSecret = [".env", ".git"].some((s) => p.includes(s));
          const body = bodyToText(res.data);
          const confirmedSecret = p.includes(".env")
            ? hasEnvLikeSecret(body)
            : p.includes(".git")
            ? looksLikeGitConfig(body)
            : false;
          const severity: Finding["severity"] = confirmedSecret ? "critical" : isSecret ? "medium" : "info";
          const signals = confirmedSecret
            ? ["confirmed-sensitive-exposure"]
            : ["public-path"];
          findings.push({
            id: `exposed-path-${p.replace(/\//g, "-")}`,
            title: `${label} is accessible: ${p}`,
            severity,
            category: "blackbox",
            description: `The path ${p} returned HTTP 200. ${confirmedSecret ? "BreachScope confirmed sensitive-looking content." : isSecret ? "No secret-shaped content was confirmed, but the path should be reviewed." : "Verify this exposure is intentional."}`,
            detail: body.slice(0, 300),
            remediation: isSecret
              ? "Block access to this path via web server config or middleware. Do not commit .env files."
              : "Restrict access if not intentionally public.",
            confidence: confirmedSecret ? "high" : "low",
            evidenceStrength: confirmedSecret ? "confirmed" : "weak",
            signals,
          });
        }
      } catch {
        // unreachable path — expected
      }
    })
  );

  return findings;
}

async function checkCORSMisconfiguration(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await axios.get(base, {
      headers: { Origin: "https://evil.example.com" },
      validateStatus: () => true,
      timeout: 8000,
    });

    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];

    if (acao === "https://evil.example.com" && acac === "true") {
      findings.push({
        id: "cors-origin-reflection",
        title: "CORS Origin reflection with credentials",
        severity: "critical",
        category: "blackbox",
        description: "The server reflects the request Origin and allows credentials. Any website can make authenticated cross-origin requests.",
        remediation: "Maintain an explicit allowlist of trusted origins. Never reflect the Origin header directly.",
        references: ["https://portswigger.net/web-security/cors"],
        confidence: "high",
        evidenceStrength: "confirmed",
        signals: ["confirmed-cors-credentials"],
      });
    } else if (acao === "*" && acac === "true") {
      findings.push({
        id: "cors-wildcard-credentials",
        title: "CORS wildcard with credentials allowed",
        severity: "medium",
        category: "blackbox",
        description: "CORS wildcard and credentials are simultaneously enabled, which browsers typically block, but indicates a configuration error.",
        remediation: "Do not combine * with credentials:true. Use explicit trusted origins.",
        confidence: "medium",
        evidenceStrength: "moderate",
        signals: ["cors-hardening"],
      });
    }
  } catch {
    // no-op
  }
  return findings;
}

async function checkMethodOverride(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await axios.request({
      method: "OPTIONS",
      url: base,
      validateStatus: () => true,
      timeout: 8000,
    });

    const allow = res.headers["allow"] ?? res.headers["access-control-allow-methods"] ?? "";
    if (typeof allow === "string" && (allow.includes("TRACE") || allow.includes("TRACK"))) {
      findings.push({
        id: "http-trace-enabled",
        title: "HTTP TRACE method enabled",
        severity: "medium",
        category: "blackbox",
        description: "TRACE is enabled, which can facilitate Cross-Site Tracing (XST) attacks to bypass HttpOnly cookies.",
        remediation: "Disable TRACE and TRACK methods in your web server configuration.",
        confidence: "high",
        evidenceStrength: "strong",
        signals: ["confirmed-dangerous-method"],
      });
    }
  } catch {
    // no-op
  }
  return findings;
}

function bodyToText(body: unknown): string {
  if (typeof body === "string") return body;
  try {
    return JSON.stringify(body);
  } catch {
    return "";
  }
}

function hasEnvLikeSecret(body: string): boolean {
  return /(?:^|\n)\s*[A-Z0-9_]{4,}\s*=\s*["']?[^"'\s]{8,}/.test(body) &&
    /(SECRET|TOKEN|KEY|PASSWORD|DATABASE_URL|PRIVATE)/i.test(body);
}

function looksLikeGitConfig(body: string): boolean {
  return /\[core\]/i.test(body) || /\[remote\s+"origin"\]/i.test(body) || /repositoryformatversion\s*=/.test(body);
}
