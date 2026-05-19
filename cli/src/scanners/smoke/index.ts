import axios from "axios";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

interface SmokeOptions {
  url: string;
  verbose?: boolean;
}

// Smoke tests verify the target is alive and not leaking error internals
export async function runSmokeTests(opts: SmokeOptions): Promise<Finding[]> {
  logger.section("Smoke Testing");
  const findings: Finding[] = [];
  const { url } = opts;
  const base = url.replace(/\/$/, "");

  const SMOKE_SUITE: Array<{
    name: string;
    fn: () => Promise<Finding[]>;
  }> = [
    { name: "Root endpoint reachability", fn: () => checkReachability(base) },
    { name: "Error page information leakage", fn: () => checkErrorLeakage(base) },
    { name: "Large payload handling", fn: () => checkLargePayload(base) },
    { name: "Auth bypass probes", fn: () => checkAuthBypass(base) },
  ];

  for (const test of SMOKE_SUITE) {
    logger.info(`Running: ${test.name}`);
    try {
      const result = await test.fn();
      findings.push(...result);
    } catch (e) {
      logger.debug(`Smoke test "${test.name}" threw:`, e);
    }
  }

  logger.info(`Smoke testing complete — ${findings.length} issue(s) found`);
  return findings;
}

async function checkReachability(base: string): Promise<Finding[]> {
  try {
    const res = await axios.get(base, { validateStatus: () => true, timeout: 10000 });
    if (res.status >= 500) {
      return [{
        id: "smoke-server-error",
        title: `Root endpoint returns ${res.status}`,
        severity: "high",
        category: "smoke",
        description: `The application root returned HTTP ${res.status}. The service may be in a degraded or broken state.`,
        remediation: "Investigate server logs for the underlying error. Do not deploy to production in this state.",
      }];
    }
  } catch {
    return [{
      id: "smoke-unreachable",
      title: "Target is unreachable",
      severity: "critical",
      category: "smoke",
      description: "The target URL could not be reached within the timeout period.",
      remediation: "Verify the URL is correct and the service is running.",
    }];
  }
  return [];
}

async function checkErrorLeakage(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const PROBE_PATHS = ["/undefined", "/api/undefined", "/%00", "/api?id=<script>"];

  for (const p of PROBE_PATHS) {
    try {
      const res = await axios.get(`${base}${p}`, { validateStatus: () => true, timeout: 5000 });
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

      const LEAK_PATTERNS = [/at\s+\w+\s+\(.*:\d+:\d+\)/, /Error:\s+Cannot/, /SyntaxError/, /TypeError/, /node_modules\//];
      for (const pat of LEAK_PATTERNS) {
        if (pat.test(body)) {
          findings.push({
            id: `smoke-error-leak-${p.replace(/[^a-z0-9]/gi, "-")}`,
            title: "Stack trace or internal error exposed in response",
            severity: "medium",
            category: "smoke",
            description: `Requesting "${p}" returned a response containing stack trace or internal error information.`,
            detail: body.slice(0, 300),
            remediation: "Add a global error handler that returns generic messages. Log details server-side only.",
          });
          break;
        }
      }
    } catch {
      // connection errors are fine here
    }
  }

  return findings;
}

async function checkLargePayload(base: string): Promise<Finding[]> {
  try {
    const bigBody = "x".repeat(1024 * 1024 * 10); // 10MB
    const res = await axios.post(base, bigBody, {
      validateStatus: () => true,
      timeout: 10000,
      headers: { "Content-Type": "text/plain" },
    });

    if (res.status === 200) {
      return [{
        id: "smoke-no-payload-limit",
        title: "No request body size limit enforced",
        severity: "medium",
        category: "smoke",
        description: "A 10MB POST body was accepted without rejection. Lack of body size limits enables DoS via memory exhaustion.",
        remediation: "Configure a body size limit (e.g., express body-parser limit option, nginx client_max_body_size).",
      }];
    }
  } catch {
    // connection reset / timeout after large payload is expected/good
  }
  return [];
}

async function checkAuthBypass(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const BYPASS_PATHS = [
    "/api/admin",
    "/admin",
    "/api/users",
    "/api/internal",
    "/internal",
    "/api/v1/users",
  ];

  for (const p of BYPASS_PATHS) {
    try {
      const res = await axios.get(`${base}${p}`, { validateStatus: () => true, timeout: 5000 });
      if (res.status === 200) {
        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        const hasData = body.length > 50 && !body.includes("Not Found") && !body.includes("404");
        if (hasData) {
          findings.push({
            id: `smoke-unauth-access-${p.replace(/\//g, "-")}`,
            title: `Unauthenticated access to ${p}`,
            severity: "high",
            category: "smoke",
            description: `"${p}" returned HTTP 200 with non-trivial content without authentication headers.`,
            remediation: "Ensure all sensitive routes require authentication. Add middleware checks before route handlers.",
          });
        }
      }
    } catch {
      // no-op
    }
  }

  return findings;
}
