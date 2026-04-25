import axios from "axios";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

const VERCEL_API = "https://api.vercel.com";

export async function scanVercel(token: string, projectId?: string): Promise<Finding[]> {
  logger.info("Scanning Vercel configuration...");
  const findings: Finding[] = [];
  const headers = { Authorization: `Bearer ${token}` };

  // ── 1. Env vars with secrets exposed in preview deployments ─────────────────
  if (projectId) {
    try {
      const res = await axios.get(`${VERCEL_API}/v9/projects/${projectId}/env`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200 && Array.isArray(res.data?.envs)) {
        for (const env of res.data.envs) {
          const name: string = env.key ?? "";
          const targets: string[] = env.target ?? [];
          const SECRET_PATTERNS = /^(SECRET|PRIVATE|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|AUTH|API_KEY|OPENAI|STRIPE|TWILIO|SENDGRID|ANTHROPIC)/i;
          if (SECRET_PATTERNS.test(name) && targets.includes("preview")) {
            findings.push({
              id: `vercel-secret-in-preview-${name}`,
              title: `Secret env var "${name}" exposed in Preview deployments`,
              severity: "high",
              category: "toolchain",
              tool: "vercel",
              description: "Sensitive environment variables are available in preview deployments, which are often publicly accessible via pull request URLs. An attacker with a PR URL can trigger requests that expose these secrets.",
              remediation: "Restrict sensitive env vars to Production only. Use Vercel's 'Sensitive' flag to prevent them from being viewable in the dashboard.",
              references: ["https://vercel.com/docs/projects/environment-variables/sensitive-environment-variables"],
            });
          }

          // Plain-text values that look like secrets (non-encrypted)
          if (env.type === "plain" && SECRET_PATTERNS.test(name)) {
            findings.push({
              id: `vercel-plaintext-secret-${name}`,
              title: `Secret "${name}" stored as plain text`,
              severity: "medium",
              category: "toolchain",
              tool: "vercel",
              description: "This environment variable contains a secret but is stored as plain text rather than an encrypted secret. It is visible to all project members in the Vercel dashboard.",
              remediation: "Delete and recreate the env var using the 'Sensitive' type so it is encrypted and hidden after creation.",
              references: ["https://vercel.com/docs/projects/environment-variables/sensitive-environment-variables"],
            });
          }
        }
      }
    } catch (e) {
      logger.debug("Vercel env probe failed:", e);
    }
  }

  // ── 2. Preview deployments have no access protection ────────────────────────
  if (projectId) {
    try {
      const res = await axios.get(`${VERCEL_API}/v9/projects/${projectId}`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200) {
        const project = res.data as Record<string, unknown>;

        if (!project["ssoProtection"] && !project["passwordProtection"]) {
          findings.push({
            id: "vercel-preview-unprotected",
            title: "Preview deployments are publicly accessible",
            severity: "medium",
            category: "toolchain",
            tool: "vercel",
            description: "Preview deployments have no SSO or password protection. External contributors and the public can access any preview URL, exposing staging data and in-progress features.",
            remediation: "Enable Vercel Authentication (SSO) or password protection for preview deployments under Project Settings → Deployment Protection.",
            references: ["https://vercel.com/docs/security/deployment-protection"],
          });
        }

        // Check if automation bypass secret is set (if not, CI bypass may be misconfigured)
        if (project["ssoProtection"] && !project["autoAssignCustomDomains"]) {
          // Automation bypass not detectable via API directly — skip
        }

        // Framework detection — Next.js specific checks
        if (project["framework"] === "nextjs") {
          const buildEnv = (project["buildEnv"] as unknown[]) ?? [];
          const hasAnalytics = buildEnv.some((e: unknown) => typeof e === "object" && e !== null && (e as Record<string,unknown>)["key"] === "NEXT_PUBLIC_VERCEL_ANALYTICS_ID");
          if (!hasAnalytics) {
            // Not a security finding — informational only, skip
          }
        }
      }
    } catch (e) {
      logger.debug("Vercel project probe failed:", e);
    }
  }

  // ── 3. Check for open team invite links ─────────────────────────────────────
  try {
    const res = await axios.get(`${VERCEL_API}/v2/teams`, {
      headers,
      validateStatus: () => true,
      timeout: 8000,
    });

    if (res.status === 200 && Array.isArray(res.data?.teams)) {
      for (const team of res.data.teams) {
        if (team.membership?.role === "OWNER" && team.inviteCode) {
          findings.push({
            id: `vercel-open-invite-${team.id}`,
            title: `Team "${team.name}" has an active open invite link`,
            severity: "medium",
            category: "toolchain",
            tool: "vercel",
            description: "An active invite link allows anyone with the URL to join your Vercel team, gaining access to all projects, env vars, and deployments.",
            remediation: "Invalidate the invite link in Team Settings. Use SAML SSO for controlled team access.",
            references: ["https://vercel.com/docs/teams-and-accounts/team-members-and-roles"],
          });
        }
      }
    }
  } catch (e) {
    logger.debug("Vercel teams probe failed:", e);
  }

  // ── 4. Check deployment log access (logs may contain secrets) ───────────────
  if (projectId) {
    try {
      const res = await axios.get(`${VERCEL_API}/v6/deployments?projectId=${projectId}&limit=1&target=preview`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200 && Array.isArray(res.data?.deployments) && res.data.deployments.length > 0) {
        const deploymentId: string = res.data.deployments[0]?.uid ?? "";
        if (deploymentId) {
          const logRes = await axios.get(`${VERCEL_API}/v2/deployments/${deploymentId}/events`, {
            headers,
            validateStatus: () => true,
            timeout: 8000,
          });
          if (logRes.status === 200 && Array.isArray(logRes.data)) {
            const logText = logRes.data.map((e: Record<string, unknown>) => String(e["text"] ?? "")).join("\n");
            const SECRET_IN_LOG = /(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}|xox[bp]-[a-zA-Z0-9-]{24,})/;
            if (SECRET_IN_LOG.test(logText)) {
              findings.push({
                id: "vercel-secret-in-deploy-log",
                title: "Secret key detected in deployment logs",
                severity: "critical",
                category: "toolchain",
                tool: "vercel",
                description: "A secret key (API key, token, or credential) was found in deployment log output. This is visible to all team members with log access.",
                remediation: "Rotate the exposed key immediately. Ensure secrets are never printed via console.log or build output. Use environment variables rather than hardcoded values.",
              });
            }
          }
        }
      }
    } catch (e) {
      logger.debug("Vercel deployment log probe failed:", e);
    }
  }

  // ── 5. Check if project has no custom domain (staging accessible on vercel.app) ─
  if (projectId) {
    try {
      const res = await axios.get(`${VERCEL_API}/v9/projects/${projectId}/domains`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200 && Array.isArray(res.data?.domains)) {
        const hasCustomDomain = res.data.domains.some(
          (d: { name?: string }) => d.name && !d.name.endsWith(".vercel.app")
        );
        if (!hasCustomDomain) {
          findings.push({
            id: "vercel-no-custom-domain",
            title: "Project only accessible on *.vercel.app — no custom domain",
            severity: "low",
            category: "toolchain",
            tool: "vercel",
            description: "The project has no custom domain. Vercel subdomain URLs are predictable and not considered production-hardened (no WAF, no custom TLS policy).",
            remediation: "Configure a custom domain with appropriate DNS settings for production workloads.",
          });
        }

        // Check for domains with misconfigured DNS (Vercel will mark them)
        const misconfigured = res.data.domains.filter(
          (d: { verified?: boolean; name?: string }) => !d.verified && !d.name?.endsWith(".vercel.app")
        );
        for (const d of misconfigured) {
          findings.push({
            id: `vercel-domain-unverified-${d.name}`,
            title: `Custom domain "${d.name}" is not verified`,
            severity: "low",
            category: "toolchain",
            tool: "vercel",
            description: "An unverified custom domain may be misconfigured, leaving DNS pointing to the wrong place or enabling subdomain takeover.",
            remediation: "Complete domain verification in Vercel or remove the stale domain entry.",
          });
        }
      }
    } catch (e) {
      logger.debug("Vercel domains probe failed:", e);
    }
  }

  // ── 6. Check for dangerously permissive CORS on API routes (via Vercel headers config) ─
  if (projectId) {
    try {
      const res = await axios.get(`${VERCEL_API}/v9/projects/${projectId}`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200) {
        const headers_config = (res.data as Record<string, unknown>)["headers"];
        if (Array.isArray(headers_config)) {
          for (const rule of headers_config) {
            const h = rule as Record<string, unknown>;
            const vals = Array.isArray(h["headers"]) ? h["headers"] as Record<string, string>[] : [];
            for (const header of vals) {
              if (
                header["key"]?.toLowerCase() === "access-control-allow-origin" &&
                header["value"] === "*"
              ) {
                findings.push({
                  id: "vercel-cors-wildcard",
                  title: "Wildcard CORS header configured at project level",
                  severity: "medium",
                  category: "toolchain",
                  tool: "vercel",
                  description: "Access-Control-Allow-Origin: * is set globally in Vercel project headers. This allows any origin to make credentialed cross-origin requests to your API routes.",
                  remediation: "Restrict CORS to specific trusted origins. Never combine wildcard CORS with credentials: 'include'.",
                  references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                });
              }
            }
          }
        }
      }
    } catch (e) {
      logger.debug("Vercel project headers check failed:", e);
    }
  }

  logger.info(`Vercel scan complete — ${findings.length} finding(s)`);
  return findings;
}
