import axios from "axios";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

export async function scanSupabase(url: string, anonKey: string): Promise<Finding[]> {
  logger.info("Scanning Supabase configuration...");
  const findings: Finding[] = [];
  const base = url.replace(/\/$/, "");
  const authHeaders = { apikey: anonKey, Authorization: `Bearer ${anonKey}` };

  // ── 1. auth.users accessible via anon key (RLS disabled or missing) ─────────
  try {
    const res = await axios.get(`${base}/rest/v1/users?limit=1`, {
      headers: authHeaders,
      validateStatus: () => true,
      timeout: 8000,
    });
    if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      findings.push({
        id: "supabase-rls-users-exposed",
        title: "auth.users table readable by anonymous key",
        severity: "critical",
        category: "toolchain",
        tool: "supabase",
        description: "Unauthenticated requests can read rows from the users table. RLS is disabled or no restrictive policy exists.",
        remediation: "Enable RLS on auth.users and add a policy: CREATE POLICY deny_anon ON auth.users USING (auth.role() = 'authenticated');",
        references: ["https://supabase.com/docs/guides/auth/row-level-security"],
      });
    }
  } catch (e) {
    logger.debug("Supabase users probe failed:", e);
  }

  // ── 2. Common sensitive tables accessible via anon key ───────────────────────
  const SENSITIVE_TABLES = ["profiles", "orders", "payments", "transactions", "messages", "documents", "invoices", "subscriptions"];
  for (const table of SENSITIVE_TABLES) {
    try {
      const res = await axios.get(`${base}/rest/v1/${table}?limit=1`, {
        headers: authHeaders,
        validateStatus: () => true,
        timeout: 5000,
      });
      if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
        findings.push({
          id: `supabase-rls-${table}-exposed`,
          title: `Table "${table}" readable without authentication`,
          severity: "high",
          category: "toolchain",
          tool: "supabase",
          description: `The "${table}" table returns rows to unauthenticated requests, indicating RLS is disabled or missing.`,
          remediation: `Enable RLS: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; and add appropriate access policies.`,
          references: ["https://supabase.com/docs/guides/auth/row-level-security"],
        });
      }
    } catch {
      // table doesn't exist or is blocked — skip
    }
  }

  // ── 3. Public storage buckets ────────────────────────────────────────────────
  try {
    const res = await axios.get(`${base}/storage/v1/bucket`, {
      headers: authHeaders,
      validateStatus: () => true,
      timeout: 8000,
    });
    if (res.status === 200 && Array.isArray(res.data)) {
      const publicBuckets = res.data.filter((b: { public?: boolean; name?: string }) => b.public);
      for (const bucket of publicBuckets) {
        findings.push({
          id: `supabase-public-bucket-${bucket.name}`,
          title: `Storage bucket "${bucket.name}" is publicly readable`,
          severity: "medium",
          category: "toolchain",
          tool: "supabase",
          description: "Public buckets allow unauthenticated read access to all stored files, including any sensitive uploads.",
          remediation: "Set the bucket to private and issue signed URLs for user-specific access.",
          references: ["https://supabase.com/docs/guides/storage/security/access-control"],
        });
      }
    }
  } catch (e) {
    logger.debug("Supabase storage probe failed:", e);
  }

  // ── 4. Service role key used instead of anon key ─────────────────────────────
  if (anonKey.startsWith("eyJ") && anonKey.length > 200) {
    try {
      const payload = JSON.parse(Buffer.from(anonKey.split(".")[1]!, "base64").toString()) as Record<string, unknown>;
      if (payload["role"] === "service_role") {
        findings.push({
          id: "supabase-service-role-key-exposed",
          title: "Service role key used as anon key",
          severity: "critical",
          category: "toolchain",
          tool: "supabase",
          description: "The configured key has service_role privileges, bypassing ALL RLS policies. If this key reaches the client, an attacker can read and write any table without restriction.",
          remediation: "Rotate the service key immediately. Only use the anon key client-side. Store the service key exclusively in server-side environment variables.",
          references: ["https://supabase.com/docs/guides/api/api-keys"],
        });
      }
    } catch {
      // non-parseable JWT — skip
    }
  }

  // ── 5. Email auth without email confirmation ──────────────────────────────────
  try {
    const res = await axios.get(`${base}/auth/v1/settings`, {
      headers: authHeaders,
      validateStatus: () => true,
      timeout: 8000,
    });
    if (res.status === 200 && typeof res.data === "object" && res.data !== null) {
      const settings = res.data as Record<string, unknown>;
      if (settings["disable_signup"] === false && settings["mailer_autoconfirm"] === true) {
        findings.push({
          id: "supabase-autoconfirm-enabled",
          title: "Email signups auto-confirmed without verification",
          severity: "medium",
          category: "toolchain",
          tool: "supabase",
          description: "Accounts are created without email verification, enabling signup with arbitrary email addresses. Attackers can impersonate any email or bypass domain-based access rules.",
          remediation: "Disable auto-confirm in Supabase Auth settings. Require email verification before granting authenticated access.",
          references: ["https://supabase.com/docs/reference/auth-server/overview"],
        });
      }
      // Unrestricted signup
      if (settings["disable_signup"] === false && !settings["signup_restrictions"]) {
        findings.push({
          id: "supabase-unrestricted-signup",
          title: "Signup open to any email address",
          severity: "low",
          category: "toolchain",
          tool: "supabase",
          description: "No email domain allowlist is configured. Anyone can create an account, which may be unintended for internal or invite-only apps.",
          remediation: "Add an email domain allowlist in Supabase Auth settings if this is an internal application.",
        });
      }
    }
  } catch (e) {
    logger.debug("Supabase auth settings probe failed:", e);
  }

  // ── 6. Realtime enabled — check if sensitive tables subscribe without RLS ────
  try {
    const res = await axios.get(`${base}/rest/v1/?apikey=${anonKey}`, {
      validateStatus: () => true,
      timeout: 5000,
    });
    if (res.status === 200 && typeof res.data === "object" && res.data !== null) {
      const paths = Object.keys(res.data as Record<string, unknown>);
      const sensitivePaths = paths.filter((p) =>
        /user|profile|order|payment|invoice|message|document|secret|admin/i.test(p)
      );
      if (sensitivePaths.length > 0) {
        findings.push({
          id: "supabase-rest-sensitive-tables-listed",
          title: `REST API exposes schema for sensitive tables: ${sensitivePaths.slice(0, 4).join(", ")}`,
          severity: "low",
          category: "toolchain",
          tool: "supabase",
          description: "The PostgREST schema endpoint lists table names visible to the anon key. Schema exposure aids attackers in crafting targeted queries.",
          remediation: "Use pg_catalog visibility settings to restrict schema exposure. Consider hiding sensitive table names from the REST schema.",
          references: ["https://supabase.com/docs/guides/api/rest/client-libs"],
        });
      }
    }
  } catch (e) {
    logger.debug("Supabase schema probe failed:", e);
  }

  // ── 7. Database connection string in env (checked by code scanner, flag here too) ─
  // This is handled by the code scanner secret patterns — no duplicate finding needed.

  logger.info(`Supabase scan complete — ${findings.length} finding(s)`);
  return findings;
}
