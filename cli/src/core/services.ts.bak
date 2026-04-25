import fs from "fs";
import path from "path";

export interface CredentialField {
  key: string;
  label: string;
  secret: boolean;
  envHint?: string;    // env var name to pre-fill from if already set
}

export interface ServiceDefinition {
  id: string;
  name: string;
  category: string;
  fields: CredentialField[];
  /** Packages that indicate this service is in use */
  packages: string[];
  /** Env var prefixes that indicate this service is configured */
  envPrefixes: string[];
}

export const SERVICE_CATALOG: ServiceDefinition[] = [
  // ── Auth & Identity ────────────────────────────────────────────────────────
  {
    id: "supabase",
    name: "Supabase",
    category: "Database / Auth",
    packages: ["@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"],
    envPrefixes: ["SUPABASE_"],
    fields: [
      { key: "url",      label: "Project URL (https://xxx.supabase.co)", secret: false, envHint: "SUPABASE_URL" },
      { key: "anon_key", label: "Anon key",                              secret: true,  envHint: "SUPABASE_ANON_KEY" },
    ],
  },
  {
    id: "firebase",
    name: "Firebase",
    category: "Database / Auth",
    packages: ["firebase", "firebase-admin", "firebase-functions"],
    envPrefixes: ["FIREBASE_", "NEXT_PUBLIC_FIREBASE_"],
    fields: [
      { key: "project_id",  label: "Project ID",             secret: false, envHint: "FIREBASE_PROJECT_ID" },
      { key: "api_key",     label: "Web API key",             secret: true,  envHint: "FIREBASE_API_KEY" },
      { key: "admin_key",   label: "Service account key JSON (paste full JSON, optional)", secret: true },
    ],
  },
  {
    id: "clerk",
    name: "Clerk",
    category: "Auth",
    packages: ["@clerk/nextjs", "@clerk/clerk-sdk-node", "@clerk/clerk-react"],
    envPrefixes: ["CLERK_", "NEXT_PUBLIC_CLERK_"],
    fields: [
      { key: "secret_key",      label: "Secret key (sk_live_...)",        secret: true,  envHint: "CLERK_SECRET_KEY" },
      { key: "publishable_key", label: "Publishable key (pk_live_...)",   secret: false, envHint: "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY" },
    ],
  },
  {
    id: "auth0",
    name: "Auth0",
    category: "Auth",
    packages: ["auth0", "@auth0/nextjs-auth0", "express-openid-connect"],
    envPrefixes: ["AUTH0_"],
    fields: [
      { key: "domain",        label: "Domain (xxx.auth0.com)",         secret: false, envHint: "AUTH0_DOMAIN" },
      { key: "client_id",     label: "Client ID",                      secret: false, envHint: "AUTH0_CLIENT_ID" },
      { key: "client_secret", label: "Client secret",                  secret: true,  envHint: "AUTH0_CLIENT_SECRET" },
      { key: "mgmt_token",    label: "Management API token (optional)", secret: true },
    ],
  },

  // ── Hosting / Infra ────────────────────────────────────────────────────────
  {
    id: "vercel",
    name: "Vercel",
    category: "Hosting",
    packages: [],
    envPrefixes: ["VERCEL_"],
    fields: [
      { key: "token",      label: "API token",            secret: true,  envHint: "VERCEL_TOKEN" },
      { key: "project_id", label: "Project ID (optional)", secret: false, envHint: "VERCEL_PROJECT_ID" },
    ],
  },
  {
    id: "github",
    name: "GitHub",
    category: "Source Control / CI",
    packages: ["@octokit/rest", "@octokit/core", "octokit"],
    envPrefixes: ["GITHUB_", "GH_"],
    fields: [
      { key: "token", label: "Personal access token or fine-grained PAT", secret: true, envHint: "GITHUB_TOKEN" },
      { key: "repo",  label: "Repo (owner/name)",                          secret: false, envHint: "GITHUB_REPO" },
    ],
  },
  {
    id: "aws",
    name: "AWS",
    category: "Cloud",
    packages: ["aws-sdk", "@aws-sdk/client-s3", "@aws-sdk/client-iam", "@aws-sdk/client-sts", "@aws-sdk/client-lambda"],
    envPrefixes: ["AWS_"],
    fields: [
      { key: "access_key_id",     label: "Access key ID",     secret: false, envHint: "AWS_ACCESS_KEY_ID" },
      { key: "secret_access_key", label: "Secret access key", secret: true,  envHint: "AWS_SECRET_ACCESS_KEY" },
      { key: "region",            label: "Region (e.g. us-east-1)", secret: false, envHint: "AWS_REGION" },
    ],
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    category: "CDN / Edge",
    packages: ["cloudflare", "@cloudflare/workers-types", "wrangler"],
    envPrefixes: ["CLOUDFLARE_", "CF_"],
    fields: [
      { key: "api_token", label: "API token",            secret: true,  envHint: "CLOUDFLARE_API_TOKEN" },
      { key: "zone_id",   label: "Zone ID (optional)",   secret: false, envHint: "CLOUDFLARE_ZONE_ID" },
      { key: "account_id", label: "Account ID (optional)", secret: false, envHint: "CLOUDFLARE_ACCOUNT_ID" },
    ],
  },

  // ── Payments ───────────────────────────────────────────────────────────────
  {
    id: "stripe",
    name: "Stripe",
    category: "Payments",
    packages: ["stripe", "@stripe/stripe-js", "@stripe/react-stripe-js"],
    envPrefixes: ["STRIPE_"],
    fields: [
      { key: "secret_key",      label: "Secret key (sk_live_... or sk_test_...)", secret: true,  envHint: "STRIPE_SECRET_KEY" },
      { key: "webhook_secret",  label: "Webhook signing secret (optional)",        secret: true,  envHint: "STRIPE_WEBHOOK_SECRET" },
    ],
  },

  // ── Messaging / Email ──────────────────────────────────────────────────────
  {
    id: "sendgrid",
    name: "SendGrid",
    category: "Email",
    packages: ["@sendgrid/mail", "@sendgrid/client"],
    envPrefixes: ["SENDGRID_"],
    fields: [
      { key: "api_key", label: "API key (SG.xxx)", secret: true, envHint: "SENDGRID_API_KEY" },
    ],
  },
  {
    id: "resend",
    name: "Resend",
    category: "Email",
    packages: ["resend"],
    envPrefixes: ["RESEND_"],
    fields: [
      { key: "api_key", label: "API key (re_xxx)", secret: true, envHint: "RESEND_API_KEY" },
    ],
  },
  {
    id: "twilio",
    name: "Twilio",
    category: "SMS / Voice",
    packages: ["twilio"],
    envPrefixes: ["TWILIO_"],
    fields: [
      { key: "account_sid", label: "Account SID (ACxxx)", secret: false, envHint: "TWILIO_ACCOUNT_SID" },
      { key: "auth_token",  label: "Auth token",           secret: true,  envHint: "TWILIO_AUTH_TOKEN" },
    ],
  },

  // ── Database ───────────────────────────────────────────────────────────────
  {
    id: "neon",
    name: "Neon",
    category: "Database",
    packages: ["@neondatabase/serverless", "neon"],
    envPrefixes: ["DATABASE_URL", "NEON_"],
    fields: [
      { key: "api_key",    label: "API key (optional — for project-level checks)", secret: true, envHint: "NEON_API_KEY" },
      { key: "project_id", label: "Project ID (optional)",                          secret: false, envHint: "NEON_PROJECT_ID" },
    ],
  },
  {
    id: "planetscale",
    name: "PlanetScale",
    category: "Database",
    packages: ["@planetscale/database", "planetscale"],
    envPrefixes: ["PLANETSCALE_", "DATABASE_URL"],
    fields: [
      { key: "service_token_id", label: "Service token ID", secret: false, envHint: "PLANETSCALE_SERVICE_TOKEN_ID" },
      { key: "service_token",    label: "Service token",     secret: true,  envHint: "PLANETSCALE_SERVICE_TOKEN" },
      { key: "org",              label: "Organization name", secret: false },
    ],
  },
  {
    id: "upstash",
    name: "Upstash (Redis)",
    category: "Database / Cache",
    packages: ["@upstash/redis", "@upstash/ratelimit", "@upstash/qstash"],
    envPrefixes: ["UPSTASH_"],
    fields: [
      { key: "rest_url",   label: "Redis REST URL",   secret: false, envHint: "UPSTASH_REDIS_REST_URL" },
      { key: "rest_token", label: "Redis REST token", secret: true,  envHint: "UPSTASH_REDIS_REST_TOKEN" },
    ],
  },

  // ── AI ─────────────────────────────────────────────────────────────────────
  {
    id: "openai",
    name: "OpenAI",
    category: "AI",
    packages: ["openai", "@openai/agents"],
    envPrefixes: ["OPENAI_"],
    fields: [
      { key: "api_key",  label: "API key (sk-...)",   secret: true,  envHint: "OPENAI_API_KEY" },
      { key: "org_id",   label: "Org ID (optional)",  secret: false, envHint: "OPENAI_ORG_ID" },
    ],
  },
  {
    id: "anthropic",
    name: "Anthropic",
    category: "AI",
    packages: ["@anthropic-ai/sdk", "@anthropic-ai/bedrock-sdk"],
    envPrefixes: ["ANTHROPIC_"],
    fields: [
      { key: "api_key", label: "API key (sk-ant-...)", secret: true, envHint: "ANTHROPIC_API_KEY" },
    ],
  },
  {
    id: "pinecone",
    name: "Pinecone",
    category: "Vector DB",
    packages: ["@pinecone-database/pinecone"],
    envPrefixes: ["PINECONE_"],
    fields: [
      { key: "api_key",     label: "API key",              secret: true,  envHint: "PINECONE_API_KEY" },
      { key: "environment", label: "Environment (e.g. gcp-starter)", secret: false, envHint: "PINECONE_ENVIRONMENT" },
    ],
  },

  // ── Observability ──────────────────────────────────────────────────────────
  {
    id: "sentry",
    name: "Sentry",
    category: "Observability",
    packages: ["@sentry/nextjs", "@sentry/node", "@sentry/react", "sentry"],
    envPrefixes: ["SENTRY_", "NEXT_PUBLIC_SENTRY_"],
    fields: [
      { key: "auth_token", label: "Auth token",   secret: true,  envHint: "SENTRY_AUTH_TOKEN" },
      { key: "org_slug",   label: "Org slug",     secret: false, envHint: "SENTRY_ORG" },
      { key: "dsn",        label: "DSN (optional)", secret: false, envHint: "SENTRY_DSN" },
    ],
  },
  {
    id: "datadog",
    name: "Datadog",
    category: "Observability",
    packages: ["dd-trace", "datadog-lambda-js", "@datadog/browser-logs"],
    envPrefixes: ["DD_", "DATADOG_"],
    fields: [
      { key: "api_key", label: "API key",           secret: true,  envHint: "DD_API_KEY" },
      { key: "app_key", label: "App key (optional)", secret: true,  envHint: "DD_APP_KEY" },
      { key: "site",    label: "Site (e.g. datadoghq.com)", secret: false, envHint: "DD_SITE" },
    ],
  },
];

export interface DiscoveredService {
  definition: ServiceDefinition;
  confidence: "env" | "package" | "both";
  detectedEnvKeys: string[];
  detectedPackages: string[];
}

/** Parse all .env* files in the project root and return known env var names */
function readEnvKeys(cwd: string): string[] {
  const envFiles = [".env", ".env.local", ".env.development", ".env.production", ".env.example"];
  const keys: string[] = [];

  for (const file of envFiles) {
    const filePath = path.join(cwd, file);
    if (!fs.existsSync(filePath)) continue;
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIdx = trimmed.indexOf("=");
        if (eqIdx > 0) keys.push(trimmed.slice(0, eqIdx).trim());
      }
    } catch {
      // skip unreadable
    }
  }

  return [...new Set(keys)];
}

/** Discover which services from the catalog are actually in use in this project */
export function discoverServices(
  cwd: string,
  installedPackages: string[]
): DiscoveredService[] {
  const envKeys = readEnvKeys(cwd);
  const packageSet = new Set(installedPackages);
  const discovered: DiscoveredService[] = [];

  for (const def of SERVICE_CATALOG) {
    const matchedPackages = def.packages.filter((p) => packageSet.has(p));
    const matchedEnvKeys = envKeys.filter((k) =>
      def.envPrefixes.some((prefix) => k.startsWith(prefix) || k === prefix)
    );

    const hasPackage = matchedPackages.length > 0;
    const hasEnv = matchedEnvKeys.length > 0;

    if (!hasPackage && !hasEnv) continue;

    discovered.push({
      definition: def,
      confidence: hasPackage && hasEnv ? "both" : hasEnv ? "env" : "package",
      detectedEnvKeys: matchedEnvKeys,
      detectedPackages: matchedPackages,
    });
  }

  // Sort: highest confidence first
  return discovered.sort((a, b) => {
    const rank = { both: 0, env: 1, package: 2 };
    return rank[a.confidence] - rank[b.confidence];
  });
}
