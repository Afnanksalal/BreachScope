import path from "path";
import fs from "fs";
import fg from "fast-glob";
import { logger } from "../core/logger.js";
import type { DetectedTool, DetectionSource } from "../core/types.js";
import { resolveKnownTool } from "../core/toolmap.js";

const IGNORE_DIRS = ["node_modules", ".git", "dist", "build", ".next", "__pycache__"];

interface RawDetection {
  name: string;
  version?: string;
  sources: Set<DetectionSource>;
}

/**
 * Detect all tools/packages used in a codebase from multiple signals.
 * Returns deduplicated DetectedTool list at depth=0.
 */
export async function detectTools(cwd: string): Promise<DetectedTool[]> {
  const raw = new Map<string, RawDetection>();

  const merge = (name: string, source: DetectionSource, version?: string) => {
    const existing = raw.get(name);
    if (existing) {
      existing.sources.add(source);
      if (version && !existing.version) existing.version = version;
    } else {
      raw.set(name, { name, version, sources: new Set([source]) });
    }
  };

  await Promise.all([
    detectFromPackageJson(cwd).then((r) => r.forEach(({ name, version }) => merge(name, "package.json", version))),
    detectFromImports(cwd).then((r) => r.forEach((name) => merge(name, "import-statement"))),
    detectFromEnvFiles(cwd).then((r) => r.forEach((name) => merge(name, "env-variable"))),
    detectFromConfigFiles(cwd).then((r) => r.forEach((name) => merge(name, "config-file"))),
  ]);

  const tools: DetectedTool[] = [];

  for (const [name, det] of raw) {
    const known = resolveKnownTool(name);
    tools.push({
      name,
      version: det.version,
      kind: known?.kind ?? "unknown",
      github: known?.github,
      homepage: known?.advisoryUrl,
      detectedFrom: Array.from(det.sources),
      depth: 0,
    });
  }

  logger.info(`Detected ${tools.length} tool(s) in codebase`);
  return tools;
}

// ─── Detection strategies ────────────────────────────────────────────────────

async function detectFromPackageJson(cwd: string): Promise<Array<{ name: string; version: string }>> {
  const pkgPath = path.join(cwd, "package.json");
  if (!fs.existsSync(pkgPath)) return [];

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
    const deps = {
      ...(pkg["dependencies"] as Record<string, string> ?? {}),
      ...(pkg["devDependencies"] as Record<string, string> ?? {}),
      ...(pkg["peerDependencies"] as Record<string, string> ?? {}),
    };
    return Object.entries(deps).map(([name, version]) => ({ name, version }));
  } catch {
    return [];
  }
}

async function detectFromImports(cwd: string): Promise<string[]> {
  const files = await fg("**/*.{ts,tsx,js,jsx,mjs,cjs}", {
    cwd,
    ignore: IGNORE_DIRS.map((d) => `**/${d}/**`),
    absolute: true,
  });

  const packages = new Set<string>();

  // Match: import ... from 'pkg', require('pkg'), import('pkg')
  const importRe = /(?:from|require|import)\s*\(?["'](@?[a-z0-9][\w.-]*(?:\/[a-z0-9][\w.-]*)?)["']/gi;

  for (const file of files.slice(0, 300)) {
    try {
      const content = fs.readFileSync(file, "utf-8");
      let match: RegExpExecArray | null;
      while ((match = importRe.exec(content)) !== null) {
        const raw = match[1]!;
        // Normalize to package name (strip sub-paths: @scope/pkg/sub → @scope/pkg)
        const pkg = raw.startsWith("@")
          ? raw.split("/").slice(0, 2).join("/")
          : raw.split("/")[0]!;
        // Skip Node built-ins and relative imports
        if (!pkg.startsWith(".") && !isBuiltin(pkg)) {
          packages.add(pkg);
        }
      }
    } catch {
      // skip unreadable
    }
  }

  return Array.from(packages);
}

async function detectFromEnvFiles(cwd: string): Promise<string[]> {
  const envFiles = [".env", ".env.local", ".env.production", ".env.example", ".env.sample"];
  const detected: string[] = [];

  // Map env var prefixes to tool names
  const ENV_MAP: Record<string, string> = {
    SUPABASE_URL: "@supabase/supabase-js",
    SUPABASE_ANON_KEY: "@supabase/supabase-js",
    SUPABASE_SERVICE_ROLE_KEY: "@supabase/supabase-js",
    VERCEL_TOKEN: "@vercel/og",
    OPENAI_API_KEY: "openai",
    ANTHROPIC_API_KEY: "@anthropic-ai/sdk",
    STRIPE_SECRET_KEY: "stripe",
    STRIPE_PUBLISHABLE_KEY: "stripe",
    SENDGRID_API_KEY: "@sendgrid/mail",
    RESEND_API_KEY: "resend",
    SENTRY_DSN: "@sentry/node",
    POSTHOG_KEY: "posthog-js",
    CLERK_SECRET_KEY: "@clerk/nextjs",
    AUTH0_SECRET: "@auth0/nextjs-auth0",
    LINEAR_API_KEY: "@linear/sdk",
    NOTION_TOKEN: "@notionhq/client",
    SLACK_TOKEN: "@slack/web-api",
    ALGOLIA_APP_ID: "algoliasearch",
    UPSTASH_REDIS_REST_URL: "@upstash/redis",
    DATABASE_URL: "pg",
    MONGODB_URI: "mongodb",
    REDIS_URL: "redis",
    FIREBASE_SERVICE_ACCOUNT: "firebase-admin",
    AWS_ACCESS_KEY_ID: "@aws-sdk/client-s3",
    GCP_PROJECT_ID: "@google-cloud/storage",
    CLOUDINARY_URL: "cloudinary",
    PUSHER_APP_ID: "pusher",
  };

  for (const envFile of envFiles) {
    const filePath = path.join(cwd, envFile);
    if (!fs.existsSync(filePath)) continue;

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      for (const line of content.split("\n")) {
        const [key] = line.split("=");
        if (!key) continue;
        const trimmed = key.trim();
        if (ENV_MAP[trimmed]) detected.push(ENV_MAP[trimmed]!);
      }
    } catch {
      // skip
    }
  }

  return [...new Set(detected)];
}

async function detectFromConfigFiles(cwd: string): Promise<string[]> {
  const detected: string[] = [];

  // Detect Prisma
  if (fs.existsSync(path.join(cwd, "prisma/schema.prisma"))) {
    detected.push("@prisma/client");
  }
  // Detect Drizzle
  if (fs.existsSync(path.join(cwd, "drizzle.config.ts")) || fs.existsSync(path.join(cwd, "drizzle.config.js"))) {
    detected.push("drizzle-orm");
  }
  // Detect Next.js
  if (fs.existsSync(path.join(cwd, "next.config.js")) || fs.existsSync(path.join(cwd, "next.config.ts"))) {
    detected.push("next");
  }
  // Detect Sentry
  if (fs.existsSync(path.join(cwd, "sentry.config.ts")) || fs.existsSync(path.join(cwd, "sentry.server.config.ts"))) {
    detected.push("@sentry/nextjs");
  }

  return detected;
}

const NODE_BUILTINS = new Set([
  "fs", "path", "os", "http", "https", "url", "crypto", "stream", "util",
  "events", "net", "dns", "child_process", "cluster", "worker_threads",
  "buffer", "string_decoder", "querystring", "readline", "zlib", "assert",
  "async_hooks", "timers", "module", "process", "v8", "vm", "tls", "dgram",
]);

function isBuiltin(pkg: string): boolean {
  return NODE_BUILTINS.has(pkg) || pkg.startsWith("node:");
}
