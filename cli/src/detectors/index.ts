import path from "path";
import fs from "fs";
import fg from "fast-glob";
import { logger } from "../core/logger.js";
import type { DetectedTool, DetectionSource } from "../core/types.js";
import { resolveKnownTool } from "../core/toolmap.js";
import {
  parseRequirementsTxt, parsePyprojectToml, parsePipfile, parseSetupPy,
} from "../scanners/dependency/python.js";
import { parseGoMod } from "../scanners/dependency/go.js";
import { parseCargoToml, parseCargoLock } from "../scanners/dependency/rust.js";

const IGNORE_DIRS = ["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"];

interface RawDetection {
  name: string;
  version?: string;
  sources: Set<DetectionSource>;
  ecosystem: string;
}

// ─── Python known-tool map ───────────────────────────────────────────────────
// Maps PyPI package names → GitHub slugs for Scorecard queries
const PYTHON_KNOWN: Record<string, { github?: string; kind: "oss" | "saas" | "hybrid" }> = {
  "django":          { github: "django/django",          kind: "oss" },
  "flask":           { github: "pallets/flask",           kind: "oss" },
  "fastapi":         { github: "tiangolo/fastapi",        kind: "oss" },
  "requests":        { github: "psf/requests",            kind: "oss" },
  "httpx":           { github: "encode/httpx",            kind: "oss" },
  "aiohttp":         { github: "aio-libs/aiohttp",        kind: "oss" },
  "sqlalchemy":      { github: "sqlalchemy/sqlalchemy",   kind: "oss" },
  "alembic":         { github: "sqlalchemy/alembic",      kind: "oss" },
  "pydantic":        { github: "pydantic/pydantic",       kind: "oss" },
  "celery":          { github: "celery/celery",           kind: "oss" },
  "redis":           { github: "redis/redis-py",          kind: "hybrid" },
  "supabase":        { github: "supabase/supabase-py",    kind: "hybrid" },
  "openai":          { github: "openai/openai-python",    kind: "saas" },
  "anthropic":       { github: "anthropic/anthropic-sdk-python", kind: "saas" },
  "boto3":           { github: "boto/boto3",              kind: "saas" },
  "botocore":        { github: "boto/botocore",           kind: "saas" },
  "google-cloud-storage": { github: "googleapis/python-storage", kind: "saas" },
  "stripe":          { github: "stripe/stripe-python",    kind: "saas" },
  "twilio":          { github: "twilio/twilio-python",    kind: "saas" },
  "pillow":          { github: "python-pillow/Pillow",    kind: "oss" },
  "numpy":           { github: "numpy/numpy",             kind: "oss" },
  "pandas":          { github: "pandas-dev/pandas",       kind: "oss" },
  "scipy":           { github: "scipy/scipy",             kind: "oss" },
  "cryptography":    { github: "pyca/cryptography",       kind: "oss" },
  "paramiko":        { github: "paramiko/paramiko",       kind: "oss" },
  "jwt":             { github: "jpadilla/pyjwt",          kind: "oss" },
  "pyjwt":           { github: "jpadilla/pyjwt",          kind: "oss" },
  "uvicorn":         { github: "encode/uvicorn",          kind: "oss" },
  "gunicorn":        { github: "benoitc/gunicorn",        kind: "oss" },
  "pytest":          { github: "pytest-dev/pytest",       kind: "oss" },
  "sentry-sdk":      { github: "getsentry/sentry-python", kind: "saas" },
};

// ─── Go known-tool map ───────────────────────────────────────────────────────
const GO_KNOWN: Record<string, { github?: string; kind: "oss" | "saas" | "hybrid" }> = {
  "github.com/gin-gonic/gin":          { github: "gin-gonic/gin",             kind: "oss" },
  "github.com/gofiber/fiber":          { github: "gofiber/fiber",              kind: "oss" },
  "github.com/labstack/echo":          { github: "labstack/echo",              kind: "oss" },
  "github.com/redis/go-redis":         { github: "redis/go-redis",             kind: "hybrid" },
  "github.com/go-redis/redis":         { github: "go-redis/redis",             kind: "hybrid" },
  "gorm.io/gorm":                      { github: "go-gorm/gorm",               kind: "oss" },
  "github.com/jmoiron/sqlx":           { github: "jmoiron/sqlx",               kind: "oss" },
  "github.com/golang-jwt/jwt":         { github: "golang-jwt/jwt",             kind: "oss" },
  "go.mongodb.org/mongo-driver":       { github: "mongodb/mongo-go-driver",    kind: "hybrid" },
  "github.com/aws/aws-sdk-go":         { github: "aws/aws-sdk-go",             kind: "saas" },
  "github.com/aws/aws-sdk-go-v2":      { github: "aws/aws-sdk-go-v2",          kind: "saas" },
  "github.com/stripe/stripe-go":       { github: "stripe/stripe-go",           kind: "saas" },
};

// ─── Rust known-tool map ─────────────────────────────────────────────────────
const RUST_KNOWN: Record<string, { github?: string; kind: "oss" | "saas" | "hybrid" }> = {
  "actix-web":  { github: "actix/actix-web",     kind: "oss" },
  "axum":       { github: "tokio-rs/axum",        kind: "oss" },
  "tokio":      { github: "tokio-rs/tokio",       kind: "oss" },
  "serde":      { github: "serde-rs/serde",       kind: "oss" },
  "reqwest":    { github: "seanmonstar/reqwest",  kind: "oss" },
  "hyper":      { github: "hyperium/hyper",       kind: "oss" },
  "redis":      { github: "redis-rs/redis-rs",    kind: "hybrid" },
  "sqlx":       { github: "launchbadge/sqlx",     kind: "oss" },
  "diesel":     { github: "diesel-rs/diesel",     kind: "oss" },
  "rustls":     { github: "rustls/rustls",        kind: "oss" },
  "ring":       { github: "briansmith/ring",      kind: "oss" },
  "openssl":    { github: "sfackler/rust-openssl", kind: "oss" },
};

// ─── Main detector ────────────────────────────────────────────────────────────

export async function detectTools(cwd: string): Promise<DetectedTool[]> {
  const raw = new Map<string, RawDetection>();

  const merge = (name: string, source: DetectionSource, ecosystem: string, version?: string) => {
    const key = `${ecosystem}:${name}`;
    const existing = raw.get(key);
    if (existing) {
      existing.sources.add(source);
      if (version && !existing.version) existing.version = version;
    } else {
      raw.set(key, { name, version, sources: new Set([source]), ecosystem });
    }
  };

  await Promise.all([
    // JS/npm
    detectFromPackageJson(cwd).then((r) => r.forEach(({ name, version }) => merge(name, "package.json", "npm", version))),
    detectFromJsImports(cwd).then((r) => r.forEach((name) => merge(name, "import-statement", "npm"))),
    detectFromEnvFiles(cwd).then((r) => r.forEach(({ name, ecosystem }) => merge(name, "env-variable", ecosystem))),
    detectFromConfigFiles(cwd).then((r) => r.forEach((name) => merge(name, "config-file", "npm"))),
    // Python
    detectFromPythonManifests(cwd).then((r) => r.forEach(({ name, version }) => merge(name, "package.json", "PyPI", version))),
    detectFromPythonImports(cwd).then((r) => r.forEach((name) => merge(name, "import-statement", "PyPI"))),
    // Go
    detectFromGoMod2(cwd).then((r) => r.forEach(({ name, version }) => merge(name, "package.json", "Go", version))),
    // Rust
    detectFromCargoToml2(cwd).then((r) => r.forEach(({ name, version }) => merge(name, "package.json", "crates.io", version))),
  ]);

  const tools: DetectedTool[] = [];

  for (const [, det] of raw) {
    const ecosystem = det.ecosystem;
    let known = ecosystem === "npm" ? resolveKnownTool(det.name) : null;

    // For Python/Go/Rust, look up from our known maps
    let github: string | undefined;
    let kind: "oss" | "saas" | "hybrid" | "unknown" = "unknown";

    if (ecosystem === "PyPI") {
      const py = PYTHON_KNOWN[det.name];
      if (py) { github = py.github; kind = py.kind; }
    } else if (ecosystem === "Go") {
      const go = GO_KNOWN[det.name];
      if (go) { github = go.github; kind = go.kind; }
      else {
        // Infer GitHub from module path (github.com/org/repo)
        const m = det.name.match(/^github\.com\/([^/]+\/[^/]+)/);
        if (m?.[1]) { github = m[1]; kind = "oss"; }
      }
    } else if (ecosystem === "crates.io") {
      const ru = RUST_KNOWN[det.name];
      if (ru) { github = ru.github; kind = ru.kind; }
    } else if (known) {
      github = known.github;
      kind   = known.kind;
    }

    tools.push({
      name: det.name,
      version: det.version,
      kind,
      github,
      detectedFrom: Array.from(det.sources),
      depth: 0,
      ecosystem,
    });
  }

  logger.info(`Detected ${tools.length} tool(s) in codebase`);
  return tools;
}

// ─── JS detection ─────────────────────────────────────────────────────────────

/**
 * Read exact installed versions from package-lock.json (npm v1/v2/v3) or
 * node_modules/<pkg>/package.json. Range specifiers like ^1.2.3 are not valid
 * OSV versions — we need the actual resolved version.
 */
function readNpmExactVersions(cwd: string): Record<string, string> {
  // npm v7+ lockfile (lockfileVersion 2 or 3): packages["node_modules/foo"].version
  const lockPath = path.join(cwd, "package-lock.json");
  if (fs.existsSync(lockPath)) {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8")) as {
        lockfileVersion?: number;
        packages?: Record<string, { version?: string }>;
        dependencies?: Record<string, { version?: string }>;
      };
      const out: Record<string, string> = {};

      if (lock.packages) {
        // v2/v3
        for (const [key, val] of Object.entries(lock.packages)) {
          if (key.startsWith("node_modules/") && val.version) {
            const name = key.slice("node_modules/".length);
            out[name] = val.version;
          }
        }
        return out;
      }

      if (lock.dependencies) {
        // v1
        for (const [name, val] of Object.entries(lock.dependencies)) {
          if (val.version) out[name] = val.version;
        }
        return out;
      }
    } catch { /* fall through */ }
  }

  // Fallback: read installed version from node_modules directly
  const nmDir = path.join(cwd, "node_modules");
  if (!fs.existsSync(nmDir)) return {};
  const out: Record<string, string> = {};
  try {
    for (const entry of fs.readdirSync(nmDir)) {
      const pkgFile = path.join(nmDir, entry, "package.json");
      if (fs.existsSync(pkgFile)) {
        try {
          const p = JSON.parse(fs.readFileSync(pkgFile, "utf-8")) as { version?: string };
          if (p.version) out[entry] = p.version;
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }
  return out;
}

/** Strip npm range operators; return undefined if no valid semver can be extracted. */
function stripRangeOps(v: string): string | undefined {
  const s = v.trim().replace(/^[=^~><!]+/, "").split(/[\s,|]/)[0] ?? "";
  return /^\d/.test(s) ? s : undefined;
}

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
    const exactVersions = readNpmExactVersions(cwd);
    return Object.entries(deps).map(([name, rangeVer]) => ({
      name,
      // Prefer lockfile exact version; fall back to stripping the range specifier
      version: exactVersions[name] ?? stripRangeOps(rangeVer) ?? rangeVer,
    }));
  } catch { return []; }
}

async function detectFromJsImports(cwd: string): Promise<string[]> {
  const files = await fg("**/*.{ts,tsx,js,jsx,mjs,cjs}", {
    cwd, ignore: IGNORE_DIRS.map((d) => `**/${d}/**`), absolute: true,
  });
  const packages = new Set<string>();
  const importRe = /(?:from|require|import)\s*\(?["'](@?[a-z0-9][\w.-]*(?:\/[a-z0-9][\w.-]*)?)["']/gi;
  for (const file of files.slice(0, 300)) {
    try {
      const content = fs.readFileSync(file, "utf-8");
      let m: RegExpExecArray | null;
      while ((m = importRe.exec(content)) !== null) {
        const raw = m[1]!;
        const pkg = raw.startsWith("@") ? raw.split("/").slice(0, 2).join("/") : raw.split("/")[0]!;
        if (!pkg.startsWith(".") && !isBuiltin(pkg)) packages.add(pkg);
      }
    } catch { /* skip */ }
  }
  return Array.from(packages);
}

async function detectFromEnvFiles(cwd: string): Promise<Array<{ name: string; ecosystem: string }>> {
  const envFiles = [".env", ".env.local", ".env.production", ".env.example", ".env.sample"];
  const ENV_MAP: Record<string, { name: string; ecosystem: string }> = {
    SUPABASE_URL:           { name: "@supabase/supabase-js", ecosystem: "npm" },
    SUPABASE_ANON_KEY:      { name: "@supabase/supabase-js", ecosystem: "npm" },
    OPENAI_API_KEY:         { name: "openai",                ecosystem: "npm" },
    ANTHROPIC_API_KEY:      { name: "@anthropic-ai/sdk",     ecosystem: "npm" },
    STRIPE_SECRET_KEY:      { name: "stripe",                ecosystem: "npm" },
    SENDGRID_API_KEY:       { name: "@sendgrid/mail",        ecosystem: "npm" },
    RESEND_API_KEY:         { name: "resend",                ecosystem: "npm" },
    SENTRY_DSN:             { name: "@sentry/node",          ecosystem: "npm" },
    CLERK_SECRET_KEY:       { name: "@clerk/nextjs",         ecosystem: "npm" },
    UPSTASH_REDIS_REST_URL: { name: "@upstash/redis",        ecosystem: "npm" },
    REDIS_URL:              { name: "redis",                 ecosystem: "npm" },
    FIREBASE_SERVICE_ACCOUNT: { name: "firebase-admin",      ecosystem: "npm" },
    AWS_ACCESS_KEY_ID:      { name: "@aws-sdk/client-s3",    ecosystem: "npm" },
  };
  const detected: Array<{ name: string; ecosystem: string }> = [];
  for (const envFile of envFiles) {
    const filePath = path.join(cwd, envFile);
    if (!fs.existsSync(filePath)) continue;
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      for (const line of content.split("\n")) {
        const [key] = line.split("=");
        if (!key) continue;
        const mapped = ENV_MAP[key.trim()];
        if (mapped) detected.push(mapped);
      }
    } catch { /* skip */ }
  }
  return [...new Map(detected.map((d) => [d.name, d])).values()];
}

async function detectFromConfigFiles(cwd: string): Promise<string[]> {
  const detected: string[] = [];
  if (fs.existsSync(path.join(cwd, "prisma/schema.prisma"))) detected.push("@prisma/client");
  if (fs.existsSync(path.join(cwd, "drizzle.config.ts")) || fs.existsSync(path.join(cwd, "drizzle.config.js"))) detected.push("drizzle-orm");
  if (fs.existsSync(path.join(cwd, "next.config.js")) || fs.existsSync(path.join(cwd, "next.config.ts"))) detected.push("next");
  if (fs.existsSync(path.join(cwd, "sentry.config.ts")) || fs.existsSync(path.join(cwd, "sentry.server.config.ts"))) detected.push("@sentry/nextjs");
  return detected;
}

// ─── Python detection ─────────────────────────────────────────────────────────

async function detectFromPythonManifests(cwd: string): Promise<Array<{ name: string; version?: string }>> {
  const pkgs: Array<{ name: string; version?: string }> = [];
  const seen = new Set<string>();
  const add = (p: { name: string; version?: string }) => { if (!seen.has(p.name)) { seen.add(p.name); pkgs.push(p); } };

  const tryParse = (file: string, parser: (c: string) => Array<{ name: string; version?: string }>) => {
    const fp = path.join(cwd, file);
    if (!fs.existsSync(fp)) return;
    try { parser(fs.readFileSync(fp, "utf-8")).forEach(add); } catch { /* skip */ }
  };

  tryParse("requirements.txt",      parseRequirementsTxt);
  tryParse("requirements-dev.txt",  parseRequirementsTxt);
  tryParse("pyproject.toml",        parsePyprojectToml);
  tryParse("Pipfile",               parsePipfile);
  tryParse("setup.py",              parseSetupPy);

  return pkgs;
}

async function detectFromPythonImports(cwd: string): Promise<string[]> {
  const pyFiles = await fg("**/*.py", {
    cwd, ignore: IGNORE_DIRS.map((d) => `**/${d}/**`), absolute: true,
  });

  const packages = new Set<string>();
  const importRe = /^(?:import|from)\s+([a-zA-Z][a-zA-Z0-9_]*)/gm;

  const PYTHON_STDLIB = new Set([
    "os", "sys", "re", "json", "math", "time", "datetime", "pathlib", "typing",
    "collections", "itertools", "functools", "io", "abc", "enum", "dataclasses",
    "logging", "unittest", "asyncio", "threading", "multiprocessing", "subprocess",
    "socket", "http", "urllib", "email", "html", "xml", "csv", "sqlite3",
    "hashlib", "hmac", "secrets", "base64", "struct", "copy", "gc", "traceback",
    "contextlib", "warnings", "inspect", "ast", "dis", "pickle", "shelve",
    "tempfile", "shutil", "glob", "fnmatch", "stat", "platform", "signal",
  ]);

  for (const file of pyFiles.slice(0, 200)) {
    try {
      const content = fs.readFileSync(file, "utf-8");
      let m: RegExpExecArray | null;
      while ((m = importRe.exec(content)) !== null) {
        const pkg = m[1]!;
        if (!PYTHON_STDLIB.has(pkg) && !pkg.startsWith("_")) {
          // Normalize common import→package name mismatches
          packages.add(IMPORT_TO_PACKAGE[pkg] ?? pkg.replace(/_/g, "-").toLowerCase());
        }
      }
    } catch { /* skip */ }
  }

  return Array.from(packages);
}

// Common import name → PyPI package name mismatches
const IMPORT_TO_PACKAGE: Record<string, string> = {
  cv2: "opencv-python",
  PIL: "pillow",
  sklearn: "scikit-learn",
  yaml: "pyyaml",
  bs4: "beautifulsoup4",
  dotenv: "python-dotenv",
  jwt: "pyjwt",
  psycopg2: "psycopg2-binary",
  pymysql: "pymysql",
  Crypto: "pycryptodome",
  usaddress: "usaddress",
};

// ─── Go detection ─────────────────────────────────────────────────────────────

async function detectFromGoMod2(cwd: string): Promise<Array<{ name: string; version?: string }>> {
  const modPath = path.join(cwd, "go.mod");
  if (!fs.existsSync(modPath)) return [];
  try {
    return parseGoMod(fs.readFileSync(modPath, "utf-8")).map((m) => ({ name: m.name, version: m.version }));
  } catch { return []; }
}

// ─── Rust detection ───────────────────────────────────────────────────────────

async function detectFromCargoToml2(cwd: string): Promise<Array<{ name: string; version?: string }>> {
  const lockPath = path.join(cwd, "Cargo.lock");
  const tomlPath = path.join(cwd, "Cargo.toml");
  if (!fs.existsSync(tomlPath) && !fs.existsSync(lockPath)) return [];
  try {
    if (fs.existsSync(lockPath)) {
      return parseCargoLock(fs.readFileSync(lockPath, "utf-8"));
    }
    return parseCargoToml(fs.readFileSync(tomlPath, "utf-8"));
  } catch { return []; }
}

// ─── Node builtins ────────────────────────────────────────────────────────────

const NODE_BUILTINS = new Set([
  "fs", "path", "os", "http", "https", "url", "crypto", "stream", "util",
  "events", "net", "dns", "child_process", "cluster", "worker_threads",
  "buffer", "string_decoder", "querystring", "readline", "zlib", "assert",
  "async_hooks", "timers", "module", "process", "v8", "vm", "tls", "dgram",
]);
function isBuiltin(pkg: string): boolean {
  return NODE_BUILTINS.has(pkg) || pkg.startsWith("node:");
}
