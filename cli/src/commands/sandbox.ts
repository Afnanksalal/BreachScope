import ora from "ora";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import fg from "fast-glob";
import { logger } from "../core/logger.js";
import { agentLoop } from "../core/ai.js";
import { fetchRemoteConfig } from "../core/remote-config.js";
import type { Finding } from "../core/types.js";
import type { ChatCompletionTool } from "openai/resources/chat/completions";
import {
  isDockerRunning,
  buildImage,
  startContainer,
  stopContainer,
  removeImage,
  getContainerIP,
  getContainerLogs,
  execInContainer,
  inspectContainer,
  detectProjectType,
  detectAppPort,
  generateDockerfile,
} from "../core/docker.js";
import { scanBuildArtifacts } from "../scanners/sandbox/index.js";
import { runSandboxAgent } from "../agents/sandbox-agent.js";
import type { SandboxAgentResult } from "../agents/sandbox-agent.js";
import { renderConsoleReport } from "../reporters/console.js";
import { renderJsonReport } from "../reporters/json.js";
import { pushScanToDashboard } from "../core/push-scan.js";

export interface SandboxOptions {
  port?: number;
  image?: string;
  timeout?: number;
  deep?: boolean;
  file?: string;
  url?: string;
  verbose?: boolean;
  output?: string;
  noCleanup?: boolean;
}

const BANNER = `
  ╔═══════════════════════════════════════╗
  ║   BreachScope Sandbox Attack Arena    ║
  ║   Isolated Docker Pentesting Engine   ║
  ╚═══════════════════════════════════════╝
`;

// ── Health check ──────────────────────────────────────────────────────────────

async function waitForApp(containerIP: string, port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  const url = `http://${containerIP}:${port}`;

  while (Date.now() < deadline) {
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (resp.status < 600) return true;
    } catch { /* not ready yet */ }
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}

// ── Monorepo detection ────────────────────────────────────────────────────────

interface ServiceInfo {
  name: string;
  relativePath: string;
  type: string;
  manifests: string[];
  label: string; // for promptSelect
}

const MANIFEST_FILES = [
  "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
  "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
  "build.gradle.kts", "composer.json", "mix.exs", "pubspec.yaml",
];

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "__pycache__", ".turbo",
  "vendor", "target", ".cache", "coverage", "out", "tmp", "docs", "scripts",
  ".github", ".vscode", "test", "tests", "spec", "e2e", "__tests__",
]);

function detectTypeLabel(dir: string): string {
  if (fs.existsSync(path.join(dir, "package.json")))     return "node";
  if (fs.existsSync(path.join(dir, "go.mod")))           return "go";
  if (fs.existsSync(path.join(dir, "Cargo.toml")))       return "rust";
  if (fs.existsSync(path.join(dir, "requirements.txt")) ||
      fs.existsSync(path.join(dir, "pyproject.toml")))   return "python";
  if (fs.existsSync(path.join(dir, "Gemfile")))          return "ruby";
  if (fs.existsSync(path.join(dir, "pom.xml")) ||
      fs.existsSync(path.join(dir, "build.gradle")))     return "java";
  if (fs.existsSync(path.join(dir, "composer.json")))    return "php";
  if (fs.existsSync(path.join(dir, "mix.exs")))          return "elixir";
  if (fs.existsSync(path.join(dir, "pubspec.yaml")))     return "dart";
  try {
    if (fs.readdirSync(dir).some(f => f.endsWith(".csproj"))) return "dotnet";
  } catch { /* ignore */ }
  return "unknown";
}

function scanForServices(rootDir: string): ServiceInfo[] {
  const services: ServiceInfo[] = [];
  let entries: fs.Dirent[] = [];
  try {
    entries = fs.readdirSync(rootDir, { withFileTypes: true });
  } catch { return []; }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;

    const subdir = path.join(rootDir, entry.name);
    const found = MANIFEST_FILES.filter(m => fs.existsSync(path.join(subdir, m)));

    // Also check for .csproj
    try {
      if (fs.readdirSync(subdir).some(f => f.endsWith(".csproj"))) found.push("*.csproj");
    } catch { /* ignore */ }

    if (found.length === 0) continue;

    const type = detectTypeLabel(subdir);
    const label = `${entry.name.padEnd(18)} · ${type.padEnd(8)} · ${found.join(", ")}`;
    services.push({ name: entry.name, relativePath: entry.name, type, manifests: found, label });
  }

  return services;
}

function isMonorepo(rootDir: string, services: ServiceInfo[]): boolean {
  if (services.length < 2) return false;
  // Explicit monorepo signals
  if (
    fs.existsSync(path.join(rootDir, "turbo.json"))  ||
    fs.existsSync(path.join(rootDir, "nx.json"))     ||
    fs.existsSync(path.join(rootDir, "lerna.json"))  ||
    fs.existsSync(path.join(rootDir, "pnpm-workspace.yaml"))
  ) return true;
  // package.json workspaces
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf-8")) as { workspaces?: unknown };
    if (pkg.workspaces) return true;
  } catch { /* ignore */ }
  // Multiple services found → treat as monorepo
  return services.length >= 2;
}

// ── Phase 0: AI codebase understanding + Dockerfile generation ────────────────

interface CodebaseAnalysis {
  dockerfile: string;
  port: number;
  summary: string;
  serviceSubpath: string; // which service the AI chose to focus on (e.g. "backend", "" for root)
}

const UNDERSTANDING_SYSTEM = `You are an elite security researcher and Docker expert. Your job:

1. THOROUGHLY READ THE CODEBASE — use read_file liberally. Read:
   - ALL manifest files: package.json, requirements.txt, pyproject.toml, Pipfile, go.mod, Cargo.toml,
     Gemfile, pom.xml, build.gradle, composer.json, *.csproj, mix.exs, pubspec.yaml — whichever exist
   - ALL .env files: .env, .env.local, .env.production, .env.development, .env.example
   - Language-specific config: wrangler.toml, config.yaml, config.toml, application.yml,
     application.properties, config/database.yml, config/secrets.yml, appsettings.json,
     config/environments/*.rb, priv/repo/migrations, prisma/schema.prisma
   - Main entry points: index.ts/js, main.py, main.go, cmd/main.go, src/main.rs, app.rb,
     lib/application.ex, bin/main.dart, Program.cs, Application.java, index.php
   - Existing Dockerfile or docker-compose.yml — this tells you EXACTLY how the app runs
   - Auth middleware, route handlers, database connection files

2. CALL write_dockerfile WITH A COMPLETE, THOROUGH DOCKERFILE

═══════════════════════════════════════════════════════
DOCKERFILE RULES — APPLIES TO ALL LANGUAGES
═══════════════════════════════════════════════════════

RULE 1 — FULL BASE IMAGES (not slim, not alpine, not distroless):
  Node.js / Bun    → node:20
  Python           → python:3.11
  Go               → golang:1.22
  Rust             → rust:1.77
  Ruby             → ruby:3.3
  Java (Maven)     → maven:3.9-eclipse-temurin-21
  Java (Gradle)    → gradle:8-jdk21
  PHP              → php:8.3-apache
  .NET             → mcr.microsoft.com/dotnet/sdk:8.0
  Elixir           → elixir:1.16
  Dart             → dart:stable

RULE 2 — ALWAYS INSTALL SYSTEM DEPENDENCIES first:
  RUN apt-get update && apt-get install -y \\
      curl wget git build-essential make \\
      postgresql-client mysql-client redis-tools \\
      netcat-openbsd libssl-dev libffi-dev ca-certificates \\
      && rm -rf /var/lib/apt/lists/*

  Additional per language:
  - Node.js with native modules: also python3, g++
  - Python with C extensions: also python3-dev, gcc, libpq-dev
  - Ruby: also libpq-dev, libmysqlclient-dev, zlib1g-dev
  - PHP: also libzip-dev, libpng-dev, libonig-dev, unzip (then docker-php-ext-install)
  - Elixir: also nodejs, npm (for Phoenix assets)
  - .NET: apt-get already included in the SDK image

RULE 3 — INSTALL ALL DEPENDENCIES (dev AND prod, no flags that skip dev):
  Node.js:    COPY package*.json yarn.lock* pnpm-lock.yaml* bun.lockb* ./
              RUN npm install                            ← no --production, no --omit=dev
              (if yarn: RUN yarn install --frozen-lockfile)
              (if pnpm: RUN npm i -g pnpm && pnpm install)
              (if bun:  RUN npm i -g bun && bun install)

  Python:     COPY requirements*.txt pyproject.toml* Pipfile* ./
              RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true
              RUN pip install --no-cache-dir -r requirements-dev.txt 2>/dev/null || true
              RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || true
              (if Pipfile: RUN pip install pipenv && pipenv install --dev --system)

  Go:         COPY go.mod go.sum* ./
              RUN go mod download

  Rust:       COPY Cargo.toml Cargo.lock* ./
              RUN mkdir -p src && echo 'fn main(){}' > src/main.rs
              RUN cargo fetch
              (do NOT run cargo build here — copy source first, then build)

  Ruby:       COPY Gemfile Gemfile.lock* ./
              RUN bundle install         ← no --without, no --deployment flag restrictions

  Java Maven: COPY pom.xml ./
              RUN mvn dependency:go-offline -q 2>/dev/null || true

  Java Gradle:COPY build.gradle* settings.gradle* gradlew* gradle/ ./
              RUN chmod +x gradlew 2>/dev/null || true
              RUN ./gradlew dependencies --no-daemon -q 2>/dev/null || true

  PHP:        COPY composer.json composer.lock* ./
              RUN composer install --no-scripts --prefer-dist

  .NET:       COPY *.csproj ./
              RUN dotnet restore

  Elixir:     RUN mix local.hex --force && mix local.rebar --force
              COPY mix.exs mix.lock* ./
              ENV MIX_ENV=dev
              RUN mix deps.get

  Dart:       COPY pubspec.yaml pubspec.lock* ./
              RUN dart pub get

RULE 4 — COPY SOURCE AFTER DEPS (preserves layer cache):
  COPY . .

RULE 5 — BUILD STEPS if the language/framework requires compilation:
  TypeScript / Next.js / Vite:  RUN npm run build 2>/dev/null || true
  Go:                           RUN go build -o /app/server . 2>/dev/null || true
  Rust:                         RUN cargo build 2>/dev/null || true  ← NOT --release
  Java Maven:                   RUN mvn package -DskipTests -q 2>/dev/null || true
  Java Gradle:                  RUN ./gradlew build -x test --no-daemon -q 2>/dev/null || true
  .NET:                         RUN dotnet build -c Debug 2>/dev/null || true
  Elixir:                       RUN mix compile 2>/dev/null || true

RULE 6 — ENVIRONMENT: prefer development/debug mode for maximum attack surface:
  Node.js:   ENV NODE_ENV=development PORT=<port>
  Python:    ENV FLASK_DEBUG=1  or  ENV DJANGO_DEBUG=True  ENV PYTHONUNBUFFERED=1
  Ruby:      ENV RAILS_ENV=development
  Go:        ENV GIN_MODE=debug  (or whatever the framework uses)
  Java:      ENV SPRING_PROFILES_ACTIVE=dev
  PHP:       ENV APP_ENV=local APP_DEBUG=true
  .NET:      ENV ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS=http://+:<port>
  Elixir:    ENV MIX_ENV=dev PHX_SERVER=true PORT=<port>

RULE 7 — EXPOSE the actual app port

RULE 8 — CMD: use dev/debug start command for maximum verbose output and attack surface:
  Node.js:       CMD ["npm", "run", "dev"]   or   CMD ["npx", "ts-node", "src/index.ts"]
                 or CMD ["node", "dist/index.js"]   based on what you read in package.json
  Python Flask:  CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000", "--debug"]
  Python Django: CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
  FastAPI:       CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
  Go:            CMD ["/app/server"]  or  CMD ["go", "run", "."]
  Rust:          CMD ["./target/debug/<binary>"]
  Ruby Rails:    CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]
  Sinatra:       CMD ["bundle", "exec", "ruby", "app.rb", "-o", "0.0.0.0"]
  Java Spring:   CMD ["java", "-jar", "target/*.jar"]  or gradle equivalent
  PHP:           Apache starts automatically; or CMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]
  .NET:          CMD ["dotnet", "<AppName>.dll"]  or  CMD ["dotnet", "run"]
  Elixir:        CMD ["mix", "phx.server"]  or  CMD ["./bin/<app>", "start"]
  Dart:          CMD ["dart", "run", "bin/server.dart"]  or  CMD ["./server"]

  If startup needs multiple steps (DB migrate then start), use:
  CMD ["sh", "-c", "npm run db:migrate 2>/dev/null; npm run dev"]

RULE 9 — NO MULTI-STAGE BUILDS. Everything in one stage. Source, deps, secrets, all of it.

═══════════════════════════════════════════════════════
IMPORTANT: Read the existing Dockerfile or docker-compose.yml FIRST if present.
The dev team already solved the startup problem — don't reinvent it, improve on it.
═══════════════════════════════════════════════════════

Call write_dockerfile when done. summary field = full security intel from your analysis.`;

async function runCodebaseUnderstandingAgent(
  buildContext: string,  // Docker build root (monorepo root or project root)
  servicePath: string,   // Service to analyze and run (may equal buildContext)
): Promise<CodebaseAnalysis> {
  const isMonorepoService = buildContext !== servicePath;
  const ignorePatterns = ["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".turbo", "vendor", "target"];

  // For monorepos: list service files fully + root manifest files only (truncated)
  let serviceFiles: string[] = [];
  let rootSummaryFiles: string[] = [];

  try {
    serviceFiles = await fg("**/*", {
      cwd: servicePath,
      ignore: ignorePatterns.map((d) => `**/${d}/**`),
      absolute: false,
      onlyFiles: true,
      followSymbolicLinks: false,
      suppressErrors: true,
    });
  } catch { /* ignore */ }

  if (isMonorepoService) {
    // Also show root-level files so AI knows about shared workspace packages
    try {
      rootSummaryFiles = await fg("*", {
        cwd: buildContext,
        absolute: false,
        onlyFiles: true,
        suppressErrors: true,
      });
    } catch { /* ignore */ }
  }

  const serviceLabel = isMonorepoService
    ? `Service: ${path.relative(buildContext, servicePath)} (inside monorepo)`
    : "Single project";

  const fileTree = [
    isMonorepoService ? `── Root files (${path.basename(buildContext)}):\n${rootSummaryFiles.join("\n")}` : "",
    `\n── Service files (${path.basename(servicePath)}):\n${serviceFiles.slice(0, 400).join("\n")}`,
  ].filter(Boolean).join("\n");

  // Collected result via tool call — more reliable than parsing AI text output
  let result: CodebaseAnalysis = { dockerfile: "", port: 0, summary: "", serviceSubpath: "" };

  const TOOLS: ChatCompletionTool[] = [
    {
      type: "function",
      function: {
        name: "read_file",
        description: "Read any file in the project. Read package.json, ALL .env files, entry points, config files, route handlers, auth middleware. Read as many files as needed.",
        parameters: {
          type: "object",
          properties: {
            path: { type: "string", description: "Relative file path from project root" },
          },
          required: ["path"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "write_dockerfile",
        description: "Call this when you have read enough files to write a complete, proper Dockerfile. This finalizes the analysis.",
        parameters: {
          type: "object",
          properties: {
            dockerfile: {
              type: "string",
              description: "The complete Dockerfile content — full image, all system deps, all package deps (dev+prod), build steps, correct CMD. Must be production-grade, not a skeleton.",
            },
            port: {
              type: "number",
              description: "The port the app listens on",
            },
            service_subpath: {
              type: "string",
              description: "For monorepos: the relative path of the service you chose to attack (e.g. 'backend', 'api', 'apps/server'). Empty string for single projects or if attacking from root.",
            },
            summary: {
              type: "string",
              description: "Security-focused summary: tech stack, framework versions, auth mechanism, database/ORM, real env var names and values found, API endpoints, hardcoded secrets, every attack surface identified",
            },
          },
          required: ["dockerfile", "port", "summary"],
        },
      },
    },
  ];

  const monorepoContext = isMonorepoService ? `
MONOREPO: Docker build context is the ROOT (${buildContext}).
The service we are attacking is at: ${path.relative(buildContext, servicePath)}
In the Dockerfile: COPY . . copies the full monorepo. WORKDIR should be /app/${path.relative(buildContext, servicePath).replace(/\\/g, "/")}.
Install root workspace deps first if a root package.json exists, then cd into the service.
` : "";

  const userMessage = `Analyze this project thoroughly then call write_dockerfile.

Build context (Docker root): ${buildContext}
${serviceLabel}
${monorepoContext}
Project files:
${fileTree}

READING ORDER — read files in this order using their path relative to the SERVICE directory:
1. package.json / requirements.txt / go.mod / Cargo.toml / composer.json / mix.exs / pubspec.yaml
2. ALL .env files (.env, .env.local, .env.production, .env.example) — these have real secrets
3. Any existing Dockerfile or docker-compose.yml — see how the dev team runs it
4. wrangler.toml, config.yaml, application.yml, appsettings.json — any config file
5. Main entry point
6. Auth middleware and route handlers

For monorepo: also read root package.json (path: "../package.json" or just "package.json" at root)
to understand workspace structure and shared dependencies.

Call write_dockerfile with a COMPLETE Dockerfile when done — not a skeleton.
${isMonorepoService ? `Remember: Dockerfile must COPY . . from root, then WORKDIR into the service subfolder.` : ""}`;


  try {
    await agentLoop(
      {
        system: UNDERSTANDING_SYSTEM,
        messages: [{ role: "user", content: userMessage }],
        tools: TOOLS,
        temperature: 0.1,
        maxTokens: 16_000,
        maxIterations: 40,
      },
      async (toolName, args) => {
        if (toolName === "read_file") {
          const reqPath = String(args["path"] ?? "").replace(/\\/g, "/");

          // Try service path first, then build context root
          const candidates = [
            path.join(servicePath, reqPath),
            path.join(buildContext, reqPath),
          ];
          for (const abs of candidates) {
            try {
              const content = fs.readFileSync(abs, "utf-8");
              return `=== ${reqPath} ===\n${content.slice(0, 4000)}`;
            } catch { /* try next */ }
          }

          // Suffix match within service files
          const allFiles = [...serviceFiles, ...rootSummaryFiles];
          const match = allFiles.find((f) =>
            f.replace(/\\/g, "/").endsWith(reqPath) || reqPath.endsWith(f.replace(/\\/g, "/"))
          );
          if (match) {
            const base = serviceFiles.includes(match) ? servicePath : buildContext;
            try {
              return `=== ${match} ===\n${fs.readFileSync(path.join(base, match), "utf-8").slice(0, 4000)}`;
            } catch { /* ignore */ }
          }

          return `File not found: ${reqPath}`;
        }

        if (toolName === "write_dockerfile") {
          const dockerfile = String(args["dockerfile"] ?? "");
          const port = Number(args["port"] ?? 0);
          const summary = String(args["summary"] ?? "");
          const serviceSubpath = String(args["service_subpath"] ?? "").replace(/\\/g, "/").replace(/^\/|\/$/g, "");
          if (dockerfile && port) {
            result = { dockerfile, port, summary, serviceSubpath };
            logger.debug(`[sandbox] Dockerfile generated (${dockerfile.split("\n").length} lines, port ${port}, service: ${serviceSubpath || "root"})`);
          }
          return JSON.stringify({ success: true, lines: dockerfile.split("\n").length, service: serviceSubpath || "root" });
        }

        return "Unknown tool";
      }
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // If write_dockerfile was already called before the crash, result is populated — use it
    if (result.dockerfile) {
      logger.debug(`[sandbox] AI analysis hit an error after writing Dockerfile — using captured result. Error: ${msg}`);
    } else {
      logger.warn(`[sandbox] AI codebase analysis failed: ${msg.slice(0, 200)}`);
    }
  }

  return result;
}

// ── .dockerignore management — ensure .env and secrets are included in context ─

function neutralizeDockerignore(cwd: string): (() => void) {
  const ignorePath = path.join(cwd, ".dockerignore");
  const backupPath = path.join(cwd, ".dockerignore.breachscope-bak");
  let hadOriginal = false;

  if (fs.existsSync(ignorePath)) {
    // Back up the original
    fs.copyFileSync(ignorePath, backupPath);
    hadOriginal = true;
  }

  // Write a permissive .dockerignore — only exclude things that break builds
  // Explicitly allow .env* so nothing is hidden from the sandbox
  fs.writeFileSync(ignorePath, [
    ".git",
    ".gitignore",
    "*.log",
    ".breachscope-sandbox.Dockerfile",
    ".dockerignore.breachscope-bak",
  ].join("\n") + "\n", "utf-8");

  return function restore() {
    try {
      if (hadOriginal) {
        fs.copyFileSync(backupPath, ignorePath);
        fs.unlinkSync(backupPath);
      } else {
        fs.unlinkSync(ignorePath);
      }
    } catch { /* ignore cleanup errors */ }
  };
}

// ── Main command ──────────────────────────────────────────────────────────────

export async function runSandbox(opts: SandboxOptions): Promise<void> {
  const cwd = process.cwd();
  const startedAt = new Date();
  const timestamp = Date.now();
  const imageName = `breachscope-sandbox-${timestamp}`;
  const containerName = `breachscope-sandbox-${timestamp}`;
  const findings: Finding[] = [];

  let containerId: string | null = null;
  let sandboxAgentResult: SandboxAgentResult | null = null;
  let restoreDockerignore: (() => void) | null = null;

  console.log(chalk.dim(BANNER));

  if (opts.verbose) logger.setVerbose(true);

  // ── Docker availability check ─────────────────────────────────────────────
  const dockerSpinner = ora("Checking Docker...").start();
  const dockerRunning = await isDockerRunning();
  if (!dockerRunning) {
    dockerSpinner.fail("Docker is not running or not installed.");
    console.log(chalk.gray("\n  Install Docker Desktop from https://www.docker.com/products/docker-desktop/"));
    console.log(chalk.gray("  Then start Docker and re-run: breachscope sandbox"));
    process.exit(1);
  }
  dockerSpinner.succeed("Docker is running");

  // ── Pull API keys from dashboard (same as scan command) ──────────────────
  const remote = await fetchRemoteConfig();
  if (remote) {
    if (!process.env["OPENAI_API_KEY"]    && remote.openaiKey)    process.env["OPENAI_API_KEY"]    = remote.openaiKey;
    if (!process.env["FIRECRAWL_API_KEY"] && remote.firecrawlKey) process.env["FIRECRAWL_API_KEY"] = remote.firecrawlKey;
  }

  // ── Project + monorepo detection (informational only — AI decides the rest) ─
  const services = scanForServices(cwd);
  const monorepo = isMonorepo(cwd, services);

  if (monorepo) {
    console.log(chalk.gray(`  Monorepo detected — ${services.length} services found:`));
    for (const s of services) {
      console.log(chalk.gray(`    · ${s.name.padEnd(20)} ${s.type.padEnd(8)} ${s.manifests.join(", ")}`));
    }
    console.log(chalk.gray("  AI will decide which service to attack.\n"));
  }

  const projectType = detectProjectType(cwd);
  const defaultPort = opts.port ?? detectAppPort(cwd, projectType);
  console.log(chalk.gray(`  Project type: ${chalk.white(projectType)} · Default port: ${chalk.white(String(defaultPort))}`));

  // ── Phase 0: AI codebase understanding ───────────────────────────────────
  let projectContext = "";
  let aiDockerfile = "";
  let detectedPort = defaultPort;
  let aiChosenSubpath = "";

  if (process.env["OPENAI_API_KEY"]) {
    logger.section("Phase 0 — AI Codebase Understanding");
    console.log(chalk.gray("  AI reading codebase — source, .env, configs, secrets...\n"));

    const analysisSpinner = ora("AI analyzing codebase...").start();
    try {
      const analysis = await runCodebaseUnderstandingAgent(cwd, cwd);
      if (analysis.dockerfile) {
        aiDockerfile = analysis.dockerfile;
        detectedPort = analysis.port || defaultPort;
        projectContext = analysis.summary;
        aiChosenSubpath = analysis.serviceSubpath;
        const serviceLabel = aiChosenSubpath ? ` · service: ${chalk.white(aiChosenSubpath)}` : "";
        analysisSpinner.succeed(
          `Codebase understood · Port ${detectedPort} · ${analysis.dockerfile.split("\n").length} line Dockerfile${serviceLabel}`
        );
        if (opts.verbose && projectContext) {
          console.log(chalk.gray(`\n  Summary: ${projectContext.slice(0, 300)}...\n`));
        }
      } else {
        analysisSpinner.warn("AI analysis returned no Dockerfile — using template Dockerfile");
      }
    } catch (e) {
      const errMsg = e instanceof Error ? e.message.slice(0, 150) : String(e).slice(0, 150);
      analysisSpinner.warn(`AI analysis error: ${errMsg}`);
    }
  } else {
    console.log(chalk.gray("  Skipping AI codebase analysis — OPENAI_API_KEY not set"));
  }

  const appPort = detectedPort;

  // ── Dockerfile preparation ────────────────────────────────────────────────
  const generatedDockerfilePath = path.join(cwd, ".breachscope-sandbox.Dockerfile");
  let dockerfilePath: string;
  let generatedDockerfileCreated = false;

  if (fs.existsSync(path.join(cwd, "Dockerfile"))) {
    // Project has its own Dockerfile — use it but we'll still copy .env via .dockerignore handling
    dockerfilePath = path.join(cwd, "Dockerfile");
    logger.info("Using project Dockerfile");
  } else if (aiDockerfile) {
    // Use AI-generated Dockerfile
    fs.writeFileSync(generatedDockerfilePath, aiDockerfile, "utf-8");
    generatedDockerfileCreated = true;
    dockerfilePath = generatedDockerfilePath;
    logger.info("Using AI-generated Dockerfile");
    logger.debug(`AI Dockerfile:\n${aiDockerfile}`);
  } else {
    // Template fallback
    const dockerfileContent = generateDockerfile(projectType, cwd);
    fs.writeFileSync(generatedDockerfilePath, dockerfileContent, "utf-8");
    generatedDockerfileCreated = true;
    dockerfilePath = generatedDockerfilePath;
    logger.info(`Using template Dockerfile for ${projectType}`);
  }

  // ── Neutralize .dockerignore so .env and secrets are copied into the image ─
  restoreDockerignore = neutralizeDockerignore(cwd);

  // Dockerfile audit intentionally skipped — sandbox runs as root with full caps by design.

  // ── Build image ───────────────────────────────────────────────────────────
  const buildSpinner = ora(`Building Docker image — copying ALL files including .env and secrets...`).start();
  try {
    await buildImage(cwd, imageName, dockerfilePath);
    buildSpinner.succeed(`Image built: ${imageName}`);
  } catch (e) {
    buildSpinner.fail(`Docker build failed: ${String(e).slice(0, 200)}`);
    await cleanup(null, imageName, generatedDockerfileCreated ? generatedDockerfilePath : null, restoreDockerignore);
    restoreDockerignore = null;
    process.exit(1);
  } finally {
    // Restore .dockerignore immediately after build — don't leave it modified
    if (restoreDockerignore) {
      restoreDockerignore();
      restoreDockerignore = null;
    }
  }

  // ── Start container ───────────────────────────────────────────────────────
  const startSpinner = ora("Starting sandbox container...").start();
  try {
    containerId = await startContainer({
      image: imageName,
      name: containerName,
      hostPort: appPort,
      containerPort: appPort,
      networkMode: "bridge",
      attackMode: true,
    });
    startSpinner.succeed(`Container started: ${containerId.slice(0, 12)}`);
  } catch (e) {
    startSpinner.fail(`Failed to start container: ${e}`);
    await cleanup(null, imageName, generatedDockerfileCreated ? generatedDockerfilePath : null, null);
    process.exit(1);
  }

  try {
    // ── Get container IP ────────────────────────────────────────────────────
    let containerIP: string;
    try {
      containerIP = await getContainerIP(containerId);
      logger.debug(`Container IP: ${containerIP}`);
    } catch {
      containerIP = "127.0.0.1";
    }

    // Container security config intentionally skipped — root + full caps is the attack arena design.

    // ── Wait for app to be ready ────────────────────────────────────────────
    const startupTimeout = Math.min(opts.timeout ?? 90, 180) * 1000;
    const healthSpinner = ora(`Waiting for app on port ${appPort} (up to ${startupTimeout / 1000}s)...`).start();
    const isReady = await waitForApp(containerIP, appPort, startupTimeout);

    const exec = (cmd: string[], timeoutMs?: number) => execInContainer(containerId!, cmd, timeoutMs);

    if (!isReady) {
      healthSpinner.warn(`App did not respond on port ${appPort} within timeout`);
      console.log(chalk.gray("  Continuing with static analysis only — AI will explore the container directly."));

      logger.section("Build Artifact Scan (static only)");
      const artifactFindings = await scanBuildArtifacts(exec);
      findings.push(...artifactFindings);
    } else {
      healthSpinner.succeed(`App is ready at http://${containerIP}:${appPort}`);

      // ── Build artifact scan ─────────────────────────────────────────────
      logger.section("Build Artifact Scan");
      const artifactSpinner = ora("Scanning container for secrets, SUID binaries, world-writable paths...").start();
      try {
        const artifactFindings = await scanBuildArtifacts(exec);
        findings.push(...artifactFindings);
        artifactSpinner.succeed(`Artifact scan — ${artifactFindings.length} issue(s)`);
      } catch (e) {
        artifactSpinner.fail(`Artifact scan failed: ${e}`);
      }
    }

    // ── AI sandbox attack agent ─────────────────────────────────────────────
    if (process.env["OPENAI_API_KEY"]) {
      logger.section("Phase 1 — AI Attack Agent");
      console.log(chalk.gray("  Root access inside container — AI has full codebase knowledge and attacks with precision."));
      console.log(chalk.gray("  Covers: env secrets · internal ports · injection · auth bypass · SSRF · JWT · SSTI · RCE...\n"));

      const agentSpinner = ora("Attack agent running — may take 5-10 minutes...").start();
      try {
        const serviceSubpath = aiChosenSubpath || "";

        const agentResult = await runSandboxAgent(
          containerId,
          containerIP,
          appPort,
          projectType,
          projectContext,
          serviceSubpath,
          exec,
          (tail) => getContainerLogs(containerId!, tail),
        );

        findings.push(...agentResult.findings);
        agentSpinner.succeed(
          `Attack complete — ${agentResult.findings.length} finding(s) · ${agentResult.tokensUsed.toLocaleString()} tokens · ${agentResult.attackLog.length} actions`
        );

        if (agentResult.attackChains.length > 0) {
          console.log(chalk.gray(`\n  Attack chains:`));
          for (const chain of agentResult.attackChains) {
            console.log(chalk.gray(`    → ${chain.slice(0, 120)}`));
          }
        }

        if (opts.verbose && agentResult.attackLog.length > 0) {
          console.log(chalk.gray(`\n  Log: ${agentResult.attackLog.slice(0, 15).join("  │  ")}`));
        }

        sandboxAgentResult = agentResult;
      } catch (e) {
        agentSpinner.fail(`Attack agent failed: ${e}`);
      }
    } else {
      logger.warn("Skipping AI attack agent — OPENAI_API_KEY not set.");
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    const result = {
      target: path.basename(cwd),
      startedAt,
      completedAt: new Date(),
      findings,
      summary: {
        total:    findings.length,
        critical: findings.filter((f) => f.severity === "critical").length,
        high:     findings.filter((f) => f.severity === "high").length,
        medium:   findings.filter((f) => f.severity === "medium").length,
        low:      findings.filter((f) => f.severity === "low").length,
        info:     findings.filter((f) => f.severity === "info").length,
      },
      metadata: {
        sandboxMode: true,
        projectType,
        containerImage: imageName,
        appPort,
      },
    };

    logger.blank();
    if (opts.output === "json" || opts.file) {
      renderJsonReport(result, opts.file);
    } else {
      renderConsoleReport(result);
      if (opts.file) renderJsonReport(result, opts.file);
    }

    try {
      const sandboxProbeData = sandboxAgentResult ? {
        sandbox: {
          projectType,
          attackLog: sandboxAgentResult.attackLog,
          attackChains: sandboxAgentResult.attackChains,
          findingsCount: sandboxAgentResult.findings.length,
          tokensUsed: sandboxAgentResult.tokensUsed,
        },
      } : undefined;

      const scanId = await pushScanToDashboard(result, {
        mode: "deep",
        scanMode: "sandbox",
        url: opts.url,
        toolsScanned: 0,
        probeData: sandboxProbeData,
      });
      if (scanId) {
        console.log(chalk.gray(`\n  Results saved — view at ${chalk.white(`https://breachscoope.vercel.app/dashboard/scan/${scanId}`)}`));
      }
    } catch { /* dashboard push is optional */ }

  } finally {
    if (!opts.noCleanup) {
      await cleanup(containerId, imageName, generatedDockerfileCreated ? generatedDockerfilePath : null, restoreDockerignore);
    } else {
      logger.info(`Container preserved (--no-cleanup): ${containerId?.slice(0, 12)}`);
      logger.info(`Remove manually: docker stop ${containerName} && docker rm ${containerName}`);
    }
  }
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

async function cleanup(
  containerId: string | null,
  imageName: string,
  generatedDockerfilePath: string | null,
  restoreDockerignore: (() => void) | null,
): Promise<void> {
  const spinner = ora("Cleaning up sandbox...").start();
  try {
    if (restoreDockerignore) restoreDockerignore();
    if (containerId) await stopContainer(containerId);
    await removeImage(imageName);
    if (generatedDockerfilePath && fs.existsSync(generatedDockerfilePath)) {
      fs.unlinkSync(generatedDockerfilePath);
    }
    spinner.succeed("Sandbox cleaned up");
  } catch (e) {
    spinner.warn(`Partial cleanup: ${e}`);
  }
}
