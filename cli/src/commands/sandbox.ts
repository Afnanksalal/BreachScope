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
  getContainerExitCode,
  isContainerRunning,
} from "../core/docker.js";
import { webSearch, crawlUrl } from "../core/crawler.js";
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

// ── Docker build log error extraction ────────────────────────────────────────

function extractBuildError(fullLog: string): string {
  const lines = fullLog.split("\n");

  // Find the first line with an error keyword
  const errorIdx = lines.findIndex((l) =>
    /\b(error|Error|ERROR|failed|FAILED|fatal|cannot find|not found|no such file|permission denied|ModuleNotFoundError|ImportError|SyntaxError|ZodError|npm ERR!|pip.*error|go: |FAILURE)\b/.test(l)
  );

  if (errorIdx === -1) {
    // No clear error — return the last 40 lines
    return lines.slice(-40).join("\n");
  }

  // 8 lines before + 25 lines after the first error
  const start = Math.max(0, errorIdx - 8);
  const end = Math.min(lines.length, errorIdx + 25);
  const context = lines.slice(start, end).join("\n");

  // Also append last 15 lines in case the real failure is there
  const tail = lines.slice(-15).join("\n");
  const combined = context === tail ? context : `${context}\n...\n${tail}`;

  return combined.slice(0, 4000);
}

// ── Dockerfile self-healing fix agent ────────────────────────────────────────
// Takes the current Dockerfile + build or runtime error, searches the web for
// solutions, and returns a fixed Dockerfile. Runs as a lean focused agent.

async function runDockerfileFixAgent(
  currentDockerfile: string,
  errorLog: string,
  projectType: string,
  projectContext: string,
  fixReason: "build" | "runtime",
): Promise<string> {
  const FIX_TOOLS: ChatCompletionTool[] = [
    {
      type: "function",
      function: {
        name: "web_search",
        description: "Search Stack Overflow, GitHub Issues, and official docs to find the solution for this specific Docker build or runtime error. Be specific — include the exact error message and framework.",
        parameters: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
          required: ["query"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "crawl_url",
        description: "Fetch a Stack Overflow answer, GitHub issue, or official docs page to get the exact fix. Use for: stackoverflow.com questions, github.com issues, docs.nestjs.com, docs.python.org, hub.docker.com official image docs.",
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
        name: "write_dockerfile",
        description: "Output the fixed Dockerfile. Call this once you know the fix.",
        parameters: {
          type: "object",
          properties: {
            dockerfile: { type: "string", description: "The complete fixed Dockerfile content" },
            explanation: { type: "string", description: "One sentence: what was wrong and what you changed" },
          },
          required: ["dockerfile", "explanation"],
        },
      },
    },
  ];

  const LANGUAGE_EDGE_CASES: Record<string, string> = {
    node: `Common Node.js Docker fixes:
- bcrypt/sharp/canvas native modules → add: RUN apt-get install -y python3 make g++ build-essential
- TypeScript not compiled → add: RUN npm run build
- NestJS wrong CMD → use: CMD ["node", "dist/main.js"]
- npm ERESOLVE peer deps → use: RUN npm install --legacy-peer-deps
- Missing node_modules → ensure COPY package*.json ./ then RUN npm install BEFORE COPY . .
- NODE_ENV=production skips dotenv → use NODE_ENV=development for sandbox or add dotenv to deps`,

    python: `Common Python Docker fixes:
- psycopg2 fails → add: RUN apt-get install -y python3-dev libpq-dev gcc
- cryptography/OpenSSL → add: RUN apt-get install -y libssl-dev libffi-dev python3-dev gcc
- Pillow/Imaging → add: RUN apt-get install -y libjpeg-dev libpng-dev
- lxml → add: RUN apt-get install -y libxml2-dev libxslt-dev
- Missing pip wheel → add: RUN pip install --upgrade pip wheel setuptools`,

    java: `Common Java Docker fixes:
- ./mvnw or ./gradlew not executable → add: RUN chmod +x ./mvnw ./gradlew
- Gradle OOM → add ENV GRADLE_OPTS="-Xmx2g -Xms512m"
- Maven heap → add ENV MAVEN_OPTS="-Xmx2g"
- Can't find artifact → ensure pom.xml is COPY'd before dependency download`,

    ruby: `Common Ruby Docker fixes:
- Native gem compilation fails → add: RUN apt-get install -y build-essential libssl-dev
- Platform mismatch → add: RUN bundle lock --add-platform linux/amd64
- Bundler version mismatch → add: RUN gem install bundler -v X.X.X
- Missing postgresql client → add: RUN apt-get install -y libpq-dev`,

    go: `Common Go Docker fixes:
- CGO with Alpine fails → add: RUN apk add --no-cache gcc g++ musl-dev OR set CGO_ENABLED=0
- Module not found → ensure: COPY go.mod go.sum ./ then RUN go mod download before COPY . .
- Wrong GOOS → use: RUN GOOS=linux GOARCH=amd64 go build`,

    php: `Common PHP Docker fixes:
- Missing PHP extensions → use: RUN apt-get install -y libpng-dev libzip-dev && docker-php-ext-install gd zip pdo pdo_mysql
- Better: use https://github.com/mlocati/docker-php-extension-installer
- Composer not found → add: COPY --from=composer:latest /usr/bin/composer /usr/bin/composer`,
  };

  const edgeCases = LANGUAGE_EDGE_CASES[projectType] ?? "";

  const systemPrompt = `You are a Docker expert specializing in fixing broken Dockerfiles. Your ONLY job is to fix the specific error and output a corrected Dockerfile.

RULES:
1. Search the web FIRST for the specific error message to find the exact fix
2. Keep the Dockerfile structure and intent intact — only fix what's broken
3. Do NOT add multi-stage builds unless specifically needed
4. Do NOT make unrelated changes
5. Call write_dockerfile once you have the fix

${edgeCases}`;

  const errorType = fixReason === "build" ? "DOCKER BUILD FAILURE" : "CONTAINER STARTUP CRASH";
  const userMessage = `${errorType}

Project type: ${projectType}
${projectContext ? `App context: ${projectContext.slice(0, 500)}` : ""}

ERROR:
${errorLog}

CURRENT DOCKERFILE:
${currentDockerfile}

INSTRUCTIONS:
1. web_search the specific error message: search for exact error text + "${projectType} docker"
2. If a Stack Overflow question looks relevant, crawl_url it to get the accepted answer
3. Apply the fix and call write_dockerfile with the corrected Dockerfile
4. Be surgical — change only what's needed to fix this error`;

  let fixedDockerfile = "";

  try {
    await agentLoop(
      {
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
        tools: FIX_TOOLS,
        temperature: 0.05,
        maxTokens: 8192,
        maxIterations: 12,
      },
      async (toolName, args) => {
        if (toolName === "web_search") {
          const q = String(args["query"] ?? "");
          logger.debug(`[dockerfile-fix] search: ${q}`);
          return webSearch(q, 8);
        }
        if (toolName === "crawl_url") {
          const url = String(args["url"] ?? "");
          logger.debug(`[dockerfile-fix] crawl: ${url}`);
          return crawlUrl(url);
        }
        if (toolName === "write_dockerfile") {
          const df = String(args["dockerfile"] ?? "");
          const explanation = String(args["explanation"] ?? "");
          if (df.includes("FROM ")) {
            fixedDockerfile = df;
            logger.debug(`[dockerfile-fix] Fixed: ${explanation}`);
          }
          return JSON.stringify({ success: true, explanation });
        }
        return "Unknown tool";
      }
    );
  } catch (e) {
    logger.debug(`[dockerfile-fix] Fix agent error: ${e}`);
  }

  return fixedDockerfile;
}

// ── Self-healing build loop ───────────────────────────────────────────────────
// Tries to build, and if it fails the AI searches the web and fixes the Dockerfile.
// Max 4 attempts (1 original + 3 fixes). Tracks error signatures to avoid loops.

async function buildWithSelfHealing(
  cwd: string,
  imageName: string,
  dockerfilePath: string,
  projectType: string,
  projectContext: string,
  onAttempt: (attempt: number, status: "building" | "failed" | "fixing" | "success", msg?: string) => void,
): Promise<void> {
  const MAX_ATTEMPTS = 4;
  const seenErrors = new Set<string>();

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    onAttempt(attempt, "building");
    try {
      await buildImage(cwd, imageName, dockerfilePath);
      onAttempt(attempt, "success");
      return;
    } catch (e) {
      const err = e as Error & { buildLog?: string };
      const fullLog = err.buildLog ?? err.message ?? String(e);
      const extracted = extractBuildError(fullLog);

      // Error signature = first 200 chars of extracted error
      const sig = extracted.slice(0, 200).replace(/\s+/g, " ");

      onAttempt(attempt, "failed", extracted.slice(0, 120).replace(/\n/g, " "));

      if (attempt >= MAX_ATTEMPTS) {
        throw new Error(`Docker build failed after ${MAX_ATTEMPTS} attempts.\nLast error:\n${extracted}`);
      }

      if (seenErrors.has(sig)) {
        throw new Error(`Docker build stuck — same error repeated.\n${extracted}`);
      }
      seenErrors.add(sig);

      if (!process.env["OPENAI_API_KEY"]) {
        throw new Error(`Docker build failed:\n${extracted}`);
      }

      onAttempt(attempt, "fixing", "Searching Stack Overflow and docs for fix...");

      const currentDockerfile = fs.readFileSync(dockerfilePath, "utf-8");
      const fixedDockerfile = await runDockerfileFixAgent(
        currentDockerfile,
        extracted,
        projectType,
        projectContext,
        "build",
      );

      if (!fixedDockerfile || fixedDockerfile === currentDockerfile) {
        throw new Error(`AI could not fix build error:\n${extracted}`);
      }

      fs.writeFileSync(dockerfilePath, fixedDockerfile, "utf-8");
      logger.debug(`[sandbox] Dockerfile updated for attempt ${attempt + 1}`);
    }
  }
}

// ── Container startup crash detection & recovery ─────────────────────────────

async function checkContainerCrashed(containerId: string, waitMs = 12_000): Promise<boolean> {
  // Poll for up to waitMs to see if the container exits immediately
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    const running = await isContainerRunning(containerId);
    if (!running) return true; // crashed
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}

async function fixStartupCrash(
  containerId: string,
  cwd: string,
  imageName: string,
  dockerfilePath: string,
  projectType: string,
  projectContext: string,
  appPort: number,
  projectEnvVars: Record<string, string>,
  containerName: string,
  onStatus: (msg: string) => void,
): Promise<string | null> {
  const MAX_RUNTIME_FIXES = 3;
  const seenErrors = new Set<string>();

  for (let attempt = 1; attempt <= MAX_RUNTIME_FIXES; attempt++) {
    const crashLogs = await getContainerLogs(containerId, 100);
    const extracted = extractBuildError(crashLogs);
    const sig = extracted.slice(0, 200).replace(/\s+/g, " ");

    onStatus(`Startup crash detected (attempt ${attempt}/${MAX_RUNTIME_FIXES}) — ${extracted.slice(0, 80).replace(/\n/g, " ")}`);

    if (seenErrors.has(sig)) {
      onStatus("Same crash repeating — giving up on startup fix");
      return null;
    }
    seenErrors.add(sig);

    if (!process.env["OPENAI_API_KEY"]) return null;

    onStatus("AI fixing Dockerfile for runtime crash...");

    const currentDockerfile = fs.readFileSync(dockerfilePath, "utf-8");
    const fixedDockerfile = await runDockerfileFixAgent(
      currentDockerfile,
      extracted,
      projectType,
      projectContext,
      "runtime",
    );

    if (!fixedDockerfile || fixedDockerfile === currentDockerfile) {
      onStatus("AI could not determine runtime fix");
      return null;
    }

    fs.writeFileSync(dockerfilePath, fixedDockerfile, "utf-8");

    // Rebuild and restart
    onStatus("Rebuilding with fix...");
    try {
      // Stop old container first
      await stopContainer(containerId);
      await removeImage(imageName);

      const restoreIgnore = neutralizeDockerignore(cwd);
      try {
        await buildImage(cwd, imageName, dockerfilePath);
      } finally {
        restoreIgnore();
      }

      const newContainerId = await startContainer({
        image: imageName,
        name: containerName,
        hostPort: appPort,
        containerPort: appPort,
        networkMode: "bridge",
        attackMode: true,
        envVars: projectEnvVars,
      });

      // Give it 12s to see if it crashes again
      const crashed = await checkContainerCrashed(newContainerId, 12_000);
      if (!crashed) {
        onStatus(`Container stable after fix (attempt ${attempt})`);
        return newContainerId;
      }

      containerId = newContainerId;
    } catch (e) {
      onStatus(`Rebuild failed: ${String(e).slice(0, 100)}`);
      return null;
    }
  }

  return null;
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

RULE 10 — NATIVE MODULE / COMPILATION DEPS (read this carefully, these cause most build failures):
  Node.js with bcrypt, argon2, sharp, canvas, sqlite3, node-gyp based packages:
    RUN apt-get install -y python3 make g++ build-essential
  Node.js with sharp specifically:
    RUN apt-get install -y libvips-dev  (or use sharp pre-built: npm install --ignore-scripts && npm rebuild sharp)
  Python with psycopg2:
    RUN apt-get install -y python3-dev libpq-dev gcc
  Python with cryptography / pyOpenSSL:
    RUN apt-get install -y libssl-dev libffi-dev python3-dev gcc
  Python with Pillow/PIL:
    RUN apt-get install -y libjpeg-dev libpng-dev zlib1g-dev
  Python with lxml:
    RUN apt-get install -y libxml2-dev libxslt1-dev
  Go with CGO (uses cgo, sqlite, etc.):
    RUN apt-get install -y gcc g++ libc6-dev  (or use CGO_ENABLED=0 if possible)
  Ruby with native gems (nokogiri, pg, mysql2):
    RUN apt-get install -y build-essential libssl-dev libreadline-dev zlib1g-dev libpq-dev
  Java/Gradle — wrapper not executable:
    RUN chmod +x ./gradlew ./mvnw 2>/dev/null || true
  Java — heap issues:
    ENV GRADLE_OPTS="-Xmx2g -Xms512m"
    ENV MAVEN_OPTS="-Xmx2g"
  PHP — missing extensions:
    RUN apt-get install -y libpng-dev libzip-dev libjpeg-dev && docker-php-ext-install gd zip pdo pdo_mysql mbstring

RULE 11 — NESTJS / TYPESCRIPT BUILD:
  NestJS apps MUST have npm run build before starting:
    RUN npm run build
  NestJS CMD should be: CMD ["node", "dist/main.js"]
  If nest-cli.json not found, try: CMD ["sh", "-c", "node dist/main.js 2>/dev/null || npm run start:prod 2>/dev/null || npm start"]
  NODE_ENV should be "development" (not "production") in sandbox — "production" blocks dotenv in many frameworks.

RULE 12 — PEER DEPENDENCY CONFLICTS:
  npm ERESOLVE errors → use: RUN npm install --legacy-peer-deps
  If package-lock.json exists with conflicts → RUN npm ci --legacy-peer-deps OR RUN rm -f package-lock.json && npm install

RULE 13 — .ENV FILES:
  The .env file IS in the build context (we ensured it). But many frameworks (NestJS, Next.js) don't auto-load .env in production.
  Add to Dockerfile: ENV NODE_ENV=development
  Or add dotenv loading: CMD ["sh", "-c", "node -r dotenv/config dist/main.js 2>/dev/null || node dist/main.js"]

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

// ── Read all .env* files from the project and return them as a flat key=value map ─
// These are injected directly as container env vars so the app sees them regardless
// of whether it uses dotenv, Zod ConfigModule, or any other config loader.

function readProjectEnvVars(cwd: string): Record<string, string> {
  const envFiles = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.example",
  ];

  const result: Record<string, string> = {};

  for (const fileName of envFiles) {
    const filePath = path.join(cwd, fileName);
    if (!fs.existsSync(filePath)) continue;
    try {
      const lines = fs.readFileSync(filePath, "utf-8").split("\n");
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eqIdx = line.indexOf("=");
        if (eqIdx < 1) continue;
        const key = line.slice(0, eqIdx).trim();
        let value = line.slice(eqIdx + 1).trim();
        // Strip surrounding quotes
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (key && value && !result[key]) {
          result[key] = value;
        }
      }
    } catch { /* skip unreadable files */ }
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

  // Write a permissive .dockerignore — exclude build artifacts and deps (re-installed inside
  // container) but keep all source files, .env*, and config files so the sandbox has full access.
  fs.writeFileSync(ignorePath, [
    // Version control
    ".git",
    ".gitignore",
    // Logs
    "*.log",
    "logs/",
    // BreachScope temp files
    ".breachscope-sandbox.Dockerfile",
    ".dockerignore.breachscope-bak",
    // Dependencies — always reinstalled inside container; copying them would be GBs and cause platform mismatch
    "**/node_modules",
    "**/vendor",
    // Build output — rebuilt inside container
    "**/dist",
    "**/build",
    "**/.next",
    "**/.nuxt",
    "**/.turbo",
    "**/target",
    "**/__pycache__",
    "**/*.pyc",
    "**/.pytest_cache",
    // IDE / OS
    "**/.vscode",
    "**/.idea",
    "**/.DS_Store",
    // Test / coverage artifacts (not needed for sandbox)
    "**/coverage",
    "**/.nyc_output",
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

  // ── Build image (with self-healing retry loop) ────────────────────────────
  const buildSpinner = ora("Building Docker image — copying ALL files including .env and secrets...").start();
  let buildAttempts = 0;
  try {
    await buildWithSelfHealing(
      cwd,
      imageName,
      dockerfilePath,
      projectType,
      projectContext,
      (attempt, status, msg) => {
        buildAttempts = attempt;
        if (status === "building" && attempt > 1) {
          buildSpinner.text = `Build attempt ${attempt}/4 — applying AI fix...`;
        } else if (status === "failed") {
          buildSpinner.text = `Build failed (attempt ${attempt}) — ${msg ?? ""}`;
        } else if (status === "fixing") {
          buildSpinner.text = `AI searching for fix... ${msg ?? ""}`;
        } else if (status === "success" && attempt > 1) {
          buildSpinner.text = `Build succeeded on attempt ${attempt}`;
        }
      },
    );
    const fixNote = buildAttempts > 1 ? ` (fixed in ${buildAttempts} attempts)` : "";
    buildSpinner.succeed(`Image built: ${imageName}${fixNote}`);
  } catch (e) {
    buildSpinner.fail(`Docker build failed after ${buildAttempts} attempt(s): ${String(e).slice(0, 200)}`);
    await cleanup(null, imageName, generatedDockerfileCreated ? generatedDockerfilePath : null, restoreDockerignore);
    restoreDockerignore = null;
    process.exit(1);
  } finally {
    if (restoreDockerignore) {
      restoreDockerignore();
      restoreDockerignore = null;
    }
  }

  // ── Read .env files and inject as container env vars ─────────────────────
  const projectEnvVars = readProjectEnvVars(cwd);
  const envVarCount = Object.keys(projectEnvVars).length;
  if (envVarCount > 0) {
    logger.info(`Injecting ${envVarCount} env var(s) from .env files directly into container`);
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
      envVars: projectEnvVars,
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
    // On Windows, Docker bridge IPs are inside a Linux VM and unreachable from the host.
    // Port mapping always exposes the container on 127.0.0.1:<hostPort>.
    if (process.platform === "win32") {
      containerIP = "127.0.0.1";
    }

    // ── Startup crash detection + self-healing ────────────────────────────
    const crashSpinner = ora("Checking container startup (5s)...").start();
    const crashed = await checkContainerCrashed(containerId, 5_000);

    // Ensure we always have a mutable Dockerfile path for fixes.
    // If using the project's own Dockerfile, copy it so we never modify the original.
    if (dockerfilePath === path.join(cwd, "Dockerfile") && !generatedDockerfileCreated) {
      fs.copyFileSync(dockerfilePath, generatedDockerfilePath);
      generatedDockerfileCreated = true;
      dockerfilePath = generatedDockerfilePath;
    }

    if (crashed) {
      crashSpinner.warn("Container crashed on startup — AI reading logs and searching for fix...");
      const fixedContainerId = await fixStartupCrash(
        containerId,
        cwd,
        imageName,
        dockerfilePath,
        projectType,
        projectContext,
        appPort,
        projectEnvVars,
        containerName,
        (msg) => { crashSpinner.text = msg; },
      );
      if (fixedContainerId) {
        containerId = fixedContainerId;
        crashSpinner.succeed("Container restarted successfully after startup fix");
        try { containerIP = await getContainerIP(containerId); } catch { /* keep old IP */ }
      } else {
        crashSpinner.warn("Could not fix startup crash — AI will attack with static analysis");
      }
    } else {
      crashSpinner.succeed("Container running");
    }

    // ── Wait for app to be ready ────────────────────────────────────────────
    const startupTimeout = Math.min(opts.timeout ?? 90, 180) * 1000;
    const healthSpinner = ora(`Waiting for app on port ${appPort} (up to ${startupTimeout / 1000}s)...`).start();
    const isReady = await waitForApp(containerIP, appPort, startupTimeout);

    const exec = (cmd: string[], timeoutMs?: number) => execInContainer(containerId!, cmd, timeoutMs);

    if (!isReady) {
      // App is running but never responded — get logs and try to fix the startup command
      const stillRunning = await isContainerRunning(containerId);
      if (stillRunning && process.env["OPENAI_API_KEY"]) {
        healthSpinner.warn(`App not responding on port ${appPort} — AI reading logs, searching for fix...`);
        const fixedContainerId = await fixStartupCrash(
          containerId,
          cwd,
          imageName,
          dockerfilePath,
          projectType,
          projectContext,
          appPort,
          projectEnvVars,
          containerName,
          (msg) => { healthSpinner.text = msg; },
        );
        if (fixedContainerId) {
          containerId = fixedContainerId;
          // Give fixed container a chance to respond
          const recheckReady = await waitForApp(containerIP, appPort, 30_000);
          if (recheckReady) {
            healthSpinner.succeed(`App is ready at http://${containerIP}:${appPort} (after fix)`);
          } else {
            healthSpinner.warn("App fixed but still not responding — AI will start it directly in container");
          }
          try { containerIP = await getContainerIP(containerId); } catch { /* keep old IP */ }
        } else {
          healthSpinner.warn("Could not fix startup — AI will start app directly in container");
        }
      } else {
        healthSpinner.warn(`App did not respond on port ${appPort} within timeout — AI will start it and attack directly`);
      }
    } else {
      healthSpinner.succeed(`App is ready at http://${containerIP}:${appPort}`);
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
          console.log(chalk.gray(`\n  Attack log (${agentResult.attackLog.length} steps):`));
          for (const entry of agentResult.attackLog.slice(0, 20)) {
            const icon = entry.type === "finding" ? "🔴" : entry.type === "credential" ? "🔑" : entry.type === "chain" ? "⛓" : entry.type === "http" ? "→" : "$";
            console.log(chalk.gray(`    ${icon} [${entry.step}] ${entry.tool}: ${entry.input.slice(0, 80)}`));
          }
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
