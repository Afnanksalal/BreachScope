import { exec, spawn } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";

const execAsync = promisify(exec);

// ── Docker availability ────────────────────────────────────────────────────────

export async function isDockerRunning(): Promise<boolean> {
  try {
    await execAsync("docker info", { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

// ── Image build ────────────────────────────────────────────────────────────────

export async function buildImage(
  contextDir: string,
  imageName: string,
  dockerfilePath?: string
): Promise<string> {
  const args = ["build", "--progress=plain", "-t", imageName];
  if (dockerfilePath) args.push("-f", dockerfilePath);
  args.push(contextDir);

  return new Promise<string>((resolve, reject) => {
    const proc = spawn("docker", args, { stdio: "pipe", timeout: 600_000 });
    let fullLog = "";
    proc.stdout.on("data", (d: Buffer) => { fullLog += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { fullLog += d.toString(); });
    proc.on("close", (code) => {
      if (code === 0) resolve(fullLog);
      else reject(Object.assign(new Error(`docker build failed (exit ${code})`), { buildLog: fullLog }));
    });
    proc.on("error", reject);
  });
}

export async function getContainerExitCode(containerId: string): Promise<number | null> {
  try {
    const { stdout } = await execAsync(
      `docker inspect --format "{{.State.ExitCode}}" ${containerId}`,
      { timeout: 5_000 }
    );
    const code = parseInt(stdout.trim(), 10);
    return isNaN(code) ? null : code;
  } catch {
    return null;
  }
}

export async function isContainerRunning(containerId: string): Promise<boolean> {
  try {
    const { stdout } = await execAsync(
      `docker inspect --format "{{.State.Running}}" ${containerId}`,
      { timeout: 5_000 }
    );
    return stdout.trim() === "true";
  } catch {
    return false;
  }
}

// ── Port availability ──────────────────────────────────────────────────────────

export async function findAvailablePort(preferred: number, maxTries = 20): Promise<number> {
  const net = await import("net");
  for (let i = 0; i < maxTries; i++) {
    const port = preferred + i;
    const available = await new Promise<boolean>((resolve) => {
      const srv = net.createServer();
      srv.once("error", () => resolve(false));
      srv.once("listening", () => srv.close(() => resolve(true)));
      srv.listen(port, "0.0.0.0");
    });
    if (available) return port;
  }
  throw new Error(`No available port found starting from ${preferred}`);
}

// ── Container lifecycle ────────────────────────────────────────────────────────

export interface StartContainerOptions {
  image: string;
  name: string;
  hostPort?: number;
  containerPort?: number;
  envVars?: Record<string, string>;
  networkMode?: string;
  memory?: string;
  /** Grant full attack-arena capabilities to the AI (installs tools, network scan) */
  attackMode?: boolean;
}

export async function startContainer(opts: StartContainerOptions): Promise<{ containerId: string; hostPort: number }> {
  const containerPort = opts.containerPort ?? opts.hostPort ?? 3000;
  const maxPortTries = 20;

  const triedNames: string[] = [];

  for (let i = 0; i < maxPortTries; i++) {
    // Each attempt gets a unique name so there is never a name conflict between retries
    const attemptName = i === 0 ? opts.name : `${opts.name}-r${i}`;
    triedNames.push(attemptName);

    // Clean up any leftover container with this name (from a crashed previous session)
    try { await execAsync(`docker rm -f ${attemptName}`, { timeout: 10_000 }); } catch { /* doesn't exist */ }

    const hostPort = opts.hostPort ? opts.hostPort + i : undefined;
    const result = await _tryStartContainer({ ...opts, name: attemptName }, hostPort, containerPort);

    if (result.ok) {
      // Clean up the unused retry containers from earlier attempts
      for (const n of triedNames.slice(0, -1)) {
        try { await execAsync(`docker rm -f ${n}`, { timeout: 10_000 }); } catch { /* ignore */ }
      }
      return { containerId: result.id, hostPort: hostPort ?? containerPort };
    }

    if (!result.portConflict) {
      try { await execAsync(`docker rm -f ${attemptName}`, { timeout: 10_000 }); } catch { /* ignore */ }
      throw new Error(result.error);
    }
    // port conflict — clean up this attempt's container and try next port
    try { await execAsync(`docker rm -f ${attemptName}`, { timeout: 10_000 }); } catch { /* ignore */ }
  }

  throw new Error(`Could not bind any host port in range ${opts.hostPort}–${(opts.hostPort ?? 3000) + maxPortTries - 1}`);
}

async function _tryStartContainer(
  opts: StartContainerOptions,
  hostPort: number | undefined,
  containerPort: number
): Promise<{ ok: true; id: string } | { ok: false; portConflict: boolean; error: string }> {
  const args = ["run", "-d", "--name", opts.name];

  if (hostPort) {
    args.push("-p", `${hostPort}:${containerPort}`);
  }

  // Write env vars to a temp file to avoid shell interpretation of special chars
  // (& in URLs, $, quotes, spaces, etc. all break when passed as -e KEY=VALUE strings)
  let envFilePath: string | null = null;
  const envVars = opts.envVars ?? {};
  if (Object.keys(envVars).length > 0) {
    const os = await import("os");
    envFilePath = path.join(os.tmpdir(), `breachscope-env-${Date.now()}.env`);
    const envFileContent = Object.entries(envVars)
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");
    fs.writeFileSync(envFilePath, envFileContent, "utf-8");
    args.push("--env-file", envFilePath);
  }

  args.push("--network", opts.networkMode ?? "bridge");
  args.push("--memory", opts.memory ?? "2g");
  args.push("--cpus", "2.0");

  if (opts.attackMode) {
    args.push("--cap-add", "NET_RAW");
    args.push("--cap-add", "NET_ADMIN");
  } else {
    args.push("--security-opt", "no-new-privileges:true");
  }

  args.push(opts.image);

  // Use spawn with array args — no shell, no special char interpretation
  return new Promise((resolve) => {
    const proc = spawn("docker", args, { stdio: "pipe", timeout: 30_000 });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.on("close", (code) => {
      if (envFilePath) { try { fs.unlinkSync(envFilePath); } catch { /* ignore */ } }
      if (code === 0) {
        resolve({ ok: true, id: stdout.trim() });
      } else {
        const msg = `docker run failed (exit ${code}): ${stderr.slice(0, 500)}`;
        const portConflict = stderr.includes("port is already allocated") || stderr.includes("Bind for") || stderr.includes("already in use");
        resolve({ ok: false, portConflict, error: msg });
      }
    });
    proc.on("error", (e) => {
      if (envFilePath) { try { fs.unlinkSync(envFilePath); } catch { /* ignore */ } }
      resolve({ ok: false, portConflict: false, error: String(e) });
    });
  });
}

export async function stopContainer(containerId: string): Promise<void> {
  try {
    await execAsync(`docker stop ${containerId}`, { timeout: 30_000 });
  } catch { /* already stopped */ }
  try {
    await execAsync(`docker rm -f ${containerId}`, { timeout: 15_000 });
  } catch { /* already removed */ }
}

export async function removeImage(imageName: string): Promise<void> {
  try {
    await execAsync(`docker rmi -f ${imageName}`, { timeout: 30_000 });
  } catch { /* ignore */ }
}

// ── Container inspection ───────────────────────────────────────────────────────

export async function getContainerIP(containerId: string): Promise<string> {
  const { stdout } = await execAsync(
    `docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" ${containerId}`,
    { timeout: 10_000 }
  );
  const ip = stdout.trim();
  if (!ip) throw new Error("Could not determine container IP address");
  return ip;
}

export async function inspectContainer(containerId: string): Promise<Record<string, unknown>> {
  const { stdout } = await execAsync(`docker inspect ${containerId}`, { timeout: 10_000 });
  const parsed = JSON.parse(stdout) as unknown[];
  return (parsed[0] ?? {}) as Record<string, unknown>;
}

// ── Exec & logs ───────────────────────────────────────────────────────────────

export async function execInContainer(
  containerId: string,
  cmd: string[],
  timeoutMs = 60_000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const proc = spawn("docker", ["exec", containerId, ...cmd], { timeout: timeoutMs });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.on("close", (code) => resolve({ stdout: stdout.slice(0, 12_000), stderr: stderr.slice(0, 3_000), exitCode: code ?? 0 }));
    proc.on("error", (e) => resolve({ stdout: "", stderr: String(e), exitCode: 1 }));
  });
}

export async function getContainerLogs(containerId: string, tail = 200): Promise<string> {
  try {
    const { stdout, stderr } = await execAsync(
      `docker logs --tail ${tail} ${containerId}`,
      { timeout: 15_000 }
    );
    return (stdout + "\n" + stderr).slice(0, 10_000);
  } catch (e) {
    return String(e);
  }
}

// ── Project detection ─────────────────────────────────────────────────────────

export type ProjectType =
  | "node"
  | "python"
  | "go"
  | "rust"
  | "ruby"
  | "java"
  | "php"
  | "dotnet"
  | "elixir"
  | "dart"
  | "unknown";

export function detectProjectType(cwd: string): ProjectType {
  const type = _detectInDir(cwd);
  if (type !== "unknown") return type;

  // Scan one level of subdirectories (monorepo root support)
  try {
    const entries = fs.readdirSync(cwd, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const sub = path.join(cwd, entry.name);
      const subType = _detectInDir(sub);
      if (subType !== "unknown") return subType;
    }
  } catch { /* ignore */ }

  return "unknown";
}

function _detectInDir(dir: string): ProjectType {
  if (fs.existsSync(path.join(dir, "package.json"))) return "node";
  if (
    fs.existsSync(path.join(dir, "requirements.txt")) ||
    fs.existsSync(path.join(dir, "pyproject.toml")) ||
    fs.existsSync(path.join(dir, "setup.py"))
  ) return "python";
  if (fs.existsSync(path.join(dir, "go.mod"))) return "go";
  if (fs.existsSync(path.join(dir, "Cargo.toml"))) return "rust";
  if (fs.existsSync(path.join(dir, "Gemfile"))) return "ruby";
  if (
    fs.existsSync(path.join(dir, "pom.xml")) ||
    fs.existsSync(path.join(dir, "build.gradle")) ||
    fs.existsSync(path.join(dir, "build.gradle.kts"))
  ) return "java";
  if (fs.existsSync(path.join(dir, "composer.json"))) return "php";
  try {
    if (fs.readdirSync(dir).some((f) => f.endsWith(".csproj") || f.endsWith(".sln"))) return "dotnet";
  } catch { /* ignore */ }
  if (fs.existsSync(path.join(dir, "mix.exs"))) return "elixir";
  if (fs.existsSync(path.join(dir, "pubspec.yaml"))) return "dart";
  return "unknown";
}

export function detectAppPort(cwd: string, projectType: ProjectType): number {
  if (projectType === "node") {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(cwd, "package.json"), "utf-8")) as {
        scripts?: Record<string, string>;
      };
      const startScript = pkg.scripts?.start ?? pkg.scripts?.dev ?? "";
      const m = startScript.match(/PORT[=\s]+(\d+)|--port\s+(\d+)|-p\s+(\d+)/);
      if (m) return parseInt(m[1] ?? m[2] ?? m[3] ?? "3000");
    } catch { /* ignore */ }
    return 3000;
  }
  if (projectType === "python")  return 8000;
  if (projectType === "go")      return 8080;
  if (projectType === "rust")    return 8080;
  if (projectType === "ruby")    return 3000;
  if (projectType === "java")    return 8080;
  if (projectType === "php")     return 80;
  if (projectType === "dotnet")  return 8080;
  if (projectType === "elixir")  return 4000;
  if (projectType === "dart")    return 8080;
  return 3000;
}

// ── Dockerfile generation ─────────────────────────────────────────────────────

export function generateDockerfile(projectType: ProjectType, cwd: string): string {
  switch (projectType) {

    // ── Node.js / Next.js ──────────────────────────────────────────────────────
    case "node": {
      let startCmd = `["npm", "start"]`;
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(cwd, "package.json"), "utf-8")) as {
          scripts?: Record<string, string>;
          main?: string;
          dependencies?: Record<string, string>;
        };
        const deps = Object.keys(pkg.dependencies ?? {});
        const isNest = deps.includes("@nestjs/core") || deps.includes("@nestjs/common");
        const isNext = deps.includes("next");
        const hasTypeScript = fs.existsSync(path.join(cwd, "tsconfig.json"));
        const hasBuildScript = !!pkg.scripts?.build;

        if (isNext) {
          return `FROM node:20
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build 2>/dev/null || true
EXPOSE 3000
ENV NODE_ENV=development PORT=3000
CMD ["npm", "start"]
`;
        }
        if (isNest) {
          return `FROM node:20
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build 2>/dev/null || true
EXPOSE 3000
ENV NODE_ENV=development PORT=3000
CMD ["sh", "-c", "node dist/main.js 2>/dev/null || npm run start:dev 2>/dev/null || npm start"]
`;
        }
        if (pkg.scripts?.start) {
          startCmd = `["npm", "start"]`;
        } else if (pkg.main) {
          startCmd = `["node", "${pkg.main}"]`;
        } else if (fs.existsSync(path.join(cwd, "server.js"))) {
          startCmd = `["node", "server.js"]`;
        } else if (fs.existsSync(path.join(cwd, "index.js"))) {
          startCmd = `["node", "index.js"]`;
        } else if (fs.existsSync(path.join(cwd, "src/index.js"))) {
          startCmd = `["node", "src/index.js"]`;
        }
        const buildStep = (hasTypeScript && hasBuildScript) ? "RUN npm run build 2>/dev/null || true\n" : "";
      } catch { /* use default */ }
      return `FROM node:20
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
${(()=>{ try { const p=JSON.parse(fs.readFileSync(path.join(cwd,"package.json"),"utf-8")) as {scripts?:Record<string,string>}; return p.scripts?.build ? "RUN npm run build 2>/dev/null || true\n" : ""; } catch { return ""; } })()}EXPOSE 3000
ENV NODE_ENV=development PORT=3000
CMD ${startCmd}
`;
    }

    // ── Python ────────────────────────────────────────────────────────────────
    case "python": {
      let installCmd = "RUN pip install --no-cache-dir -r requirements.txt";
      let cmdLine = `["python", "-m", "http.server", "8000"]`;

      if (fs.existsSync(path.join(cwd, "requirements.txt"))) {
        try {
          const reqs = fs.readFileSync(path.join(cwd, "requirements.txt"), "utf-8").toLowerCase();
          if (reqs.includes("uvicorn")) {
            const main = fs.existsSync(path.join(cwd, "main.py")) ? "main" : "app";
            cmdLine = `["uvicorn", "${main}:app", "--host", "0.0.0.0", "--port", "8000"]`;
          } else if (reqs.includes("gunicorn")) {
            cmdLine = `["gunicorn", "-b", "0.0.0.0:8000", "app:app"]`;
          } else if (reqs.includes("flask")) {
            cmdLine = `["python", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "8000"]`;
          } else if (reqs.includes("django")) {
            cmdLine = `["python", "manage.py", "runserver", "0.0.0.0:8000"]`;
          }
        } catch { /* ignore */ }
      } else if (fs.existsSync(path.join(cwd, "pyproject.toml"))) {
        installCmd = "RUN pip install --no-cache-dir .";
      }

      return `FROM python:3.11-slim
WORKDIR /app
COPY ${fs.existsSync(path.join(cwd, "requirements.txt")) ? "requirements.txt" : "pyproject.toml"} ./
${installCmd}
COPY . .
EXPOSE 8000
ENV PYTHONUNBUFFERED=1
CMD ${cmdLine}
`;
    }

    // ── Go ────────────────────────────────────────────────────────────────────
    case "go":
      return `FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
`;

    // ── Rust ──────────────────────────────────────────────────────────────────
    case "rust":
      return `FROM rust:1.77-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release 2>/dev/null; rm -rf src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/* /app/
EXPOSE 8080
CMD ["/app/server"]
`;

    // ── Ruby ──────────────────────────────────────────────────────────────────
    case "ruby": {
      const isRails = fs.existsSync(path.join(cwd, "config/application.rb"));
      const cmd = isRails
        ? `["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]`
        : `["bundle", "exec", "ruby", "app.rb", "-o", "0.0.0.0"]`;
      return `FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test
COPY . .
EXPOSE 3000
ENV RAILS_ENV=production
CMD ${cmd}
`;
    }

    // ── Java (Maven or Gradle) ────────────────────────────────────────────────
    case "java": {
      const isGradle = fs.existsSync(path.join(cwd, "build.gradle")) || fs.existsSync(path.join(cwd, "build.gradle.kts"));
      if (isGradle) {
        return `FROM gradle:8-jdk21 AS builder
WORKDIR /app
COPY build.gradle* settings.gradle* gradle* ./
COPY gradle gradle
RUN gradle dependencies --no-daemon -q 2>/dev/null || true
COPY . .
RUN gradle bootJar --no-daemon -q 2>/dev/null || gradle jar --no-daemon -q 2>/dev/null || gradle build --no-daemon -q

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar 2>/dev/null || COPY --from=builder /app/build/libs/ /app/
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
`;
      }
      return `FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:go-offline -q 2>/dev/null || true
COPY . .
RUN mvn package -DskipTests -q

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
`;
    }

    // ── PHP ───────────────────────────────────────────────────────────────────
    case "php": {
      const isLaravel = fs.existsSync(path.join(cwd, "artisan"));
      const isSym = fs.existsSync(path.join(cwd, "symfony.lock")) || fs.existsSync(path.join(cwd, "bin/console"));
      const webRoot = isLaravel ? "/var/www/html/public" : isSym ? "/var/www/html/public" : "/var/www/html";
      return `FROM php:8.3-apache
WORKDIR /var/www/html
RUN apt-get update && apt-get install -y unzip curl libzip-dev libpng-dev libonig-dev \\
    && docker-php-ext-install pdo pdo_mysql mbstring zip gd \\
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader --no-scripts
COPY . .
${isLaravel ? "RUN php artisan key:generate --force 2>/dev/null || true\nRUN chmod -R 775 storage bootstrap/cache\n" : ""}ENV APACHE_DOCUMENT_ROOT=${webRoot}
RUN sed -ri -e 's!/var/www/html!${webRoot}!g' /etc/apache2/sites-available/*.conf
RUN a2enmod rewrite
EXPOSE 80
`;
    }

    // ── .NET (ASP.NET Core) ───────────────────────────────────────────────────
    case "dotnet": {
      const csprojs = fs.readdirSync(cwd).filter((f) => f.endsWith(".csproj"));
      const proj = csprojs[0] ?? "*.csproj";
      return `FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder
WORKDIR /app
COPY ${proj} ./
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app/out

FROM mcr.microsoft.com/dotnet/aspnet:8.0
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/out .
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
CMD ["dotnet", "${proj.replace(".csproj", ".dll")}"]
`;
    }

    // ── Elixir / Phoenix ──────────────────────────────────────────────────────
    case "elixir": {
      const appName = (() => {
        try {
          const mix = fs.readFileSync(path.join(cwd, "mix.exs"), "utf-8");
          const m = mix.match(/app:\s*:([a-z_]+)/);
          return m?.[1] ?? "app";
        } catch { return "app"; }
      })();
      return `FROM elixir:1.16-alpine AS builder
RUN apk add --no-cache build-base nodejs npm git
WORKDIR /app
COPY mix.exs mix.lock ./
RUN mix local.hex --force && mix local.rebar --force
ENV MIX_ENV=prod
RUN mix deps.get --only prod
COPY . .
RUN mix compile
RUN mix release

FROM alpine:3.20
RUN apk add --no-cache libstdc++ openssl ncurses-libs curl
WORKDIR /app
COPY --from=builder /app/_build/prod/rel/${appName} .
EXPOSE 4000
ENV PHX_SERVER=true PORT=4000
CMD ["./bin/${appName}", "start"]
`;
    }

    // ── Dart ──────────────────────────────────────────────────────────────────
    case "dart": {
      const entrypoint = fs.existsSync(path.join(cwd, "bin/server.dart")) ? "bin/server.dart"
        : fs.existsSync(path.join(cwd, "bin/main.dart"))  ? "bin/main.dart"
        : "bin/server.dart";
      return `FROM dart:stable AS builder
WORKDIR /app
COPY pubspec.yaml pubspec.lock* ./
RUN dart pub get
COPY . .
RUN dart compile exe ${entrypoint} -o /app/server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
`;
    }

    default:
      // Unknown project type — build a generic attack container with the code mounted.
      // Installs common runtimes and recon tools, then tries to auto-detect and start whatever is here.
      return `FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \\
    curl wget netcat-openbsd nmap sqlmap nikto \\
    python3 python3-pip nodejs npm \\
    postgresql-client redis-tools jq git \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
EXPOSE 3000 8000 8080
CMD ["sh", "-c", "\\
  echo '=== BreachScope sandbox: auto-detecting project ===' && \\
  if [ -f package.json ]; then npm install --silent 2>/dev/null; node $(node -e \"try{const p=require('./package.json');console.log(p.main||'index.js')}catch(e){console.log('index.js')}\") 2>/dev/null || npm start 2>/dev/null; \\
  elif [ -f requirements.txt ]; then pip install -q -r requirements.txt 2>/dev/null; python3 -m flask run --host=0.0.0.0 --port=8000 2>/dev/null || python3 -m http.server 8000; \\
  elif [ -f manage.py ]; then python3 manage.py runserver 0.0.0.0:8000 2>/dev/null; \\
  elif [ -f app.py ] || [ -f main.py ]; then python3 app.py 2>/dev/null || python3 main.py 2>/dev/null || python3 -m http.server 8000; \\
  else python3 -m http.server 8000; \\
  fi"]
`;
  }
}
