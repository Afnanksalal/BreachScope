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
): Promise<void> {
  const args = ["build", "-t", imageName];
  if (dockerfilePath) args.push("-f", dockerfilePath);
  args.push(contextDir);

  await new Promise<void>((resolve, reject) => {
    const proc = spawn("docker", args, { stdio: "pipe", timeout: 600_000 });
    let errOutput = "";
    proc.stderr.on("data", (d: Buffer) => { errOutput += d.toString(); });
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`docker build failed (exit ${code}):\n${errOutput.slice(-2000)}`));
    });
    proc.on("error", reject);
  });
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

export async function startContainer(opts: StartContainerOptions): Promise<string> {
  const args = ["run", "-d", "--name", opts.name];

  if (opts.hostPort && opts.containerPort) {
    args.push("-p", `${opts.hostPort}:${opts.containerPort}`);
  } else if (opts.hostPort) {
    args.push("-p", `${opts.hostPort}:3000`);
  }

  for (const [k, v] of Object.entries(opts.envVars ?? {})) {
    args.push("-e", `${k}=${v}`);
  }

  args.push("--network", opts.networkMode ?? "bridge");
  args.push("--memory", opts.memory ?? "2g");
  args.push("--cpus", "2.0");

  if (opts.attackMode) {
    // Attack-arena mode: AI runs as root with full capability set
    // Network caps so nmap/netcat/tcpdump work inside the container
    args.push("--cap-add", "NET_RAW");
    args.push("--cap-add", "NET_ADMIN");
    // No privilege or security restrictions — AI owns this container
  } else {
    args.push("--security-opt", "no-new-privileges:true");
  }

  args.push(opts.image);

  const { stdout } = await execAsync(`docker ${args.join(" ")}`, { timeout: 30_000 });
  return stdout.trim();
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
  if (fs.existsSync(path.join(cwd, "package.json"))) return "node";
  if (
    fs.existsSync(path.join(cwd, "requirements.txt")) ||
    fs.existsSync(path.join(cwd, "pyproject.toml")) ||
    fs.existsSync(path.join(cwd, "setup.py"))
  ) return "python";
  if (fs.existsSync(path.join(cwd, "go.mod"))) return "go";
  if (fs.existsSync(path.join(cwd, "Cargo.toml"))) return "rust";
  if (fs.existsSync(path.join(cwd, "Gemfile"))) return "ruby";
  if (
    fs.existsSync(path.join(cwd, "pom.xml")) ||
    fs.existsSync(path.join(cwd, "build.gradle")) ||
    fs.existsSync(path.join(cwd, "build.gradle.kts"))
  ) return "java";
  if (fs.existsSync(path.join(cwd, "composer.json"))) return "php";
  if (
    fs.readdirSync(cwd).some((f) => f.endsWith(".csproj") || f.endsWith(".sln"))
  ) return "dotnet";
  if (fs.existsSync(path.join(cwd, "mix.exs"))) return "elixir";
  if (fs.existsSync(path.join(cwd, "pubspec.yaml"))) return "dart";
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
        if (deps.includes("next")) {
          return `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build 2>/dev/null || true
EXPOSE 3000
ENV NODE_ENV=production PORT=3000
CMD ["npm", "start"]
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
      } catch { /* use default */ }
      return `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
ENV NODE_ENV=production PORT=3000
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
      return `FROM alpine:3.20
WORKDIR /app
COPY . .
EXPOSE 3000
CMD ["sh", "-c", "echo 'Unknown project type' && sleep 3600"]
`;
  }
}
