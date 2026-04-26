import fs from "fs";
import type { Finding } from "../../core/types.js";

// ── Dockerfile security audit ─────────────────────────────────────────────────

export function auditDockerfile(dockerfilePath: string): Finding[] {
  const findings: Finding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(dockerfilePath, "utf-8");
  } catch {
    return [];
  }

  const lines = content.split("\n");

  // Running as root (no USER directive)
  const hasUser = lines.some((l) => /^USER\s+(?!root\b)/i.test(l.trim()));
  const hasRootUser = lines.some((l) => /^USER\s+root/i.test(l.trim()));
  if (!hasUser || hasRootUser) {
    findings.push({
      id: "sandbox-dockerfile-root",
      title: "Container Runs as Root",
      severity: "high",
      category: "code",
      description:
        "The Dockerfile has no USER directive (or explicitly uses root). Running containers as root gives attackers full control over the container filesystem if they achieve code execution.",
      remediation: "Add `USER node` (or another non-root user) before the CMD instruction. Create the user if needed: `RUN addgroup -S app && adduser -S app -G app`.",
      references: ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"],
    });
  }

  // ADD used instead of COPY (can extract tar archives)
  const addLines = lines.filter((l) => /^ADD\s+https?:\/\//i.test(l.trim()));
  if (addLines.length > 0) {
    findings.push({
      id: "sandbox-dockerfile-add-remote",
      title: "Dockerfile Fetches Remote Content with ADD",
      severity: "high",
      category: "code",
      description:
        `The Dockerfile uses ADD with a remote URL (${addLines[0]?.trim().slice(0, 80)}). This downloads and executes arbitrary remote content at build time, which is a supply chain risk.`,
      remediation: "Use COPY for local files. For remote content, use curl/wget in a RUN command with checksum verification.",
    });
  }

  // curl | bash / wget | sh patterns (RCE risk in build)
  const curlBash = lines.filter((l) => /curl[^|]*\|\s*(bash|sh|python|node)/i.test(l) || /wget[^|]*\|\s*(bash|sh|python|node)/i.test(l));
  if (curlBash.length > 0) {
    findings.push({
      id: "sandbox-dockerfile-curl-pipe",
      title: "Dockerfile Uses curl-pipe-shell Pattern",
      severity: "high",
      category: "code",
      description:
        `Dockerfile runs a remote script directly via pipe (${curlBash[0]?.trim().slice(0, 100)}). If the remote URL is compromised, arbitrary code runs during image build — a common supply chain attack vector.`,
      remediation: "Download scripts separately, verify checksums, then execute. Never pipe remote content directly to a shell.",
    });
  }

  // Secrets hardcoded in ENV
  const secretEnv = lines.filter((l) => {
    const upper = l.toUpperCase();
    return /^ENV\s+/.test(l.trim()) && (
      upper.includes("PASSWORD") ||
      upper.includes("SECRET") ||
      upper.includes("API_KEY") ||
      upper.includes("PRIVATE_KEY") ||
      upper.includes("TOKEN") ||
      upper.includes("AWS_")
    );
  });
  if (secretEnv.length > 0) {
    findings.push({
      id: "sandbox-dockerfile-secret-env",
      title: "Secrets Hardcoded in Dockerfile ENV",
      severity: "critical",
      category: "code",
      description:
        `Dockerfile uses ENV to set sensitive values (${secretEnv[0]?.trim().slice(0, 80)}). These values are baked into every image layer and visible via \`docker inspect\` or \`docker history\`.`,
      remediation: "Never store secrets in ENV instructions. Use Docker Secrets, environment files at runtime, or a secrets manager (Vault, AWS Secrets Manager).",
      detail: secretEnv.slice(0, 3).join("\n"),
    });
  }

  // Using :latest tag
  const latestFrom = lines.filter((l) => /^FROM\s+[^\s]+:latest/i.test(l.trim()));
  if (latestFrom.length > 0) {
    findings.push({
      id: "sandbox-dockerfile-latest",
      title: "Dockerfile Uses :latest Image Tag",
      severity: "low",
      category: "code",
      description:
        "The Dockerfile pins to :latest, which is not reproducible and may silently pull a compromised or breaking image version.",
      remediation: "Pin to a specific digest or version tag (e.g., node:20.11.0-alpine3.19) and update deliberately.",
    });
  }

  // No HEALTHCHECK
  const hasHealthcheck = lines.some((l) => /^HEALTHCHECK/i.test(l.trim()));
  if (!hasHealthcheck) {
    findings.push({
      id: "sandbox-dockerfile-no-healthcheck",
      title: "No HEALTHCHECK Directive",
      severity: "low",
      category: "code",
      description:
        "The Dockerfile lacks a HEALTHCHECK instruction. Without health checks, orchestrators cannot detect and restart unhealthy containers.",
      remediation: "Add `HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1` or equivalent.",
    });
  }

  return findings;
}

// ── Container security config check ──────────────────────────────────────────

export function checkContainerSecurityConfig(inspectData: Record<string, unknown>): Finding[] {
  const findings: Finding[] = [];

  try {
    const hostConfig = (inspectData["HostConfig"] ?? {}) as Record<string, unknown>;
    const config = (inspectData["Config"] ?? {}) as Record<string, unknown>;

    // Privileged mode
    if (hostConfig["Privileged"] === true) {
      findings.push({
        id: "sandbox-container-privileged",
        title: "Container Running in Privileged Mode",
        severity: "critical",
        category: "code",
        description:
          "The container is running with --privileged, giving it full access to the host kernel and all devices. A compromised container can trivially escape to the host.",
        remediation: "Remove --privileged. Grant only specific capabilities needed (e.g., --cap-add NET_ADMIN).",
      });
    }

    // Dangerous capabilities
    const capAdd = (hostConfig["CapAdd"] as string[] | null) ?? [];
    const dangerousCaps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "SYS_MODULE", "DAC_OVERRIDE"];
    const foundDangerous = capAdd.filter((c) => dangerousCaps.includes(c));
    if (foundDangerous.length > 0) {
      findings.push({
        id: "sandbox-container-capabilities",
        title: `Dangerous Capabilities Granted: ${foundDangerous.join(", ")}`,
        severity: "high",
        category: "code",
        description:
          `Container has dangerous Linux capabilities: ${foundDangerous.join(", ")}. These expand the blast radius of container compromise — SYS_ADMIN in particular allows container escape.`,
        remediation: "Remove unnecessary capabilities. Use --cap-drop ALL and add back only what's needed.",
      });
    }

    // Host network mode
    const networkMode = String(hostConfig["NetworkMode"] ?? "");
    if (networkMode === "host") {
      findings.push({
        id: "sandbox-container-host-network",
        title: "Container Uses Host Network Mode",
        severity: "high",
        category: "code",
        description:
          "Container runs with --network host, sharing the host's network namespace. Attackers who compromise the container have direct access to all host network interfaces and services.",
        remediation: "Use bridge or overlay networking and expose only required ports.",
      });
    }

    // PID namespace sharing
    const pidMode = String(hostConfig["PidMode"] ?? "");
    if (pidMode === "host") {
      findings.push({
        id: "sandbox-container-host-pid",
        title: "Container Shares Host PID Namespace",
        severity: "high",
        category: "code",
        description:
          "Container uses --pid=host, allowing it to see and signal all host processes. This is a major container escape vector.",
        remediation: "Remove --pid=host.",
      });
    }

    // Mounts of sensitive host paths
    const mounts = (inspectData["Mounts"] as Array<{ Source: string; Type: string }> | null) ?? [];
    const sensitiveMounts = mounts.filter(
      (m) => m.Type === "bind" && (
        m.Source === "/" ||
        m.Source === "/etc" ||
        m.Source === "/var/run/docker.sock" ||
        m.Source.startsWith("/proc") ||
        m.Source.startsWith("/sys")
      )
    );
    for (const mount of sensitiveMounts) {
      const isSock = mount.Source === "/var/run/docker.sock";
      findings.push({
        id: `sandbox-container-mount-${mount.Source.replace(/\//g, "-")}`,
        title: isSock ? "Docker Socket Mounted in Container" : `Sensitive Host Path Mounted: ${mount.Source}`,
        severity: "critical",
        category: "code",
        description: isSock
          ? "The Docker daemon socket is mounted inside the container. This allows full control of the Docker host — any process in the container can spawn privileged containers, extract secrets, or escape to the host."
          : `Sensitive host path ${mount.Source} is bind-mounted into the container, potentially exposing host system files.`,
        remediation: isSock
          ? "Remove the /var/run/docker.sock mount. Use Docker Swarm secrets or a dedicated Docker API proxy if container-level Docker access is required."
          : `Avoid bind-mounting ${mount.Source}. Use Docker volumes for data sharing.`,
      });
    }

    // Read-only root filesystem (good — flag if absent)
    const readonlyRootfs = Boolean(hostConfig["ReadonlyRootfs"]);
    if (!readonlyRootfs) {
      findings.push({
        id: "sandbox-container-writable-root",
        title: "Container Root Filesystem is Writable",
        severity: "low",
        category: "code",
        description:
          "The container does not use --read-only. A writable root filesystem makes it easier for attackers to plant backdoors or modify application binaries after compromise.",
        remediation: "Add --read-only to the container run command and mount tmpfs for writable paths (e.g., --tmpfs /tmp).",
      });
    }

    // No security-opt no-new-privileges (check absence)
    const securityOpt = (hostConfig["SecurityOpt"] as string[] | null) ?? [];
    const hasNoNewPriv = securityOpt.some((s) => s.includes("no-new-privileges"));
    if (!hasNoNewPriv) {
      findings.push({
        id: "sandbox-container-new-privs",
        title: "Container Allows Privilege Escalation",
        severity: "medium",
        category: "code",
        description:
          "The container lacks --security-opt no-new-privileges:true. Processes inside can potentially gain elevated privileges via setuid binaries.",
        remediation: "Add --security-opt no-new-privileges:true to all container run commands.",
      });
    }

    // User check — running as root
    const user = String(config["User"] ?? "");
    if (!user || user === "root" || user === "0") {
      findings.push({
        id: "sandbox-container-runtime-root",
        title: "Application Process Running as Root Inside Container",
        severity: "high",
        category: "code",
        description:
          "The container's main process runs as root (UID 0). If an attacker achieves code execution, they immediately have root inside the container and can exploit further vulnerabilities to escape.",
        remediation: "Set a non-root USER in the Dockerfile. Ensure the application files are owned by that user.",
      });
    }
  } catch { /* ignore parse errors */ }

  return findings;
}

// ── Build artifact scan ───────────────────────────────────────────────────────

type ExecFn = (cmd: string[]) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export async function scanBuildArtifacts(execFn: ExecFn): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check for .env files baked into the image
  const envSearch = await execFn([
    "find", "/app", "-name", ".env*", "-not", "-path", "*/node_modules/*",
    "-not", "-path", "*/.git/*", "-type", "f",
  ]);

  if (envSearch.stdout.trim()) {
    const envFiles = envSearch.stdout.trim().split("\n").filter(Boolean);

    for (const envFile of envFiles.slice(0, 5)) {
      const catResult = await execFn(["cat", envFile]);
      const content = catResult.stdout;

      // Look for actual secrets (non-empty values that look real)
      const secretLines = content.split("\n").filter((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) return false;
        const upper = trimmed.toUpperCase();
        const hasSecretKey = upper.includes("PASSWORD") || upper.includes("SECRET") ||
          upper.includes("API_KEY") || upper.includes("PRIVATE_KEY") ||
          upper.includes("TOKEN") || upper.includes("AWS_") || upper.includes("DATABASE_URL");
        const hasValue = trimmed.includes("=") && (trimmed.split("=")[1]?.trim().length ?? 0) > 0;
        const isPlaceholder = /your[_-]|example|changeme|placeholder|<|>/i.test(trimmed);
        return hasSecretKey && hasValue && !isPlaceholder;
      });

      if (secretLines.length > 0) {
        findings.push({
          id: `sandbox-artifact-env-${envFile.replace(/\//g, "-")}`,
          title: `Secrets Found in Baked-In .env File: ${envFile}`,
          severity: "critical",
          category: "code",
          description:
            `${envFile} is baked into the Docker image and contains ${secretLines.length} line(s) with apparent secrets. Anyone who pulls this image has access to these credentials.`,
          remediation: "Add .env files to .dockerignore. Pass secrets at runtime via environment variables or a secrets manager. Never bake credentials into images.",
          detail: secretLines.slice(0, 3).map((l) => {
            const [key] = l.split("=");
            return `${key}=[REDACTED]`;
          }).join("\n"),
        });
      } else if (content.trim().length > 0) {
        findings.push({
          id: `sandbox-artifact-env-exposed-${envFile.replace(/\//g, "-")}`,
          title: `.env File Baked Into Image: ${envFile}`,
          severity: "medium",
          category: "code",
          description:
            `${envFile} is present in the Docker image. Even if currently empty or using placeholder values, this is a misconfiguration — real deployments may accidentally bake in secrets.`,
          remediation: "Add all .env files to .dockerignore.",
        });
      }
    }
  }

  // Check for world-writable directories (privilege escalation risk)
  const writableDirs = await execFn([
    "find", "/app", "-type", "d", "-perm", "-0002", "-not", "-path", "*/node_modules/*",
  ]);
  if (writableDirs.stdout.trim()) {
    const dirs = writableDirs.stdout.trim().split("\n").filter(Boolean);
    findings.push({
      id: "sandbox-artifact-world-writable",
      title: `World-Writable Directories in Container: ${dirs.length} found`,
      severity: "medium",
      category: "code",
      description:
        `${dirs.length} world-writable director${dirs.length === 1 ? "y" : "ies"} found in /app: ${dirs.slice(0, 3).join(", ")}. Any process can write to these paths.`,
      remediation: "Fix permissions: `chmod 755 /app` and ensure only the app user can write to required directories.",
      detail: dirs.slice(0, 10).join("\n"),
    });
  }

  // Check for SUID binaries
  const suidBins = await execFn([
    "find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f",
  ]);
  const suidList = suidBins.stdout.trim().split("\n").filter(Boolean);
  const knownSafe = new Set(["su", "sudo", "ping", "passwd", "newgrp", "chsh", "chfn", "mount", "umount", "at", "crontab"]);
  const unusualSuid = suidList.filter((b) => {
    const base = b.split("/").pop() ?? "";
    return !knownSafe.has(base);
  });
  if (unusualSuid.length > 0) {
    findings.push({
      id: "sandbox-artifact-suid",
      title: `Unusual SUID Binaries Found: ${unusualSuid.length}`,
      severity: "high",
      category: "code",
      description:
        `Found ${unusualSuid.length} SUID binary${unusualSuid.length === 1 ? "" : "ies"} not in the expected set: ${unusualSuid.slice(0, 3).join(", ")}. These can be used to escalate privileges inside the container.`,
      remediation: "Remove SUID bits from binaries that don't need them: `chmod u-s /path/to/binary`. Audit why these binaries have SUID.",
      detail: unusualSuid.join("\n"),
    });
  }

  // Check for secrets in compiled/built JavaScript
  const distPaths = ["/app/dist", "/app/.next/static", "/app/build", "/app/public/build"];
  for (const distPath of distPaths) {
    const grepResult = await execFn([
      "sh", "-c",
      `grep -r -l --include="*.js" --include="*.map" -E "(sk-[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9]{35,}|AAAA[a-zA-Z0-9+/]{100,}|[a-z0-9]{32,}secret[a-z0-9_-]*=)" ${distPath} 2>/dev/null | head -5`,
    ]);
    if (grepResult.stdout.trim() && grepResult.exitCode === 0) {
      findings.push({
        id: `sandbox-artifact-secret-in-bundle-${distPath.replace(/\//g, "-")}`,
        title: `Potential Secrets Detected in Compiled Bundle: ${distPath}`,
        severity: "high",
        category: "code",
        description:
          `Patterns matching API keys or secrets were found in compiled JavaScript in ${distPath}. These secrets are exposed to anyone who loads your application.`,
        remediation: "Never import secrets in client-side code. Use server-side API routes to proxy authenticated requests. Audit your webpack/vite bundles.",
        detail: grepResult.stdout.trim().slice(0, 500),
      });
    }
  }

  // Check app is not running as root
  const idResult = await execFn(["id"]);
  if (idResult.stdout.includes("uid=0")) {
    findings.push({
      id: "sandbox-artifact-running-root",
      title: "Application Process Running as UID 0 (root)",
      severity: "high",
      category: "code",
      description:
        "The application process inside the container is running as root (uid=0). Code execution vulnerabilities in the app give attackers root access within the container.",
      remediation: "Add `USER <non-root>` to your Dockerfile before CMD/ENTRYPOINT.",
    });
  }

  return findings;
}
