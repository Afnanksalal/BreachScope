import ora from "ora";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import { logger } from "../core/logger.js";
import type { Finding } from "../core/types.js";
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
import { auditDockerfile, checkContainerSecurityConfig, scanBuildArtifacts } from "../scanners/sandbox/index.js";
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
      if (resp.status < 600) return true; // any HTTP response = app is up
    } catch { /* not ready yet */ }
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
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

  // ── Project detection ─────────────────────────────────────────────────────
  const projectType = detectProjectType(cwd);
  const appPort = opts.port ?? detectAppPort(cwd, projectType);
  const hostPort = appPort; // Map same port to host for access

  console.log(chalk.gray(`  Detected project: ${chalk.white(projectType)} · App port: ${chalk.white(String(appPort))}`));

  // ── Dockerfile preparation ────────────────────────────────────────────────
  const existingDockerfile = path.join(cwd, "Dockerfile");
  const generatedDockerfile = path.join(cwd, ".breachscope-sandbox.Dockerfile");
  let dockerfilePath = existingDockerfile;
  let generatedDockerfileCreated = false;

  if (!fs.existsSync(existingDockerfile)) {
    if (projectType === "unknown") {
      logger.warn("Unknown project type and no Dockerfile found. Cannot build sandbox container.");
      logger.warn("Add a Dockerfile to your project root or ensure a package.json / requirements.txt exists.");
      process.exit(1);
    }

    const dockerfileContent = generateDockerfile(projectType, cwd);
    fs.writeFileSync(generatedDockerfile, dockerfileContent, "utf-8");
    generatedDockerfileCreated = true;
    dockerfilePath = generatedDockerfile;
    logger.info(`Generated Dockerfile for ${projectType} project`);
    logger.debug(`Generated Dockerfile:\n${dockerfileContent}`);
  }

  // ── Static: Dockerfile audit ──────────────────────────────────────────────
  logger.section("Dockerfile Security Audit");
  const dockerfileFindings = auditDockerfile(dockerfilePath);
  findings.push(...dockerfileFindings);
  if (dockerfileFindings.length === 0) {
    logger.success("Dockerfile — no issues found");
  } else {
    logger.info(`Dockerfile audit — ${dockerfileFindings.length} issue(s)`);
  }

  // ── Build image ───────────────────────────────────────────────────────────
  const buildSpinner = ora(`Building Docker image (${imageName})...`).start();
  try {
    await buildImage(cwd, imageName, dockerfilePath);
    buildSpinner.succeed(`Image built: ${imageName}`);
  } catch (e) {
    buildSpinner.fail(`Docker build failed: ${String(e).slice(0, 200)}`);
    await cleanup(null, imageName, generatedDockerfileCreated ? generatedDockerfile : null);
    process.exit(1);
  }

  // ── Start container ───────────────────────────────────────────────────────
  const startSpinner = ora("Starting sandbox container...").start();
  try {
    containerId = await startContainer({
      image: imageName,
      name: containerName,
      hostPort,
      containerPort: appPort,
      networkMode: "bridge",
      attackMode: true,
    });
    startSpinner.succeed(`Container started: ${containerId.slice(0, 12)}`);
  } catch (e) {
    startSpinner.fail(`Failed to start container: ${e}`);
    await cleanup(null, imageName, generatedDockerfileCreated ? generatedDockerfile : null);
    process.exit(1);
  }

  try {
    // ── Get container IP ────────────────────────────────────────────────────
    let containerIP: string;
    try {
      containerIP = await getContainerIP(containerId);
      logger.debug(`Container IP: ${containerIP}`);
    } catch {
      // Fall back to localhost with host port mapping
      containerIP = "127.0.0.1";
    }

    // ── Container security inspection ───────────────────────────────────────
    logger.section("Container Security Configuration");
    try {
      const inspectData = await inspectContainer(containerId);
      const configFindings = checkContainerSecurityConfig(inspectData);
      findings.push(...configFindings);
      if (configFindings.length === 0) {
        logger.success("Container config — no critical misconfigurations");
      } else {
        logger.info(`Container config — ${configFindings.length} issue(s)`);
      }
    } catch (e) {
      logger.warn(`Container inspection failed: ${e}`);
    }

    // ── Wait for app to be ready ────────────────────────────────────────────
    const startupTimeout = Math.min(opts.timeout ?? 60, 120) * 1000;
    const healthSpinner = ora(`Waiting for app on port ${appPort} (up to ${startupTimeout / 1000}s)...`).start();
    const isReady = await waitForApp(containerIP, appPort, startupTimeout);

    if (!isReady) {
      healthSpinner.warn(`App did not respond on port ${appPort} within timeout`);
      console.log(chalk.gray("  Container may need a longer startup time or uses a different port."));
      console.log(chalk.gray("  Continuing with static analysis only..."));

      // Fallback: just run static analysis
      logger.section("Build Artifact Scan (static only)");
      const exec = (cmd: string[]) => execInContainer(containerId!, cmd);
      const artifactFindings = await scanBuildArtifacts(exec);
      findings.push(...artifactFindings);
    } else {
      healthSpinner.succeed(`App is ready at http://${containerIP}:${appPort}`);

      // ── Build artifact scan (runs inside container) ─────────────────────
      logger.section("Build Artifact Scan");
      const exec = (cmd: string[]) => execInContainer(containerId!, cmd);
      const artifactSpinner = ora("Scanning container for secrets, SUID binaries, world-writable paths...").start();
      try {
        const artifactFindings = await scanBuildArtifacts(exec);
        findings.push(...artifactFindings);
        artifactSpinner.succeed(`Artifact scan — ${artifactFindings.length} issue(s)`);
      } catch (e) {
        artifactSpinner.fail(`Artifact scan failed: ${e}`);
      }

      // ── AI sandbox attack agent ─────────────────────────────────────────
      if (process.env["OPENAI_API_KEY"]) {
        logger.section("AI-Powered Attack Agent");
        console.log(chalk.gray("  Root access inside container — AI installs tools, scans ports, attacks endpoints."));
        console.log(chalk.gray("  Covers: env secrets · internal ports · injection · auth bypass · SSRF · JWT · SSTI...\n"));

        const agentSpinner = ora("Attack agent running — may take 3-8 minutes...").start();
        try {
          const agentResult = await runSandboxAgent(
            containerId,
            containerIP,
            appPort,
            projectType,
            exec,
            (tail) => getContainerLogs(containerId!, tail),
          );

          findings.push(...agentResult.findings);
          agentSpinner.succeed(
            `Attack agent — ${agentResult.findings.length} finding(s) · ${agentResult.tokensUsed.toLocaleString()} tokens · ${agentResult.attackLog.length} actions`
          );

          if (agentResult.attackChains.length > 0) {
            console.log(chalk.gray(`\n  Attack chains:`));
            for (const chain of agentResult.attackChains) {
              console.log(chalk.gray(`    → ${chain.slice(0, 120)}`));
            }
          }

          if (opts.verbose && agentResult.attackLog.length > 0) {
            console.log(chalk.gray(`\n  Log: ${agentResult.attackLog.slice(0, 10).join("  │  ")}`));
          }

          // Store for dashboard push
          sandboxAgentResult = agentResult;
        } catch (e) {
          agentSpinner.fail(`Attack agent failed: ${e}`);
        }
      } else {
        logger.warn("Skipping AI attack agent — OPENAI_API_KEY not set.");
        logger.warn("Set OPENAI_API_KEY to run autonomous attack simulation.");
      }
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

    // Push to dashboard if authenticated
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
    // ── Cleanup — always runs ───────────────────────────────────────────────
    if (!opts.noCleanup) {
      await cleanup(containerId, imageName, generatedDockerfileCreated ? generatedDockerfile : null);
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
  generatedDockerfilePath: string | null
): Promise<void> {
  const spinner = ora("Cleaning up sandbox...").start();
  try {
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
