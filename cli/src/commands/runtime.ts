import { Command } from "commander";
import { spawn } from "child_process";
import fs from "fs";
import { logger } from "../core/logger.js";

export function makeRuntimeCommand(): Command {
  return new Command("runtime")
    .description("Run runtime security monitoring using an installed eBPF sensor such as tracee")
    .option("--container <id>", "container id/name to filter events")
    .option("--duration <seconds>", "monitor duration", "60")
    .option("-f, --file <path>", "write raw JSONL events to a file")
    .option("--dry-run", "print the tracee command without executing it")
    .action(async (opts) => {
      const args = buildTraceeArgs(opts.container, Number.parseInt(opts.duration, 10) || 60);
      if (opts.dryRun) {
        console.log(`tracee ${args.join(" ")}`);
        return;
      }
      await runTracee(args, opts.file);
    });
}

function buildTraceeArgs(container: string | undefined, durationSeconds: number): string[] {
  const args = ["--output", "json", "--scope", "comm!=tracee"];
  if (container) args.push("--scope", `container=${container}`);
  args.push("--timeout", `${durationSeconds}s`);
  return args;
}

async function runTracee(args: string[], outputFile?: string): Promise<void> {
  if (process.platform !== "linux") {
    logger.warn("eBPF runtime monitoring requires Linux. Use --dry-run to generate the command for a Linux runner.");
    process.exitCode = 1;
    return;
  }

  const out = outputFile ? fs.createWriteStream(outputFile, { flags: "w" }) : null;
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("tracee", args, { stdio: ["ignore", "pipe", "pipe"] });
    proc.stdout.on("data", (chunk: Buffer) => {
      if (out) out.write(chunk);
      else process.stdout.write(chunk);
    });
    proc.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk));
    proc.on("error", reject);
    proc.on("close", (code) => {
      out?.end();
      if (code === 0) resolve();
      else reject(new Error(`tracee exited with code ${code}`));
    });
  }).catch((error) => {
    logger.error(`Runtime monitor failed: ${error}`);
    logger.info("Install Tracee from https://aquasecurity.github.io/tracee/latest/ or run this command in a prepared Linux CI image.");
    process.exitCode = 1;
  });
}
