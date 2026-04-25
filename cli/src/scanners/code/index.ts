import path from "path";
import fg from "fast-glob";
import fs from "fs";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";
import { AUDIT_PATTERNS } from "./patterns.js";

const SCAN_EXTENSIONS = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "rb", "php"];
const IGNORE_DIRS = ["node_modules", ".git", "dist", "build", ".next", "__pycache__"];

export async function runCodeAudit(cwd: string): Promise<Finding[]> {
  logger.section("Static Code Audit");
  const findings: Finding[] = [];

  const pattern = `**/*.{${SCAN_EXTENSIONS.join(",")}}`;
  const files = await fg(pattern, {
    cwd,
    ignore: IGNORE_DIRS.map((d) => `**/${d}/**`),
    absolute: true,
  });

  logger.info(`Scanning ${files.length} source file(s)...`);

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");

    for (const rule of AUDIT_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i]!)) {
          const relativePath = path.relative(cwd, file);
          findings.push({
            id: `code-${rule.id}-${relativePath}:${i + 1}`,
            title: rule.title,
            severity: rule.severity,
            category: "code",
            description: rule.description,
            remediation: rule.remediation,
            file: relativePath,
            line: i + 1,
            detail: lines[i]!.trim(),
          });
        }
      }
    }
  }

  logger.info(`Found ${findings.length} code issue(s)`);
  return findings;
}
