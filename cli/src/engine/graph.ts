import type { DependencyGraph, ToolKind } from "../core/types.js";

/**
 * Build a visual dependency graph from scanned tools.
 * Used for reporting and cycle detection.
 */
export class DepGraph {
  private nodes = new Map<string, { kind: ToolKind; riskScore: number; depth: number }>();
  private edges = new Set<string>(); // "from→to"

  addNode(id: string, kind: ToolKind, riskScore: number, depth: number): void {
    if (!this.nodes.has(id)) {
      this.nodes.set(id, { kind, riskScore, depth });
    }
  }

  addEdge(from: string, to: string): void {
    this.edges.add(`${from}→${to}`);
  }

  hasNode(id: string): boolean {
    return this.nodes.has(id);
  }

  toJSON(): DependencyGraph {
    return {
      nodes: Array.from(this.nodes.entries()).map(([id, data]) => ({ id, ...data })),
      edges: Array.from(this.edges).map((e) => {
        const [from, to] = e.split("→");
        return { from: from!, to: to! };
      }),
    };
  }
}

/**
 * Filter out packages we never want to recurse into.
 * These are ecosystem-level utilities with no meaningful security surface.
 */
const SKIP_PACKAGES = new Set([
  "tslib", "typescript", "eslint", "prettier", "vitest", "jest",
  "webpack", "vite", "esbuild", "rollup", "turbo",
  "react-dom", "@types/react", "@types/node",
  "lodash", "lodash-es", "ramda", "underscore",
  "date-fns", "moment", "dayjs",
  "clsx", "classnames", "tailwind-merge",
  "zod", "yup", "joi",
  "chalk", "ora", "commander", "inquirer",
  "dotenv", "cross-env",
]);

export function shouldSkipPackage(name: string): boolean {
  if (SKIP_PACKAGES.has(name)) return true;
  // Skip all @types/* packages
  if (name.startsWith("@types/")) return true;
  // Skip test frameworks
  if (/vitest|jest|mocha|chai|sinon|cypress|playwright/.test(name)) return true;
  return false;
}
