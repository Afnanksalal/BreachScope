import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import type { BreachScopeConfig } from "./types.js";

const CONFIG_FILES = [
  "breachscope.yaml",
  "breachscope.yml",
  "breachscope.json",
  ".breachscope.yaml",
  ".breachscope.yml",
];

const DEFAULTS: BreachScopeConfig = {
  version: "1",
  targets: ["all"],
  toolchain: {},
  output: { format: "console", verbose: false },
  thresholds: { failOn: "high" },
};

export function loadConfig(configPath?: string): BreachScopeConfig {
  const filePath = configPath ?? findConfigFile();
  if (!filePath) return { ...DEFAULTS };

  const raw = fs.readFileSync(filePath, "utf-8");
  const parsed = filePath.endsWith(".json")
    ? JSON.parse(raw)
    : yaml.load(raw);

  return deepMerge(DEFAULTS, parsed as Partial<BreachScopeConfig>);
}

function findConfigFile(): string | null {
  let dir = process.cwd();
  while (true) {
    for (const name of CONFIG_FILES) {
      const candidate = path.join(dir, name);
      if (fs.existsSync(candidate)) return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function deepMerge<T extends object>(base: T, override: Partial<T>): T {
  const result = { ...base };
  for (const key of Object.keys(override) as (keyof T)[]) {
    const v = override[key];
    if (v !== undefined && typeof v === "object" && !Array.isArray(v)) {
      result[key] = deepMerge(base[key] as object, v as object) as T[keyof T];
    } else if (v !== undefined) {
      result[key] = v as T[keyof T];
    }
  }
  return result;
}

export function generateConfig(dest: string): void {
  const template = `# BreachScope configuration
version: "1"
project: "my-project"

targets:
  - all  # dependency | toolchain | code | blackbox | smoke | all

toolchain:
  supabase:
    url: ""          # or set SUPABASE_URL env var
    anonKey: ""      # or set SUPABASE_ANON_KEY env var
  vercel:
    token: ""        # or set VERCEL_TOKEN env var
  github:
    token: ""        # or set GITHUB_TOKEN env var

# AI multi-agent mode (breachscope scan --ai)
# Keys can also be set as environment variables
ai:
  openaiApiKey: ""     # or set OPENAI_API_KEY env var
  firecrawlApiKey: "" # or set FIRECRAWL_API_KEY env var
  model: gpt-4o        # gpt-4o | gpt-4o-mini
  maxTokensPerAgent: 4096

output:
  format: console    # console | json | html | sarif
  verbose: false

thresholds:
  failOn: high       # critical | high | medium | low
`;
  fs.writeFileSync(dest, template, "utf-8");
}
