import fs from "fs";
import path from "path";
import { Command } from "commander";
import { logger } from "../core/logger.js";

export function makeInitCiCommand(): Command {
  return new Command("init-ci")
    .description("Install BreachScope GitHub Actions workflows for PR, scheduled, and sandbox gates")
    .option("--force", "overwrite existing workflow files")
    .action((opts) => {
      const dir = path.join(process.cwd(), ".github", "workflows");
      fs.mkdirSync(dir, { recursive: true });
      writeWorkflow(path.join(dir, "breachscope-pr.yml"), prWorkflow(), Boolean(opts.force));
      writeWorkflow(path.join(dir, "breachscope-scheduled.yml"), scheduledWorkflow(), Boolean(opts.force));
      writeWorkflow(path.join(dir, "breachscope-sandbox.yml"), sandboxWorkflow(), Boolean(opts.force));
      writeWorkflow(path.join(dir, "breachscope-dependabot-automerge.yml"), dependabotAutomergeWorkflow(), Boolean(opts.force));
      logger.success("Installed BreachScope GitHub Actions workflows.");
    });
}

function dependabotAutomergeWorkflow(): string {
  return `name: BreachScope Dependabot Auto-Merge

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: write
  pull-requests: write

jobs:
  safe-dependency-update:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g breachscope
      - run: breachscope scan --ci --fail-on high --new-findings-only --baseline breachscope-baseline.json
        env:
          BREACHSCOPE_API_KEY: \${{ secrets.BREACHSCOPE_API_KEY }}
      - run: gh pr merge --auto --squash "$PR_URL"
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          PR_URL: \${{ github.event.pull_request.html_url }}
`;
}

function writeWorkflow(file: string, contents: string, force: boolean): void {
  if (fs.existsSync(file) && !force) {
    logger.warn(`${path.relative(process.cwd(), file)} exists; use --force to overwrite.`);
    return;
  }
  fs.writeFileSync(file, contents, "utf-8");
}

function prWorkflow(): string {
  return `name: BreachScope PR Gate

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  breachscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g breachscope
      - run: breachscope scan --ci --fail-on high --baseline breachscope-baseline.json --new-findings-only --output sarif --file breachscope.sarif
        env:
          BREACHSCOPE_API_KEY: \${{ secrets.BREACHSCOPE_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: breachscope.sarif
`;
}

function scheduledWorkflow(): string {
  return `name: BreachScope Scheduled Audit

on:
  schedule:
    - cron: "17 4 * * *"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g breachscope
      - run: breachscope scan --ci --fail-on critical --output json --file breachscope-results.json
        env:
          BREACHSCOPE_API_KEY: \${{ secrets.BREACHSCOPE_API_KEY }}
`;
}

function sandboxWorkflow(): string {
  return `name: BreachScope Sandbox Gate

on:
  workflow_dispatch:
  pull_request:
    branches: [main, master]

permissions:
  contents: read

jobs:
  sandbox:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g breachscope
      - run: breachscope sandbox --bug --ci --output json --file breachscope-sandbox.json
        env:
          BREACHSCOPE_API_KEY: \${{ secrets.BREACHSCOPE_API_KEY }}
          OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
`;
}
