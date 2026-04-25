import chalk, { type ChalkInstance } from "chalk";

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type Level = keyof typeof LEVELS;

let _verbose = false;
let _level: Level = "info";

export const logger = {
  setVerbose(v: boolean) { _verbose = v; if (v) _level = "debug"; },

  debug(...args: unknown[]) {
    if (_verbose) console.log(chalk.gray("[debug]"), ...args);
  },

  info(...args: unknown[]) {
    if (LEVELS[_level] <= LEVELS.info) console.log(chalk.blue("  ›"), ...args);
  },

  success(...args: unknown[]) {
    console.log(chalk.green("  ✓"), ...args);
  },

  warn(...args: unknown[]) {
    console.warn(chalk.yellow("  ⚠"), ...args);
  },

  error(...args: unknown[]) {
    console.error(chalk.red("  ✗"), ...args);
  },

  finding(severity: string, title: string) {
    const colors: Record<string, ChalkInstance> = {
      critical: chalk.bgRed.white,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.cyan,
      info: chalk.gray,
    };
    const badge = (colors[severity] ?? chalk.white)(` ${severity.toUpperCase()} `);
    console.log(`  ${badge}  ${title}`);
  },

  section(title: string) {
    console.log("\n" + chalk.bold.white(`── ${title} `) + chalk.gray("─".repeat(Math.max(0, 50 - title.length))));
  },

  blank() { console.log(); },
};
