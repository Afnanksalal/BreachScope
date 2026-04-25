// Bundles the ESM TypeScript output into a single CJS file for pkg.
// Run: node bundle.mjs
import { build } from "esbuild";
import { existsSync, mkdirSync, realpathSync } from "fs";
import { resolve } from "path";

if (!existsSync("bundle")) mkdirSync("bundle");

const chalkVendor = resolve("node_modules/chalk/source/vendor");

await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  outfile: "bundle/index.cjs",
  external: [
    "playwright", "playwright-core",  // browser binaries must be installed separately
    "tiktoken",                        // WASM — handled via pkg assets
    "open",                            // ships xdg-open shell script — handled via pkg assets
  ],
  // Explicitly resolve chalk v5's package-imports (#ansi-styles, #supports-color)
  // so pkg never sees the bare # specifiers in the bundle
  alias: {
    "#ansi-styles":    `${chalkVendor}/ansi-styles/index.js`,
    "#supports-color": `${chalkVendor}/supports-color/index.js`,
  },
  conditions: ["node", "require", "default"],
  logLevel: "warning",
});

console.log("Bundle written to bundle/index.cjs");
