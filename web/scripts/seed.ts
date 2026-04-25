import "dotenv/config";
import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";
import * as schema from "../lib/schema";
import { generateApiKey } from "../lib/api-keys";
import { encrypt } from "../lib/crypto";

const SEED_EMAIL = process.env["SEED_EMAIL"];
if (!SEED_EMAIL) throw new Error("SEED_EMAIL env var required for seeding");

const SEED_PASSWORD = process.env["SEED_PASSWORD"];

async function main() {
  const url = process.env["DATABASE_URL"];
  if (!url) throw new Error("DATABASE_URL is not set");

  const sql = neon(url);
  const db = drizzle(sql, { schema });

  const passwordHash = SEED_PASSWORD ? await bcrypt.hash(SEED_PASSWORD, 12) : undefined;

  // Upsert seed user
  const [user] = await db
    .insert(schema.users)
    .values({ email: SEED_EMAIL!, name: "Dev User", passwordHash })
    .onConflictDoUpdate({
      target: schema.users.email,
      set: { name: "Dev User", ...(passwordHash ? { passwordHash } : {}) },
    })
    .returning();

  if (!user) throw new Error("Failed to upsert seed user");

  console.log(`Seed user: ${user.id} (${user.email})`);

  // Seed an API key
  const { fullKey, prefix, hash } = generateApiKey();
  await db
    .insert(schema.apiKeys)
    .values({ userId: user.id, name: "dev-key", keyHash: hash, keyPrefix: prefix })
    .onConflictDoNothing();

  console.log(`API key (save this — shown once): ${fullKey}`);

  // Seed settings (only if OPENAI_API_KEY and FIRECRAWL_API_KEY are set)
  const openaiRaw = process.env["SEED_OPENAI_KEY"];
  const firecrawlRaw = process.env["SEED_FIRECRAWL_KEY"];

  await db
    .insert(schema.userSettings)
    .values({
      userId: user.id,
      openaiKeyEnc: openaiRaw ? encrypt(openaiRaw) : null,
      firecrawlKeyEnc: firecrawlRaw ? encrypt(firecrawlRaw) : null,
      defaultMode: "basic",
      defaultScanMode: "all",
    })
    .onConflictDoUpdate({
      target: schema.userSettings.userId,
      set: {
        openaiKeyEnc: openaiRaw ? encrypt(openaiRaw) : null,
        firecrawlKeyEnc: firecrawlRaw ? encrypt(firecrawlRaw) : null,
      },
    });

  // Seed a completed scan with findings
  const [scan] = await db
    .insert(schema.scans)
    .values({
      userId: user.id,
      project: "example-app",
      mode: "basic",
      scanMode: "all",
      startedAt: new Date(Date.now() - 120_000),
      completedAt: new Date(),
      findingsTotal: 3,
      findingsCritical: 1,
      findingsHigh: 1,
      findingsMedium: 1,
      findingsLow: 0,
      toolsScanned: 12,
    })
    .returning();

  if (!scan) throw new Error("Failed to insert seed scan");

  await db.insert(schema.findings).values([
    {
      scanId: scan.id,
      title: "Hardcoded API key in source",
      severity: "critical",
      category: "code",
      description: "An OpenAI API key is committed directly in src/config.ts.",
      remediation: "Rotate the key immediately and move it to an environment variable.",
      file: "src/config.ts",
      line: 12,
    },
    {
      scanId: scan.id,
      title: "Outdated dependency with known CVE",
      severity: "high",
      category: "dependency",
      description: "lodash@4.17.20 has CVE-2021-23337 (command injection via template).",
      remediation: "Upgrade lodash to ^4.17.21.",
      tool: "lodash",
    },
    {
      scanId: scan.id,
      title: "Deprecated Node.js TLS option in use",
      severity: "medium",
      category: "toolchain",
      description: "NODE_TLS_REJECT_UNAUTHORIZED=0 found in .env.production.",
      remediation: "Remove the flag; use proper certificate configuration.",
      file: ".env.production",
    },
  ]);

  console.log(`Seed scan: ${scan.id} with 3 findings`);
  console.log("Seeding complete.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
