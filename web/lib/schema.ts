import {
  pgTable, uuid, text, timestamp, integer, index, uniqueIndex, primaryKey,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import type { AdapterAccountType } from "next-auth/adapters";

// ─── Users ────────────────────────────────────────────────────────────────────
export const users = pgTable("users", {
  id:            uuid("id").primaryKey().defaultRandom(),
  email:         text("email").notNull().unique(),
  name:          text("name"),
  image:         text("image"),
  emailVerified: timestamp("email_verified", { mode: "date" }),
  passwordHash:  text("password_hash"),   // null for OAuth-only users
  avatarUrl:     text("avatar_url"),
  createdAt:     timestamp("created_at").defaultNow().notNull(),
});

// ─── Auth accounts — exact NextAuth DrizzleAdapter schema ────────────────────
export const accounts = pgTable("accounts", {
  userId:            uuid("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  type:              text("type").$type<AdapterAccountType>().notNull(),
  provider:          text("provider").notNull(),
  providerAccountId: text("providerAccountId").notNull(),
  refresh_token:     text("refresh_token"),
  access_token:      text("access_token"),
  expires_at:        integer("expires_at"),
  token_type:        text("token_type"),
  scope:             text("scope"),
  id_token:          text("id_token"),
  session_state:     text("session_state"),
}, (t) => [primaryKey({ columns: [t.provider, t.providerAccountId] })]);

// ─── Sessions — sessionToken is the PK (NextAuth DrizzleAdapter requirement) ─
export const sessions = pgTable("sessions", {
  sessionToken: text("sessionToken").primaryKey(),
  userId:       uuid("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  expires:      timestamp("expires", { mode: "date" }).notNull(),
});

// ─── CLI device auth (device flow for `breachscope login`) ────────────────────
export const cliAuthStates = pgTable("cli_auth_states", {
  id:        uuid("id").primaryKey().defaultRandom(),
  state:     text("state").notNull().unique(),
  userId:    uuid("user_id").references(() => users.id, { onDelete: "cascade" }),
  token:     text("token"),            // populated once user authenticates
  expiresAt: timestamp("expires_at").notNull(),
  usedAt:    timestamp("used_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (t) => [index("cli_auth_state_idx").on(t.state)]);

// ─── API Keys (for CLI → Dashboard communication) ─────────────────────────────
export const apiKeys = pgTable("api_keys", {
  id:          uuid("id").primaryKey().defaultRandom(),
  userId:      uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  name:        text("name").notNull(),
  keyHash:     text("key_hash").notNull().unique(),  // sha256 of the full key
  keyPrefix:   text("key_prefix").notNull(),         // first 12 chars (for display)
  lastUsedAt:  timestamp("last_used_at"),
  revokedAt:   timestamp("revoked_at"),
  createdAt:   timestamp("created_at").defaultNow().notNull(),
}, (t) => [index("api_keys_user_idx").on(t.userId)]);

// ─── User settings (encrypted external API keys) ──────────────────────────────
export const userSettings = pgTable("user_settings", {
  userId:              uuid("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  openaiKeyEnc:        text("openai_key_enc"),     // AES-256-GCM encrypted
  firecrawlKeyEnc:     text("firecrawl_key_enc"),
  defaultMode:         text("default_mode").default("basic"),
  defaultScanMode:     text("default_scan_mode").default("all"),
  updatedAt:           timestamp("updated_at").defaultNow().notNull(),
});

// ─── Scans ────────────────────────────────────────────────────────────────────
export const scans = pgTable("scans", {
  id:               uuid("id").primaryKey().defaultRandom(),
  userId:           uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  apiKeyId:         uuid("api_key_id").references(() => apiKeys.id, { onDelete: "set null" }),
  project:          text("project"),
  mode:             text("mode").notNull(),       // basic | major | deep
  scanMode:         text("scan_mode").notNull(),  // breach | bug | all
  target:           text("target"),
  url:              text("url"),
  startedAt:        timestamp("started_at").notNull(),
  completedAt:      timestamp("completed_at"),
  findingsTotal:    integer("findings_total").default(0),
  findingsCritical: integer("findings_critical").default(0),
  findingsHigh:     integer("findings_high").default(0),
  findingsMedium:   integer("findings_medium").default(0),
  findingsLow:      integer("findings_low").default(0),
  toolsScanned:     integer("tools_scanned").default(0),
  createdAt:        timestamp("created_at").defaultNow().notNull(),
}, (t) => [index("scans_user_idx").on(t.userId)]);

// ─── Findings ─────────────────────────────────────────────────────────────────
export const findings = pgTable("findings", {
  id:          uuid("id").primaryKey().defaultRandom(),
  scanId:      uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  title:       text("title").notNull(),
  severity:    text("severity").notNull(),
  category:    text("category").notNull(),
  description: text("description").notNull(),
  remediation: text("remediation"),
  tool:        text("tool"),
  file:        text("file"),
  line:        integer("line"),
  references:  text("references"),   // JSON array stored as text
  createdAt:   timestamp("created_at").defaultNow().notNull(),
}, (t) => [index("findings_scan_idx").on(t.scanId)]);

// ─── Relations ────────────────────────────────────────────────────────────────
export const usersRelations = relations(users, ({ many, one }) => ({
  accounts:    many(accounts),
  sessions:    many(sessions),
  apiKeys:     many(apiKeys),
  scans:       many(scans),
  settings:    one(userSettings, { fields: [users.id], references: [userSettings.userId] }),
}));

export const scansRelations = relations(scans, ({ many, one }) => ({
  findings: many(findings),
  apiKey:   one(apiKeys, { fields: [scans.apiKeyId], references: [apiKeys.id] }),
  user:     one(users, { fields: [scans.userId], references: [users.id] }),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  scan: one(scans, { fields: [findings.scanId], references: [scans.id] }),
}));

// ─── Types ────────────────────────────────────────────────────────────────────
export type User = typeof users.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type UserSettings = typeof userSettings.$inferSelect;
