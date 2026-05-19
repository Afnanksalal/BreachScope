import {
  pgTable, uuid, text, timestamp, integer, boolean, jsonb, index, uniqueIndex, primaryKey,
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

// Tenancy and project controls
export const organizations = pgTable("organizations", {
  id:        uuid("id").primaryKey().defaultRandom(),
  name:      text("name").notNull(),
  slug:      text("slug").notNull().unique(),
  ssoDomain: text("sso_domain"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const organizationMembers = pgTable("organization_members", {
  organizationId: uuid("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  userId:         uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role:           text("role").notNull().default("member"), // owner | admin | security | auditor | member
  createdAt:      timestamp("created_at").defaultNow().notNull(),
}, (t) => [
  primaryKey({ columns: [t.organizationId, t.userId] }),
  index("organization_members_user_idx").on(t.userId),
]);

export const projects = pgTable("projects", {
  id:             uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  ownerUserId:    uuid("owner_user_id").references(() => users.id, { onDelete: "cascade" }),
  name:           text("name").notNull(),
  slug:           text("slug").notNull(),
  repositoryUrl:  text("repository_url"),
  defaultBranch:  text("default_branch").default("main"),
  createdAt:      timestamp("created_at").defaultNow().notNull(),
}, (t) => [
  uniqueIndex("projects_org_slug_idx").on(t.organizationId, t.slug),
  index("projects_owner_idx").on(t.ownerUserId),
]);

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
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:   uuid("project_id").references(() => projects.id, { onDelete: "cascade" }),
  name:        text("name").notNull(),
  scopes:      jsonb("scopes").$type<string[]>().default([]),
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
  sandboxScanMode:     text("sandbox_scan_mode").default("all"),
  sandboxDeep:         text("sandbox_deep").default("false"),
  updatedAt:           timestamp("updated_at").defaultNow().notNull(),
});

// ─── Scans ────────────────────────────────────────────────────────────────────
export const scans = pgTable("scans", {
  id:               uuid("id").primaryKey().defaultRandom(),
  userId:           uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  organizationId:   uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:        uuid("project_id").references(() => projects.id, { onDelete: "set null" }),
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
  riskData:         text("risk_data"),    // JSON array of ToolRiskEntry[]
  probeData:        text("probe_data"),   // JSON ProbeActivity (service probes + attack probe steps)
  aiReport:         text("ai_report"),    // JSON AISynthesis: executiveSummary, topPriority, attackChains
  createdAt:        timestamp("created_at").defaultNow().notNull(),
}, (t) => [
  index("scans_user_idx").on(t.userId),
  index("scans_project_idx").on(t.projectId),
  index("scans_created_idx").on(t.createdAt),
]);

// ─── Findings ─────────────────────────────────────────────────────────────────
export const findings = pgTable("findings", {
  id:          uuid("id").primaryKey().defaultRandom(),
  scanId:      uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  title:       text("title").notNull(),
  severity:    text("severity").notNull(),
  category:    text("category").notNull(),
  description: text("description").notNull(),
  detail:      text("detail"),        // matched code line or raw evidence snippet
  remediation: text("remediation"),
  tool:        text("tool"),
  file:        text("file"),
  line:        integer("line"),
  references:  text("references"),   // JSON array stored as text
  fingerprint: text("fingerprint"),
  status:      text("status").default("open"),
  assigneeId:  uuid("assignee_id").references(() => users.id, { onDelete: "set null" }),
  dueAt:       timestamp("due_at"),
  acceptedRiskReason: text("accepted_risk_reason"),
  suppressedUntil: timestamp("suppressed_until"),
  vexStatus:   text("vex_status"),
  compliance:  jsonb("compliance").$type<string[]>(),
  createdAt:   timestamp("created_at").defaultNow().notNull(),
}, (t) => [
  index("findings_scan_idx").on(t.scanId),
  index("findings_fingerprint_idx").on(t.fingerprint),
  index("findings_status_idx").on(t.status),
]);

export const policies = pgTable("policies", {
  id:             uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:      uuid("project_id").references(() => projects.id, { onDelete: "cascade" }),
  name:           text("name").notNull(),
  enabled:        boolean("enabled").default(true).notNull(),
  document:       jsonb("document").$type<Record<string, unknown>>().notNull(),
  createdAt:      timestamp("created_at").defaultNow().notNull(),
  updatedAt:      timestamp("updated_at").defaultNow().notNull(),
}, (t) => [
  index("policies_org_idx").on(t.organizationId),
  index("policies_project_idx").on(t.projectId),
]);

export const integrations = pgTable("integrations", {
  id:             uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:      uuid("project_id").references(() => projects.id, { onDelete: "cascade" }),
  provider:       text("provider").notNull(), // github | gitlab | bitbucket | jira | linear | slack | teams | pagerduty | saml | scim
  name:           text("name").notNull(),
  enabled:        boolean("enabled").default(true).notNull(),
  config:         jsonb("config").$type<Record<string, unknown>>().default({}),
  secretRef:      text("secret_ref"),
  createdAt:      timestamp("created_at").defaultNow().notNull(),
  updatedAt:      timestamp("updated_at").defaultNow().notNull(),
}, (t) => [
  index("integrations_org_idx").on(t.organizationId),
  index("integrations_project_idx").on(t.projectId),
  index("integrations_provider_idx").on(t.provider),
]);

export const integrationDeliveries = pgTable("integration_deliveries", {
  id:             uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:      uuid("project_id").references(() => projects.id, { onDelete: "cascade" }),
  integrationId:  uuid("integration_id").references(() => integrations.id, { onDelete: "set null" }),
  scanId:         uuid("scan_id").references(() => scans.id, { onDelete: "cascade" }),
  provider:       text("provider").notNull(),
  action:         text("action").notNull().default("notify"),
  status:         text("status").notNull().default("pending"), // pending | delivered | retrying | failed | skipped
  attempts:       integer("attempts").default(0).notNull(),
  maxAttempts:    integer("max_attempts").default(3).notNull(),
  nextAttemptAt:  timestamp("next_attempt_at"),
  deliveredAt:    timestamp("delivered_at"),
  externalUrl:    text("external_url"),
  lastError:      text("last_error"),
  payload:        jsonb("payload").$type<Record<string, unknown>>().default({}),
  createdAt:      timestamp("created_at").defaultNow().notNull(),
  updatedAt:      timestamp("updated_at").defaultNow().notNull(),
}, (t) => [
  index("integration_deliveries_project_idx").on(t.projectId),
  index("integration_deliveries_scan_idx").on(t.scanId),
  index("integration_deliveries_integration_idx").on(t.integrationId),
  index("integration_deliveries_status_idx").on(t.status),
  index("integration_deliveries_next_attempt_idx").on(t.nextAttemptAt),
]);

export const auditLogs = pgTable("audit_logs", {
  id:             uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id, { onDelete: "cascade" }),
  projectId:      uuid("project_id").references(() => projects.id, { onDelete: "set null" }),
  actorUserId:    uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
  action:         text("action").notNull(),
  targetType:     text("target_type").notNull(),
  targetId:       text("target_id"),
  metadata:       jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt:      timestamp("created_at").defaultNow().notNull(),
}, (t) => [
  index("audit_logs_org_idx").on(t.organizationId),
  index("audit_logs_created_idx").on(t.createdAt),
]);

// ─── Relations ────────────────────────────────────────────────────────────────
export const usersRelations = relations(users, ({ many, one }) => ({
  accounts:    many(accounts),
  sessions:    many(sessions),
  apiKeys:     many(apiKeys),
  scans:       many(scans),
  memberships: many(organizationMembers),
  settings:    one(userSettings, { fields: [users.id], references: [userSettings.userId] }),
}));

export const organizationsRelations = relations(organizations, ({ many }) => ({
  members: many(organizationMembers),
  projects: many(projects),
  apiKeys: many(apiKeys),
  scans: many(scans),
  policies: many(policies),
  integrations: many(integrations),
  integrationDeliveries: many(integrationDeliveries),
  auditLogs: many(auditLogs),
}));

export const projectsRelations = relations(projects, ({ one, many }) => ({
  organization: one(organizations, { fields: [projects.organizationId], references: [organizations.id] }),
  owner: one(users, { fields: [projects.ownerUserId], references: [users.id] }),
  scans: many(scans),
  apiKeys: many(apiKeys),
  policies: many(policies),
  integrations: many(integrations),
  integrationDeliveries: many(integrationDeliveries),
}));

export const scansRelations = relations(scans, ({ many, one }) => ({
  findings: many(findings),
  apiKey:   one(apiKeys, { fields: [scans.apiKeyId], references: [apiKeys.id] }),
  user:     one(users, { fields: [scans.userId], references: [users.id] }),
  organization: one(organizations, { fields: [scans.organizationId], references: [organizations.id] }),
  project:  one(projects, { fields: [scans.projectId], references: [projects.id] }),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  scan: one(scans, { fields: [findings.scanId], references: [scans.id] }),
}));

export const integrationDeliveriesRelations = relations(integrationDeliveries, ({ one }) => ({
  organization: one(organizations, { fields: [integrationDeliveries.organizationId], references: [organizations.id] }),
  project: one(projects, { fields: [integrationDeliveries.projectId], references: [projects.id] }),
  integration: one(integrations, { fields: [integrationDeliveries.integrationId], references: [integrations.id] }),
  scan: one(scans, { fields: [integrationDeliveries.scanId], references: [scans.id] }),
}));

// ─── Types ────────────────────────────────────────────────────────────────────
export type User = typeof users.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type UserSettings = typeof userSettings.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type OrganizationMember = typeof organizationMembers.$inferSelect;
export type Project = typeof projects.$inferSelect;
export type Policy = typeof policies.$inferSelect;
export type Integration = typeof integrations.$inferSelect;
export type IntegrationDelivery = typeof integrationDeliveries.$inferSelect;
export type AuditLog = typeof auditLogs.$inferSelect;
