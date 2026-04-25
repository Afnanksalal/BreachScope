import type { ToolKind } from "./types.js";

export interface KnownTool {
  github?: string;
  kind: ToolKind;
  /** True if this package also has a hosted SaaS component */
  hasSaas?: boolean;
  /** Canonical service name (e.g. "Supabase" for @supabase/supabase-js) */
  displayName?: string;
  /** Known security advisory page */
  advisoryUrl?: string;
}

/**
 * Static registry of well-known npm packages → their GitHub repos and classification.
 * Avoids burning GPT tokens for packages we already know about.
 * Keyed by exact npm package name.
 */
export const KNOWN_TOOLS: Record<string, KnownTool> = {
  // ── Database / BaaS ──────────────────────────────────────────────────────
  "@supabase/supabase-js":     { github: "supabase/supabase-js",        kind: "hybrid", hasSaas: true,  displayName: "Supabase" },
  "@supabase/ssr":             { github: "supabase/ssr",                 kind: "hybrid", hasSaas: true,  displayName: "Supabase SSR" },
  "@supabase/auth-helpers-nextjs": { github: "supabase/auth-helpers",   kind: "hybrid", hasSaas: true,  displayName: "Supabase Auth" },
  "firebase":                  { github: "firebase/firebase-js-sdk",     kind: "hybrid", hasSaas: true,  displayName: "Firebase" },
  "firebase-admin":            { github: "firebase/firebase-admin-node", kind: "hybrid", hasSaas: true,  displayName: "Firebase Admin" },
  "@firebase/app":             { github: "firebase/firebase-js-sdk",     kind: "hybrid", hasSaas: true,  displayName: "Firebase" },
  "mongodb":                   { github: "mongodb/node-mongodb-native",  kind: "oss",                    displayName: "MongoDB" },
  "mongoose":                  { github: "Automattic/mongoose",          kind: "oss",                    displayName: "Mongoose" },
  "pg":                        { github: "brianc/node-postgres",         kind: "oss",                    displayName: "node-postgres" },
  "postgres":                  { github: "porsager/postgres",            kind: "oss",                    displayName: "postgres.js" },
  "@prisma/client":            { github: "prisma/prisma",                kind: "oss",                    displayName: "Prisma" },
  "drizzle-orm":               { github: "drizzle-team/drizzle-orm",     kind: "oss",                    displayName: "Drizzle ORM" },
  "kysely":                    { github: "kysely-org/kysely",            kind: "oss",                    displayName: "Kysely" },
  "redis":                     { github: "redis/node-redis",             kind: "oss",                    displayName: "Redis" },
  "ioredis":                   { github: "redis/ioredis",                kind: "oss",                    displayName: "ioredis" },
  "@upstash/redis":            { github: "upstash/upstash-redis",        kind: "hybrid", hasSaas: true,  displayName: "Upstash Redis" },
  "@upstash/ratelimit":        { github: "upstash/ratelimit",            kind: "hybrid", hasSaas: true,  displayName: "Upstash Ratelimit" },
  "convex":                    { github: "get-convex/convex-js",         kind: "hybrid", hasSaas: true,  displayName: "Convex" },
  "pocketbase":                { github: "pocketbase/js-sdk",            kind: "hybrid", hasSaas: false, displayName: "PocketBase" },
  "@planetscale/database":     { github: "planetscale/database-js",      kind: "hybrid", hasSaas: true,  displayName: "PlanetScale" },
  "@neon-tech/serverless":     { github: "neondatabase/serverless",      kind: "hybrid", hasSaas: true,  displayName: "Neon" },
  "@neondatabase/serverless":  { github: "neondatabase/serverless",      kind: "hybrid", hasSaas: true,  displayName: "Neon" },

  // ── Auth ─────────────────────────────────────────────────────────────────
  "@clerk/nextjs":             { github: "clerk/javascript",             kind: "hybrid", hasSaas: true,  displayName: "Clerk" },
  "@clerk/clerk-react":        { github: "clerk/javascript",             kind: "hybrid", hasSaas: true,  displayName: "Clerk" },
  "@auth0/nextjs-auth0":       { github: "auth0/nextjs-auth0",           kind: "hybrid", hasSaas: true,  displayName: "Auth0" },
  "next-auth":                 { github: "nextauthjs/next-auth",         kind: "oss",                    displayName: "NextAuth.js" },
  "lucia":                     { github: "lucia-auth/lucia",             kind: "oss",                    displayName: "Lucia" },
  "better-auth":               { github: "better-auth/better-auth",      kind: "oss",                    displayName: "Better Auth" },
  "passport":                  { github: "jaredhanson/passport",         kind: "oss",                    displayName: "Passport.js" },
  "jsonwebtoken":              { github: "auth0/node-jsonwebtoken",       kind: "oss",                    displayName: "jsonwebtoken",  advisoryUrl: "https://github.com/auth0/node-jsonwebtoken/security/advisories" },
  "jose":                      { github: "panva/jose",                   kind: "oss",                    displayName: "jose" },

  // ── Payments ─────────────────────────────────────────────────────────────
  "stripe":                    { github: "stripe/stripe-node",           kind: "hybrid", hasSaas: true,  displayName: "Stripe" },
  "@stripe/stripe-js":         { github: "stripe/stripe-js",            kind: "hybrid", hasSaas: true,  displayName: "Stripe.js" },
  "braintree":                 { github: "braintree/braintree_node",     kind: "hybrid", hasSaas: true,  displayName: "Braintree" },
  "paddle-js":                 { github: "PaddleHQ/paddle-js-wrapper",   kind: "hybrid", hasSaas: true,  displayName: "Paddle" },
  "lemonsqueezy":              { kind: "saas", hasSaas: true,            displayName: "Lemon Squeezy" },

  // ── Deployment / Infrastructure ───────────────────────────────────────────
  "@vercel/og":                { github: "vercel/satori",                kind: "hybrid", hasSaas: true,  displayName: "Vercel OG" },
  "@vercel/analytics":         { github: "vercel/analytics",             kind: "hybrid", hasSaas: true,  displayName: "Vercel Analytics" },
  "@vercel/speed-insights":    { github: "vercel/speed-insights",        kind: "hybrid", hasSaas: true,  displayName: "Vercel Speed Insights" },
  "next":                      { github: "vercel/next.js",               kind: "oss",                    displayName: "Next.js" },

  // ── AI & ML ───────────────────────────────────────────────────────────────
  "openai":                    { github: "openai/openai-node",           kind: "hybrid", hasSaas: true,  displayName: "OpenAI" },
  "@anthropic-ai/sdk":         { github: "anthropic-ai/sdk-python",      kind: "hybrid", hasSaas: true,  displayName: "Anthropic" },
  "anthropic":                 { github: "anthropic-ai/sdk-python",      kind: "hybrid", hasSaas: true,  displayName: "Anthropic" },
  "@google/generative-ai":     { kind: "hybrid", hasSaas: true,          displayName: "Google Gemini" },
  "groq-sdk":                  { kind: "hybrid", hasSaas: true,          displayName: "Groq" },
  "@ai-sdk/openai":            { github: "vercel/ai",                    kind: "hybrid", hasSaas: true,  displayName: "Vercel AI SDK" },
  "ai":                        { github: "vercel/ai",                    kind: "oss",                    displayName: "Vercel AI SDK" },
  "langchain":                 { github: "langchain-ai/langchainjs",     kind: "oss",                    displayName: "LangChain" },
  "@langchain/core":           { github: "langchain-ai/langchainjs",     kind: "oss",                    displayName: "LangChain Core" },
  "llamaindex":                { github: "run-llama/LlamaIndexTS",       kind: "oss",                    displayName: "LlamaIndex" },

  // ── Communication & Email ─────────────────────────────────────────────────
  "resend":                    { github: "resend/resend-node",           kind: "hybrid", hasSaas: true,  displayName: "Resend" },
  "nodemailer":                { github: "nodemailer/nodemailer",         kind: "oss",                    displayName: "Nodemailer" },
  "@sendgrid/mail":            { github: "sendgrid/sendgrid-nodejs",     kind: "hybrid", hasSaas: true,  displayName: "SendGrid" },
  "postmark":                  { github: "wildbit/postmark-node",        kind: "hybrid", hasSaas: true,  displayName: "Postmark" },
  "pusher":                    { github: "pusher/pusher-http-node",      kind: "hybrid", hasSaas: true,  displayName: "Pusher" },
  "pusher-js":                 { github: "pusher/pusher-js",             kind: "hybrid", hasSaas: true,  displayName: "Pusher" },
  "socket.io":                 { github: "socketio/socket.io",           kind: "oss",                    displayName: "Socket.IO" },

  // ── Observability & Logging ───────────────────────────────────────────────
  "@sentry/node":              { github: "getsentry/sentry-javascript",  kind: "hybrid", hasSaas: true,  displayName: "Sentry" },
  "@sentry/nextjs":            { github: "getsentry/sentry-javascript",  kind: "hybrid", hasSaas: true,  displayName: "Sentry Next.js" },
  "posthog-js":                { github: "PostHog/posthog-js",           kind: "hybrid", hasSaas: true,  displayName: "PostHog" },
  "posthog-node":              { github: "PostHog/posthog-node",         kind: "hybrid", hasSaas: true,  displayName: "PostHog Node" },
  "@datadog/datadog-api-client": { kind: "hybrid", hasSaas: true,        displayName: "Datadog" },
  "pino":                      { github: "pinojs/pino",                  kind: "oss",                    displayName: "Pino" },
  "winston":                   { github: "winstonjs/winston",            kind: "oss",                    displayName: "Winston" },

  // ── Project Management / Productivity ────────────────────────────────────
  "@linear/sdk":               { github: "linear/linear",               kind: "hybrid", hasSaas: true,  displayName: "Linear" },
  "@notionhq/client":          { github: "makenotion/notion-sdk-js",     kind: "hybrid", hasSaas: true,  displayName: "Notion" },
  "@slack/web-api":            { github: "slackapi/node-slack-sdk",      kind: "hybrid", hasSaas: true,  displayName: "Slack" },

  // ── Storage & CDN ─────────────────────────────────────────────────────────
  "@aws-sdk/client-s3":        { github: "aws/aws-sdk-js-v3",           kind: "hybrid", hasSaas: true,  displayName: "AWS S3" },
  "@aws-sdk/client-ses":       { github: "aws/aws-sdk-js-v3",           kind: "hybrid", hasSaas: true,  displayName: "AWS SES" },
  "aws-sdk":                   { github: "aws/aws-sdk-js",              kind: "hybrid", hasSaas: true,  displayName: "AWS SDK v2" },
  "@google-cloud/storage":     { github: "googleapis/nodejs-storage",   kind: "hybrid", hasSaas: true,  displayName: "GCS" },
  "cloudinary":                { github: "cloudinary/cloudinary_npm",   kind: "hybrid", hasSaas: true,  displayName: "Cloudinary" },
  "@uploadthing/react":        { github: "pingdotgg/uploadthing",        kind: "hybrid", hasSaas: true,  displayName: "UploadThing" },

  // ── Feature Flags ─────────────────────────────────────────────────────────
  "@growthbook/growthbook":    { github: "growthbook/growthbook",        kind: "hybrid", hasSaas: true,  displayName: "GrowthBook" },
  "launchdarkly-js-client-sdk": { kind: "hybrid", hasSaas: true,        displayName: "LaunchDarkly" },

  // ── Security ──────────────────────────────────────────────────────────────
  "bcrypt":                    { github: "kelektiv/node.bcrypt.js",      kind: "oss",                    displayName: "bcrypt" },
  "bcryptjs":                  { github: "dcodeIO/bcrypt.js",            kind: "oss",                    displayName: "bcryptjs" },
  "argon2":                    { github: "ranisalt/node-argon2",         kind: "oss",                    displayName: "argon2" },
  "crypto-js":                 { github: "brix/crypto-js",              kind: "oss",                    displayName: "crypto-js",     advisoryUrl: "https://github.com/brix/crypto-js/security/advisories" },
  "helmet":                    { github: "helmetjs/helmet",              kind: "oss",                    displayName: "Helmet.js" },
  "cors":                      { github: "expressjs/cors",              kind: "oss",                    displayName: "cors" },

  // ── Search ────────────────────────────────────────────────────────────────
  "algoliasearch":             { github: "algolia/algoliasearch-client-javascript", kind: "hybrid", hasSaas: true, displayName: "Algolia" },
  "@elastic/elasticsearch":    { github: "elastic/elasticsearch-js",    kind: "hybrid", hasSaas: true,  displayName: "Elasticsearch" },
  "typesense":                 { github: "typesense/typesense-js",       kind: "hybrid", hasSaas: false, displayName: "Typesense" },

  // ── CMS ───────────────────────────────────────────────────────────────────
  "@sanity/client":            { github: "sanity-io/client",             kind: "hybrid", hasSaas: true,  displayName: "Sanity" },
  "contentful":                { github: "contentful/contentful.js",    kind: "hybrid", hasSaas: true,  displayName: "Contentful" },
  "@directus/sdk":             { github: "directus/directus",           kind: "hybrid", hasSaas: false, displayName: "Directus" },
};

/**
 * Resolve a package name to known tool data. Returns null for unknown packages.
 */
export function resolveKnownTool(packageName: string): KnownTool | null {
  return KNOWN_TOOLS[packageName] ?? null;
}

/**
 * Given a GitHub slug "org/repo", return the npm package name(s) that correspond to it.
 */
export function githubToPackages(slug: string): string[] {
  return Object.entries(KNOWN_TOOLS)
    .filter(([, v]) => v.github === slug)
    .map(([k]) => k);
}
