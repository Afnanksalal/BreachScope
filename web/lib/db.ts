import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema";

function databaseUrl(): string | undefined {
  return process.env["DATABASE_URL"]?.trim() || undefined;
}

function createDb(url = databaseUrl()) {
  if (!url) {
    throw new Error("DATABASE_URL is required for database access.");
  }

  const sql = neon(url);
  return drizzle(sql, { schema });
}

let dbInstance: ReturnType<typeof createDb> | undefined = databaseUrl() ? createDb() : undefined;

export function hasDatabaseUrl(): boolean {
  return Boolean(databaseUrl());
}

export function getDb(): ReturnType<typeof createDb> {
  dbInstance ??= createDb();
  return dbInstance;
}

const dbProxy = new Proxy({} as ReturnType<typeof createDb>, {
  get(_target, prop) {
    const instance = getDb();
    const value = Reflect.get(instance, prop, instance) as unknown;
    return typeof value === "function" ? value.bind(instance) : value;
  },
});

export const db = dbInstance ?? dbProxy;

export type DB = typeof db;
