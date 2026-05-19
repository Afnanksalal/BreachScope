import { NextRequest, NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";
import { users } from "@/lib/schema";
import { clientIp, rateLimit } from "@/lib/rate-limit";

export async function POST(req: NextRequest) {
  const limited = await rateLimit(`register:${clientIp(req)}`, 5, 15 * 60 * 1000);
  if (!limited.ok) {
    return NextResponse.json({ error: "Too many registration attempts" }, { status: 429 });
  }

  const body: unknown = await req.json().catch(() => null);
  if (typeof body !== "object" || body === null) {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }
  const { email, password, name } = body as Record<string, unknown>;

  const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }
  if (typeof password !== "string" || password.length < 12 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return NextResponse.json({ error: "Password must be at least 12 characters and include letters and numbers" }, { status: 400 });
  }

  const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, normalizedEmail)).limit(1);
  if (existing) {
    return NextResponse.json({ ok: true }, { status: 202 });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const [user] = await db
    .insert(users)
    .values({ email: normalizedEmail, name: typeof name === "string" ? name.slice(0, 120) : undefined, passwordHash })
    .returning({ id: users.id, email: users.email });

  if (!user) return NextResponse.json({ error: "Failed to create account" }, { status: 500 });

  return NextResponse.json({ ok: true }, { status: 201 });
}
