import { timingSafeEqual } from "crypto";
import { NextRequest, NextResponse } from "next/server";

export interface ScimAuthorization {
  organizationId: string;
}

export function authorizeScim(req: NextRequest): ScimAuthorization | NextResponse {
  if (process.env.ENABLE_SCIM !== "true") {
    return NextResponse.json({ error: "SCIM is not enabled" }, { status: 404 });
  }

  const organizationId = process.env.SCIM_ORGANIZATION_ID;
  const token = process.env.SCIM_BEARER_TOKEN;
  if (!organizationId || !token) {
    return NextResponse.json({ error: "SCIM is not configured" }, { status: 503 });
  }

  const header = req.headers.get("authorization") ?? "";
  const candidate = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!safeTokenEqual(candidate, token)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return { organizationId };
}

export function isScimAuthorized(value: ScimAuthorization | NextResponse): value is ScimAuthorization {
  return !(value instanceof Response);
}

function safeTokenEqual(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
