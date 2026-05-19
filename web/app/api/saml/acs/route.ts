import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const form = await req.formData().catch(() => null);
  const samlResponse = form?.get("SAMLResponse");
  if (typeof samlResponse !== "string" || samlResponse.length === 0) {
    return NextResponse.json({ error: "Missing SAMLResponse" }, { status: 400 });
  }

  return NextResponse.json({
    error: "SAML assertion validation is not configured",
    detail: "Set up a production SAML validator with IdP certificate pinning before enabling SSO login.",
  }, { status: 501 });
}
