import { NextResponse } from "next/server";

export async function GET(): Promise<NextResponse> {
  const entityId = process.env.SAML_ENTITY_ID ?? "https://breachscope.local/saml";
  const acsUrl = process.env.SAML_ACS_URL ?? "https://breachscope.local/api/saml/acs";
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${escapeXml(entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${escapeXml(acsUrl)}" index="1" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
  return new NextResponse(xml, {
    headers: { "Content-Type": "application/samlmetadata+xml" },
  });
}

function escapeXml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
