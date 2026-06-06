import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/LegalPage";
import { APP_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Privacy - BreachScope",
  description: "Privacy policy for BreachScope, including data categories, purposes, retention, sharing, rights, and customer-owned provider keys.",
  alternates: {
    canonical: `${APP_URL}/privacy`,
  },
};

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacy Policy"
      description="How BreachScope handles account data, scan data, logs, settings, and optional customer-supplied provider keys."
    >
      <LegalSection title="Data We Collect">
        <p>
          We collect account information, authentication records, project and repository metadata, scan records, findings, policy records, integration metadata, API key metadata, audit logs, settings, and support or security communications you send to us.
        </p>
        <p>
          If you choose to save provider keys for workflows such as model-assisted analysis, web intelligence, notifications, or ticket routing, those keys are customer-supplied and encrypted before storage.
        </p>
      </LegalSection>

      <LegalSection title="How We Use Data">
        <ul className="list-disc space-y-2 pl-5">
          <li>Provide CLI authentication, dashboard access, project management, and scan ingestion.</li>
          <li>Store findings, triage decisions, policy results, evidence exports, and audit history.</li>
          <li>Run customer-enabled integrations with customer-owned credentials.</li>
          <li>Protect the service through rate limiting, abuse prevention, monitoring, and security investigations.</li>
          <li>Maintain documentation, legal notices, product quality, and operational support.</li>
        </ul>
      </LegalSection>

      <LegalSection title="What We Do Not Do">
        <p>
          We do not provide third-party service accounts or credentials. We do not intentionally publish dashboard, API, login, or CLI auth data to crawlers. We do not use saved provider keys for workflows you have not enabled.
        </p>
      </LegalSection>

      <LegalSection title="Sharing And Providers">
        <p>
          We may share data with infrastructure, authentication, database, analytics, email, hosting, storage, logging, security, and support providers that help operate BreachScope. Customer-enabled integrations may send selected findings or notifications to providers you configure.
        </p>
        <p>
          Public product pages, legal pages, sitemap, robots policy, and AI-readable product files may be indexed. Private dashboard and API routes are disallowed for crawlers.
        </p>
      </LegalSection>

      <LegalSection title="Retention And Deletion">
        <p>
          Account records, scan records, findings, settings, and audit logs are retained while needed to provide the service, meet security needs, resolve disputes, comply with legal obligations, or preserve audit history. You can delete scan data in dashboard settings where the feature is available.
        </p>
      </LegalSection>

      <LegalSection title="Security">
        <p>
          API keys are hashed where they are used for authentication. Saved provider keys are encrypted at rest. Scan upload payloads are validated and size-limited. Sandbox scans exclude local environment files by default.
        </p>
      </LegalSection>

      <LegalSection title="Your Choices And Rights">
        <p>
          Depending on your location, you may have rights to access, correct, delete, restrict, export, object to processing, or withdraw consent where consent is the basis for processing. Contact the project maintainer or service operator listed in the repository for privacy requests.
        </p>
      </LegalSection>

      <LegalSection title="Changes">
        <p>
          We will update this policy when data practices materially change. New data uses should be reflected here before they begin.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
