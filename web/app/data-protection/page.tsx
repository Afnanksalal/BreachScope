import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/LegalPage";

const APP_URL = "https://breachscoope.vercel.app";

export const metadata: Metadata = {
  title: "Data Protection - BreachScope",
  description: "Data protection terms for BreachScope, including roles, safeguards, deletion, incidents, subprocessors, and customer-owned credentials.",
  alternates: {
    canonical: `${APP_URL}/data-protection`,
  },
};

export default function DataProtectionPage() {
  return (
    <LegalPage
      title="Data Protection"
      description="Operational data protection terms for BreachScope account data, scan data, logs, settings, and optional customer-owned provider keys."
    >
      <LegalSection title="Roles">
        <p>
          For account, billing where applicable, product analytics, security, and site operations, the service operator generally acts as an independent controller. For scan data, findings, project records, integration metadata, and customer-supplied provider keys processed through the service, the operator generally acts as a processor or service provider on behalf of the customer.
        </p>
      </LegalSection>

      <LegalSection title="Processing Instructions">
        <p>
          BreachScope processes customer data to provide the product, secure the service, troubleshoot issues, comply with law, and complete workflows the customer enables. Customer-enabled workflows may include scan ingestion, policy evaluation, evidence export, notification routing, ticket creation, model-assisted analysis, and web intelligence.
        </p>
      </LegalSection>

      <LegalSection title="Security Measures">
        <ul className="list-disc space-y-2 pl-5">
          <li>Scoped dashboard API keys for automation.</li>
          <li>Hashing for authentication API keys.</li>
          <li>AES-256-GCM encryption for saved provider keys.</li>
          <li>Payload validation and upload size limits.</li>
          <li>Audit logs for sensitive project activity.</li>
          <li>Sandbox defaults that exclude local environment files unless explicitly included.</li>
          <li>Rate limiting support through Upstash Redis configuration.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Subprocessors And Integrations">
        <p>
          BreachScope may use hosting, database, authentication, analytics, logging, email, security, and support providers to operate the service. Customer-enabled integrations send selected data to provider accounts configured by the customer. Customers are responsible for provider terms, credentials, and access scopes.
        </p>
      </LegalSection>

      <LegalSection title="Deletion And Return">
        <p>
          Scan records and findings can be deleted through available dashboard controls. Account, audit, security, and backup records may remain for a limited period where needed for legal, security, continuity, or dispute-resolution reasons.
        </p>
      </LegalSection>

      <LegalSection title="Incidents">
        <p>
          If BreachScope becomes aware of unauthorized access to customer data, the operator should investigate, contain the issue, preserve relevant logs, and notify affected customers without undue delay where notification is required.
        </p>
      </LegalSection>

      <LegalSection title="International Transfers">
        <p>
          Data may be processed in locations where the service, hosting providers, or customer-enabled integrations operate. Customers are responsible for deciding whether connected providers and transfer mechanisms fit their compliance needs.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
