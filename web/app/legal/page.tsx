import type { Metadata } from "next";
import { LegalLinkGrid, LegalPage, LegalSection } from "@/components/LegalPage";

const APP_URL = "https://breachscoope.vercel.app";

export const metadata: Metadata = {
  title: "Legal - BreachScope",
  description: "BreachScope legal center with terms, privacy, acceptable use, data protection, and security policy documents.",
  alternates: {
    canonical: `${APP_URL}/legal`,
  },
};

export default function LegalIndexPage() {
  return (
    <LegalPage
      title="Legal center"
      description="Plain-language policies for using BreachScope, connecting customer-owned services, and understanding how data is handled."
    >
      <LegalSection title="Policy Library">
        <LegalLinkGrid />
      </LegalSection>

      <LegalSection title="Customer-Owned Services">
        <p>
          BreachScope provides a platform for scanning, release evidence, triage, audit logs, and integration routing. Users bring their own third-party accounts and credentials for services such as GitHub, Slack, Jira, Linear, PagerDuty, OpenAI, Firecrawl, cloud providers, and incident tools.
        </p>
        <p>
          The platform does not provide third-party credentials, does not authorize scans against systems the user does not control, and does not replace the terms or security requirements of connected providers.
        </p>
      </LegalSection>

      <LegalSection title="Public And Private Surfaces">
        <p>
          Public pages include the homepage, docs, roadmap, legal policies, sitemap, robots policy, and AI-readable product files. Dashboard, API, login, and CLI auth routes are private or operational surfaces and are blocked from crawlers in robots.txt.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
