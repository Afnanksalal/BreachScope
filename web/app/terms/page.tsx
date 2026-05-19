import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/LegalPage";

const APP_URL = "https://breachscoope.vercel.app";

export const metadata: Metadata = {
  title: "Terms - BreachScope",
  description: "Terms for using BreachScope, including account responsibilities, authorized scanning, customer content, and third-party integrations.",
  alternates: {
    canonical: `${APP_URL}/terms`,
  },
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Terms of Service"
      description="The rules for using BreachScope, connecting your own systems, and running security workflows through the platform."
    >
      <LegalSection title="Using BreachScope">
        <p>
          BreachScope is a security workflow for local scans, CI policy gates, dashboard evidence, finding triage, audit logs, and integration routing. You may use the service only for systems, repositories, accounts, networks, and applications you own or are authorized to test.
        </p>
        <p>
          You are responsible for your account activity, access credentials, scan targets, submitted content, and compliance with laws, provider terms, and internal authorization requirements.
        </p>
      </LegalSection>

      <LegalSection title="Customer Content And Credentials">
        <p>
          Customer content includes scan inputs, scan results, findings, projects, policies, integration metadata, audit logs, settings, comments, and files or URLs submitted to BreachScope. You retain your rights in customer content.
        </p>
        <p>
          Third-party accounts and credentials are customer-owned. BreachScope does not provide Slack, GitHub, Jira, Linear, PagerDuty, OpenAI, Firecrawl, cloud, repository, or incident-management accounts. If you save provider keys, BreachScope stores them encrypted and uses them only to provide the workflows you enable.
        </p>
      </LegalSection>

      <LegalSection title="Security Testing">
        <p>
          You must not scan, probe, exploit, overload, or collect data from targets without permission. Sandbox and active testing features are intended for disposable test environments or authorized assets. You are responsible for excluding secrets when active testing does not require them.
        </p>
      </LegalSection>

      <LegalSection title="Service Changes And Availability">
        <p>
          BreachScope may change features, limits, routes, documentation, and policies as the product evolves. The service may be interrupted for maintenance, security updates, provider outages, or operational reasons.
        </p>
      </LegalSection>

      <LegalSection title="Disclaimers And Liability">
        <p>
          Security tools can miss issues, report false positives, or depend on third-party data that changes over time. BreachScope does not guarantee that a project is vulnerability-free or compliant with every law, standard, or contract.
        </p>
        <p>
          To the maximum extent allowed by law, BreachScope is provided without warranties, and liability is limited to the amount permitted by applicable law and the license or agreement that governs your use.
        </p>
      </LegalSection>

      <LegalSection title="Termination">
        <p>
          Access may be suspended or terminated for policy violations, security risk, unlawful use, non-payment where applicable, or conduct that threatens the platform, users, providers, or third parties.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
