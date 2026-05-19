import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/LegalPage";

const APP_URL = "https://breachscoope.vercel.app";

export const metadata: Metadata = {
  title: "Acceptable Use - BreachScope",
  description: "Acceptable use rules for BreachScope security scanning, sandbox testing, integrations, and customer-owned provider accounts.",
  alternates: {
    canonical: `${APP_URL}/acceptable-use`,
  },
};

export default function AcceptableUsePage() {
  return (
    <LegalPage
      title="Acceptable Use Policy"
      description="Boundaries for scanning, sandbox testing, integrations, and customer-owned provider credentials."
    >
      <LegalSection title="Authorized Use Only">
        <p>
          Use BreachScope only for assets, accounts, repositories, applications, and networks you own or have explicit permission to test. You are responsible for documenting authorization before running scans, probes, sandbox testing, or integrations.
        </p>
      </LegalSection>

      <LegalSection title="Prohibited Activity">
        <ul className="list-disc space-y-2 pl-5">
          <li>Scanning, probing, exploiting, or collecting data from unauthorized systems.</li>
          <li>Credential theft, credential stuffing, phishing, token harvesting, or session abuse.</li>
          <li>Malware, persistence, destructive payloads, data exfiltration, or unauthorized privilege escalation.</li>
          <li>Bypassing rate limits, access controls, provider terms, or platform safeguards.</li>
          <li>Using integrations to spam, harass, impersonate, or send misleading incident notifications.</li>
          <li>Uploading unlawful content, sensitive data you are not authorized to process, or secrets that active testing does not require.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Sandbox And Active Testing">
        <p>
          Sandbox features may run active probes inside isolated environments. Use them against disposable test environments or targets that explicitly allow that activity. Secrets are excluded by default; include real secrets only when the test is authorized and the environment is disposable.
        </p>
      </LegalSection>

      <LegalSection title="Provider Rules">
        <p>
          You must follow the terms, acceptable use rules, rate limits, and security requirements of every connected provider. BreachScope does not grant permission to use Slack, GitHub, Jira, Linear, PagerDuty, OpenAI, Firecrawl, cloud, or repository services.
        </p>
      </LegalSection>

      <LegalSection title="Enforcement">
        <p>
          Activity that creates security risk, legal risk, service disruption, provider abuse, or harm to third parties may result in throttling, suspension, deletion, or referral to the appropriate contact path.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
