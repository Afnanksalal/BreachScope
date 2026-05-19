import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/LegalPage";

const APP_URL = "https://breachscoope.vercel.app";

export const metadata: Metadata = {
  title: "Security Policy - BreachScope",
  description: "BreachScope security policy with supported versions, vulnerability reporting, scope, response targets, and current security practices.",
  alternates: {
    canonical: `${APP_URL}/security`,
  },
};

export default function SecurityPolicyPage() {
  return (
    <LegalPage
      title="Security Policy"
      description="How to report vulnerabilities, what is in scope, and the current safeguards used across the CLI, dashboard, API, and release workflow."
    >
      <LegalSection title="Supported Versions">
        <div className="overflow-hidden rounded-lg border border-white/[0.08]">
          <table className="w-full text-sm">
            <tbody>
              <tr className="border-b border-white/[0.06]">
                <td className="bg-white/[0.025] px-4 py-3 font-mono text-xs text-white/62">0.3.x</td>
                <td className="px-4 py-3 text-white/52">Current</td>
              </tr>
              <tr>
                <td className="bg-white/[0.025] px-4 py-3 font-mono text-xs text-white/62">&lt; 0.3.0</td>
                <td className="px-4 py-3 text-white/52">Unsupported</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LegalSection>

      <LegalSection title="Reporting A Vulnerability">
        <p>Do not report vulnerabilities through public GitHub issues.</p>
        <p>
          Email: <a href="mailto:itsafnanksalal@gmail.com" className="text-white underline decoration-white/20 underline-offset-4 hover:text-white/75">itsafnanksalal@gmail.com</a>
        </p>
        <p>PGP is available on request.</p>
        <p>Please include the affected component, reproduction steps, impact assessment, safe logs or screenshots, and suggested mitigation if known.</p>
      </LegalSection>

      <LegalSection title="Response Targets">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {[
            ["Acknowledgement", "48 hours"],
            ["Initial assessment", "7 days"],
            ["Patch timeline", "14 days"],
            ["Coordinated disclosure", "90 days unless risk requires faster action"],
          ].map(([step, target]) => (
            <div key={step} className="rounded-lg border border-white/[0.08] bg-white/[0.03] p-4">
              <p className="text-sm font-semibold text-white">{step}</p>
              <p className="mt-1 text-xs text-white/42">{target}</p>
            </div>
          ))}
        </div>
      </LegalSection>

      <LegalSection title="Scope">
        <p>In scope:</p>
        <ul className="list-disc space-y-2 pl-5">
          <li><code className="font-mono text-white/70">breachscope</code> CLI package.</li>
          <li>Dashboard application and API routes.</li>
          <li>Authentication, API key, SCIM, SAML, scan ingestion, and triage flows.</li>
          <li>Release, npm package, and GitHub Actions workflows.</li>
        </ul>
        <p>Out of scope:</p>
        <ul className="list-disc space-y-2 pl-5">
          <li>Vulnerabilities in third-party projects that BreachScope scans.</li>
          <li>Denial of service through intentional resource exhaustion.</li>
          <li>Social engineering.</li>
          <li>Findings that require access to another user&apos;s dashboard account without an underlying vulnerability.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Current Security Practices">
        <ul className="list-disc space-y-2 pl-5">
          <li>Dependency audits run in CI.</li>
          <li>CLI and web builds are typechecked, linted, tested, and audited.</li>
          <li>API keys are hashed before storage.</li>
          <li>Dashboard secrets are encrypted with AES-256-GCM.</li>
          <li>Scan ingestion validates payload size, fields, dates, finding count, and embedded JSON.</li>
          <li>API key scopes are enforced for scan upload and CLI config access.</li>
          <li>CLI auth polling is replay-safe.</li>
          <li>Sandbox secrets are excluded by default and require <code className="font-mono text-white/70">--include-secrets</code>.</li>
          <li>SAML ACS fails closed until assertion validation and IdP certificate pinning are configured.</li>
        </ul>
      </LegalSection>
    </LegalPage>
  );
}
