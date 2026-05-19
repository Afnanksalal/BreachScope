import type { Finding } from "./types.js";

interface ComplianceRule {
  id: string;
  patterns: RegExp[];
}

const RULES: ComplianceRule[] = [
  { id: "OWASP-A01:2021 Broken Access Control", patterns: [/auth bypass/i, /access control/i, /idor/i, /permission/i] },
  { id: "OWASP-A02:2021 Cryptographic Failures", patterns: [/crypto/i, /hash/i, /secret/i, /token/i, /password/i, /tls/i] },
  { id: "OWASP-A03:2021 Injection", patterns: [/sqli/i, /sql injection/i, /command injection/i, /xss/i, /ssti/i, /ldap/i] },
  { id: "OWASP-A05:2021 Security Misconfiguration", patterns: [/cors/i, /header/i, /debug/i, /misconfig/i, /docker/i] },
  { id: "OWASP-A06:2021 Vulnerable and Outdated Components", patterns: [/cve/i, /osv/i, /dependency/i, /vulnerable package/i] },
  { id: "OWASP-A07:2021 Identification and Authentication Failures", patterns: [/jwt/i, /session/i, /login/i, /credential/i] },
  { id: "OWASP-A08:2021 Software and Data Integrity Failures", patterns: [/supply chain/i, /integrity/i, /lockfile/i, /provenance/i] },
  { id: "OWASP-A10:2021 Server-Side Request Forgery", patterns: [/ssrf/i, /server-side request forgery/i] },
  { id: "SOC2-CC6.1 Logical Access Controls", patterns: [/auth/i, /access/i, /permission/i, /api key/i] },
  { id: "SOC2-CC7.1 Vulnerability Management", patterns: [/cve/i, /vulnerability/i, /finding/i, /dependency/i] },
  { id: "ISO27001-A.8.8 Management of Technical Vulnerabilities", patterns: [/cve/i, /vulnerability/i, /patch/i, /outdated/i] },
  { id: "NIST-RA-5 Vulnerability Monitoring and Scanning", patterns: [/scan/i, /vulnerability/i, /cve/i, /osv/i] },
  { id: "PCI-DSS-6.2 Custom Software Security", patterns: [/injection/i, /xss/i, /auth/i, /code/i] },
];

export function mapCompliance(finding: Finding): string[] {
  const haystack = [
    finding.id,
    finding.title,
    finding.category,
    finding.description,
    finding.detail ?? "",
    finding.remediation ?? "",
    finding.tool ?? "",
  ].join(" ");

  const matches = RULES
    .filter((rule) => rule.patterns.some((pattern) => pattern.test(haystack)))
    .map((rule) => rule.id);

  return [...new Set([...(finding.compliance ?? []), ...matches])];
}

export function attachCompliance(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({
    ...finding,
    compliance: mapCompliance(finding),
  }));
}
