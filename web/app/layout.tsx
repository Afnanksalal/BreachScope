import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Providers } from "./providers";
import { Analytics } from "@vercel/analytics/next";

const APP_URL = "https://breachscoope.vercel.app";
const TITLE = "BreachScope - Security Workbench for Modern Teams";
const DESC = "Detect supply chain, code, SaaS toolchain, runtime, and release risk before it becomes an incident. Scan locally, enforce policy in CI, and manage evidence in the dashboard.";
const REPO_URL = "https://github.com/Afnanksalal/BreachScope";

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebSite",
      "@id": `${APP_URL}/#website`,
      name: "BreachScope",
      url: APP_URL,
      description: DESC,
      inLanguage: "en-US",
    },
    {
      "@type": "SoftwareApplication",
      "@id": `${APP_URL}/#software`,
      name: "BreachScope",
      applicationCategory: "SecurityApplication",
      operatingSystem: "macOS, Windows, Linux",
      softwareRequirements: "Node.js 18 or higher",
      url: APP_URL,
      codeRepository: REPO_URL,
      license: `${REPO_URL}/blob/master/LICENSE`,
      description: DESC,
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
      featureList: [
        "Supply-chain and dependency scanning",
        "Static code security audit",
        "SaaS toolchain posture checks",
        "Blackbox HTTP probing",
        "Docker sandbox attack simulation",
        "Runtime Tracee evidence command",
        "Policy-as-code CI gates",
        "SARIF, CycloneDX SBOM, and OpenVEX exports",
        "Dashboard with audit logs and scoped API keys",
      ],
    },
    {
      "@type": "Organization",
      "@id": `${APP_URL}/#organization`,
      name: "BreachScope",
      url: APP_URL,
      sameAs: [REPO_URL],
    },
  ],
};

export const metadata: Metadata = {
  metadataBase: new URL(APP_URL),
  title: {
    default: TITLE,
    template: "%s | BreachScope",
  },
  description: DESC,
  keywords: [
    "security scanner",
    "supply chain security",
    "toolchain security",
    "policy as code",
    "SARIF",
    "SBOM",
    "OpenVEX",
    "SCIM",
    "SAML",
    "runtime security",
    "developer security",
  ],
  authors: [{ name: "BreachScope", url: APP_URL }],
  creator: "BreachScope",
  publisher: "BreachScope",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    url: APP_URL,
    siteName: "BreachScope",
    title: TITLE,
    description: DESC,
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    site: "@breachscope",
    title: TITLE,
    description: DESC,
  },
  icons: {
    icon: [{ url: "/favicon.svg", type: "image/svg+xml" }],
    shortcut: "/favicon.svg",
    apple: "/favicon.svg",
  },
  manifest: "/manifest.json",
  alternates: {
    canonical: APP_URL,
    types: {
      "text/plain": `${APP_URL}/llms.txt`,
      "text/plain; profile=llms-full": `${APP_URL}/llms-full.txt`,
    },
  },
};

export const viewport: Viewport = {
  themeColor: "#030305",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <script
          type="application/ld+json"
          suppressHydrationWarning
          dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData).replace(/</g, "\\u003c") }}
        />
        <Providers>{children}</Providers>
        <Analytics />
      </body>
    </html>
  );
}
