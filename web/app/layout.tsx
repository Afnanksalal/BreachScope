import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Providers } from "./providers";

const APP_URL = "https://breachscoope.vercel.app";
const TITLE   = "BreachScope — Supply Chain & Toolchain Security Scanner";
const DESC    = "Detect supply chain and toolchain breaches before they become incidents. Scan dependencies, audit code, probe live toolchains, and smoke test — all from a single CLI.";

export const metadata: Metadata = {
  metadataBase: new URL(APP_URL),
  title: {
    default:  TITLE,
    template: "%s | BreachScope",
  },
  description: DESC,
  keywords: [
    "supply chain security", "toolchain security", "dependency audit",
    "security scanner", "CLI security tool", "breach detection",
    "Supabase security", "Vercel security", "GitHub security audit",
    "CVE scanner", "open source security",
  ],
  authors:  [{ name: "BreachScope", url: APP_URL }],
  creator:  "BreachScope",
  publisher:"BreachScope",
  robots: {
    index:             true,
    follow:            true,
    googleBot: {
      index:               true,
      follow:              true,
      "max-image-preview": "large",
      "max-snippet":       -1,
    },
  },
  openGraph: {
    type:        "website",
    url:         APP_URL,
    siteName:    "BreachScope",
    title:       TITLE,
    description: DESC,
    locale:      "en_US",
  },
  twitter: {
    card:        "summary_large_image",
    site:        "@breachscope",
    title:       TITLE,
    description: DESC,
  },
  icons: {
    icon:        [{ url: "/favicon.svg", type: "image/svg+xml" }],
    shortcut:    "/favicon.svg",
    apple:       "/favicon.svg",
  },
  manifest:    "/manifest.json",
  alternates:  {
    canonical: APP_URL,
    types: {
      "text/plain": `${APP_URL}/llms.txt`,
    },
  },
};

export const viewport: Viewport = {
  themeColor:   "#030305",
  colorScheme:  "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
