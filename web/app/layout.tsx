import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "BreachScope — Supply Chain & Toolchain Security Scanner",
  description:
    "Detect supply chain and toolchain breaches before they become incidents. Scan dependencies, audit code, probe toolchains, and smoke test — all from a single CLI.",
  keywords: ["security", "supply chain", "breach", "cli", "audit", "supabase", "vercel"],
  authors: [{ name: "BreachScope" }],
  openGraph: {
    title: "BreachScope",
    description: "Find toolchain breaches before they find you.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "BreachScope",
    description: "Find toolchain breaches before they find you.",
  },
};

export const viewport: Viewport = {
  themeColor: "#030305",
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
