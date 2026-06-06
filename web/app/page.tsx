import type { Metadata } from "next";
import { Nav } from "@/components/Nav";
import { Hero } from "@/components/Hero";
import { Features } from "@/components/Features";
import { TrustModel } from "@/components/TrustModel";
import { SocialProof } from "@/components/SocialProof";
import { Install } from "@/components/Install";
import { Footer } from "@/components/Footer";
import { APP_URL } from "@/lib/site";

const LLM_ALTERNATES = {
  "text/plain": `${APP_URL}/llms.txt`,
  "text/plain; profile=llms-full": `${APP_URL}/llms-full.txt`,
};

export const metadata: Metadata = {
  title: "BreachScope - Security Workbench for Modern Teams",
  description:
    "Open-source security workflow for code, dependencies, SaaS posture, runtime evidence, release gates, SARIF, SBOM, OpenVEX, audit logs, and customer-owned integrations.",
  alternates: {
    canonical: APP_URL,
    types: LLM_ALTERNATES,
  },
};

export default function HomePage() {
  return (
    <main className="relative bg-black">
      <Nav />
      <Hero />
      <Features />
      <TrustModel />
      <SocialProof />
      <Install />
      <Footer />
    </main>
  );
}
