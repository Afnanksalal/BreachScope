import type { Metadata } from "next";
import { Nav } from "@/components/Nav";

export const metadata: Metadata = {
  title: "BreachScope — Supply Chain & Toolchain Security Scanner",
  description:
    "Open-source CLI that detects supply chain attacks, misconfigurations, and toolchain breaches across your entire stack — dependencies, code, Supabase, Vercel, GitHub, Stripe, and more.",
  alternates: { canonical: "https://breachscoope.vercel.app" },
};
import { Hero } from "@/components/Hero";
import { Features } from "@/components/Features";
import { SocialProof } from "@/components/SocialProof";
import { Install } from "@/components/Install";
import { Footer } from "@/components/Footer";

export default function HomePage() {
  return (
    <main className="relative">
      <Nav />
      <Hero />
      <Features />
      <SocialProof />
      <Install />
      <Footer />
    </main>
  );
}
