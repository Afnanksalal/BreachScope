import type { Metadata } from "next";
import { Nav } from "@/components/Nav";

export const metadata: Metadata = {
  title: "BreachScope — Supply Chain & Toolchain Security Scanner",
  description:
    "Open-source CLI that spins up a Docker attack arena, runs an AI agent as root, and autonomously hunts vulnerabilities across your entire stack — dependencies, code, toolchains, and live endpoints. Supports 10 languages.",
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
