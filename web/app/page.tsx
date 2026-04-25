import { Nav } from "@/components/Nav";
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
