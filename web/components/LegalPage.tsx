import Link from "next/link";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";

export function LegalPage({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <Nav />
      <main className="min-h-screen bg-black px-4 pb-24 pt-24 sm:px-6 sm:pb-28 sm:pt-28">
        <div className="mx-auto max-w-4xl">
          <header className="border-b border-white/[0.07] pb-10">
            <p className="mb-4 text-xs font-semibold uppercase text-white/35">Legal</p>
            <h1 className="text-4xl font-semibold leading-tight text-white md:text-6xl">{title}</h1>
            <p className="mt-5 max-w-2xl text-base leading-8 text-white/52">{description}</p>
            <p className="mt-5 text-xs text-white/32">Last updated: May 20, 2026</p>
          </header>

          <article className="legal-content mt-10 space-y-10 text-sm leading-7 text-white/58">
            {children}
          </article>
        </div>
      </main>
      <Footer />
    </>
  );
}

export function LegalSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-white/[0.07] pb-10 last:border-0">
      <h2 className="mb-4 text-2xl font-semibold text-white">{title}</h2>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

export function LegalLinkGrid() {
  const links: Array<[string, string, string]> = [
    ["Terms", "/terms", "Service rules, user responsibilities, and customer content."],
    ["Privacy", "/privacy", "Data categories, purposes, retention, sharing, and rights."],
    ["Acceptable Use", "/acceptable-use", "Authorized testing boundaries and abuse restrictions."],
    ["Data Protection", "/data-protection", "Processing roles, safeguards, incident process, and deletion."],
    ["Security", "/security", "Supported versions, reporting process, scope, and current safeguards."],
  ];

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {links.map(([title, href, body]) => (
        <Link key={href} href={href} className="rounded-lg border border-white/[0.08] bg-white/[0.03] p-4 transition-colors hover:border-white/[0.16] hover:bg-white/[0.055]">
          <span className="text-sm font-semibold text-white">{title}</span>
          <span className="mt-2 block text-xs leading-5 text-white/42">{body}</span>
        </Link>
      ))}
    </div>
  );
}
