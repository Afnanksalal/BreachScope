import Link from "next/link";

const LINKS = {
  Product: [
    { label: "Features",   href: "#features" },
    { label: "How It Works", href: "#install" },
    { label: "Changelog",  href: "/docs#changelog" },
    { label: "Roadmap",    href: "/docs#roadmap" },
  ],
  Resources: [
    { label: "Documentation", href: "/docs" },
    { label: "Releases",      href: "https://github.com/breachscope/breachscope/releases", external: true },
    { label: "Contributing",  href: "https://github.com/breachscope/breachscope/blob/main/CONTRIBUTING.md", external: true },
  ],
  Legal: [
    { label: "MIT License",   href: "/docs#license" },
    { label: "Security Policy", href: "/docs#security" },
    { label: "Privacy",       href: "/privacy" },
  ],
};

export function Footer() {
  return (
    <footer className="relative border-t border-white/[0.05]">
      {/* Main footer */}
      <div className="max-w-6xl mx-auto px-6 py-16 grid grid-cols-1 md:grid-cols-5 gap-12">
        {/* Brand */}
        <div className="md:col-span-2">
          <Link href="/" className="inline-block mb-4 group">
            <span className="font-serif italic text-xl text-white group-hover:text-breach-300 transition-colors">
              BreachScope
            </span>
          </Link>
          <p className="text-white/45 text-sm leading-relaxed max-w-xs">
            Open-source supply chain and toolchain security scanner.
            Built for developers who ship fast and need to sleep well.
          </p>
        </div>

        {/* Link columns */}
        {Object.entries(LINKS).map(([section, items]) => (
          <div key={section}>
            <p className="text-white/35 text-xs font-semibold uppercase tracking-widest mb-4">
              {section}
            </p>
            <ul className="space-y-3">
              {items.map((item) => (
                <li key={item.label}>
                  {"external" in item && item.external ? (
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-white/60 text-sm hover:text-white/70 transition-colors"
                    >
                      {item.label}
                    </a>
                  ) : (
                    <Link
                      href={item.href}
                      className="text-white/60 text-sm hover:text-white/70 transition-colors"
                    >
                      {item.label}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* Bottom bar */}
      <div className="border-t border-white/[0.05]">
        <div className="max-w-6xl mx-auto px-6 py-5 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p className="text-white/35 text-xs">
            © {new Date().getFullYear()} BreachScope. Open source under the MIT license.
          </p>
          <div className="flex items-center gap-4">
            <span className="text-white/30 text-xs font-mono">v0.1.0</span>
            <span className="text-white/20 text-xs">·</span>
            <span className="text-white/30 text-xs font-mono">Node.js ≥ 18</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

