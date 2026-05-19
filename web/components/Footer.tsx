import Link from "next/link";

const LINKS = {
  Platform: [
    { label: "Features", href: "/#features" },
    { label: "Workflow", href: "/#workflow" },
    { label: "Install", href: "/#install" },
    { label: "Dashboard", href: "/dashboard" },
    { label: "Roadmap", href: "/roadmap" },
  ],
  Resources: [
    { label: "Documentation", href: "/docs" },
    { label: "Controls guide", href: "/docs#controls" },
    { label: "Releases", href: "https://github.com/Afnanksalal/BreachScope/releases", external: true },
    { label: "Contributing", href: "https://github.com/Afnanksalal/BreachScope/blob/master/CONTRIBUTING.md", external: true },
  ],
  Legal: [
    { label: "Legal center", href: "/legal" },
    { label: "Terms", href: "/terms" },
    { label: "Privacy", href: "/privacy" },
    { label: "Acceptable use", href: "/acceptable-use" },
    { label: "Data protection", href: "/data-protection" },
    { label: "Security policy", href: "/security" },
    { label: "MIT license", href: "https://github.com/Afnanksalal/BreachScope/blob/master/LICENSE", external: true },
  ],
};

export function Footer() {
  return (
    <footer className="relative border-t border-white/[0.06] bg-black">
      <div className="mx-auto grid max-w-7xl grid-cols-1 gap-10 px-4 py-14 sm:px-6 md:grid-cols-[1.3fr_0.8fr_0.8fr_0.8fr]">
        <div>
          <Link href="/" className="mb-4 inline-block font-serif text-xl font-semibold italic text-white">
            BreachScope
          </Link>
          <p className="max-w-sm text-sm leading-6 text-white/45">
            Open-source security workflow for local scans, release evidence, triage, and customer-owned integrations.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {["SARIF", "SBOM", "OpenVEX", "SCIM", "SAML"].map((item) => (
              <span key={item} className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-xs text-white/38">
                {item}
              </span>
            ))}
          </div>
        </div>

        {Object.entries(LINKS).map(([section, items]) => (
          <div key={section}>
            <p className="mb-4 text-xs font-semibold uppercase text-white/32">{section}</p>
            <ul className="space-y-3">
              {items.map((item) => (
                <li key={item.label}>
                  {"external" in item && item.external ? (
                    <a href={item.href} target="_blank" rel="noopener noreferrer" className="text-sm text-white/56 transition-colors hover:text-white">
                      {item.label}
                    </a>
                  ) : (
                    <Link href={item.href} className="text-sm text-white/56 transition-colors hover:text-white">
                      {item.label}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="border-t border-white/[0.06]">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 px-4 py-5 text-center sm:flex-row sm:px-6 sm:text-left">
          <p className="text-xs text-white/32">Copyright {new Date().getFullYear()} Afnan K Salal. Open source under the MIT license.</p>
          <div className="flex items-center gap-3 text-xs text-white/32">
            <span className="font-mono">v0.3.0</span>
            <span>Node.js 18+</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
