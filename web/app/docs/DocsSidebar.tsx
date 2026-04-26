"use client";

import { useEffect, useState } from "react";

const SECTIONS = [
  {
    title: "Getting Started",
    items: [
      { label: "Installation", anchor: "installation" },
      { label: "Quick Start", anchor: "quick-start" },
      { label: "Configuration", anchor: "configuration" },
    ],
  },
  {
    title: "Commands",
    items: [
      { label: "scan", anchor: "scan" },
      { label: "sandbox", anchor: "sandbox" },
      { label: "login", anchor: "login" },
      { label: "audit", anchor: "audit" },
      { label: "probe", anchor: "probe" },
      { label: "smoke", anchor: "smoke" },
      { label: "deps", anchor: "deps" },
      { label: "init", anchor: "init" },
    ],
  },
  {
    title: "Dashboard",
    items: [
      { label: "Overview", anchor: "dashboard" },
      { label: "Scan history", anchor: "scan-history" },
      { label: "API keys", anchor: "api-keys" },
      { label: "Settings", anchor: "settings" },
    ],
  },
  {
    title: "Integrations",
    items: [
      { label: "Overview", anchor: "integrations-overview" },
      { label: "Supabase, Vercel, GitHub", anchor: "toolchain-scanners" },
      { label: "Live service probes", anchor: "live-probes" },
    ],
  },
  {
    title: "CI/CD",
    items: [
      { label: "GitHub Actions", anchor: "github-actions" },
      { label: "Exit codes", anchor: "exit-codes" },
      { label: "SARIF output", anchor: "sarif" },
    ],
  },
  {
    title: "Changelog",
    items: [
      { label: "v0.3.1", anchor: "changelog" },
      { label: "v0.3.0", anchor: "changelog-030" },
      { label: "v0.2.0", anchor: "changelog-020" },
      { label: "v0.1.0", anchor: "changelog-010" },
    ],
  },
];

export function DocsSidebar() {
  const [active, setActive] = useState("installation");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const ids = SECTIONS.flatMap((s) => s.items.map((i) => i.anchor));
    const observers: IntersectionObserver[] = [];

    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      const obs = new IntersectionObserver(
        ([entry]) => { if (entry?.isIntersecting) setActive(id); },
        { rootMargin: "-20% 0px -70% 0px" }
      );
      obs.observe(el);
      observers.push(obs);
    });

    return () => observers.forEach((o) => o.disconnect());
  }, []);

  const handleClick = (anchor: string) => {
    setOpen(false);
    const el = document.getElementById(anchor);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const SidebarContent = () => (
    <nav className="space-y-7">
      {SECTIONS.map((section) => (
        <div key={section.title}>
          <p className="text-[10px] font-semibold text-white/25 uppercase tracking-[0.15em] mb-3 px-2">
            {section.title}
          </p>
          <ul className="space-y-0.5">
            {section.items.map((item) => {
              const isActive = active === item.anchor;
              return (
                <li key={item.anchor}>
                  <button
                    onClick={() => handleClick(item.anchor)}
                    className={`w-full text-left text-sm px-2 py-1.5 rounded-md transition-all duration-150 ${
                      isActive
                        ? "text-white bg-white/[0.07] font-medium"
                        : "text-white/40 hover:text-white/70 hover:bg-white/[0.04]"
                    }`}
                  >
                    {isActive && (
                      <span className="inline-block w-1 h-1 rounded-full bg-breach-500 mr-2 mb-0.5" />
                    )}
                    {item.label}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );

  return (
    <>
      {/* Mobile toggle */}
      <div className="lg:hidden fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setOpen(!open)}
          className="w-12 h-12 rounded-full bg-white/10 border border-white/10 backdrop-blur flex items-center justify-center text-white shadow-xl"
        >
          {open ? (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile drawer */}
      {open && (
        <div className="lg:hidden fixed inset-0 z-40 flex">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <div className="relative w-72 bg-[#0a0a0a] border-r border-white/[0.06] h-full overflow-y-auto p-6 pt-20">
            <SidebarContent />
          </div>
        </div>
      )}

      {/* Desktop sidebar */}
      <aside className="hidden lg:block w-52 shrink-0">
        <div
          className="sticky top-24 overflow-y-auto pr-2"
          style={{ maxHeight: "calc(100vh - 7rem)" }}
        >
          <SidebarContent />
        </div>
      </aside>
    </>
  );
}
