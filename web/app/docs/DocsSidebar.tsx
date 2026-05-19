"use client";

import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";

const SECTIONS = [
  {
    title: "Start",
    items: [
      { label: "Install", anchor: "installation" },
      { label: "Quick start", anchor: "quick-start" },
      { label: "Configuration", anchor: "configuration" },
      { label: "Data and keys", anchor: "data-and-keys" },
    ],
  },
  {
    title: "Commands",
    items: [
      { label: "scan", anchor: "scan" },
      { label: "sandbox", anchor: "sandbox" },
      { label: "sbom", anchor: "sbom" },
      { label: "vex", anchor: "vex" },
      { label: "runtime", anchor: "runtime" },
    ],
  },
  {
    title: "Operations",
    items: [
      { label: "Controls", anchor: "controls" },
      { label: "Policy", anchor: "policy" },
      { label: "Dashboard", anchor: "dashboard" },
      { label: "Identity", anchor: "identity" },
      { label: "Integrations", anchor: "integrations" },
    ],
  },
  {
    title: "Reference",
    items: [
      { label: "Security defaults", anchor: "security" },
      { label: "CI/CD", anchor: "ci" },
      { label: "Deployment", anchor: "deployment" },
      { label: "Legal", anchor: "legal" },
      { label: "Changelog", anchor: "changelog" },
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
        { rootMargin: "-20% 0px -70% 0px" },
      );
      obs.observe(el);
      observers.push(obs);
    });

    return () => observers.forEach((o) => o.disconnect());
  }, []);

  const handleClick = (anchor: string) => {
    setOpen(false);
    document.getElementById(anchor)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      <div className="fixed bottom-6 right-6 z-50 lg:hidden">
        <button
          onClick={() => setOpen(!open)}
          className="flex h-11 w-11 items-center justify-center rounded-lg border border-white/[0.1] bg-black/85 text-white/70 backdrop-blur"
          aria-label={open ? "Close docs menu" : "Open docs menu"}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {open && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <div className="relative h-full w-[min(18rem,calc(100vw-2rem))] overflow-y-auto border-r border-white/[0.08] bg-[#050606] p-6 pt-20">
            <DocsSidebarContent active={active} onSelect={handleClick} />
          </div>
        </div>
      )}

      <aside className="hidden w-56 shrink-0 lg:block">
        <div className="sticky top-24 overflow-y-auto pr-3" style={{ maxHeight: "calc(100vh - 7rem)" }}>
          <DocsSidebarContent active={active} onSelect={handleClick} />
        </div>
      </aside>
    </>
  );
}

function DocsSidebarContent({ active, onSelect }: { active: string; onSelect: (anchor: string) => void }) {
  return (
    <nav className="space-y-7">
      {SECTIONS.map((section) => (
        <div key={section.title}>
          <p className="mb-3 px-2 text-[10px] font-semibold uppercase text-white/25">
            {section.title}
          </p>
          <ul className="space-y-1">
            {section.items.map((item) => {
              const isActive = active === item.anchor;
              return (
                <li key={item.anchor}>
                  <button
                    onClick={() => onSelect(item.anchor)}
                    className={`w-full rounded-md px-2 py-1.5 text-left text-sm transition-colors ${
                      isActive
                        ? "bg-white/[0.08] text-white"
                        : "text-white/42 hover:bg-white/[0.045] hover:text-white/75"
                    }`}
                  >
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
}
