"use client";

import { useState, useEffect } from "react";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { clsx } from "clsx";

const GITHUB_REPO = "Afnanksalal/BreachScope";

function useGitHubStars() {
  const [stars, setStars] = useState<number | null>(null);
  useEffect(() => {
    fetch(`https://api.github.com/repos/${GITHUB_REPO}`, {
      headers: { Accept: "application/vnd.github+json" },
    })
      .then((r) => r.json())
      .then((d: { stargazers_count?: number }) => {
        if (typeof d.stargazers_count === "number") setStars(d.stargazers_count);
      })
      .catch(() => {});
  }, []);
  return stars;
}

function formatStars(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

const NAV_LINKS: Array<{ label: string; href: string; external?: boolean }> = [
  { label: "Product",  href: "/#features" },
  { label: "Workflow", href: "/#workflow" },
  { label: "Install",  href: "/#install" },
  { label: "Docs",     href: "/docs" },
  { label: "Legal",    href: "/legal" },
];

export function Nav() {
  const { data: session, status } = useSession();
  const isLoggedIn = status === "authenticated" && !!session?.user;
  const isLoading  = status === "loading";
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const stars = useGitHubStars();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Close on route change / escape
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Lock body scroll when drawer open
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  return (
    <>
      <nav
        className={clsx(
          "fixed left-0 right-0 top-0 z-50 border-b transition-all duration-300",
          scrolled || open
            ? "border-white/[0.08] bg-black/[0.78] shadow-2xl shadow-black/30 backdrop-blur-xl"
            : "border-transparent bg-transparent",
        )}
      >
        <div className="mx-auto flex h-[60px] max-w-7xl items-center justify-between px-5">

          {/* Wordmark */}
          <Link href="/" className="group" onClick={() => setOpen(false)}>
            <span className="font-serif text-[1.18rem] font-semibold italic text-white transition-colors duration-150 group-hover:text-white/70">
              BreachScope
            </span>
          </Link>

          {/* Desktop nav links */}
          <ul className="hidden md:flex items-center gap-7">
            {NAV_LINKS.map((link) => (
              <li key={link.href}>
                <Link
                  href={link.href}
                  target={link.external ? "_blank" : undefined}
                  rel={link.external ? "noopener noreferrer" : undefined}
                  className="text-[0.8125rem] text-white/48 hover:text-white/85 transition-colors duration-150"
                >
                  {link.label}
                </Link>
              </li>
            ))}
          </ul>

          {/* Desktop right side */}
          <div className="hidden md:flex items-center gap-2.5">
            <a
              href={`https://github.com/${GITHUB_REPO}`}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="GitHub"
              className="flex items-center gap-1.5 px-2.5 h-8 rounded-lg text-white/40 hover:text-white/75 hover:bg-white/[0.06] transition-all duration-150"
            >
              <GitHubIcon />
              {stars !== null && (
                <span className="text-[0.7rem] font-mono text-white/35 tabular-nums">
                  {formatStars(stars)}
                </span>
              )}
            </a>
            <div className="w-px h-4 bg-white/[0.08]" />
            {isLoading ? (
              <div className="w-[6.5rem] h-8 rounded-lg bg-white/[0.04] animate-pulse" />
            ) : isLoggedIn ? (
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-1.5 rounded-lg bg-white px-4 py-2 text-[0.8125rem] font-semibold text-black transition-colors hover:bg-white/90"
              >
                Dashboard
                <ArrowIcon />
              </Link>
            ) : (
              <>
                <Link href="/login" className="text-[0.8125rem] text-white/50 hover:text-white/85 transition-colors px-3 py-2">
                  Sign in
                </Link>
                <Link href="/login" className="inline-flex items-center rounded-lg bg-white px-4 py-2 text-[0.8125rem] font-semibold text-black transition-colors hover:bg-white/90">
                  Get started
                </Link>
              </>
            )}
          </div>

          {/* Mobile hamburger */}
          <button
            className="md:hidden flex items-center justify-center w-9 h-9 rounded-lg text-white/50 hover:text-white hover:bg-white/[0.06] transition-all"
            onClick={() => setOpen((v) => !v)}
            aria-label={open ? "Close menu" : "Open menu"}
          >
            {open ? <XIcon /> : <MenuIcon />}
          </button>
        </div>
      </nav>

      {/* Mobile drawer overlay */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/65 backdrop-blur-sm md:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      {/* Mobile drawer */}
      <aside className={clsx(
        "fixed bottom-3 right-3 top-3 z-50 flex w-[min(22rem,calc(100vw-1.5rem))] flex-col overflow-hidden rounded-xl border border-white/[0.09] bg-[#050606]/96 shadow-2xl shadow-black/60 backdrop-blur-xl md:hidden",
        "transition-all duration-300 ease-out",
        open ? "translate-x-0 opacity-100 pointer-events-auto" : "translate-x-[calc(100%+1rem)] opacity-0 pointer-events-none"
      )}>
        <div className="flex h-14 shrink-0 items-center justify-between border-b border-white/[0.06] px-5">
          <Link href="/" className="font-serif text-lg font-semibold italic text-white" onClick={() => setOpen(false)}>
            BreachScope
          </Link>
          <button
            className="flex h-9 w-9 items-center justify-center rounded-lg text-white/50 transition-all hover:bg-white/[0.06] hover:text-white"
            onClick={() => setOpen(false)}
            aria-label="Close menu"
          >
            <XIcon />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-5">
          <p className="mb-3 px-3 text-[10px] font-semibold uppercase text-white/28">Navigate</p>
          <div className="space-y-1">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              target={link.external ? "_blank" : undefined}
              rel={link.external ? "noopener noreferrer" : undefined}
              onClick={() => setOpen(false)}
              className="flex items-center justify-between rounded-lg px-3 py-3 text-sm text-white/62 transition-all hover:bg-white/[0.06] hover:text-white"
            >
              <span>{link.label}</span>
              <ArrowIcon />
            </Link>
          ))}
          </div>
        </div>

        <div className="flex shrink-0 flex-col gap-2 border-t border-white/[0.06] px-5 pb-5 pt-4">
          <a
            href={`https://github.com/${GITHUB_REPO}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] transition-all"
            onClick={() => setOpen(false)}
          >
            <GitHubIcon />
            GitHub
            {stars !== null && (
              <span className="ml-auto text-[0.7rem] font-mono text-white/30">{formatStars(stars)}</span>
            )}
          </a>
          {isLoggedIn ? (
            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className="flex items-center justify-center gap-1.5 px-4 py-3 rounded-lg bg-white text-black text-sm font-semibold hover:bg-white/90 transition-colors"
            >
              Dashboard <ArrowIcon />
            </Link>
          ) : (
            <>
              <Link
                href="/login"
                onClick={() => setOpen(false)}
                className="flex items-center justify-center px-4 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] border border-white/[0.08] transition-all"
              >
                Sign in
              </Link>
              <Link
                href="/login"
                onClick={() => setOpen(false)}
                className="flex items-center justify-center px-4 py-3 rounded-lg bg-white text-black text-sm font-semibold hover:bg-white/90 transition-colors"
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </aside>
    </>
  );
}

function GitHubIcon() {
  return (
    <svg className="w-[1.05rem] h-[1.05rem]" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
    </svg>
  );
}

function MenuIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5M3.75 17.25h16.5" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}
