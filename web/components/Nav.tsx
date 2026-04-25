"use client";

import { useSession } from "next-auth/react";
import Link from "next/link";

const NAV_LINKS: Array<{ label: string; href: string; external?: boolean }> = [
  { label: "Features",    href: "#features" },
  { label: "How It Works", href: "#install" },
  { label: "Docs",        href: "/docs" },
];

export function Nav() {
  const { data: session, status } = useSession();
  const isLoggedIn = status === "authenticated" && !!session?.user;
  const isLoading  = status === "loading";

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-black/75 backdrop-blur-xl border-b border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-6 h-[60px] flex items-center justify-between">

        {/* Wordmark */}
        <Link href="/" className="group">
          <span className="font-serif italic text-[1.15rem] text-white tracking-tight group-hover:text-white/70 transition-colors duration-150">
            BreachScope
          </span>
        </Link>

        {/* Nav links */}
        <ul className="hidden md:flex items-center gap-7">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              {link.external ? (
                <a
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[0.8125rem] text-white/45 hover:text-white/85 transition-colors duration-150 tracking-wide"
                >
                  {link.label}
                </a>
              ) : (
                <Link
                  href={link.href}
                  className="text-[0.8125rem] text-white/45 hover:text-white/85 transition-colors duration-150 tracking-wide"
                >
                  {link.label}
                </Link>
              )}
            </li>
          ))}
        </ul>

        {/* Right side */}
        <div className="hidden md:flex items-center gap-2.5">
          {/* GitHub */}
          <a
            href="https://github.com/breachscope/breachscope"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
            className="w-8 h-8 flex items-center justify-center rounded-lg text-white/40 hover:text-white/75 hover:bg-white/[0.06] transition-all duration-150"
          >
            <GitHubIcon />
          </a>

          <div className="w-px h-4 bg-white/[0.08]" />

          {isLoading ? (
            <div className="w-[6.5rem] h-8 rounded-lg bg-white/[0.04] animate-pulse" />
          ) : isLoggedIn ? (
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white text-black text-[0.8125rem] font-semibold hover:bg-white/90 transition-colors duration-150"
            >
              Dashboard
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </Link>
          ) : (
            <>
              <Link
                href="/login"
                className="text-[0.8125rem] text-white/50 hover:text-white/85 transition-colors duration-150 px-3 py-2"
              >
                Sign in
              </Link>
              <Link
                href="/login"
                className="inline-flex items-center px-4 py-2 rounded-lg bg-white text-black text-[0.8125rem] font-semibold hover:bg-white/90 transition-colors duration-150"
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}

function GitHubIcon() {
  return (
    <svg className="w-[1.05rem] h-[1.05rem]" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}
