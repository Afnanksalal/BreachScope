"use client";

import { signOut } from "next-auth/react";
import type { Session } from "next-auth";
import Link from "next/link";

interface TopBarProps {
  session?: Session | null;
  title: string;
  subtitle?: string;
  back?: string;
}

export function TopBar({ session, title, subtitle, back }: TopBarProps) {
  return (
    <header className="h-16 border-b border-white/5 flex items-center justify-between px-8 shrink-0">
      <div className="flex items-center gap-3">
        {back && (
          <Link
            href={back}
            className="text-white/30 hover:text-white/70 transition-colors mr-1"
            aria-label="Back"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
            </svg>
          </Link>
        )}
        <div>
          <h1 className="text-white font-semibold text-base">{title}</h1>
          {subtitle && <p className="text-white/35 text-xs">{subtitle}</p>}
        </div>
      </div>

      {session && (
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3">
            {session.user?.image && (
              <img
                src={session.user.image}
                alt={session.user.name ?? "User"}
                className="w-7 h-7 rounded-full ring-1 ring-white/10"
              />
            )}
            <div className="hidden sm:block">
              <p className="text-white/70 text-xs font-medium">{session.user?.name}</p>
              <p className="text-white/30 text-xs">{session.user?.email}</p>
            </div>
          </div>
          <button
            onClick={() => signOut({ callbackUrl: "/" })}
            className="text-xs text-white/30 hover:text-white/60 transition-colors px-3 py-1.5 rounded-lg hover:bg-white/5"
          >
            Sign out
          </button>
        </div>
      )}
    </header>
  );
}
