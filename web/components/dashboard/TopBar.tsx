"use client";

import { signOut } from "next-auth/react";
import type { Session } from "next-auth";
import Image from "next/image";
import Link from "next/link";

interface TopBarProps {
  session?: Session | null;
  title: string;
  subtitle?: string;
  back?: string;
}

export function TopBar({ session, title, subtitle, back }: TopBarProps) {
  return (
    <header className="flex min-h-16 shrink-0 items-center justify-between gap-3 border-b border-white/[0.07] bg-black/35 py-3 pl-16 pr-4 backdrop-blur-xl md:px-8">
      <div className="flex min-w-0 items-center gap-3">
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
        <div className="min-w-0">
          <h1 className="truncate text-base font-semibold leading-tight text-white">{title}</h1>
          {subtitle && <p className="text-white/38 text-xs mt-0.5">{subtitle}</p>}
        </div>
      </div>

      {session && (
        <div className="flex min-w-0 items-center gap-2 sm:gap-4">
          <div className="flex min-w-0 items-center gap-3">
            {session.user?.image && (
              <Image
                src={session.user.image}
                alt={session.user.name ?? "User"}
                width={28}
                height={28}
                unoptimized
                className="w-7 h-7 rounded-full ring-1 ring-white/10"
              />
            )}
            <div className="hidden min-w-0 sm:block">
              <p className="truncate text-xs font-medium text-white/70">{session.user?.name}</p>
              <p className="truncate text-xs text-white/30">{session.user?.email}</p>
            </div>
          </div>
          <button
            onClick={() => signOut({ callbackUrl: "/" })}
            className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5 text-xs text-white/38 transition-colors hover:bg-white/[0.07] hover:text-white sm:px-3"
          >
            Sign out
          </button>
        </div>
      )}
    </header>
  );
}
