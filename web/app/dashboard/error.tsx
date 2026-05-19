"use client";

import Link from "next/link";

export default function DashboardError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#020303] px-4">
      <div className="w-full max-w-xl rounded-lg border border-white/[0.08] bg-white/[0.035] p-6">
        <p className="text-xs font-semibold uppercase text-white/32">Dashboard</p>
        <h1 className="mt-3 text-2xl font-semibold text-white">Something blocked this dashboard view.</h1>
        <p className="mt-3 text-sm leading-6 text-white/52">
          The session is active, but the dashboard could not finish loading this view. Retry once; if it keeps happening, check the production database migration and environment variables.
        </p>
        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <button
            onClick={reset}
            className="rounded-lg bg-white px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-white/90"
          >
            Retry
          </button>
          <Link
            href="/docs#deployment"
            className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-4 py-2 text-center text-sm text-white/62 transition-colors hover:bg-white/[0.07] hover:text-white"
          >
            Deployment docs
          </Link>
        </div>
      </div>
    </div>
  );
}
