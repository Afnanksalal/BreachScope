"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { useEffect, useState, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { signIn, useSession } from "next-auth/react";
import { motion } from "framer-motion";

type Status = "loading" | "unauthenticated" | "ready" | "authenticating" | "complete" | "error";
type OAuthProvider = "github" | "google";

export default function CliAuthPage() {
  return (
    <Suspense>
      <CliAuthContent />
    </Suspense>
  );
}

function CliAuthContent() {
  const params = useSearchParams();
  const state = params.get("state");
  const { data: session, status } = useSession();
  const [pageStatus, setPageStatus] = useState<Status>("loading");
  const [error, setError] = useState<string | null>(null);
  const [oauthProviders, setOauthProviders] = useState<OAuthProvider[]>([]);

  useEffect(() => {
    let mounted = true;
    fetch("/api/auth/providers")
      .then((res) => res.ok ? res.json() : null)
      .then((data: unknown) => {
        if (!mounted || typeof data !== "object" || data === null) return;
        const providers = Object.keys(data as Record<string, unknown>)
          .filter((provider): provider is OAuthProvider => provider === "github" || provider === "google");
        setOauthProviders(providers);
      })
      .catch(() => undefined);
    return () => { mounted = false; };
  }, []);

  const completeCliAuth = useCallback(async () => {
    if (!state) return;
    setPageStatus("authenticating");
    try {
      const res = await fetch("/api/cli/auth/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ state }),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error ?? "Failed to complete authentication");
        setPageStatus("error");
        return;
      }

      setPageStatus("complete");
    } catch {
      setError("Network error - please try again");
      setPageStatus("error");
    }
  }, [state]);

  useEffect(() => {
    if (!state) {
      setError("Invalid or missing state parameter");
      setPageStatus("error");
      return;
    }

    if (status === "loading") return;

    if (status === "unauthenticated") {
      setPageStatus("unauthenticated");
      return;
    }

    if (status === "authenticated" && session?.user?.id) {
      setPageStatus("ready");
    }
  }, [status, session, state]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-0 px-4 py-10 sm:px-6">
      {/* Background radial */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(220,38,38,0.16),transparent_34%),radial-gradient(circle_at_50%_100%,rgba(255,255,255,0.08),transparent_28%)]" />

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative w-full max-w-md"
      >
        {/* Card */}
        <div className="rounded-lg border border-white/[0.10] bg-surface-50/80 p-5 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-sm sm:p-8">
          {/* Logo */}
          <div className="mb-8">
            <span className="font-serif italic text-lg text-white">BreachScope</span>
          </div>

          {pageStatus === "loading" && <LoadingState />}
          {pageStatus === "unauthenticated" && <SignInState providers={oauthProviders} />}
          {pageStatus === "ready" && <AuthorizeState onAuthorize={completeCliAuth} />}
          {pageStatus === "authenticating" && <AuthenticatingState />}
          {pageStatus === "complete" && <CompleteState />}
          {pageStatus === "error" && <ErrorState message={error ?? "Unknown error"} />}
        </div>

        {/* Security note */}
        <p className="text-center text-white/20 text-xs mt-6">
          This grants the BreachScope CLI access to your account.
          You can revoke access anytime from the dashboard.
        </p>
      </motion.div>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="text-center py-8">
      <div className="w-8 h-8 border-2 border-breach-600/40 border-t-breach-600 rounded-full animate-spin mx-auto mb-4" />
      <p className="text-white/50 text-sm">Checking authentication...</p>
    </div>
  );
}

function SignInState({ providers }: { providers: OAuthProvider[] }) {
  return (
    <div>
      <h1 className="text-2xl font-serif italic text-white mb-2">Sign in to continue</h1>
      <p className="text-white/45 text-sm mb-8">
        Authorize the BreachScope CLI to access your account.
      </p>
      <div className="space-y-3">
        {providers.includes("github") && (
          <button
            onClick={() => signIn("github", { callbackUrl: window.location.href })}
            className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg bg-white/[0.08] border border-white/10 text-white/80 text-sm font-medium hover:bg-white/[0.12] hover:border-white/20 transition-all"
          >
            <GithubIcon />
            Continue with GitHub
          </button>
        )}
        {providers.includes("google") && (
          <button
            onClick={() => signIn("google", { callbackUrl: window.location.href })}
            className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg bg-white/[0.08] border border-white/10 text-white/80 text-sm font-medium hover:bg-white/[0.12] hover:border-white/20 transition-all"
          >
            <GoogleIcon />
            Continue with Google
          </button>
        )}
        {providers.length === 0 && (
          <button
            type="button"
            onClick={() => { window.location.href = `/login?callbackUrl=${encodeURIComponent(window.location.href)}`; }}
            className="w-full rounded-lg bg-white px-4 py-3 text-sm font-semibold text-black transition-colors hover:bg-white/90 focus:outline-none focus:ring-2 focus:ring-white/40"
          >
            Continue to sign in
          </button>
        )}
      </div>
    </div>
  );
}

function AuthorizeState({ onAuthorize }: { onAuthorize: () => void }) {
  return (
    <div>
      <h1 className="text-2xl font-serif italic text-white mb-2">Authorize CLI access</h1>
      <p className="text-white/45 text-sm mb-8">
        This creates a scoped BreachScope CLI key for this device.
      </p>
      <button
        type="button"
        onClick={onAuthorize}
        className="w-full rounded-lg bg-white px-4 py-3 text-sm font-semibold text-black transition-colors hover:bg-white/90 focus:outline-none focus:ring-2 focus:ring-white/40"
      >
        Authorize BreachScope CLI
      </button>
    </div>
  );
}

function AuthenticatingState() {
  return (
    <div className="text-center py-8">
      <div className="w-8 h-8 border-2 border-breach-600/40 border-t-breach-600 rounded-full animate-spin mx-auto mb-4" />
      <p className="text-white font-medium mb-1">Authorizing CLI...</p>
      <p className="text-white/40 text-sm">Almost there</p>
    </div>
  );
}

function CompleteState() {
  return (
    <div className="text-center py-6">
      <div className="w-14 h-14 rounded-full bg-green-500/15 border border-green-500/30 flex items-center justify-center mx-auto mb-5">
        <svg className="w-7 h-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      </div>
      <h2 className="text-xl font-semibold text-white mb-2">You&apos;re logged in</h2>
      <p className="text-white/40 text-sm mb-6">
        Return to your terminal - BreachScope is ready.
      </p>
      <p className="text-white/25 text-xs">You can close this tab.</p>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="text-center py-6">
      <div className="w-14 h-14 rounded-full bg-red-500/15 border border-red-500/30 flex items-center justify-center mx-auto mb-5">
        <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </div>
      <h2 className="text-xl font-semibold text-white mb-2">Authentication failed</h2>
      <p className="text-red-400/80 text-sm">{message}</p>
    </div>
  );
}

function GithubIcon() {
  return (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg className="w-4 h-4" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}
