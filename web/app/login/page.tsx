"use client";

import { signIn } from "next-auth/react";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

type Mode = "signin" | "register";
type OAuthProvider = "github" | "google";

export default function LoginPage() {
  const [mode, setMode]       = useState<Mode>("signin");
  const [email, setEmail]     = useState("");
  const [password, setPassword] = useState("");
  const [name, setName]       = useState("");
  const [oauthLoading, setOauthLoading] = useState<string | null>(null);
  const [oauthProviders, setOauthProviders] = useState<OAuthProvider[]>([]);
  const [callbackUrl] = useState(() => initialCallbackUrl());
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);

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

  function switchMode(next: Mode) {
    setMode(next);
    setError(null);
    setPassword("");
  }

  async function handleOAuth(provider: "github" | "google") {
    setOauthLoading(provider);
    await signIn(provider, { callbackUrl });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "register") {
        const res = await fetch("/api/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, name: name || undefined }),
        });
        const data = await res.json() as { error?: string };
        if (!res.ok) { setError(data.error ?? "Registration failed"); return; }
        // auto sign in after registration
      }

      const result = await signIn("credentials", {
        email,
        password,
        redirect: false,
      });

      if (result?.error) {
        setError(mode === "signin" ? "Invalid email or password" : "Account created but sign-in failed - try again");
      } else {
        window.location.href = callbackUrl;
      }
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#000] px-4 py-10">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="text-center mb-8"
        >
          <Link href="/" className="inline-block group mb-5">
            <span className="font-serif italic text-xl text-white group-hover:text-white/70 transition-colors">
              BreachScope
            </span>
          </Link>
          <h1 className="text-white text-[1.4rem] font-semibold tracking-tight">
            {mode === "signin" ? "Sign in" : "Create account"}
          </h1>
          <p className="text-white/35 text-sm mt-1.5">
            {mode === "signin" ? "Access your security dashboard" : "Start securing your stack today"}
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.08 }}
          className="space-y-3"
        >
          {oauthProviders.includes("github") && (
            <button
              type="button"
              onClick={() => handleOAuth("github")}
              disabled={!!oauthLoading || loading}
              className="w-full flex items-center justify-center gap-3 px-5 py-3 rounded-lg bg-white/[0.05] border border-white/[0.08] text-white/75 text-sm font-medium hover:bg-white/[0.09] hover:text-white/95 transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {oauthLoading === "github" ? <SpinnerIcon /> : <GitHubIcon />}
              Continue with GitHub
            </button>
          )}

          {oauthProviders.includes("google") && (
            <button
              type="button"
              onClick={() => handleOAuth("google")}
              disabled={!!oauthLoading || loading}
              className="w-full flex items-center justify-center gap-3 px-5 py-3 rounded-lg bg-white/[0.05] border border-white/[0.08] text-white/75 text-sm font-medium hover:bg-white/[0.09] hover:text-white/95 transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {oauthLoading === "google" ? <SpinnerIcon /> : <GoogleIcon />}
              Continue with Google
            </button>
          )}

          {oauthProviders.length > 0 && (
            <div className="flex items-center gap-3 py-1">
              <div className="flex-1 h-px bg-white/[0.07]" />
              <span className="text-white/25 text-xs">or</span>
              <div className="flex-1 h-px bg-white/[0.07]" />
            </div>
          )}

          {/* Email/password form */}
          <form onSubmit={handleSubmit} className="space-y-2.5">
            {mode === "register" && (
              <label className="block">
                <span className="sr-only">Name</span>
                <input
                  type="text"
                  placeholder="Name (optional)"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  className="w-full px-4 py-3 rounded-lg bg-white/[0.04] border border-white/[0.08] text-white/85 placeholder-white/25 text-sm outline-none focus:border-white/20 focus:bg-white/[0.06] transition-all duration-150"
                />
              </label>
            )}

            <label className="block">
              <span className="sr-only">Email</span>
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-4 py-3 rounded-lg bg-white/[0.04] border border-white/[0.08] text-white/85 placeholder-white/25 text-sm outline-none focus:border-white/20 focus:bg-white/[0.06] transition-all duration-150"
              />
            </label>

            <label className="block">
              <span className="sr-only">Password</span>
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={mode === "register" ? 8 : 1}
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                className="w-full px-4 py-3 rounded-lg bg-white/[0.04] border border-white/[0.08] text-white/85 placeholder-white/25 text-sm outline-none focus:border-white/20 focus:bg-white/[0.06] transition-all duration-150"
              />
            </label>

            {error && (
              <p className="text-red-400/80 text-xs px-1">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading || !!oauthLoading}
              className="w-full flex items-center justify-center gap-2 px-5 py-3 rounded-lg bg-white text-black text-sm font-semibold hover:bg-white/90 transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? <SpinnerIcon dark /> : null}
              {mode === "signin" ? "Sign in" : "Create account"}
            </button>
          </form>

          {/* Mode toggle */}
          <p className="text-center text-white/30 text-xs pt-1">
            {mode === "signin" ? (
              <>
                No account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("register")}
                  className="text-white/55 hover:text-white/80 transition-colors underline underline-offset-2"
                >
                  Create one
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signin")}
                  className="text-white/55 hover:text-white/80 transition-colors underline underline-offset-2"
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="text-center text-white/18 text-xs mt-8 leading-relaxed"
        >
          By continuing you agree to our{" "}
          <Link href="/terms" className="text-white/35 hover:text-white/55 transition-colors">Terms</Link>
          {" "}and{" "}
          <Link href="/privacy" className="text-white/35 hover:text-white/55 transition-colors">Privacy Policy</Link>.
        </motion.p>
      </div>
    </div>
  );
}

function GitHubIcon() {
  return (
    <svg className="w-[1.1rem] h-[1.1rem] shrink-0" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg className="w-[1.1rem] h-[1.1rem] shrink-0" viewBox="0 0 24 24">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>
  );
}

function SpinnerIcon({ dark }: { dark?: boolean }) {
  return (
    <svg className={`w-4 h-4 animate-spin shrink-0 ${dark ? "text-black/40" : "text-white/40"}`} fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function initialCallbackUrl(): string {
  if (typeof window === "undefined") return "/dashboard";
  const requested = new URLSearchParams(window.location.search).get("callbackUrl");
  if (!requested) return "/dashboard";
  try {
    const url = new URL(requested, window.location.origin);
    return url.origin === window.location.origin ? `${url.pathname}${url.search}${url.hash}` : "/dashboard";
  } catch {
    return "/dashboard";
  }
}
