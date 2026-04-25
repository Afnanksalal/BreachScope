"use client";

import { useState, useEffect, useTransition } from "react";
import { TopBar } from "@/components/dashboard/TopBar";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

function timeAgo(date: string | null): string {
  if (!date) return "Never";
  const diff = (Date.now() - new Date(date).getTime()) / 1000;
  if (diff < 60) return "Just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export default function KeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, startCreate] = useTransition();
  const [newKeyName, setNewKeyName] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  async function loadKeys() {
    const res = await fetch("/api/keys");
    if (res.ok) setKeys(await res.json());
    setLoading(false);
  }

  useEffect(() => { loadKeys(); }, []);

  function handleCreate() {
    if (!newKeyName.trim()) return;
    startCreate(async () => {
      const res = await fetch("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newKeyName.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setNewKeyValue(data.fullKey);
        setNewKeyName("");
        setShowForm(false);
        loadKeys();
      }
    });
  }

  async function handleRevoke(id: string) {
    setRevoking(id);
    await fetch("/api/keys", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    setRevoking(null);
    loadKeys();
  }

  async function copyKey() {
    if (!newKeyValue) return;
    await navigator.clipboard.writeText(newKeyValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const activeKeys = keys.filter((k) => !k.revokedAt);

  return (
    <>
      <TopBar title="API Keys" subtitle="Manage CLI authentication" />

      <div className="flex-1 p-8 space-y-6">
        {/* Revealed key banner */}
        <AnimatePresence>
          {newKeyValue && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="rounded-2xl border border-green-500/20 bg-green-500/[0.05] p-5"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-green-400 font-semibold text-sm">API key created</p>
                  <p className="text-white/40 text-xs mt-0.5">Copy it now — it won't be shown again.</p>
                </div>
                <button
                  onClick={() => setNewKeyValue(null)}
                  className="text-white/30 hover:text-white/60 text-xs transition-colors"
                >
                  Dismiss
                </button>
              </div>
              <div className="flex items-center gap-3 bg-black/60 border border-white/[0.08] rounded-xl px-4 py-3">
                <code className="flex-1 text-white/80 font-mono text-sm tracking-wide break-all">
                  {newKeyValue}
                </code>
                <button
                  onClick={copyKey}
                  className={clsx(
                    "shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
                    copied
                      ? "bg-green-500/20 text-green-400 border border-green-500/30"
                      : "bg-white/[0.06] text-white/60 border border-white/[0.10] hover:bg-white/10"
                  )}
                >
                  {copied ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="mt-3 p-3 rounded-xl bg-white/[0.04] border border-white/[0.08]">
                <p className="text-white/35 text-xs mb-1">Use with CLI:</p>
                <code className="text-white/55 text-xs font-mono">breachscope login --token {newKeyValue.slice(0, 20)}...</code>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Header actions */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold">Active Keys</h2>
            <p className="text-white/30 text-sm mt-0.5">{activeKeys.length} key{activeKeys.length !== 1 ? "s" : ""}</p>
          </div>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-black text-sm font-semibold hover:bg-white/90 transition-colors"
          >
            <span className="text-lg leading-none">+</span>
            New Key
          </button>
        </div>

        {/* Create form */}
        <AnimatePresence>
          {showForm && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <div className="rounded-2xl bg-white/[0.04] p-5">
                <p className="text-white/60 text-sm font-medium mb-4">Create a new API key</p>
                <div className="flex gap-3">
                  <input
                    autoFocus
                    type="text"
                    placeholder="Key name (e.g. CI/CD, Local Dev)"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleCreate()}
                    className="flex-1 bg-black/40 border border-white/[0.08] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-white/20 transition-colors"
                  />
                  <button
                    onClick={handleCreate}
                    disabled={creating || !newKeyName.trim()}
                    className="px-5 py-2.5 rounded-xl bg-white text-black text-sm font-semibold hover:bg-white/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    {creating ? "Creating…" : "Create"}
                  </button>
                  <button
                    onClick={() => { setShowForm(false); setNewKeyName(""); }}
                    className="px-4 py-2.5 rounded-xl bg-white/[0.05] border border-white/[0.08] text-white/40 text-sm hover:text-white/60 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Keys table */}
        <div className="rounded-2xl bg-white/[0.04] overflow-hidden">
          {loading ? (
            <div className="px-5 py-12 text-center text-white/20 text-sm">Loading…</div>
          ) : activeKeys.length === 0 ? (
            <div className="px-5 py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center mx-auto mb-4">
                <KeyIconLg />
              </div>
              <p className="text-white/30 text-sm mb-2">No API keys yet</p>
              <p className="text-white/20 text-xs">Create a key to connect the CLI to your account.</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/[0.05]">
                  {["Name", "Key", "Last Used", "Created", ""].map((h) => (
                    <th key={h} className="px-5 py-3 text-left text-xs text-white/25 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {activeKeys.map((key) => (
                  <tr key={key.id} className="border-b border-white/[0.05] last:border-0 hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-4">
                      <p className="text-white/80 text-sm font-medium">{key.name}</p>
                    </td>
                    <td className="px-5 py-4">
                      <code className="text-white/55 text-xs font-mono bg-white/[0.05] border border-white/[0.08] px-2 py-1 rounded-lg">
                        {key.keyPrefix}••••••••
                      </code>
                    </td>
                    <td className="px-5 py-4 text-white/35 text-xs">{timeAgo(key.lastUsedAt)}</td>
                    <td className="px-5 py-4 text-white/25 text-xs">{timeAgo(key.createdAt)}</td>
                    <td className="px-5 py-4 text-right">
                      <button
                        onClick={() => handleRevoke(key.id)}
                        disabled={revoking === key.id}
                        className="text-xs text-red-400/60 hover:text-red-400 transition-colors disabled:opacity-40"
                      >
                        {revoking === key.id ? "Revoking…" : "Revoke"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Info cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              title: "CLI Authentication",
              body: "Run breachscope login in your terminal. It opens a browser to authorize the CLI with your account securely.",
            },
            {
              title: "Key Security",
              body: "Keys are shown once at creation. We store only a SHA-256 hash — if lost, revoke and create a new one.",
            },
            {
              title: "Permissions",
              body: "Each key has full access to your account. Scope-limited keys are coming in a future release.",
            },
          ].map(({ title, body }) => (
            <div key={title} className="p-4 rounded-2xl bg-white/[0.04]">
              <p className="text-white/50 text-xs font-semibold uppercase tracking-wider mb-2">{title}</p>
              <p className="text-white/30 text-xs leading-relaxed">{body}</p>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function KeyIconLg() {
  return (
    <svg className="w-5 h-5 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
    </svg>
  );
}
