"use client";

import { useCallback, useEffect, useState, useTransition } from "react";
import { TopBar } from "@/components/dashboard/TopBar";
import { CheckboxControl } from "@/components/ui/CheckboxControl";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

const DEFAULT_SCOPES = ["scan:write", "config:read"];
const AVAILABLE_SCOPES = [
  { value: "scan:write", label: "Scan upload" },
  { value: "config:read", label: "Read config" },
  { value: "secrets:read", label: "Read secrets" },
  { value: "settings:write", label: "Write settings" },
];

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
  const [selectedScopes, setSelectedScopes] = useState<string[]>(DEFAULT_SCOPES);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  const loadKeys = useCallback(async () => {
    const res = await fetch("/api/keys");
    if (res.ok) setKeys(await res.json());
    setLoading(false);
  }, []);

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { void loadKeys(); }, [loadKeys]);

  function handleCreate() {
    if (!newKeyName.trim()) return;
    startCreate(async () => {
      const res = await fetch("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newKeyName.trim(), scopes: selectedScopes }),
      });
      if (res.ok) {
        const data = await res.json();
        setNewKeyValue(data.fullKey);
        setNewKeyName("");
        setSelectedScopes(DEFAULT_SCOPES);
        setShowForm(false);
        void loadKeys();
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
    void loadKeys();
  }

  async function copyKey() {
    if (!newKeyValue) return;
    await navigator.clipboard.writeText(newKeyValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function toggleScope(scope: string) {
    setSelectedScopes((current) => (
      current.includes(scope)
        ? current.filter((item) => item !== scope)
        : [...current, scope]
    ));
  }

  const activeKeys = keys.filter((k) => !k.revokedAt);

  return (
    <>
      <TopBar title="API Keys" subtitle="Manage CLI authentication" />

      <div className="flex-1 space-y-6 px-4 py-5 sm:px-6 md:p-8">
        {/* Revealed key banner */}
        <AnimatePresence>
          {newKeyValue && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="rounded-lg border border-green-500/20 bg-green-500/[0.05] p-5"
            >
              <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="text-green-400 font-semibold text-sm">API key created</p>
                  <p className="text-white/40 text-xs mt-0.5">Copy it now; it won&apos;t be shown again.</p>
                </div>
                <button
                  onClick={() => setNewKeyValue(null)}
                  className="text-white/30 hover:text-white/60 text-xs transition-colors"
                >
                  Dismiss
                </button>
              </div>
              <div className="flex flex-col gap-3 rounded-lg border border-white/[0.08] bg-black/60 px-4 py-3 sm:flex-row sm:items-center">
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
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="mt-3 p-3 rounded-lg bg-white/[0.04] border border-white/[0.08]">
                <p className="text-white/35 text-xs mb-1">Use with CLI:</p>
                <code className="break-words font-mono text-xs text-white/55">breachscope login --token {newKeyValue.slice(0, 20)}...</code>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Header actions */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-white font-semibold">Active Keys</h2>
            <p className="text-white/30 text-sm mt-0.5">{activeKeys.length} key{activeKeys.length !== 1 ? "s" : ""}</p>
          </div>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white text-black text-sm font-semibold hover:bg-white/90 transition-colors"
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
              <div className="rounded-lg bg-white/[0.04] p-5">
                <p className="text-white/60 text-sm font-medium mb-4">Create a new API key</p>
                <div className="flex flex-col gap-3 sm:flex-row">
                  <input
                    autoFocus
                    type="text"
                    placeholder="Key name (e.g. CI/CD, Local Dev)"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleCreate()}
                    className="flex-1 bg-black/40 border border-white/[0.08] rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-white/20 transition-colors"
                  />
                  <button
                    onClick={handleCreate}
                    disabled={creating || !newKeyName.trim()}
                    className="px-5 py-2.5 rounded-lg bg-white text-black text-sm font-semibold hover:bg-white/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    {creating ? "Creating..." : "Create"}
                  </button>
                  <button
                    onClick={() => { setShowForm(false); setNewKeyName(""); }}
                    className="px-4 py-2.5 rounded-lg bg-white/[0.05] border border-white/[0.08] text-white/40 text-sm hover:text-white/60 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
                <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {AVAILABLE_SCOPES.map((scope) => (
                    <CheckboxControl
                      key={scope.value}
                      checked={selectedScopes.includes(scope.value)}
                      onChange={() => toggleScope(scope.value)}
                      label={scope.label}
                    />
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Keys table */}
        <div className="rounded-lg bg-white/[0.04] overflow-hidden">
          {loading ? (
            <div className="px-5 py-12 text-center text-sm text-white/20">Loading...</div>
          ) : activeKeys.length === 0 ? (
            <div className="px-5 py-16 text-center">
              <div className="w-12 h-12 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center mx-auto mb-4">
                <KeyIconLg />
              </div>
              <p className="text-white/30 text-sm mb-2">No API keys yet</p>
              <p className="text-white/20 text-xs">Create a key to connect the CLI to your account.</p>
            </div>
          ) : (
            <>
            <div className="grid gap-3 p-3 md:hidden">
              {activeKeys.map((key) => (
                <div key={key.id} className="rounded-lg border border-white/[0.07] bg-black/20 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-white/80">{key.name}</p>
                      <code className="mt-2 inline-block rounded-lg border border-white/[0.08] bg-white/[0.05] px-2 py-1 font-mono text-xs text-white/55">
                        {key.keyPrefix}********
                      </code>
                    </div>
                    <button
                      onClick={() => handleRevoke(key.id)}
                      disabled={revoking === key.id}
                      className="shrink-0 text-xs text-red-400/60 transition-colors hover:text-red-400 disabled:opacity-40"
                    >
                      {revoking === key.id ? "Revoking..." : "Revoke"}
                    </button>
                  </div>
                  <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-white/35 min-[420px]:grid-cols-2">
                    <p><span className="text-white/22">Scopes:</span> {formatScopes(key.scopes)}</p>
                    <p><span className="text-white/22">Last used:</span> {timeAgo(key.lastUsedAt)}</p>
                    <p><span className="text-white/22">Created:</span> {timeAgo(key.createdAt)}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="hidden overflow-x-auto md:block">
            <table className="w-full min-w-[760px]">
              <thead>
                <tr className="border-b border-white/[0.05]">
                  {["Name", "Key", "Scopes", "Last Used", "Created", ""].map((h) => (
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
                        {key.keyPrefix}********
                      </code>
                    </td>
                    <td className="px-5 py-4 text-white/35 text-xs">{formatScopes(key.scopes)}</td>
                    <td className="px-5 py-4 text-white/35 text-xs">{timeAgo(key.lastUsedAt)}</td>
                    <td className="px-5 py-4 text-white/25 text-xs">{timeAgo(key.createdAt)}</td>
                    <td className="px-5 py-4 text-right">
                      <button
                        onClick={() => handleRevoke(key.id)}
                        disabled={revoking === key.id}
                        className="text-xs text-red-400/60 hover:text-red-400 transition-colors disabled:opacity-40"
                      >
                        {revoking === key.id ? "Revoking..." : "Revoke"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            </>
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
              body: "Keys are shown once at creation. We store only a SHA-256 hash. If lost, revoke and create a new one.",
            },
            {
              title: "Permissions",
              body: "Grant only the scopes each automation path needs. Secret access is separate from scan upload and config read.",
            },
          ].map(({ title, body }) => (
            <div key={title} className="p-4 rounded-lg bg-white/[0.04]">
              <p className="text-white/50 text-xs font-semibold uppercase tracking-wider mb-2">{title}</p>
              <p className="text-white/30 text-xs leading-relaxed">{body}</p>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function formatScopes(scopes: string[] | null): string {
  const values = Array.isArray(scopes) && scopes.length > 0 ? scopes : DEFAULT_SCOPES;
  return values.join(", ");
}

function KeyIconLg() {
  return (
    <svg className="w-5 h-5 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
    </svg>
  );
}
