"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { useCallback, useEffect, useMemo, useState } from "react";
import { TopBar } from "@/components/dashboard/TopBar";

interface Project {
  id: string;
  name: string;
  slug: string;
  repositoryUrl: string | null;
  defaultBranch: string | null;
}

interface Policy {
  id: string;
  name: string;
  enabled: boolean;
  document: Record<string, unknown>;
}

interface Integration {
  id: string;
  provider: string;
  name: string;
  enabled: boolean;
}

interface AuditLog {
  id: string;
  action: string;
  targetType: string;
  targetId: string | null;
  createdAt: string;
}

const PROVIDERS = ["github", "gitlab", "bitbucket", "jira", "linear", "slack", "teams", "pagerduty", "saml", "scim"];

export default function ControlsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [projectName, setProjectName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [policyName, setPolicyName] = useState("Default security gate");
  const [policyDocument, setPolicyDocument] = useState(defaultPolicy());
  const [provider, setProvider] = useState("github");
  const [integrationName, setIntegrationName] = useState("GitHub");
  const [saving, setSaving] = useState(false);

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId),
    [projects, selectedProjectId],
  );

  const loadProjects = useCallback(async () => {
    const res = await fetch("/api/projects");
    if (!res.ok) return;
    const rows = await res.json() as Project[];
    setProjects(rows);
    setSelectedProjectId((current) => current || rows[0]?.id || "");
  }, []);

  const loadPolicies = useCallback(async (projectId: string) => {
    const res = await fetch(`/api/policies?projectId=${projectId}`);
    if (res.ok) setPolicies(await res.json());
  }, []);

  const loadIntegrations = useCallback(async (projectId: string) => {
    const res = await fetch(`/api/integrations?projectId=${projectId}`);
    if (res.ok) setIntegrations(await res.json());
  }, []);

  const loadAuditLogs = useCallback(async (projectId: string) => {
    const res = await fetch(`/api/audit-logs?projectId=${projectId}`);
    if (res.ok) setAuditLogs(await res.json());
  }, []);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    if (!selectedProjectId) return;
    void Promise.all([loadPolicies(selectedProjectId), loadIntegrations(selectedProjectId), loadAuditLogs(selectedProjectId)]);
  }, [selectedProjectId, loadPolicies, loadIntegrations, loadAuditLogs]);

  async function createProject() {
    if (!projectName.trim()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: projectName.trim(), repositoryUrl: repoUrl.trim() || undefined }),
      });
      if (res.ok) {
        const project = await res.json() as Project;
        setProjectName("");
        setRepoUrl("");
        await loadProjects();
        setSelectedProjectId(project.id);
      }
    } finally {
      setSaving(false);
    }
  }

  async function createPolicy() {
    if (!selectedProjectId || !policyName.trim()) return;
    setSaving(true);
    try {
      const parsed = JSON.parse(policyDocument) as Record<string, unknown>;
      const res = await fetch("/api/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId: selectedProjectId, name: policyName.trim(), document: parsed }),
      });
      if (res.ok) await loadPolicies(selectedProjectId);
    } finally {
      setSaving(false);
    }
  }

  async function createIntegration() {
    if (!selectedProjectId) return;
    setSaving(true);
    try {
      const res = await fetch("/api/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId: selectedProjectId, provider, name: integrationName.trim() || provider }),
      });
      if (res.ok) await loadIntegrations(selectedProjectId);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <TopBar title="Controls" subtitle="Projects, policies, customer-owned integrations, and audit logs" />
      <div className="flex-1 space-y-8 overflow-y-auto px-4 py-5 sm:px-6 md:px-8 md:py-8">
        <section className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="border border-white/[0.08] rounded-lg bg-white/[0.03] p-5">
            <div className="mb-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <h2 className="text-white text-sm font-semibold">Projects</h2>
                <p className="text-white/35 text-xs">Group scans, policies, integrations, and audit history by application.</p>
              </div>
              <select
                value={selectedProjectId}
                onChange={(event) => setSelectedProjectId(event.target.value)}
                className="bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white"
              >
                <option value="">Select project</option>
                {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
              </select>
            </div>
            <div className="space-y-2">
              {projects.map((project) => (
                <button
                  key={project.id}
                  onClick={() => setSelectedProjectId(project.id)}
                  className={`w-full text-left border rounded-lg px-4 py-3 transition-colors ${project.id === selectedProjectId ? "border-white/20 bg-white/[0.06]" : "border-white/[0.06] bg-black/20 hover:bg-white/[0.04]"}`}
                >
                  <div className="flex items-center justify-between gap-4">
                    <span className="min-w-0 truncate text-sm font-medium text-white">{project.name}</span>
                    <span className="text-white/25 text-xs">{project.defaultBranch || "main"}</span>
                  </div>
                  <p className="mt-1 break-all text-xs text-white/35">{project.repositoryUrl || project.slug}</p>
                </button>
              ))}
              {projects.length === 0 && <p className="text-white/35 text-sm">No projects yet.</p>}
            </div>
          </div>

          <div className="border border-white/[0.08] rounded-lg bg-white/[0.03] p-5">
            <h2 className="text-white text-sm font-semibold mb-4">Create Project</h2>
            <div className="space-y-3">
              <input value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="Project name" className="w-full bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25" />
              <input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="Repository URL" className="w-full bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25" />
              <button disabled={saving || !projectName.trim()} onClick={createProject} className="w-full rounded-lg bg-white text-black text-sm font-medium py-2 disabled:opacity-40">Create</button>
            </div>
          </div>
        </section>

        {selectedProject && (
          <section className="grid gap-4 xl:grid-cols-3">
            <Panel title="Policy-as-Code" subtitle={selectedProject.name}>
              <div className="space-y-3">
                <input value={policyName} onChange={(e) => setPolicyName(e.target.value)} className="w-full bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white" />
                <textarea value={policyDocument} onChange={(e) => setPolicyDocument(e.target.value)} rows={10} className="w-full rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 font-mono text-xs text-white" />
                <button disabled={saving} onClick={createPolicy} className="w-full rounded-lg bg-white text-black text-sm font-medium py-2 disabled:opacity-40">Save Policy</button>
                <List rows={policies.map((item) => `${item.enabled ? "on" : "off"} - ${item.name}`)} empty="No policies." />
              </div>
            </Panel>

            <Panel title="Integrations" subtitle="SCM, ticketing, chat, incident, SSO">
              <div className="space-y-3">
                <select value={provider} onChange={(e) => { setProvider(e.target.value); setIntegrationName(labelForProvider(e.target.value)); }} className="w-full bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white">
                  {PROVIDERS.map((item) => <option key={item} value={item}>{labelForProvider(item)}</option>)}
                </select>
                <input value={integrationName} onChange={(e) => setIntegrationName(e.target.value)} className="w-full bg-black/40 border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white" />
                <button disabled={saving} onClick={createIntegration} className="w-full rounded-lg bg-white text-black text-sm font-medium py-2 disabled:opacity-40">Add Integration</button>
                <List rows={integrations.map((item) => `${item.enabled ? "on" : "off"} - ${labelForProvider(item.provider)} - ${item.name}`)} empty="No integrations." />
              </div>
            </Panel>

            <Panel title="Audit Logs" subtitle="Last 200 events">
              <List rows={auditLogs.map((item) => `${new Date(item.createdAt).toLocaleString()} - ${item.action} - ${item.targetType}`)} empty="No audit events." />
            </Panel>
          </section>
        )}
      </div>
    </>
  );
}

function Panel({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="min-h-0 rounded-lg border border-white/[0.08] bg-white/[0.03] p-5 xl:min-h-[24rem]">
      <h2 className="text-white text-sm font-semibold">{title}</h2>
      <p className="text-white/35 text-xs mb-4">{subtitle}</p>
      {children}
    </div>
  );
}

function List({ rows, empty }: { rows: string[]; empty: string }) {
  if (rows.length === 0) return <p className="text-white/35 text-sm">{empty}</p>;
  return (
    <div className="space-y-2 pt-2">
      {rows.map((row) => (
        <div key={row} className="break-words rounded-lg border border-white/[0.06] bg-black/20 px-3 py-2 text-xs text-white/60">
          {row}
        </div>
      ))}
    </div>
  );
}

function labelForProvider(value: string): string {
  const labels: Record<string, string> = {
    github: "GitHub",
    gitlab: "GitLab",
    bitbucket: "Bitbucket",
    jira: "Jira",
    linear: "Linear",
    slack: "Slack",
    teams: "Teams",
    pagerduty: "PagerDuty",
    saml: "SAML",
    scim: "SCIM",
  };
  return labels[value] ?? value;
}

function defaultPolicy(): string {
  return JSON.stringify({
    failOn: "high",
    maxFindings: { critical: 0 },
    blockedPackages: [],
    deniedCategories: [],
    suppressions: [],
  }, null, 2);
}
