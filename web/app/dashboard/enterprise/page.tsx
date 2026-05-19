"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { TopBar } from "@/components/dashboard/TopBar";
import { CheckboxControl } from "@/components/ui/CheckboxControl";
import { CustomSelect } from "@/components/ui/CustomSelect";
import { clsx } from "clsx";

interface Project {
  id: string;
  organizationId: string | null;
  name: string;
  slug: string;
  repositoryUrl: string | null;
  defaultBranch: string | null;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
  ssoDomain: string | null;
  role: string;
  projectCount: number;
}

interface OrgMember {
  userId: string;
  email: string;
  name: string | null;
  role: string;
  createdAt: string;
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
  config: Record<string, unknown> | null;
  hasSecret: boolean;
  updatedAt: string;
}

interface AuditLog {
  id: string;
  action: string;
  targetType: string;
  targetId: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
}

interface IntegrationDelivery {
  id: string;
  provider: string;
  action: string;
  status: string;
  attempts: number;
  maxAttempts: number;
  scanId: string | null;
  nextAttemptAt: string | null;
  deliveredAt: string | null;
  externalUrl: string | null;
  lastError: string | null;
  createdAt: string;
}

interface Feedback {
  type: "success" | "error" | "info";
  title: string;
  body?: string;
  href?: string;
}

const PROVIDERS = ["github", "jira", "linear", "slack", "teams", "pagerduty", "saml", "scim", "gitlab", "bitbucket"];
const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical", description: "Only critical findings create delivery work." },
  { value: "high", label: "High", description: "Critical and high findings create delivery work." },
  { value: "medium", label: "Medium", description: "Medium and above findings create delivery work." },
  { value: "low", label: "Low", description: "Low and above findings create delivery work." },
  { value: "info", label: "Info", description: "Every completed scan creates delivery work." },
];
const ROLE_OPTIONS = [
  { value: "owner", label: "Owner", description: "Full workspace and billing control." },
  { value: "admin", label: "Admin", description: "Manage projects, members, and integrations." },
  { value: "security", label: "Security", description: "Operate scans, policies, and triage." },
  { value: "auditor", label: "Auditor", description: "Read evidence and audit history." },
  { value: "member", label: "Member", description: "Default workspace access." },
];

const PROVIDER_COPY: Record<string, { label: string; purpose: string; secretLabel: string }> = {
  github: { label: "GitHub", purpose: "Repository posture, pull request review, workflow controls, and issue routing.", secretLabel: "Fine-grained PAT or GitHub App token" },
  jira: { label: "Jira", purpose: "Create remediation tickets for findings that need ownership.", secretLabel: "Jira API token" },
  linear: { label: "Linear", purpose: "Create lightweight engineering follow-up issues.", secretLabel: "Linear API key" },
  slack: { label: "Slack", purpose: "Send scan and policy events to a channel webhook.", secretLabel: "Incoming webhook URL" },
  teams: { label: "Teams", purpose: "Send scan and policy events to a Teams webhook.", secretLabel: "Incoming webhook URL" },
  pagerduty: { label: "PagerDuty", purpose: "Trigger incidents for severe findings.", secretLabel: "Events routing key" },
  saml: { label: "SAML", purpose: "Track identity provider metadata for SSO rollout.", secretLabel: "Optional signing secret" },
  scim: { label: "SCIM", purpose: "Track lifecycle provisioning configuration.", secretLabel: "Optional bearer token" },
  gitlab: { label: "GitLab", purpose: "Create GitLab issues from scan findings for the configured project.", secretLabel: "Project access token" },
  bitbucket: { label: "Bitbucket", purpose: "Create Bitbucket issues from scan findings for the configured repository.", secretLabel: "App password or access token" },
};

export default function ControlsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState("");
  const [orgName, setOrgName] = useState("");
  const [orgDomain, setOrgDomain] = useState("");
  const [orgMembers, setOrgMembers] = useState<OrgMember[]>([]);
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("security");
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [deliveries, setDeliveries] = useState<IntegrationDelivery[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditActionFilter, setAuditActionFilter] = useState("");
  const [auditTargetFilter, setAuditTargetFilter] = useState("");
  const [projectName, setProjectName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [defaultBranch, setDefaultBranch] = useState("main");
  const [policyName, setPolicyName] = useState("Default security gate");
  const [policyDocument, setPolicyDocument] = useState(defaultPolicy());
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [auditingId, setAuditingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const [provider, setProvider] = useState("github");
  const [integrationName, setIntegrationName] = useState("GitHub");
  const [secret, setSecret] = useState("");
  const [minimumSeverity, setMinimumSeverity] = useState("high");
  const [githubRepo, setGithubRepo] = useState("");
  const [githubBranch, setGithubBranch] = useState("main");
  const [githubCreateIssues, setGithubCreateIssues] = useState(false);
  const [githubLabels, setGithubLabels] = useState("security, breachscope");
  const [auditPrNumber, setAuditPrNumber] = useState("");
  const [auditCreateIssue, setAuditCreateIssue] = useState(false);
  const [auditCommentOnPr, setAuditCommentOnPr] = useState(false);
  const [jiraSiteUrl, setJiraSiteUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("");
  const [jiraIssueType, setJiraIssueType] = useState("Bug");
  const [jiraLabels, setJiraLabels] = useState("security, breachscope");
  const [jiraPriority, setJiraPriority] = useState("");
  const [linearTeamId, setLinearTeamId] = useState("");
  const [linearProjectId, setLinearProjectId] = useState("");
  const [linearLabelIds, setLinearLabelIds] = useState("");
  const [linearPriority, setLinearPriority] = useState("2");
  const [channel, setChannel] = useState("");
  const [pagerDutyService, setPagerDutyService] = useState("");
  const [gitlabInstanceUrl, setGitlabInstanceUrl] = useState("https://gitlab.com");
  const [gitlabProjectPath, setGitlabProjectPath] = useState("");
  const [gitlabCreateIssues, setGitlabCreateIssues] = useState(true);
  const [gitlabLabels, setGitlabLabels] = useState("security, breachscope");
  const [bitbucketWorkspace, setBitbucketWorkspace] = useState("");
  const [bitbucketRepoSlug, setBitbucketRepoSlug] = useState("");
  const [bitbucketUsername, setBitbucketUsername] = useState("");
  const [bitbucketCreateIssues, setBitbucketCreateIssues] = useState(true);
  const [samlEntityId, setSamlEntityId] = useState("");
  const [samlSsoUrl, setSamlSsoUrl] = useState("");
  const [scimTenant, setScimTenant] = useState("");

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId),
    [projects, selectedProjectId],
  );
  const selectedOrganization = useMemo(
    () => organizations.find((organization) => organization.id === selectedOrgId),
    [organizations, selectedOrgId],
  );

  const providerMeta = getProviderMeta(provider);
  const githubIntegrations = integrations.filter((item) => item.provider === "github");

  const loadOrganizations = useCallback(async () => {
    const res = await fetch("/api/organizations");
    if (!res.ok) return;
    const rows = await res.json() as Organization[];
    setOrganizations(rows);
    setSelectedOrgId((current) => current || rows[0]?.id || "");
  }, []);

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

  const loadDeliveries = useCallback(async (projectId: string) => {
    const res = await fetch(`/api/integration-deliveries?projectId=${projectId}`);
    if (res.ok) setDeliveries(await res.json());
  }, []);

  const loadAuditLogs = useCallback(async (projectId: string, action = auditActionFilter, targetType = auditTargetFilter) => {
    const params = new URLSearchParams({ projectId });
    if (action.trim()) params.set("action", action.trim());
    if (targetType.trim()) params.set("targetType", targetType.trim());
    const res = await fetch(`/api/audit-logs?${params}`);
    if (res.ok) setAuditLogs(await res.json());
  }, [auditActionFilter, auditTargetFilter]);

  const loadMembers = useCallback(async (organizationId: string) => {
    if (!organizationId) return setOrgMembers([]);
    const res = await fetch(`/api/organizations/members?organizationId=${organizationId}`);
    if (res.ok) setOrgMembers(await res.json());
    else setOrgMembers([]);
  }, []);

  useEffect(() => {
    void Promise.all([loadOrganizations(), loadProjects()]);
  }, [loadOrganizations, loadProjects]);

  useEffect(() => {
    if (!selectedProjectId) return;
    void Promise.all([loadPolicies(selectedProjectId), loadIntegrations(selectedProjectId), loadDeliveries(selectedProjectId), loadAuditLogs(selectedProjectId)]);
  }, [selectedProjectId, loadPolicies, loadIntegrations, loadDeliveries, loadAuditLogs]);

  useEffect(() => {
    if (!selectedOrgId) return;
    void loadMembers(selectedOrgId);
  }, [selectedOrgId, loadMembers]);

  useEffect(() => {
    if (!selectedProject) return;
    if (!githubRepo && selectedProject.repositoryUrl) setGithubRepo(selectedProject.repositoryUrl);
    if (!gitlabProjectPath && selectedProject.repositoryUrl) setGitlabProjectPath(selectedProject.repositoryUrl);
    if (selectedProject.defaultBranch) setGithubBranch(selectedProject.defaultBranch);
  }, [selectedProject, githubRepo, gitlabProjectPath]);

  async function createOrganization() {
    if (!orgName.trim()) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await fetch("/api/organizations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: orgName.trim(), ssoDomain: orgDomain.trim() || undefined }),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Workspace could not be created."));
      const organization = await res.json() as Organization;
      setOrgName("");
      setOrgDomain("");
      await loadOrganizations();
      setSelectedOrgId(organization.id);
      setFeedback({ type: "success", title: "Workspace created", body: `${organization.name} is ready for shared projects and roles.` });
    } finally {
      setSaving(false);
    }
  }

  async function addMember() {
    if (!selectedOrgId || !memberEmail.trim()) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await fetch("/api/organizations/members", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ organizationId: selectedOrgId, email: memberEmail.trim(), role: memberRole }),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Member could not be added."));
      setMemberEmail("");
      await loadMembers(selectedOrgId);
      setFeedback({ type: "success", title: "Member updated", body: "Workspace access is now reflected in the member table." });
    } finally {
      setSaving(false);
    }
  }

  async function createProject() {
    if (!projectName.trim()) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: projectName.trim(),
          organizationId: selectedOrgId || undefined,
          repositoryUrl: repoUrl.trim() || undefined,
          defaultBranch: defaultBranch.trim() || "main",
        }),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Project could not be created."));
      const project = await res.json() as Project;
      setProjectName("");
      setRepoUrl("");
      setDefaultBranch("main");
      await loadProjects();
      setSelectedProjectId(project.id);
      setFeedback({ type: "success", title: "Project created", body: `${project.name} is ready for scans and integrations.` });
    } finally {
      setSaving(false);
    }
  }

  async function createPolicy() {
    if (!selectedProjectId || !policyName.trim()) return;
    setSaving(true);
    setFeedback(null);
    try {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(policyDocument) as Record<string, unknown>;
      } catch {
        setFeedback({ type: "error", title: "Policy JSON is invalid", body: "Fix the JSON document before saving the policy." });
        return;
      }
      const res = await fetch("/api/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId: selectedProjectId, name: policyName.trim(), document: parsed }),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Policy could not be saved."));
      await Promise.all([loadPolicies(selectedProjectId), loadAuditLogs(selectedProjectId)]);
      setFeedback({ type: "success", title: "Policy saved", body: "The project gate is now part of the audit trail." });
    } finally {
      setSaving(false);
    }
  }

  async function createIntegration() {
    if (!selectedProjectId) return;
    setSaving(true);
    setFeedback(null);
    try {
      const payload = buildIntegrationPayload();
      const res = await fetch("/api/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Integration could not be added."));
      await Promise.all([loadIntegrations(selectedProjectId), loadAuditLogs(selectedProjectId)]);
      setSecret("");
      setFeedback({ type: "success", title: `${providerMeta.label} connected`, body: "The integration is encrypted, scoped to this project, and ready to test." });
    } finally {
      setSaving(false);
    }
  }

  async function testIntegration(integrationId: string) {
    setTestingId(integrationId);
    setFeedback(null);
    try {
      const res = await fetch("/api/integrations/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ integrationId }),
      });
      const data = await res.json().catch(() => null) as Record<string, unknown> | null;
      if (!res.ok) {
        setFeedback({ type: "error", title: "Integration test failed", body: stringFrom(data?.["error"]) || stringFrom(data?.["message"]) || "Provider rejected the request." });
        return;
      }
      setFeedback({ type: "success", title: "Integration test passed", body: stringFrom(data?.["message"]) || "Provider accepted the test request." });
    } finally {
      setTestingId(null);
    }
  }

  async function deleteIntegration(integrationId: string) {
    setDeletingId(integrationId);
    setFeedback(null);
    try {
      const res = await fetch("/api/integrations", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: integrationId }),
      });
      if (!res.ok) return setFeedback(await responseFeedback(res, "Integration could not be removed."));
      await Promise.all([loadIntegrations(selectedProjectId), loadAuditLogs(selectedProjectId)]);
      setFeedback({ type: "success", title: "Integration removed", body: "The project route was deleted." });
    } finally {
      setDeletingId(null);
    }
  }

  async function runGitHubAudit(integrationId: string) {
    setAuditingId(integrationId);
    setFeedback(null);
    try {
      const res = await fetch("/api/integrations/github/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          integrationId,
          prNumber: auditPrNumber.trim() || undefined,
          createIssue: auditCreateIssue,
          commentOnPr: auditCommentOnPr,
        }),
      });
      const data = await res.json().catch(() => null) as Record<string, unknown> | null;
      if (!res.ok) {
        setFeedback({ type: "error", title: "GitHub audit failed", body: stringFrom(data?.["error"]) || "The audit could not be completed." });
        return;
      }
      await Promise.all([loadAuditLogs(selectedProjectId), loadIntegrations(selectedProjectId)]);
      setFeedback({
        type: "success",
        title: "GitHub audit complete",
        body: `${stringFrom(data?.["totalFindings"]) || "0"} finding(s) were saved as a dashboard scan.`,
        href: stringFrom(data?.["scanUrl"]),
      });
    } finally {
      setAuditingId(null);
    }
  }

  function buildIntegrationPayload() {
    const base = {
      projectId: selectedProjectId,
      provider,
      name: integrationName.trim() || providerMeta.label,
      secret: secret.trim() || undefined,
      config: { minimumSeverity },
    };

    if (provider === "github") {
      return {
        ...base,
        config: {
          repoFullName: githubRepo.trim(),
          defaultBranch: githubBranch.trim() || "main",
          createIssues: githubCreateIssues,
          labels: githubLabels.split(",").map((item) => item.trim()).filter(Boolean),
          minimumSeverity,
        },
      };
    }
    if (provider === "gitlab") {
      return {
        ...base,
        config: {
          instanceUrl: gitlabInstanceUrl.trim() || "https://gitlab.com",
          projectPath: gitlabProjectPath.trim(),
          createIssues: gitlabCreateIssues,
          labels: gitlabLabels.split(",").map((item) => item.trim()).filter(Boolean),
          minimumSeverity,
        },
      };
    }
    if (provider === "bitbucket") {
      return {
        ...base,
        config: {
          workspace: bitbucketWorkspace.trim(),
          repoSlug: bitbucketRepoSlug.trim(),
          username: bitbucketUsername.trim(),
          createIssues: bitbucketCreateIssues,
          minimumSeverity,
        },
      };
    }
    if (provider === "jira") {
      return {
        ...base,
        config: {
          siteUrl: jiraSiteUrl.trim(),
          email: jiraEmail.trim(),
          projectKey: jiraProjectKey.trim(),
          issueType: jiraIssueType.trim() || "Bug",
          labels: jiraLabels.split(",").map((item) => item.trim()).filter(Boolean),
          priorityName: jiraPriority.trim(),
          minimumSeverity,
        },
      };
    }
    if (provider === "linear") {
      return {
        ...base,
        config: {
          teamId: linearTeamId.trim(),
          projectId: linearProjectId.trim(),
          labelIds: linearLabelIds.split(",").map((item) => item.trim()).filter(Boolean),
          priority: Number.parseInt(linearPriority, 10),
          minimumSeverity,
        },
      };
    }
    if (provider === "slack" || provider === "teams") return { ...base, config: { channel: channel.trim(), minimumSeverity } };
    if (provider === "pagerduty") return { ...base, config: { serviceName: pagerDutyService.trim(), minimumSeverity } };
    if (provider === "saml") return { ...base, config: { entityId: samlEntityId.trim(), ssoUrl: samlSsoUrl.trim() } };
    if (provider === "scim") return { ...base, config: { tenant: scimTenant.trim() } };
    return base;
  }

  return (
    <>
      <TopBar title="Controls" subtitle="Projects, policy gates, provider routing, GitHub audits, and evidence logs" />
      <div className="flex-1 space-y-6 overflow-y-auto px-4 py-5 sm:px-6 md:px-8 md:py-8">
        {feedback && <FeedbackBanner feedback={feedback} onDismiss={() => setFeedback(null)} />}

        <section className="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <Panel title="Workspace" subtitle="Shared ownership, role controls, and project scope.">
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-[1fr_auto]">
                <CustomSelect
                  value={selectedOrgId}
                  onChange={setSelectedOrgId}
                  placeholder="Personal workspace"
                  ariaLabel="Select workspace"
                  options={organizations.map((organization) => ({
                    value: organization.id,
                    label: organization.name,
                    description: `${organization.role} - ${organization.projectCount} project${organization.projectCount === 1 ? "" : "s"}`,
                  }))}
                />
                <span className="rounded-lg border border-white/[0.08] bg-black/25 px-3 py-2 text-xs text-white/35">
                  {selectedOrganization?.ssoDomain || "No SSO domain"}
                </span>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <input value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Workspace name" className={inputClass()} />
                <input value={orgDomain} onChange={(e) => setOrgDomain(e.target.value)} placeholder="sso.company.com" className={inputClass()} />
                <button disabled={saving || !orgName.trim()} onClick={createOrganization} className={primaryButtonClass()}>
                  Create workspace
                </button>
              </div>
            </div>
          </Panel>

          <Panel title="Team Access" subtitle={selectedOrganization ? `${selectedOrganization.name} members` : "Create a workspace to add members."}>
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-[1fr_12rem_auto]">
                <input value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} placeholder="teammate@company.com" className={inputClass()} />
                <CustomSelect value={memberRole} onChange={setMemberRole} ariaLabel="Member role" options={ROLE_OPTIONS} />
                <button disabled={saving || !selectedOrgId || !memberEmail.trim()} onClick={addMember} className={primaryButtonClass()}>
                  Add member
                </button>
              </div>
              <div className="grid gap-2">
                {orgMembers.map((member) => (
                  <div key={member.userId} className="flex flex-col gap-2 rounded-lg border border-white/[0.06] bg-black/20 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-white/70">{member.name || member.email}</p>
                      <p className="truncate text-white/32">{member.email}</p>
                    </div>
                    <span className="w-fit rounded border border-white/[0.08] px-2 py-0.5 text-white/40">{member.role}</span>
                  </div>
                ))}
                {selectedOrgId && orgMembers.length === 0 && <p className="text-sm text-white/35">No members visible for this workspace.</p>}
              </div>
            </div>
          </Panel>
        </section>

        <section className="rounded-lg border border-white/[0.08] bg-white/[0.035] p-5">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wider text-white/35">Control pipeline</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">From repository signal to tracked remediation</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-white/48">
                Connect a project once, enforce its policy, audit the repository and pull requests, then send the result back into the dashboard as scan evidence.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:min-w-[30rem]">
              {[
                ["Projects", projects.length],
                ["Policies", policies.length],
                ["Integrations", integrations.length],
                ["GitHub", githubIntegrations.length],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/[0.08] bg-black/25 px-3 py-3">
                  <p className="text-lg font-semibold text-white">{value}</p>
                  <p className="mt-1 text-xs text-white/35">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid gap-4 lg:grid-cols-[1.25fr_0.75fr]">
          <Panel title="Projects" subtitle="Application boundary for scans, policies, integrations, and evidence.">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <CustomSelect
                value={selectedProjectId}
                onChange={setSelectedProjectId}
                placeholder="Select project"
                ariaLabel="Select project"
                options={projects.map((project) => ({
                  value: project.id,
                  label: project.name,
                  description: project.repositoryUrl || project.slug,
                }))}
                className="w-full sm:max-w-xs"
              />
              {selectedProject?.repositoryUrl && (
                <a className="truncate text-xs text-white/35 transition-colors hover:text-white/60" href={selectedProject.repositoryUrl} target="_blank" rel="noreferrer">
                  {selectedProject.repositoryUrl}
                </a>
              )}
            </div>
            <div className="grid gap-2">
              {projects.map((project) => (
                <button
                  key={project.id}
                  onClick={() => setSelectedProjectId(project.id)}
                  className={clsx(
                    "w-full rounded-lg border px-4 py-3 text-left transition-colors",
                    project.id === selectedProjectId ? "border-white/20 bg-white/[0.06]" : "border-white/[0.06] bg-black/20 hover:bg-white/[0.04]",
                  )}
                >
                  <div className="flex items-start justify-between gap-4">
                    <span className="min-w-0 truncate text-sm font-medium text-white">{project.name}</span>
                    <span className="shrink-0 rounded border border-white/[0.08] px-2 py-0.5 text-xs text-white/35">{project.defaultBranch || "main"}</span>
                  </div>
                  <p className="mt-1 break-all text-xs text-white/35">{project.repositoryUrl || project.slug}</p>
                </button>
              ))}
              {projects.length === 0 && <p className="text-sm text-white/35">No projects yet.</p>}
            </div>
          </Panel>

          <Panel title="Create Project" subtitle="Start with the repository. Integrations inherit this context.">
            <div className="space-y-3">
              <input value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="Project name" className={inputClass()} />
              <input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repo" className={inputClass()} />
              <input value={defaultBranch} onChange={(e) => setDefaultBranch(e.target.value)} placeholder="Default branch" className={inputClass()} />
              <button disabled={saving || !projectName.trim()} onClick={createProject} className={primaryButtonClass()}>
                {saving ? "Creating..." : "Create project"}
              </button>
            </div>
          </Panel>
        </section>

        {selectedProject && (
          <section className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
            <Panel title="Policy Gate" subtitle={selectedProject.name}>
              <div className="space-y-3">
                <input value={policyName} onChange={(e) => setPolicyName(e.target.value)} className={inputClass()} />
                <textarea value={policyDocument} onChange={(e) => setPolicyDocument(e.target.value)} rows={12} className="w-full rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 font-mono text-xs leading-5 text-white outline-none transition-colors placeholder:text-white/25 focus:border-white/20" />
                <button disabled={saving} onClick={createPolicy} className={primaryButtonClass()}>Save policy</button>
                <DenseList rows={policies.map((item) => `${item.enabled ? "on" : "off"} - ${item.name}`)} empty="No policies saved." />
              </div>
            </Panel>

            <Panel title="Provider Integrations" subtitle="Secrets are encrypted and never returned by the API.">
              <div className="space-y-5">
                <div className="grid gap-3 md:grid-cols-2">
                  <CustomSelect
                    value={provider}
                    onChange={(next) => {
                      setProvider(next);
                      setIntegrationName(getProviderMeta(next).label);
                    }}
                    ariaLabel="Select provider"
                    options={PROVIDERS.map((item) => ({
                      value: item,
                      label: getProviderMeta(item).label,
                      description: getProviderMeta(item).purpose,
                    }))}
                  />
                  <input value={integrationName} onChange={(e) => setIntegrationName(e.target.value)} placeholder="Integration name" className={inputClass()} />
                  <div className="md:col-span-2">
                    <CustomSelect
                      value={minimumSeverity}
                      onChange={setMinimumSeverity}
                      ariaLabel="Minimum severity"
                      options={SEVERITY_OPTIONS}
                    />
                  </div>
                </div>

                <div className="rounded-lg border border-white/[0.06] bg-black/20 p-4">
                  <p className="text-sm font-medium text-white/75">{providerMeta.label}</p>
                  <p className="mt-1 text-xs leading-5 text-white/35">{providerMeta.purpose}</p>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <ProviderFields
                      provider={provider}
                      values={{
                        githubRepo, githubBranch, githubCreateIssues, githubLabels,
                        jiraSiteUrl, jiraEmail, jiraProjectKey, jiraIssueType, jiraLabels, jiraPriority,
                        linearTeamId, linearProjectId, linearLabelIds, linearPriority,
                        channel, pagerDutyService,
                        gitlabInstanceUrl, gitlabProjectPath, gitlabCreateIssues, gitlabLabels,
                        bitbucketWorkspace, bitbucketRepoSlug, bitbucketUsername, bitbucketCreateIssues,
                        samlEntityId, samlSsoUrl, scimTenant,
                      }}
                      setters={{
                        setGithubRepo, setGithubBranch, setGithubCreateIssues, setGithubLabels,
                        setJiraSiteUrl, setJiraEmail, setJiraProjectKey, setJiraIssueType, setJiraLabels, setJiraPriority,
                        setLinearTeamId, setLinearProjectId, setLinearLabelIds, setLinearPriority,
                        setChannel, setPagerDutyService,
                        setGitlabInstanceUrl, setGitlabProjectPath, setGitlabCreateIssues, setGitlabLabels,
                        setBitbucketWorkspace, setBitbucketRepoSlug, setBitbucketUsername, setBitbucketCreateIssues,
                        setSamlEntityId, setSamlSsoUrl, setScimTenant,
                      }}
                    />
                    <div className="space-y-2">
                      <label className="text-xs font-medium text-white/45">{providerMeta.secretLabel}</label>
                      <input
                        value={secret}
                        onChange={(e) => setSecret(e.target.value)}
                        placeholder="Stored encrypted. Leave blank only for metadata-only records."
                        type="password"
                        className={inputClass()}
                      />
                    </div>
                  </div>
                </div>

                <button disabled={saving} onClick={createIntegration} className={primaryButtonClass()}>
                  {saving ? "Saving..." : `Add ${providerMeta.label}`}
                </button>

                {githubIntegrations.length > 0 && (
                  <div className="rounded-lg border border-cyan-400/15 bg-cyan-400/[0.035] p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-end">
                      <div className="flex-1">
                        <label className="text-xs font-medium text-cyan-100/55">Pull request number</label>
                        <input value={auditPrNumber} onChange={(e) => setAuditPrNumber(e.target.value)} placeholder="Optional, e.g. 42" className={inputClass("mt-1")} />
                      </div>
                      <CheckboxControl
                        checked={auditCreateIssue}
                        onChange={setAuditCreateIssue}
                        label="Create GitHub issue"
                        className="md:min-h-[2.625rem]"
                      />
                      <CheckboxControl
                        checked={auditCommentOnPr}
                        onChange={setAuditCommentOnPr}
                        label="Comment on PR"
                        className="md:min-h-[2.625rem]"
                      />
                    </div>
                  </div>
                )}

                <IntegrationList
                  integrations={integrations}
                  testingId={testingId}
                  deletingId={deletingId}
                  auditingId={auditingId}
                  onTest={testIntegration}
                  onDelete={deleteIntegration}
                  onAudit={runGitHubAudit}
                />

                <DeliveryTimeline deliveries={deliveries} />
              </div>
            </Panel>
          </section>
        )}

        {selectedProject && (
          <Panel title="Audit Trail" subtitle="Last 200 project events">
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
                <input value={auditActionFilter} onChange={(e) => setAuditActionFilter(e.target.value)} placeholder="Filter action" className={inputClass()} />
                <input value={auditTargetFilter} onChange={(e) => setAuditTargetFilter(e.target.value)} placeholder="Target type" className={inputClass()} />
                <button onClick={() => { void loadAuditLogs(selectedProjectId); }} className={secondaryButtonClass("px-4 py-2 text-sm")}>Apply</button>
              </div>
              <DenseList
                rows={auditLogs.map((item) => `${new Date(item.createdAt).toLocaleString()} - ${item.action} - ${item.targetType}${item.targetId ? ` - ${item.targetId.slice(0, 8)}` : ""}${item.metadata?.provider ? ` - ${String(item.metadata.provider)}` : ""}`)}
                empty="No audit events yet."
              />
            </div>
          </Panel>
        )}
      </div>
    </>
  );
}

interface ProviderValues {
  githubRepo: string;
  githubBranch: string;
  githubCreateIssues: boolean;
  githubLabels: string;
  jiraSiteUrl: string;
  jiraEmail: string;
  jiraProjectKey: string;
  jiraIssueType: string;
  jiraLabels: string;
  jiraPriority: string;
  linearTeamId: string;
  linearProjectId: string;
  linearLabelIds: string;
  linearPriority: string;
  channel: string;
  pagerDutyService: string;
  gitlabInstanceUrl: string;
  gitlabProjectPath: string;
  gitlabCreateIssues: boolean;
  gitlabLabels: string;
  bitbucketWorkspace: string;
  bitbucketRepoSlug: string;
  bitbucketUsername: string;
  bitbucketCreateIssues: boolean;
  samlEntityId: string;
  samlSsoUrl: string;
  scimTenant: string;
}

interface ProviderSetters {
  setGithubRepo: (value: string) => void;
  setGithubBranch: (value: string) => void;
  setGithubCreateIssues: (value: boolean) => void;
  setGithubLabels: (value: string) => void;
  setJiraSiteUrl: (value: string) => void;
  setJiraEmail: (value: string) => void;
  setJiraProjectKey: (value: string) => void;
  setJiraIssueType: (value: string) => void;
  setJiraLabels: (value: string) => void;
  setJiraPriority: (value: string) => void;
  setLinearTeamId: (value: string) => void;
  setLinearProjectId: (value: string) => void;
  setLinearLabelIds: (value: string) => void;
  setLinearPriority: (value: string) => void;
  setChannel: (value: string) => void;
  setPagerDutyService: (value: string) => void;
  setGitlabInstanceUrl: (value: string) => void;
  setGitlabProjectPath: (value: string) => void;
  setGitlabCreateIssues: (value: boolean) => void;
  setGitlabLabels: (value: string) => void;
  setBitbucketWorkspace: (value: string) => void;
  setBitbucketRepoSlug: (value: string) => void;
  setBitbucketUsername: (value: string) => void;
  setBitbucketCreateIssues: (value: boolean) => void;
  setSamlEntityId: (value: string) => void;
  setSamlSsoUrl: (value: string) => void;
  setScimTenant: (value: string) => void;
}

function ProviderFields({ provider, values, setters }: {
  provider: string;
  values: ProviderValues;
  setters: ProviderSetters;
}) {
  if (provider === "github") {
    return (
      <>
        <Field label="Repository" value={values.githubRepo} setValue={setters.setGithubRepo} placeholder="owner/repo or GitHub URL" />
        <Field label="Default branch" value={values.githubBranch} setValue={setters.setGithubBranch} placeholder="main" />
        <Field label="Issue labels" value={values.githubLabels} setValue={setters.setGithubLabels} placeholder="security, breachscope" />
        <CheckboxControl
          checked={values.githubCreateIssues}
          onChange={setters.setGithubCreateIssues}
          label="Allow scan notifications to create issues"
        />
      </>
    );
  }
  if (provider === "jira") {
    return (
      <>
        <Field label="Site URL" value={values.jiraSiteUrl} setValue={setters.setJiraSiteUrl} placeholder="https://company.atlassian.net" />
        <Field label="Email" value={values.jiraEmail} setValue={setters.setJiraEmail} placeholder="security@company.com" />
        <Field label="Project key" value={values.jiraProjectKey} setValue={setters.setJiraProjectKey} placeholder="SEC" />
        <Field label="Issue type" value={values.jiraIssueType} setValue={setters.setJiraIssueType} placeholder="Bug" />
        <Field label="Labels" value={values.jiraLabels} setValue={setters.setJiraLabels} placeholder="security, breachscope" />
        <Field label="Priority override" value={values.jiraPriority} setValue={setters.setJiraPriority} placeholder="Blank maps severity automatically" />
      </>
    );
  }
  if (provider === "linear") {
    return (
      <>
        <Field label="Team ID" value={values.linearTeamId} setValue={setters.setLinearTeamId} placeholder="Linear team UUID" />
        <Field label="Project ID" value={values.linearProjectId} setValue={setters.setLinearProjectId} placeholder="Optional Linear project UUID" />
        <Field label="Label IDs" value={values.linearLabelIds} setValue={setters.setLinearLabelIds} placeholder="Comma-separated label UUIDs" />
        <Field label="Priority" value={values.linearPriority} setValue={setters.setLinearPriority} placeholder="1 urgent, 2 high, 3 medium, 4 low" />
      </>
    );
  }
  if (provider === "slack" || provider === "teams") return <Field label="Channel" value={values.channel} setValue={setters.setChannel} placeholder="#security or team name" />;
  if (provider === "pagerduty") return <Field label="Service name" value={values.pagerDutyService} setValue={setters.setPagerDutyService} placeholder="Production security" />;
  if (provider === "gitlab") {
    return (
      <>
        <Field label="Instance URL" value={values.gitlabInstanceUrl} setValue={setters.setGitlabInstanceUrl} placeholder="https://gitlab.com" />
        <Field label="Project path" value={values.gitlabProjectPath} setValue={setters.setGitlabProjectPath} placeholder="group/project or numeric project ID" />
        <Field label="Issue labels" value={values.gitlabLabels} setValue={setters.setGitlabLabels} placeholder="security, breachscope" />
        <CheckboxControl checked={values.gitlabCreateIssues} onChange={setters.setGitlabCreateIssues} label="Create GitLab issues from scan findings" />
      </>
    );
  }
  if (provider === "bitbucket") {
    return (
      <>
        <Field label="Workspace" value={values.bitbucketWorkspace} setValue={setters.setBitbucketWorkspace} placeholder="workspace" />
        <Field label="Repository slug" value={values.bitbucketRepoSlug} setValue={setters.setBitbucketRepoSlug} placeholder="repo-slug" />
        <Field label="Username" value={values.bitbucketUsername} setValue={setters.setBitbucketUsername} placeholder="Required for app passwords" />
        <CheckboxControl checked={values.bitbucketCreateIssues} onChange={setters.setBitbucketCreateIssues} label="Create Bitbucket issues from scan findings" />
      </>
    );
  }
  if (provider === "saml") {
    return (
      <>
        <Field label="Entity ID" value={values.samlEntityId} setValue={setters.setSamlEntityId} placeholder="IdP entity ID" />
        <Field label="SSO URL" value={values.samlSsoUrl} setValue={setters.setSamlSsoUrl} placeholder="https://idp.example.com/sso" />
      </>
    );
  }
  if (provider === "scim") return <Field label="Tenant" value={values.scimTenant} setValue={setters.setScimTenant} placeholder="Workspace or tenant name" />;
  return <p className="text-xs leading-5 text-white/35 md:col-span-2">Select a supported provider to configure its delivery fields.</p>;
}

function Field({ label, value, setValue, placeholder }: { label: string; value: string; setValue: (value: string) => void; placeholder: string }) {
  return (
    <div className="space-y-2">
      <label className="text-xs font-medium text-white/45">{label}</label>
      <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={placeholder} className={inputClass()} />
    </div>
  );
}

function IntegrationList({ integrations, testingId, deletingId, auditingId, onTest, onDelete, onAudit }: {
  integrations: Integration[];
  testingId: string | null;
  deletingId: string | null;
  auditingId: string | null;
  onTest: (id: string) => void;
  onDelete: (id: string) => void;
  onAudit: (id: string) => void;
}) {
  if (integrations.length === 0) return <p className="text-sm text-white/35">No integrations configured.</p>;

  return (
    <div className="space-y-2">
      {integrations.map((item) => (
        <div key={item.id} className="rounded-lg border border-white/[0.07] bg-black/20 p-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-white">{item.name}</p>
                <span className="rounded border border-white/[0.08] px-2 py-0.5 text-xs text-white/35">{PROVIDER_COPY[item.provider]?.label ?? item.provider}</span>
                <span className={clsx("rounded border px-2 py-0.5 text-xs", item.hasSecret ? "border-green-400/20 text-green-300/70" : "border-amber-300/20 text-amber-200/65")}>
                  {item.hasSecret ? "secret set" : "metadata only"}
                </span>
              </div>
              <p className="mt-2 break-all text-xs leading-5 text-white/35">{describeIntegration(item)}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => onTest(item.id)} disabled={testingId === item.id} className={secondaryButtonClass()}>
                {testingId === item.id ? "Testing..." : "Test"}
              </button>
              {item.provider === "github" && (
                <button onClick={() => onAudit(item.id)} disabled={auditingId === item.id || !item.hasSecret} className={secondaryButtonClass("border-cyan-400/20 text-cyan-200/75 hover:bg-cyan-400/10")}>
                  {auditingId === item.id ? "Auditing..." : "Run audit"}
                </button>
              )}
              <button onClick={() => onDelete(item.id)} disabled={deletingId === item.id} className={secondaryButtonClass("border-red-400/20 text-red-300/70 hover:bg-red-500/10")}>
                {deletingId === item.id ? "Removing..." : "Remove"}
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function DeliveryTimeline({ deliveries }: { deliveries: IntegrationDelivery[] }) {
  const counts = deliveries.reduce<Record<string, number>>((acc, delivery) => {
    acc[delivery.status] = (acc[delivery.status] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/20 p-4">
      <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-semibold text-white/80">Delivery status</p>
          <p className="mt-1 text-xs text-white/35">Post-scan actions, provider failures, and retry state.</p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          {["delivered", "retrying", "failed", "skipped"].map((status) => (
            <span key={status} className="rounded border border-white/[0.08] px-2 py-0.5 text-white/40">
              {status}: {counts[status] ?? 0}
            </span>
          ))}
        </div>
      </div>
      {deliveries.length === 0 ? (
        <p className="text-sm text-white/35">No delivery work has been created for this project yet.</p>
      ) : (
        <div className="grid gap-2">
          {deliveries.slice(0, 8).map((delivery) => (
            <div key={delivery.id} className="rounded-lg border border-white/[0.06] bg-white/[0.025] px-3 py-2">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-white/65">
                    {PROVIDER_COPY[delivery.provider]?.label ?? delivery.provider} - {delivery.action}
                  </p>
                  <p className="mt-1 truncate text-xs text-white/32">
                    {delivery.lastError || (delivery.externalUrl ? delivery.externalUrl : `Scan ${delivery.scanId?.slice(0, 8) ?? "unknown"}`)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className={clsx("rounded border px-2 py-0.5 text-xs", deliveryTone(delivery.status))}>{delivery.status}</span>
                  <span className="text-xs text-white/28">{delivery.attempts}/{delivery.maxAttempts}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FeedbackBanner({ feedback, onDismiss }: { feedback: Feedback; onDismiss: () => void }) {
  const tone = feedback.type === "success"
    ? "border-green-400/20 bg-green-400/[0.055] text-green-100/80"
    : feedback.type === "error"
      ? "border-red-400/20 bg-red-400/[0.055] text-red-100/80"
      : "border-cyan-400/20 bg-cyan-400/[0.055] text-cyan-100/80";
  return (
    <div className={clsx("rounded-lg border p-4", tone)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-sm font-semibold">{feedback.title}</p>
          {feedback.body && <p className="mt-1 text-xs leading-5 opacity-75">{feedback.body}</p>}
          {feedback.href && (
            <Link href={feedback.href} className="mt-2 inline-block text-xs font-medium underline underline-offset-4">
              Open dashboard scan
            </Link>
          )}
        </div>
        <button onClick={onDismiss} className="text-xs opacity-60 transition-opacity hover:opacity-100">Dismiss</button>
      </div>
    </div>
  );
}

function Panel({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <section className="min-w-0 rounded-lg border border-white/[0.08] bg-white/[0.03] p-5">
      <div className="mb-4">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        <p className="mt-1 text-xs leading-5 text-white/35">{subtitle}</p>
      </div>
      {children}
    </section>
  );
}

function DenseList({ rows, empty }: { rows: string[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-white/35">{empty}</p>;
  return (
    <div className="grid gap-2">
      {rows.map((row) => (
        <div key={row} className="break-words rounded-lg border border-white/[0.06] bg-black/20 px-3 py-2 text-xs leading-5 text-white/60">
          {row}
        </div>
      ))}
    </div>
  );
}

function describeIntegration(item: Integration): string {
  const config = item.config ?? {};
  if (item.provider === "github") {
    return `Repository ${stringFrom(config.repoFullName) || "not set"} on ${stringFrom(config.defaultBranch) || "main"}. Issue routing ${config.createIssues === true ? "enabled" : "off"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  }
  if (item.provider === "gitlab") return `Project ${stringFrom(config.projectPath) || "not set"} at ${stringFrom(config.instanceUrl) || "https://gitlab.com"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  if (item.provider === "bitbucket") return `${stringFrom(config.workspace) || "workspace"}/${stringFrom(config.repoSlug) || "repo"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  if (item.provider === "jira") return `${stringFrom(config.siteUrl)} project ${stringFrom(config.projectKey)} as ${stringFrom(config.issueType) || "Bug"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  if (item.provider === "linear") return `Team ${stringFrom(config.teamId) || "not set"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  if (item.provider === "slack" || item.provider === "teams") return `Channel ${stringFrom(config.channel) || "not set"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  if (item.provider === "pagerduty") return `Service ${stringFrom(config.serviceName) || "not set"}. Threshold ${stringFrom(config.minimumSeverity) || "high"}.`;
  return Object.keys(config).length > 0 ? JSON.stringify(config) : "No provider metadata.";
}

function inputClass(extra = ""): string {
  return clsx("w-full rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-sm text-white outline-none transition-colors placeholder:text-white/25 focus:border-white/20", extra);
}

function primaryButtonClass(): string {
  return "w-full rounded-lg bg-white px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-white/90 disabled:cursor-not-allowed disabled:opacity-40";
}

function secondaryButtonClass(extra = ""): string {
  return clsx("rounded-lg border border-white/[0.10] bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-white/60 transition-colors hover:bg-white/[0.08] hover:text-white disabled:cursor-not-allowed disabled:opacity-40", extra);
}

function deliveryTone(status: string): string {
  if (status === "delivered") return "border-green-400/20 text-green-300/70 bg-green-400/[0.04]";
  if (status === "retrying" || status === "pending") return "border-amber-300/20 text-amber-200/70 bg-amber-300/[0.04]";
  if (status === "failed") return "border-red-400/20 text-red-300/70 bg-red-400/[0.04]";
  return "border-white/[0.08] text-white/40 bg-white/[0.03]";
}

async function responseFeedback(res: Response, fallback: string): Promise<Feedback> {
  const data = await res.json().catch(() => null) as Record<string, unknown> | null;
  return { type: "error", title: fallback, body: stringFrom(data?.["error"]) || `HTTP ${res.status}` };
}

function stringFrom(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return "";
}

function getProviderMeta(provider: string): { label: string; purpose: string; secretLabel: string } {
  return PROVIDER_COPY[provider] ?? PROVIDER_COPY.github ?? {
    label: provider,
    purpose: "Project integration route.",
    secretLabel: "Secret",
  };
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
