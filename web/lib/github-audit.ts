import { createHash } from "crypto";

export type AuditSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface GitHubAuditFinding {
  title: string;
  severity: AuditSeverity;
  category: string;
  description: string;
  detail?: string;
  remediation?: string;
  tool?: string;
  file?: string;
  line?: number;
  references?: string[];
  fingerprint?: string;
  compliance?: string[];
}

export interface GitHubOpenPullRequest {
  number: number;
  title: string;
  author: string;
  url: string;
  base: string;
  head: string;
  draft: boolean;
  updatedAt: string;
  changedFiles?: number;
  additions?: number;
  deletions?: number;
}

export interface GitHubPrAudit {
  number: number;
  title: string;
  url: string;
  author: string;
  base: string;
  head: string;
  draft: boolean;
  additions: number;
  deletions: number;
  changedFiles: number;
  files: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }>;
}

export interface GitHubAuditResult {
  repoFullName: string;
  repositoryUrl: string;
  defaultBranch: string;
  visibility: string;
  findings: GitHubAuditFinding[];
  openPullRequests: GitHubOpenPullRequest[];
  pullRequest?: GitHubPrAudit;
  steps: string[];
}

interface GitHubJsonResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  text: string;
  headers: Headers;
}

interface GitHubRepo {
  full_name: string;
  html_url: string;
  visibility?: string;
  private?: boolean;
  archived?: boolean;
  default_branch?: string;
  security_and_analysis?: Record<string, { status?: string } | undefined>;
}

interface GitHubProtection {
  required_pull_request_reviews?: {
    required_approving_review_count?: number;
    dismiss_stale_reviews?: boolean;
    require_code_owner_reviews?: boolean;
  };
  required_status_checks?: {
    strict?: boolean;
    contexts?: string[];
    checks?: Array<{ context?: string; app_id?: number }>;
  };
  enforce_admins?: { enabled?: boolean } | null;
  allow_force_pushes?: { enabled?: boolean } | null;
  allow_deletions?: { enabled?: boolean } | null;
}

interface GitHubContentItem {
  name?: string;
  path?: string;
  type?: string;
  content?: string;
  encoding?: string;
}

interface GitHubPullRequest {
  number: number;
  title: string;
  html_url: string;
  draft?: boolean;
  user?: { login?: string };
  base?: { ref?: string };
  head?: { ref?: string; repo?: { full_name?: string } | null };
  created_at?: string;
  updated_at?: string;
  additions?: number;
  deletions?: number;
  changed_files?: number;
}

interface GitHubPullFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
}

const GITHUB_API = "https://api.github.com";
const GITHUB_API_VERSION = "2026-03-10";
const FULL_SHA = /^[a-f0-9]{40}$/i;

export function parseGitHubRepo(value: string | null | undefined): string | null {
  const raw = value?.trim().replace(/\.git$/i, "");
  if (!raw) return null;

  const ssh = raw.match(/^git@github\.com:([^/\s]+\/[^/\s]+)$/i);
  if (ssh?.[1]) return normalizeRepoSlug(ssh[1]);

  const url = raw.match(/^https?:\/\/github\.com\/([^/\s]+\/[^/\s?#]+)(?:[/?#].*)?$/i);
  if (url?.[1]) return normalizeRepoSlug(url[1]);

  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(raw)) return normalizeRepoSlug(raw);
  return null;
}

export async function testGitHubAccess(token: string, repoFullName: string): Promise<{ ok: boolean; status: number; message: string; htmlUrl?: string }> {
  const repo = parseGitHubRepo(repoFullName);
  if (!repo) return { ok: false, status: 400, message: "Use owner/repo or a GitHub repository URL." };

  const res = await githubJson<GitHubRepo>(token, `/repos/${repo}`);
  if (!res.ok || !res.data) {
    return { ok: false, status: res.status, message: readableGitHubError(res, "Could not read repository.") };
  }

  return {
    ok: true,
    status: res.status,
    message: `Connected to ${res.data.full_name}.`,
    htmlUrl: res.data.html_url,
  };
}

export async function auditGitHubRepository(opts: {
  token: string;
  repoFullName: string;
  defaultBranch?: string | null;
  prNumber?: number | null;
}): Promise<GitHubAuditResult> {
  const repoSlug = parseGitHubRepo(opts.repoFullName);
  if (!repoSlug) throw new Error("Use owner/repo or a GitHub repository URL.");

  const repoRes = await githubJson<GitHubRepo>(opts.token, `/repos/${repoSlug}`);
  if (!repoRes.ok || !repoRes.data) {
    throw new Error(readableGitHubError(repoRes, "Could not read GitHub repository."));
  }

  const repo = repoRes.data;
  const defaultBranch = opts.defaultBranch?.trim() || repo.default_branch || "main";
  const findings: GitHubAuditFinding[] = [];
  const steps: string[] = [`Read repository metadata for ${repo.full_name}.`];

  findings.push(...auditRepoMetadata(repo));

  const protection = await auditBranchProtection(opts.token, repoSlug, defaultBranch);
  steps.push(protection.step);
  findings.push(...protection.findings);

  const actions = await auditActionsPermissions(opts.token, repoSlug);
  steps.push(actions.step);
  findings.push(...actions.findings);

  const codeowners = await auditCodeowners(opts.token, repoSlug, defaultBranch);
  steps.push(codeowners.step);
  findings.push(...codeowners.findings);

  const workflows = await auditWorkflows(opts.token, repoSlug, defaultBranch);
  steps.push(workflows.step);
  findings.push(...workflows.findings);

  const prs = await listOpenPullRequests(opts.token, repoSlug);
  steps.push(`Read ${prs.length} open pull request${prs.length === 1 ? "" : "s"}.`);
  findings.push(...auditOpenPullRequests(prs));

  let pullRequest: GitHubPrAudit | undefined;
  if (opts.prNumber && Number.isInteger(opts.prNumber) && opts.prNumber > 0) {
    pullRequest = await auditPullRequest(opts.token, repoSlug, opts.prNumber, findings);
    steps.push(`Audited pull request #${opts.prNumber}.`);
  }

  return {
    repoFullName: repo.full_name,
    repositoryUrl: repo.html_url,
    defaultBranch,
    visibility: repo.visibility ?? (repo.private ? "private" : "public"),
    findings: findings.map((finding) => ({
      ...finding,
      tool: finding.tool ?? "github",
      fingerprint: finding.fingerprint ?? fingerprint(repoSlug, finding),
    })),
    openPullRequests: prs,
    pullRequest,
    steps,
  };
}

export async function createGitHubIssue(
  token: string,
  repoFullName: string,
  title: string,
  body: string,
  labels: string[] = ["security"]
): Promise<{ ok: boolean; status: number; url?: string; error?: string }> {
  const repo = parseGitHubRepo(repoFullName);
  if (!repo) return { ok: false, status: 400, error: "Invalid GitHub repository." };

  const res = await githubJson<{ html_url?: string }>(token, `/repos/${repo}/issues`, {
    method: "POST",
    body: JSON.stringify({ title: title.slice(0, 240), body, labels: labels.slice(0, 10) }),
  });

  return res.ok
    ? { ok: true, status: res.status, url: res.data?.html_url }
    : { ok: false, status: res.status, error: readableGitHubError(res, "Could not create GitHub issue.") };
}

export async function commentOnGitHubPullRequest(
  token: string,
  repoFullName: string,
  prNumber: number,
  body: string
): Promise<{ ok: boolean; status: number; url?: string; error?: string }> {
  const repo = parseGitHubRepo(repoFullName);
  if (!repo) return { ok: false, status: 400, error: "Invalid GitHub repository." };

  const res = await githubJson<{ html_url?: string }>(token, `/repos/${repo}/issues/${prNumber}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });

  return res.ok
    ? { ok: true, status: res.status, url: res.data?.html_url }
    : { ok: false, status: res.status, error: readableGitHubError(res, "Could not comment on pull request.") };
}

export function buildGitHubAuditMarkdown(result: GitHubAuditResult, scanUrl?: string): string {
  const counts = countBySeverity(result.findings);
  const pr = result.pullRequest ? `\n\nPull request: #${result.pullRequest.number} ${result.pullRequest.title}` : "";
  const top = result.findings
    .filter((finding) => finding.severity === "critical" || finding.severity === "high")
    .slice(0, 8)
    .map((finding) => `- **${finding.severity.toUpperCase()}** ${finding.title}: ${finding.remediation ?? finding.description}`)
    .join("\n") || "- No critical or high findings.";

  return [
    "## BreachScope GitHub audit",
    "",
    `Repository: ${result.repoFullName}`,
    `Default branch: ${result.defaultBranch}`,
    `Visibility: ${result.visibility}`,
    `Findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low${pr}`,
    scanUrl ? `Dashboard scan: ${scanUrl}` : "",
    "",
    "### Priority findings",
    top,
  ].filter(Boolean).join("\n");
}

function auditRepoMetadata(repo: GitHubRepo): GitHubAuditFinding[] {
  const findings: GitHubAuditFinding[] = [];
  const security = repo.security_and_analysis;

  if (repo.archived) {
    findings.push({
      title: "Repository is archived",
      severity: "medium",
      category: "toolchain",
      description: "Archived repositories often stop receiving dependency updates, workflow fixes, and branch-protection changes while still being reused by teams.",
      remediation: "Confirm this repository is not in an active delivery path. If it is active, unarchive it and restore normal maintenance controls.",
      references: ["https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories"],
    });
  }

  if ((repo.visibility ?? (repo.private ? "private" : "public")) === "public") {
    findings.push({
      title: "Repository is public",
      severity: "low",
      category: "toolchain",
      description: "Public repositories expose source code, comments, issues, and commit history to anyone. This is acceptable only when intentional.",
      remediation: "Confirm no secrets, internal endpoints, credentials, or unreleased business logic are present in code or history.",
    });
  }

  if (security) {
    if (security.secret_scanning?.status !== "enabled") {
      findings.push({
        title: "Secret scanning is not enabled",
        severity: "medium",
        category: "toolchain",
        description: "GitHub secret scanning helps detect known credential patterns committed to the repository.",
        remediation: "Enable secret scanning in repository code security settings.",
        references: ["https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"],
      });
    }
    if (security.secret_scanning_push_protection?.status !== "enabled") {
      findings.push({
        title: "Secret scanning push protection is not enabled",
        severity: "medium",
        category: "toolchain",
        description: "Push protection can block supported secret patterns before they land in the repository.",
        remediation: "Enable push protection in repository code security settings.",
        references: ["https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations"],
      });
    }
    if (security.dependabot_security_updates?.status !== "enabled") {
      findings.push({
        title: "Dependabot security updates are not enabled",
        severity: "low",
        category: "supply-chain",
        description: "Dependabot security updates open remediation pull requests for known vulnerable dependencies.",
        remediation: "Enable Dependabot security updates for this repository.",
        references: ["https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates"],
      });
    }
  }

  return findings;
}

async function auditBranchProtection(token: string, repo: string, branch: string): Promise<{ step: string; findings: GitHubAuditFinding[] }> {
  const res = await githubJson<GitHubProtection>(token, `/repos/${repo}/branches/${encodeURIComponent(branch)}/protection`);
  const findings: GitHubAuditFinding[] = [];

  if (res.status === 404) {
    findings.push({
      title: `Default branch "${branch}" has no protection rules`,
      severity: "high",
      category: "toolchain",
      description: "The default branch can be changed without the expected review and CI controls.",
      remediation: "Require pull requests, approving reviews, status checks, stale-review dismissal, and code-owner review on the default branch.",
      references: ["https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches"],
    });
    return { step: `Branch protection was not found for ${branch}.`, findings };
  }

  if (!res.ok || !res.data) {
    return { step: `Branch protection could not be read for ${branch} (${res.status}).`, findings };
  }

  const protection = res.data;
  const reviews = protection.required_pull_request_reviews;
  const statusChecks = protection.required_status_checks;

  if (!reviews) {
    findings.push({
      title: `Default branch "${branch}" does not require pull request reviews`,
      severity: "high",
      category: "toolchain",
      description: "A compromised writer can merge directly without another reviewer.",
      remediation: "Require at least one approving review before merge.",
    });
  } else {
    if ((reviews.required_approving_review_count ?? 0) < 1) {
      findings.push({
        title: `Default branch "${branch}" allows merges with no approving review`,
        severity: "high",
        category: "toolchain",
        description: "Pull request review is configured but the required approval count is zero.",
        remediation: "Set required approving reviews to one or more.",
      });
    }
    if (!reviews.dismiss_stale_reviews) {
      findings.push({
        title: `Default branch "${branch}" keeps stale approvals after new commits`,
        severity: "medium",
        category: "toolchain",
        description: "A pull request can be approved, then changed materially without resetting the approval.",
        remediation: "Enable stale approval dismissal on new commits.",
      });
    }
    if (!reviews.require_code_owner_reviews) {
      findings.push({
        title: `Default branch "${branch}" does not require code-owner review`,
        severity: "low",
        category: "toolchain",
        description: "Sensitive paths can change without automatically requiring the owners for that area.",
        remediation: "Enable code-owner review and keep CODEOWNERS current.",
      });
    }
  }

  if (!statusChecks) {
    findings.push({
      title: `Default branch "${branch}" does not require status checks`,
      severity: "high",
      category: "toolchain",
      description: "Pull requests can merge even if CI, tests, or scan checks are failing or absent.",
      remediation: "Require CI and security scan checks before merge.",
    });
  } else if (!statusChecks.strict) {
    findings.push({
      title: `Default branch "${branch}" does not require branches to be up to date`,
      severity: "low",
      category: "toolchain",
      description: "Required checks can pass on an older base commit and then merge into a changed branch.",
      remediation: "Require branches to be up to date before merging.",
    });
  }

  if (protection.enforce_admins?.enabled === false) {
    findings.push({
      title: `Admins can bypass protection on "${branch}"`,
      severity: "medium",
      category: "toolchain",
      description: "Administrator bypass creates a privileged route around the same controls other writers must follow.",
      remediation: "Enable branch protection enforcement for administrators.",
    });
  }

  if (protection.allow_force_pushes?.enabled) {
    findings.push({
      title: `Force pushes are allowed on "${branch}"`,
      severity: "high",
      category: "toolchain",
      description: "Force pushes can rewrite reviewed or released history and hide malicious changes.",
      remediation: "Disable force pushes on protected branches.",
    });
  }

  if (protection.allow_deletions?.enabled) {
    findings.push({
      title: `Branch deletion is allowed for "${branch}"`,
      severity: "high",
      category: "toolchain",
      description: "Default branch deletion can disrupt release and recovery workflows.",
      remediation: "Disable branch deletion on protected branches.",
    });
  }

  return { step: `Read branch protection for ${branch}.`, findings };
}

async function auditActionsPermissions(token: string, repo: string): Promise<{ step: string; findings: GitHubAuditFinding[] }> {
  const res = await githubJson<Record<string, unknown>>(token, `/repos/${repo}/actions/permissions`);
  const findings: GitHubAuditFinding[] = [];
  if (!res.ok || !res.data) return { step: `Actions permissions could not be read (${res.status}).`, findings };

  if (res.data.default_workflow_permissions === "write") {
    findings.push({
      title: "GitHub Actions default workflow token has write permission",
      severity: "high",
      category: "toolchain",
      description: "Every workflow gets broad write access unless jobs override it. A compromised action can modify repository state.",
      remediation: "Set default workflow token permissions to read-only and grant write permission per job only when needed.",
      references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"],
    });
  }

  if (res.data.can_approve_pull_request_reviews === true) {
    findings.push({
      title: "GitHub Actions can approve pull requests",
      severity: "high",
      category: "toolchain",
      description: "A workflow can approve pull requests, creating an automation path around human review.",
      remediation: "Disable workflow pull-request approval unless a controlled release bot requires it.",
    });
  }

  return { step: "Read GitHub Actions workflow permissions.", findings };
}

async function auditCodeowners(token: string, repo: string, branch: string): Promise<{ step: string; findings: GitHubAuditFinding[] }> {
  const paths = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];
  for (const path of paths) {
    const res = await githubJson<GitHubContentItem>(token, `/repos/${repo}/contents/${encodeURIComponentPath(path)}?ref=${encodeURIComponent(branch)}`);
    if (res.ok) return { step: `Found CODEOWNERS at ${path}.`, findings: [] };
  }

  return {
    step: "CODEOWNERS was not found in the supported locations.",
    findings: [{
      title: "No CODEOWNERS file found",
      severity: "low",
      category: "toolchain",
      description: "GitHub cannot automatically request domain-owner review for sensitive paths without a CODEOWNERS file.",
      remediation: "Add CODEOWNERS for authentication, payments, infrastructure, workflow, and release paths.",
      references: ["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"],
    }],
  };
}

async function auditWorkflows(token: string, repo: string, branch: string): Promise<{ step: string; findings: GitHubAuditFinding[] }> {
  const listRes = await githubJson<GitHubContentItem[]>(token, `/repos/${repo}/contents/.github/workflows?ref=${encodeURIComponent(branch)}`);
  const findings: GitHubAuditFinding[] = [];
  if (listRes.status === 404) return { step: "No GitHub Actions workflow directory found.", findings };
  if (!listRes.ok || !Array.isArray(listRes.data)) return { step: `Workflow directory could not be read (${listRes.status}).`, findings };

  let unpinned = 0;
  const riskyWorkflowFiles = new Set<string>();
  const files = listRes.data
    .filter((item) => item.type === "file" && /\.(ya?ml)$/i.test(item.name ?? ""))
    .slice(0, 25);

  for (const file of files) {
    if (!file.path) continue;
    const fileRes = await githubJson<GitHubContentItem>(token, `/repos/${repo}/contents/${encodeURIComponentPath(file.path)}?ref=${encodeURIComponent(branch)}`);
    if (!fileRes.ok || !fileRes.data) continue;
    const content = decodeContent(fileRes.data);
    if (!content) continue;

    for (const match of content.matchAll(/uses:\s*["']?([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([^\s"'#]+)/g)) {
      const ref = match[2] ?? "";
      if (!FULL_SHA.test(ref)) unpinned++;
    }

    if (/pull_request_target\s*:/.test(content) && /actions\/checkout/.test(content)) {
      riskyWorkflowFiles.add(file.path);
    }

    if (/permissions\s*:\s*write-all/.test(content)) {
      findings.push({
        title: `Workflow ${file.path} grants write-all permissions`,
        severity: "high",
        category: "toolchain",
        description: "The workflow grants broad repository write permission to the job token.",
        remediation: "Replace write-all with the smallest explicit permissions block required by the job.",
        file: file.path,
        references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"],
      });
    }
  }

  if (unpinned > 0) {
    findings.push({
      title: `${unpinned} GitHub Action reference${unpinned === 1 ? "" : "s"} are not pinned to commit SHAs`,
      severity: "medium",
      category: "supply-chain",
      description: "Actions pinned to tags or branches can move without a repository code change.",
      remediation: "Pin third-party Actions to full commit SHAs and automate updates with a trusted dependency workflow.",
      references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
    });
  }

  for (const path of riskyWorkflowFiles) {
    findings.push({
      title: `Workflow ${path} combines pull_request_target with checkout`,
      severity: "high",
      category: "toolchain",
      description: "pull_request_target runs with base-repository context. Combining it with untrusted checkout patterns can expose secrets or write permissions.",
      remediation: "Use pull_request for untrusted code, avoid checking out PR head in privileged workflows, and split label/comment automation from build execution.",
      file: path,
      references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"],
    });
  }

  return { step: `Audited ${files.length} GitHub Actions workflow file${files.length === 1 ? "" : "s"}.`, findings };
}

async function listOpenPullRequests(token: string, repo: string): Promise<GitHubOpenPullRequest[]> {
  const res = await githubJson<GitHubPullRequest[]>(token, `/repos/${repo}/pulls?state=open&sort=updated&direction=desc&per_page=30`);
  if (!res.ok || !Array.isArray(res.data)) return [];
  return res.data.map((pr) => ({
    number: pr.number,
    title: pr.title,
    author: pr.user?.login ?? "unknown",
    url: pr.html_url,
    base: pr.base?.ref ?? "",
    head: pr.head?.ref ?? "",
    draft: Boolean(pr.draft),
    updatedAt: pr.updated_at ?? "",
    changedFiles: pr.changed_files,
    additions: pr.additions,
    deletions: pr.deletions,
  }));
}

function auditOpenPullRequests(prs: GitHubOpenPullRequest[]): GitHubAuditFinding[] {
  const findings: GitHubAuditFinding[] = [];
  if (prs.length >= 20) {
    findings.push({
      title: "Repository has a large open pull request queue",
      severity: "low",
      category: "toolchain",
      description: `${prs.length} open pull requests were returned by the latest audit. Large queues can hide risky or stale changes.`,
      remediation: "Triage stale pull requests and require current CI before merge.",
    });
  }

  const stale = prs.filter((pr) => pr.updatedAt && daysSince(pr.updatedAt) > 30);
  if (stale.length > 0) {
    findings.push({
      title: `${stale.length} open pull request${stale.length === 1 ? "" : "s"} are stale`,
      severity: "low",
      category: "toolchain",
      description: "Stale pull requests often drift from the protected branch and may contain outdated checks or approvals.",
      remediation: "Refresh stale pull requests, re-run required checks, or close them.",
    });
  }

  return findings;
}

async function auditPullRequest(
  token: string,
  repo: string,
  prNumber: number,
  findings: GitHubAuditFinding[]
): Promise<GitHubPrAudit> {
  const prRes = await githubJson<GitHubPullRequest>(token, `/repos/${repo}/pulls/${prNumber}`);
  if (!prRes.ok || !prRes.data) throw new Error(readableGitHubError(prRes, `Could not read pull request #${prNumber}.`));

  const filesRes = await githubJson<GitHubPullFile[]>(token, `/repos/${repo}/pulls/${prNumber}/files?per_page=100`);
  const files = Array.isArray(filesRes.data) ? filesRes.data : [];
  const pr = prRes.data;

  const workflowFiles = files.filter((file) => /^\.github\/workflows\//.test(file.filename));
  const sensitiveFiles = files.filter((file) => isSensitivePath(file.filename));
  const sourceFiles = files.filter((file) => isSourcePath(file.filename));
  const testFiles = files.filter((file) => isTestPath(file.filename));
  const lockFiles = files.filter((file) => isLockfile(file.filename));
  const manifestFiles = files.filter((file) => isManifest(file.filename));

  if (workflowFiles.length > 0) {
    findings.push({
      title: `Pull request #${prNumber} changes GitHub Actions workflows`,
      severity: "high",
      category: "toolchain",
      description: "Workflow changes can alter CI permissions, release steps, credentials, or deployment paths.",
      remediation: "Require review from repository administrators or platform owners before merging workflow changes.",
      detail: workflowFiles.map((file) => file.filename).join("\n"),
      references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"],
    });
  }

  if (sensitiveFiles.length > 0) {
    findings.push({
      title: `Pull request #${prNumber} touches sensitive paths`,
      severity: "medium",
      category: "code",
      description: "The pull request modifies files related to auth, infrastructure, deployment, billing, or runtime policy.",
      remediation: "Require domain-owner review and verify tests cover the changed control path.",
      detail: sensitiveFiles.slice(0, 20).map((file) => file.filename).join("\n"),
    });
  }

  if (sourceFiles.length > 0 && testFiles.length === 0) {
    findings.push({
      title: `Pull request #${prNumber} changes application code without tests`,
      severity: "low",
      category: "code",
      description: "Application code changed, but the first 100 changed files did not include test files.",
      remediation: "Add or update tests covering the changed behavior, especially for security-sensitive code.",
    });
  }

  if (lockFiles.length > 0 && manifestFiles.length === 0) {
    findings.push({
      title: `Pull request #${prNumber} changes lockfiles without manifests`,
      severity: "medium",
      category: "supply-chain",
      description: "Lockfile-only dependency changes can hide transitive package shifts without an obvious top-level dependency change.",
      remediation: "Review dependency diff output and confirm the lockfile update is expected.",
      detail: lockFiles.map((file) => file.filename).join("\n"),
    });
  }

  const totalChangedLines = (pr.additions ?? 0) + (pr.deletions ?? 0);
  if (totalChangedLines > 2000 || (pr.changed_files ?? files.length) > 60) {
    findings.push({
      title: `Pull request #${prNumber} is too large for reliable review`,
      severity: "low",
      category: "code",
      description: `The pull request changes ${totalChangedLines.toLocaleString()} lines across ${(pr.changed_files ?? files.length).toLocaleString()} files.`,
      remediation: "Split the change or require deeper review with focused ownership for each changed area.",
    });
  }

  return {
    number: pr.number,
    title: pr.title,
    url: pr.html_url,
    author: pr.user?.login ?? "unknown",
    base: pr.base?.ref ?? "",
    head: pr.head?.ref ?? "",
    draft: Boolean(pr.draft),
    additions: pr.additions ?? files.reduce((sum, file) => sum + file.additions, 0),
    deletions: pr.deletions ?? files.reduce((sum, file) => sum + file.deletions, 0),
    changedFiles: pr.changed_files ?? files.length,
    files: files.map((file) => ({
      filename: file.filename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      changes: file.changes,
    })),
  };
}

async function githubJson<T>(token: string, path: string, init?: RequestInit): Promise<GitHubJsonResult<T>> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text().catch(() => "");
  let data: T | null = null;
  if (text) {
    try { data = JSON.parse(text) as T; } catch { data = null; }
  }
  return { ok: res.ok, status: res.status, data, text, headers: res.headers };
}

function readableGitHubError(res: GitHubJsonResult<unknown>, fallback: string): string {
  const data = res.data;
  if (data && typeof data === "object" && "message" in data && typeof data.message === "string") {
    return `${fallback} GitHub returned ${res.status}: ${data.message}`;
  }
  if (res.text) return `${fallback} GitHub returned ${res.status}: ${res.text.slice(0, 240)}`;
  return `${fallback} GitHub returned ${res.status}.`;
}

function decodeContent(item: GitHubContentItem): string {
  if (item.encoding !== "base64" || !item.content) return "";
  return Buffer.from(item.content.replace(/\s/g, ""), "base64").toString("utf8");
}

function normalizeRepoSlug(slug: string): string {
  const [owner, repo] = slug.split("/");
  return `${owner}/${repo}`;
}

function encodeURIComponentPath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function isSensitivePath(path: string): boolean {
  return /(^|\/)(auth|session|jwt|rbac|iam|billing|payment|checkout|middleware|proxy|infra|terraform|k8s|kubernetes|docker|Dockerfile|\.github\/workflows)(\/|\.|$)/i.test(path);
}

function isSourcePath(path: string): boolean {
  return /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|rb|java|kt|php|cs|swift)$/.test(path) && !isTestPath(path);
}

function isTestPath(path: string): boolean {
  return /(^|\/)(__tests__|tests?|spec|e2e)(\/|$)|\.(test|spec)\./i.test(path);
}

function isLockfile(path: string): boolean {
  return /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|packages\.lock\.json|go\.sum)$/i.test(path);
}

function isManifest(path: string): boolean {
  return /(^|\/)(package\.json|Cargo\.toml|Gemfile|pyproject\.toml|requirements\.txt|composer\.json|go\.mod|pom\.xml|build\.gradle|build\.gradle\.kts|.*\.csproj)$/i.test(path);
}

function daysSince(value: string): number {
  return (Date.now() - new Date(value).getTime()) / 86400000;
}

function countBySeverity(findings: GitHubAuditFinding[]): Record<AuditSeverity, number> {
  return findings.reduce((acc, finding) => {
    acc[finding.severity] += 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<AuditSeverity, number>);
}

function fingerprint(repo: string, finding: GitHubAuditFinding): string {
  return createHash("sha256")
    .update([repo, finding.title, finding.file ?? "", finding.detail ?? ""].join("|"))
    .digest("hex");
}
