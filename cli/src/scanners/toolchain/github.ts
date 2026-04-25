import axios from "axios";
import { logger } from "../../core/logger.js";
import type { Finding } from "../../core/types.js";

const GH_API = "https://api.github.com";

export async function scanGitHub(token: string, repo?: string): Promise<Finding[]> {
  logger.info("Scanning GitHub configuration...");
  const findings: Finding[] = [];
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  if (repo) {
    const parts = repo.split("/");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      logger.warn(`[github] Invalid repo format "${repo}" — expected "owner/repo"`);
      return findings;
    }
    const [owner, repoName] = parts as [string, string];

    // ── 1. Branch protection on main / master ──────────────────────────────────
    for (const branch of ["main", "master"]) {
      try {
        const res = await axios.get(`${GH_API}/repos/${owner}/${repoName}/branches/${branch}/protection`, {
          headers,
          validateStatus: () => true,
          timeout: 8000,
        });

        if (res.status === 404) {
          findings.push({
            id: `github-no-branch-protection-${branch}`,
            title: `Branch "${branch}" has no protection rules`,
            severity: "high",
            category: "toolchain",
            tool: "github",
            description: `The ${branch} branch is unprotected — anyone with write access can force-push, delete it, or merge without review, enabling direct code injection.`,
            remediation: "Enable branch protection: require PRs, at least 1 approving review, status checks passing, and dismiss stale reviews on push.",
            references: ["https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches"],
          });
        } else if (res.status === 200) {
          const p = res.data as Record<string, unknown>;

          if (!p["required_pull_request_reviews"]) {
            findings.push({
              id: `github-no-pr-review-${branch}`,
              title: `Branch "${branch}" does not require PR reviews`,
              severity: "medium",
              category: "toolchain",
              tool: "github",
              description: "Without required reviews, a single compromised or insider account can merge malicious code directly to the default branch.",
              remediation: "Require at least 1 approving review. Enable 'Dismiss stale reviews' and 'Restrict who can dismiss pull request reviews'.",
            });
          }

          if (!p["required_status_checks"]) {
            findings.push({
              id: `github-no-status-checks-${branch}`,
              title: `Branch "${branch}" does not require status checks to pass`,
              severity: "low",
              category: "toolchain",
              tool: "github",
              description: "Merges are allowed regardless of CI status. Broken or untested code can reach production.",
              remediation: "Configure required status checks for branch protection. Require your CI workflow to pass before merge.",
            });
          }

          const reviews = p["required_pull_request_reviews"] as Record<string, unknown> | undefined;
          if (reviews && !reviews["dismiss_stale_reviews"]) {
            findings.push({
              id: `github-stale-reviews-not-dismissed-${branch}`,
              title: `Branch "${branch}" does not dismiss stale approvals on new commits`,
              severity: "low",
              category: "toolchain",
              tool: "github",
              description: "An approved PR remains approved after new commits are pushed. An attacker could get approval on benign code then push malicious changes.",
              remediation: "Enable 'Dismiss stale pull request approvals when new commits are pushed' in branch protection settings.",
            });
          }

          if (!p["enforce_admins"]) {
            findings.push({
              id: `github-admins-bypass-protection-${branch}`,
              title: `Admins can bypass branch protection on "${branch}"`,
              severity: "low",
              category: "toolchain",
              tool: "github",
              description: "Repository admins are exempt from branch protection rules, creating a privileged path for unreviewed code to reach the default branch.",
              remediation: "Enable 'Do not allow bypassing the above settings' so admins are subject to the same rules.",
            });
          }
        }
      } catch (e) {
        logger.debug(`GitHub branch protection check failed for ${branch}:`, e);
      }
    }

    // ── 2. Actions default workflow permissions ────────────────────────────────
    try {
      const res = await axios.get(`${GH_API}/repos/${owner}/${repoName}/actions/permissions`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200) {
        const perms = res.data as Record<string, unknown>;
        if (perms["default_workflow_permissions"] === "write") {
          findings.push({
            id: "github-actions-write-default",
            title: "GitHub Actions default workflow permissions set to write",
            severity: "high",
            category: "toolchain",
            tool: "github",
            description: "Every workflow run has write access to the repository by default. A compromised or malicious workflow (including from a supply chain attack on a third-party Action) can exfiltrate secrets, tamper with releases, or push code.",
            remediation: "Set default permissions to read-only in Settings → Actions → Workflow permissions. Grant write access explicitly per job via the 'permissions:' block.",
            references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"],
          });
        }

        if (perms["can_approve_pull_request_reviews"] === true) {
          findings.push({
            id: "github-actions-can-approve-prs",
            title: "GitHub Actions can approve pull requests",
            severity: "high",
            category: "toolchain",
            tool: "github",
            description: "Workflows are allowed to approve pull requests. A compromised workflow or a workflow triggered by a malicious PR can approve and merge its own code.",
            remediation: "Disable 'Allow GitHub Actions to approve pull requests' in Settings → Actions → Workflow permissions.",
          });
        }
      }
    } catch (e) {
      logger.debug("GitHub Actions permissions check failed:", e);
    }

    // ── 3. Secret scanning and push protection ────────────────────────────────
    try {
      const res = await axios.get(`${GH_API}/repos/${owner}/${repoName}`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200) {
        const repoData = res.data as Record<string, unknown>;
        const security = repoData["security_and_analysis"] as Record<string, Record<string, string>> | undefined;

        if (security?.["secret_scanning"]?.["status"] !== "enabled") {
          findings.push({
            id: "github-secret-scanning-disabled",
            title: "GitHub secret scanning is not enabled",
            severity: "medium",
            category: "toolchain",
            tool: "github",
            description: "Secret scanning automatically detects tokens, API keys, and credentials committed to the repository. Without it, leaked secrets may go unnoticed.",
            remediation: "Enable secret scanning in Settings → Security → Code security and analysis.",
            references: ["https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"],
          });
        }

        if (security?.["secret_scanning_push_protection"]?.["status"] !== "enabled") {
          findings.push({
            id: "github-push-protection-disabled",
            title: "GitHub push protection (secret scanning) is not enabled",
            severity: "medium",
            category: "toolchain",
            tool: "github",
            description: "Push protection blocks commits containing known secret patterns before they reach the repository. Without it, secrets can be committed and must be reactively rotated.",
            remediation: "Enable push protection in Settings → Security → Code security and analysis → Push protection.",
            references: ["https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations"],
          });
        }

        if (security?.["dependabot_security_updates"]?.["status"] !== "enabled") {
          findings.push({
            id: "github-dependabot-disabled",
            title: "Dependabot security updates are not enabled",
            severity: "low",
            category: "toolchain",
            tool: "github",
            description: "Dependabot automatically opens PRs to fix known vulnerable dependencies. Without it, vulnerable packages may persist in the codebase indefinitely.",
            remediation: "Enable Dependabot security updates in Settings → Security → Code security and analysis.",
            references: ["https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates"],
          });
        }

        // Public repo — info-level finding
        if (repoData["visibility"] === "public") {
          findings.push({
            id: "github-repo-public",
            title: "Repository is public",
            severity: "low",
            category: "toolchain",
            tool: "github",
            description: "The repository is publicly readable. Any sensitive data in the codebase, comments, commit history, or issues is exposed to the internet.",
            remediation: "Audit the repository for accidental secret commits. Ensure no sensitive business logic is exposed that could aid attackers.",
          });
        }
      }
    } catch (e) {
      logger.debug("GitHub repo metadata check failed:", e);
    }

    // ── 4. CODEOWNERS file present ────────────────────────────────────────────
    try {
      const res = await axios.get(`${GH_API}/repos/${owner}/${repoName}/contents/CODEOWNERS`, {
        headers,
        validateStatus: () => true,
        timeout: 5000,
      });
      if (res.status === 404) {
        findings.push({
          id: "github-no-codeowners",
          title: "No CODEOWNERS file found",
          severity: "low",
          category: "toolchain",
          tool: "github",
          description: "Without a CODEOWNERS file, no automatic review requests are made for changes to sensitive files (auth, payments, infrastructure). Critical paths can be merged without domain-expert review.",
          remediation: "Add a CODEOWNERS file mapping sensitive directories to responsible owners. Combine with branch protection's 'Require review from Code Owners'.",
          references: ["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"],
        });
      }
    } catch (e) {
      logger.debug("GitHub CODEOWNERS check failed:", e);
    }

    // ── 5. Workflow files using third-party Actions pinned to tags not SHAs ───
    try {
      const workflowsRes = await axios.get(`${GH_API}/repos/${owner}/${repoName}/contents/.github/workflows`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (workflowsRes.status === 200 && Array.isArray(workflowsRes.data)) {
        let unpinnedCount = 0;
        for (const file of workflowsRes.data.slice(0, 10)) {
          const fileRes = await axios.get(
            `${GH_API}/repos/${owner}/${repoName}/contents/.github/workflows/${(file as Record<string, string>)["name"]}`,
            { headers, validateStatus: () => true, timeout: 5000 }
          );
          if (fileRes.status === 200) {
            const content = Buffer.from((fileRes.data as Record<string, string>)["content"] ?? "", "base64").toString();
            // Match `uses: owner/action@v1` (tag) vs `uses: owner/action@sha` (hash)
            const tagPinned = content.match(/uses:\s+[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+@(?![\da-f]{40})[^\s#]+/g) ?? [];
            unpinnedCount += tagPinned.length;
          }
        }
        if (unpinnedCount > 0) {
          findings.push({
            id: "github-actions-unpinned-deps",
            title: `${unpinnedCount} GitHub Action(s) pinned to tags, not commit SHAs`,
            severity: "medium",
            category: "toolchain",
            tool: "github",
            description: "Actions pinned to version tags (e.g. @v3) can be updated by the action owner to include malicious code without changing the tag. SHA pinning guarantees the exact code that runs.",
            remediation: "Pin all third-party Actions to their full commit SHA. Use tools like Dependabot or pin-github-action to automate this.",
            references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
          });
        }
      }
    } catch (e) {
      logger.debug("GitHub workflow file check failed:", e);
    }

    // ── 6. Environments with no protection rules ───────────────────────────────
    try {
      const res = await axios.get(`${GH_API}/repos/${owner}/${repoName}/environments`, {
        headers,
        validateStatus: () => true,
        timeout: 8000,
      });

      if (res.status === 200 && Array.isArray(res.data?.environments)) {
        const prodEnvs = res.data.environments.filter((e: Record<string, unknown>) =>
          /prod|production|live/i.test(String(e["name"] ?? ""))
        );
        for (const env of prodEnvs) {
          const protectionRules = Array.isArray(env["protection_rules"]) ? env["protection_rules"] : [];
          if (protectionRules.length === 0) {
            findings.push({
              id: `github-env-no-protection-${env["name"]}`,
              title: `Production environment "${env["name"]}" has no protection rules`,
              severity: "high",
              category: "toolchain",
              tool: "github",
              description: "The production environment can be deployed to without any approval gate. A compromised branch or malicious PR workflow could push directly to production.",
              remediation: "Add required reviewers to the production environment. Enable 'Required reviewers' in Settings → Environments.",
              references: ["https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment"],
            });
          }
        }
      }
    } catch (e) {
      logger.debug("GitHub environments check failed:", e);
    }
  }

  // ── 7. Token scope — overprivileged ──────────────────────────────────────────
  try {
    const res = await axios.get(`${GH_API}/user`, {
      headers,
      validateStatus: () => true,
      timeout: 8000,
    });

    const scopes = String(res.headers["x-oauth-scopes"] ?? "");
    if (scopes.includes("repo") && scopes.includes("admin")) {
      findings.push({
        id: "github-token-overprivileged",
        title: "GitHub token has admin + repo scope",
        severity: "high",
        category: "toolchain",
        tool: "github",
        description: "The configured GitHub token has full administrative permissions. A leaked token grants an attacker complete repo control — force-push, delete branches, modify settings, read all secrets.",
        remediation: "Rotate the token. Use fine-grained PATs scoped to only the required permissions and repositories.",
        references: ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token"],
      });
    }

    if (scopes.includes("write:packages") || scopes.includes("delete:packages")) {
      findings.push({
        id: "github-token-package-write",
        title: "GitHub token can write or delete packages",
        severity: "medium",
        category: "toolchain",
        tool: "github",
        description: "The token has package write/delete permissions. If leaked, an attacker could publish malicious package versions to GitHub Packages, affecting anyone who depends on them.",
        remediation: "Use a dedicated token with only the minimum package permissions needed. Never reuse tokens across contexts.",
      });
    }
  } catch (e) {
    logger.debug("GitHub token scope check failed:", e);
  }

  logger.info(`GitHub scan complete — ${findings.length} finding(s)`);
  return findings;
}
