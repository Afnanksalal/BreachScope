# Vercel Integration

BreachScope checks Vercel projects for preview exposure, secret handling, and team access risks.

## Configuration

```bash
export VERCEL_TOKEN=your_token
export VERCEL_PROJECT_ID=prj_xxx # optional
```

Or in `breachscope.yaml`:

```yaml
toolchain:
  vercel:
    token: ""
    projectId: ""
```

Use the least-privileged token that can read the project metadata required for scanning.

## Checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| Sensitive variables exposed to preview deployments | High | Compromised preview builds can leak production-grade secrets |
| Unprotected preview deployments | Medium | Anyone with a preview URL may reach internal application states |
| Open team invite links | Low/Medium | Unauthorized users may join the team and access projects |
| Misconfigured custom domains | Medium | DNS mistakes can enable takeover or traffic interception |

## Recommended Fixes

- Restrict sensitive environment variables to production only.
- Enable Vercel deployment protection for previews.
- Rotate and remove unused team invite links.
- Use SSO and domain allowlists for team membership.
- Review domain verification and DNS status after every project/domain change.

## Dashboard Use

Route high-severity Vercel findings to PagerDuty or Jira through project integrations, then track remediation in finding triage and audit logs.
