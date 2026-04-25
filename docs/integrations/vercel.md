# Vercel Integration

BreachScope probes your Vercel project for secrets exposure and access control gaps — the class of issues that led to the 2024 Vercel breach.

## Setup

```yaml
toolchain:
  vercel:
    token: ""      # or VERCEL_TOKEN env var
    projectId: ""  # optional, enables project-level checks
```

```bash
export VERCEL_TOKEN=your_token_here
export VERCEL_PROJECT_ID=prj_xxx  # optional
```

## What gets checked

### Secrets in preview deployments

Preview deployments are publicly accessible via PR URLs. If environment variables with names matching `SECRET_*`, `*_KEY`, `*_TOKEN`, `PASSWORD`, etc. are available in preview environments, they can be leaked via a compromised preview build.

**Fix:** Restrict sensitive env vars to `production` only. Use Vercel's sensitive value flag to prevent them from appearing in the dashboard.

### Unprotected preview deployments

Without Vercel Authentication or password protection, preview deployments are publicly accessible to anyone with the URL.

**Fix:** Enable deployment protection for preview deployments in your project settings.

### Open team invite links

An active invite link allows anyone who finds it to join your Vercel team and gain access to projects, env vars, and deployments.

**Fix:** Invalidate unused invite links. Use SAML SSO with an allowlisted domain for team access.

## Severity mapping

| Finding | Severity |
|---------|----------|
| Secret in preview deployment | HIGH |
| Unprotected preview deployments | MEDIUM |
| Open team invite link | LOW |
