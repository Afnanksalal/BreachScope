# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.1   | ✓ Current |
| < 0.3.1 | ✗ Unsupported |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in BreachScope itself, report it responsibly:

**Email:** itsafnanksalal@gmail.com  
**PGP:** Available on request

### What to include

- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations

### What to expect

- **Acknowledgement** within 48 hours
- **Initial assessment** within 7 days
- **Patch timeline** communicated within 14 days
- **Credit** in the release notes (if desired)

## Scope

In scope:
- The `breachscope` CLI package
- The web application (`breachscoope.vercel.app`)
- Supply chain of our published npm package

Out of scope:
- Vulnerabilities in packages that BreachScope *scans* (report those to the respective projects)
- Social engineering attacks
- Denial of service via intentional resource exhaustion

## Responsible Disclosure

We follow a 90-day disclosure timeline. After 90 days from the initial report (or sooner if a patch is available), we may disclose the vulnerability publicly regardless of patch status.

## Security Practices

BreachScope eats its own dog food. The repository is scanned on every push:
- `breachscope scan --ci` runs in GitHub Actions
- OpenSSF Scorecard is enabled on this repository
- Dependabot is configured for automated dependency updates
- Branch protection requires review on `master`
