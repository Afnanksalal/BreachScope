# Contributing to BreachScope

BreachScope is a security tool. Contributions should improve accuracy, safety, evidence quality, or operational reliability.

## Development Setup

```bash
git clone https://github.com/Afnanksalal/BreachScope.git
cd BreachScope

cd cli
npm install
npm run build
npm test

cd ../web
npm install
npm run build
npm test
```

## Useful Commands

```bash
# CLI
cd cli
npm run lint
npx tsc --noEmit
npm test
npm run build
npm audit --audit-level=moderate

# Web
cd web
npm run lint
npx tsc --noEmit
npm test
npm run build
npm audit --audit-level=moderate
```

## Areas That Need Contributions

- lower-false-positive detection patterns
- new ecosystem parsers for SBOM and OSV matching
- additional policy-as-code checks
- better fix suggestion templates
- integration executors for more ticketing or incident systems
- dashboard usability improvements for triage and audit workflows
- tests for CLI and API edge cases

## Detection Rule Standards

Rules must be precise enough for production use.

Before submitting a new rule:

1. Test it against at least three real projects.
2. Include one vulnerable fixture or clear reproduction.
3. Document likely false positives.
4. Provide a specific remediation.
5. Keep severity defensible.

Rules live primarily in `cli/src/scanners/code/patterns.ts`.

## Dependency Scanner Standards

New scanners should:

- parse manifests with structured parsers where practical
- query OSV with the correct ecosystem name
- preserve package version when available
- avoid network calls when no manifest is present
- include focused tests

## Product Feature Standards

Dashboard and workflow changes must consider:

- API key scopes
- project ownership boundaries
- audit logging
- validation of user input
- stable JSON shape for CLI uploads
- migration impact
- CI and test coverage

## Pull Request Checklist

- [ ] lint passes
- [ ] typecheck passes
- [ ] tests pass
- [ ] build passes
- [ ] npm audit is clean at moderate level or higher
- [ ] docs are updated when behavior changes
- [ ] security-sensitive behavior is covered by tests

## Security Reports

Do not disclose vulnerabilities through public issues. Follow [SECURITY.md](SECURITY.md).
