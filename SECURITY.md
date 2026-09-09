# Security

SentinelAI is intended for authorized, local assessments. It does not verify that
a target is in a bounty program's scope, and an observation is not a confirmed
vulnerability. Check scope and automation rules yourself before sending requests.

## Running it safely

- Keep the app bound to loopback. No login or deployment hardening is provided.
- Debug mode is off by default. Enable it only during local development.
- Keep credentials, scan databases and real reports out of commits and issues.
- The app uses a random session key per process unless SENTINELAI_SECRET_KEY is set.
  Restarting clears existing browser sessions when no stable key is configured.
- API URL query values are redacted; URL paths, selected response headers and DNS
  values may still contain sensitive information. Website results retain entered
  URLs. Review any exported report before sharing it.
- Some endpoints change state even on GET. Use only endpoints you are permitted
  to assess; do not assume every GET is harmless.

## Reporting a vulnerability in SentinelAI

Use the repository's private vulnerability reporting option if enabled. Otherwise,
contact the repository owner privately before sharing sensitive details. Do not
post credentials, real target data or exploit details in a public issue.

See docs/product-roadmap.md for known hardening work. This project is not a
production service, penetration-test certification or automatic bounty generator.
