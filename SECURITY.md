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

## Local training lab

The deliberately vulnerable API is created only during a local training run, with
synthetic records and random credentials. It binds to loopback on an ephemeral
port and is shut down afterward. It is not a deployment example. No external URL
or real credential input is accepted by this workflow. See
[the lab's scope and limits](docs/access-control-lab.md).

Dashboard forms require CSRF tokens; requests using untrusted Host values or
cross-origin POSTs are rejected. These safeguards do not make the app suitable
for public hosting. The lab's scope restrictions do not apply to the existing
Website/API/Domain/IP scanners.
