# Security

SentinelAI is intended for authorized assessments. It does not verify that a target
is in a bounty program's scope, and an observation is not a confirmed vulnerability.
Check scope and automation rules yourself before sending requests.

## Running it safely

- For private use, run `python app.py`; Waitress binds to loopback by default.
- For internet deployment, use the checked-in Docker and Render configuration with
  `SENTINELAI_PUBLIC_MODE=1`. Never expose the unrestricted local mode.
- Keep credentials, scan databases and real reports out of commits and issues.
- The app uses a random session key per process unless SENTINELAI_SECRET_KEY is set.
  Restarting clears existing browser sessions when no stable key is configured.
- Website and API URL query values are redacted; URL paths, selected response
  headers and DNS values may still contain sensitive information. Review any
  exported report before sharing it.
- Some endpoints change state even on GET. Use only endpoints you are permitted
  to assess; do not assume every GET is harmless.

## Reporting a vulnerability in SentinelAI

Use the repository's private vulnerability reporting option if enabled. Otherwise,
contact the repository owner privately before sharing sensitive details. Do not
post credentials, real target data or exploit details in a public issue.

This project is not a penetration-test certification or automatic bounty generator.

## Public-mode boundaries

Public mode rejects embedded URL credentials, nonstandard ports, local-name
suffixes, non-global IP literals and hostnames resolving to any non-global address.
Redirects receive the same validation. Requests do not use environment proxies,
`.netrc` credentials, retries or response bodies. Per-client submission limits,
a global concurrency cap, short network timeouts and per-browser result isolation
reduce abuse and accidental disclosure.

These controls reduce risk; they do not prove authorization or eliminate all abuse.
DNS and network state can change between validation and connection, and a public
scanner still sends traffic from the hosting account. Monitor Render usage and
logs, keep dependencies patched, and disable the service if it is abused. Do not
add active probing, credentials, arbitrary headers, uploads or target-controlled
callbacks without a new threat model and tests.

## Local training lab

The deliberately vulnerable API is created only during a local training run, with
synthetic records and random credentials. It binds to loopback on an ephemeral
port and is shut down afterward. It is not a deployment example. No external URL
or real credential input is accepted by this workflow. See
[the lab's scope and limits](docs/access-control-lab.md).

Dashboard forms require CSRF tokens; requests using untrusted Host values or
cross-origin POSTs are rejected. The lab is always unavailable in public mode.
