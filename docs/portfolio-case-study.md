# SentinelAI — Portfolio Case Study

## Summary

SentinelAI is a Python and Flask security-observation dashboard created as a
cybersecurity learning project. It converts bounded HTTP, DNS and IP evidence into
readable pages plus Markdown and JSON reports.

The project is publicly available as a free beta on Render. It is not marketed as an
AI-powered scanner because no AI model is currently part of the application.

## Problem

Raw response headers, DNS records and IP properties are easy to misinterpret.
SentinelAI was built to gather a deliberately limited set of observations, preserve
the evidence and explain what each observation does—and does not—establish.

## Implemented assessments

- Website: HTTPS and common browser security-header observations.
- API: one unauthenticated GET response without reading the body.
- Domain: exact-name A, AAAA, CNAME, MX, NS, TXT and CAA queries.
- IP address: local address classification and optional PTR lookup, without a port scan.
- Local training lab: synthetic broken-versus-fixed object authorization comparison;
  this lab is disabled on the public service.

## Engineering decisions

- Separate scanner modules return a shared result shape.
- SQLite migrations preserve older local results.
- POST/Redirect/GET prevents refresh from repeating a scan.
- Markdown and JSON exports preserve evidence outside the temporary dashboard.
- Waitress serves direct local runs; Gunicorn serves the live Render application.
- A Dockerfile runs Gunicorn as a non-root container user for container deployments.
- GitHub Actions exercises portable tests on macOS, Linux and Windows and builds the
  production container on Linux.

## Public safety controls

- Public destinations only for outbound Website and API requests.
- DNS resolution checks before requests and after each redirect.
- Standard HTTP/HTTPS ports only; no embedded URL credentials.
- Bounded time, response metadata and redirect count.
- CSRF, Origin and trusted-host validation.
- Secure cookies and browser security headers.
- Ten submissions per ten minutes per client and four concurrent scans per process.
- Browser-session ownership checks for result pages and exports.
- Public removal of the deliberately vulnerable local lab.

## Verification

The public hardening release passed 29 regression tests, dependency auditing, Bandit,
Gunicorn and Waitress smoke tests. Render logs confirmed a live Gunicorn worker and
200 responses for the scanner, health endpoint and portfolio page. The public local-
lab route returned 404.

## Current limitations

- Public history is temporary SQLite data, not durable account storage.
- There are no user accounts, verified customer targets, background workers or billing.
- In-memory rate limits are per process.
- Header and record presence are not proof that a system is secure or vulnerable.
- SentinelAI does not exploit targets, guess credentials or sweep ports.

## Lessons

The project reinforced that evidence needs context, public deployment changes the
threat model, proxy behavior must be tested, and security controls should fail closed.
It also showed why product claims must be kept separate from future roadmap ideas.
