# SentinelAI — Learning & Development Journal

## Project Overview

**Project Name:** SentinelAI

**Project Type:** AI-Assisted Web Security Assessment & Reporting Platform

**Objective:**
Build a web security assessment platform that can perform authorized security checks, organize findings, assess risk, and eventually use AI to assist with vulnerability explanations, remediation recommendations, and security report generation.

---

# Phase 1 — Foundations

## Day 1 — Development Environment & First Python Program

### What I learned

- Python files use the `.py` extension.
- VS Code can be used to write and run Python programs.
- The `print()` function displays information in the terminal.
- Variables allow information to be stored and reused.

### What I did

I verified that Python was installed.

**Python version:** Python 3.9.6

I created the SentinelAI project folder and opened it manually in VS Code.

I created `main.py` and ran:

```python
print("Hello, SentinelAI!")
```

### Result

The terminal displayed:

```text
Hello, SentinelAI!
```

I also practiced variables with:

```python
name = "Jesse"
print("Hello, " + name)
```

and a security-related example.

### Challenge

The `code .` command did not automatically open the folder in VS Code.

### Resolution

I opened the folder manually through VS Code and continued successfully.

---

## Day 2 — Python Data Types

### Concepts introduced

- String (`str`)
- Integer (`int`)
- Float (`float`)
- Boolean (`bool`)
- `type()` function

### Cybersecurity connection

SentinelAI will use different data types for values such as:

```python
target = "OWASP Juice Shop"
port = 443
is_https = True
risk_score = 7.5
```

### Next learning task

Complete the mini challenge using variables for:

- Name
- Age
- Country
- Whether currently learning cybersecurity
- A chosen security score

After that, continue to Python conditional statements (`if`).

---

## September 8, 2026 — API Security Scanner milestone

### What changed

Added `api_scanner.py` alongside the original website scanner. The dashboard now
selects Website or API, routes to the corresponding scanner, and labels history.
New results can be reopened. SQLite gains columns through an additive, repeatable
migration, preserving old website records. API scans show observations rather
than applying a website-oriented score to APIs.

### Concepts introduced

- A GET request reads one endpoint; it does not assess an entire API.
- 2xx means success, 3xx may redirect, 401 relates to authentication, 403 means
  refusal, and 429 indicates too many requests. These do not explain every policy.
- Content-Type describes the response media type. HTTPS protects transport.
- CORS controls browser access. A response header alone does not prove a policy
  is safe, and this scanner does not send Origin or OPTIONS requests.
- Rate-limit headers advertise information; observing them does not test enforcement.
- Context matters: public endpoints may return 200 without credentials, and
  browser security headers do not apply equally to every API.
- Modular functions, request timeouts, resource cleanup, input validation, query
  redaction, JSON serialization, SQLite migration, and local regression tests.

### Verification approach

Local HTTP fixtures cover 200, 401, 403, 302, 429 and 500. Tests check that redirects
produce only one request, no Authorization header is sent, query secrets are not
saved, invalid input and network failures are handled, old history survives
migration, and both Website and API routes save and display results.

### What to learn next

1. Read `scan_api()` and follow URL → GET → headers → observations → saved result.
2. Compare 401 and 403 using the local test server and explain their limitations.
3. Learn authentication versus authorization and CORS preflight with a small API
   you own before designing further checks.
4. Learn why presence checks cannot replace configuration review or enforcement tests.

No IP, domain reconnaissance, smart-contract scanning, or AI model was added.

---

## September 9, 2026 — Domain/IP and product-quality milestone

### What changed

Added Domain and IP Address as separate types while retaining Website/API behavior
and saved data. Domain queries A, AAAA, CNAME, MX, NS, TXT and CAA for an exact name.
IP provides local range metadata and an optional PTR lookup. No target services
are contacted by these modules. Evidence and explanations are displayed separately.

Improved the dashboard with type-specific input guidance, progress feedback,
assessment counts, target search and history filters. New results include UTC
recording time, elapsed time and scanner version. Markdown and JSON downloads make
results portable. A POST now redirects to the saved result: refreshing it does not
send the request again. Invalid Domain/IP input preserves the chosen type and value
so it can be corrected. Unexpected failures show a generic message rather than
leaking raw exceptions into the dashboard.

### Why these design decisions matter

- **Modularity:** each scanner produces a result dictionary; routing, storage and
  reporting remain shared. A new module should not alter the meaning of old data.
- **Bounded work:** DNS attempts and elapsed time are limited. NXDOMAIN, no-answer,
  failure, truncation and timeout are distinguished instead of called insecure.
- **Evidence versus conclusions:** record presence and IP flags are observations,
  not proof of a vulnerability. Reports must state their limits.
- **Validation:** domain labels, IDNA and IPv4/IPv6 inputs are parsed before lookup.
  The DNS utility uses an argument array and never a shell command built from input.
- **Untrusted output:** DNS/header strings are escaped on display. Markdown evidence
  uses a fence longer than any backtick sequence inside the data.
- **Persistence:** parameterized SQL, additive migrations and temporary test
  databases prevent avoidable history loss. UTC timestamps disambiguate new records.
- **Usability:** helpful examples and progress feedback reduce incorrect inputs;
  result URLs and downloads turn a one-off scan into reusable evidence.

### Study plan

1. Explain A versus AAAA, CNAME, MX, NS, TXT, CAA, PTR and TTL in your own words.
2. Compare no-answer, NXDOMAIN and SERVFAIL using the deterministic test fixtures.
3. Inspect `127.0.0.1`, `::1` and `2001:db8::1` with reverse DNS disabled. Explain
   why classification is local and why it cannot establish reachability.
4. Trace form → scanner → result → SQLite → saved page → Markdown/JSON download.
5. Learn the POST/Redirect/GET pattern and reproduce the refresh regression test.
6. Add one useful assertion to a test before expanding scanning capability.

### Quality targets

A useful product must be measured by reliable behavior, clear evidence and usable
reports—not by promises about finding vulnerabilities. Production deployment,
authenticated API workflows and AI explanations each need their own design and
verification milestone. See the product roadmap for the remaining work.

### Verification results

- All 12 regression tests passed from the installed project on macOS.
- Real `dig` queries returned records for example.com and a PTR answer for loopback.
- Live HTTP submissions saved both IP and Domain results; JSON/Markdown exports,
  type filters and the previous API result returned successfully.
- The real DNS smoke test exposed an unsupported `dig -r` option on macOS 9.10.6;
  the command was corrected and the live lookup repeated successfully.
- Final visual browser verification was blocked by the in-app browser's localhost
  navigation policy. HTTP and automated checks passed; visual verification remains
  separate from these checks.


## September 9, 2026 — Private GitHub preparation

Added source-control exclusions for databases, credentials, generated reports and
virtual environments. Added a macOS test workflow, monthly dependency-update
configuration, security notes and a short contribution/Git guide. Debug mode now
requires explicit opt-in; session secrets are supplied by the environment or
generated at startup. Updated Flask and Requests pins before regression testing.

Git records local changes; GitHub stores and reviews the remote copy. Private
repository hosting does not deploy the Flask server. Learn status, diff, staging,
commits, branches and pull requests before using force-push or history rewriting.
The first commit records the current source snapshot; earlier journal entries
remain learning notes, not reconstructed Git history.


## September 9, 2026 — Local two-account API lesson

Added a separate, reproducible lab with broken and fixed ownership checks. Each
run creates accounts A and B, two synthetic private records, and a temporary
loopback server. Four control/comparison requests per version establish whether
B can read A's exact private record. A 200 response alone is never treated as proof.

Introduced lab-specific origin/path allowlists, request and response-size budgets,
credential isolation in memory, safe exports, server cleanup and a per-process
single-run lock. Added session-bound CSRF protection to all dashboard POST forms,
trusted local hosts and cross-origin submission checks. Existing assessment
modules retain their workflows, with CSRF-aware regression tests.

The test workflow now covers portable behavior on macOS, Linux and Windows, with
DNS-specific tests remaining on macOS. The lab itself has no Unix DNS dependency.

Study authentication versus authorization first, then control experiments, precise
evidence comparison, false positives, scope enforcement and secret redaction.
Follow docs/access-control-lab.md. These lab-only controls are not yet a general
external API testing or bounty-scope system.


## September 13, 2026 — Public hardening and Render beta launch

### Completed work

Replaced development-server deployment with Gunicorn for the public service and
Waitress for direct local runs. Added a production Dockerfile, Render configuration,
health endpoint and public portfolio page. The live Render service runs the Python
runtime with Gunicorn; the Dockerfile remains a separately tested deployment option.

Public mode now requires an environment-supplied secret and enables secure cookies,
trusted-host checks, HTTPS-aware proxy handling, CSRF and Origin checks, browser
security headers, request-size limits, per-client scan limits and a four-scan global
concurrency bound. Website and API targets reject local, private, reserved and
special-use addresses, embedded credentials and nonstandard ports. Every redirect
destination is revalidated. The local vulnerable training lab returns 404 publicly.

Each public browser session receives a random owner token so visitors cannot open or
export another visitor's stored result. The service still uses temporary SQLite;
therefore this is isolation for a beta session, not durable account storage.

### Verification results

- 29 regression tests passed after adding the Render proxy-origin regression.
- The pinned dependencies returned no known vulnerabilities in `pip-audit`.
- Bandit completed without an unresolved finding.
- Gunicorn and Waitress smoke tests returned a healthy application.
- Render reported the final clean commit live; Gunicorn listened on the assigned
  port and the service returned 200 for `/`, `/healthz` and `/project`.
- The public `/lab` route returned 404 as designed.

### Challenges and resolutions

The GitHub connector could not perform a normal local `git push`, so Git blob, tree,
commit and fast-forward reference operations were used without rewriting existing
history. Render did not receive the connector-created push event automatically, so
the same committed revisions were deliberately deployed through the Render API.

A cloud verification browser sent `Origin: null` for form submissions. SentinelAI
rejected it with 403. A temporary diagnostic recorded only origin/proxy metadata and
confirmed that Render supplied the correct HTTPS scheme and host. The diagnostic was
then removed. The protection was not weakened to accept opaque origins. A regression
test verifies legitimate HTTPS origins when the proxy includes the default port.

### Lessons learned

- Public deployment changes the threat model; input validation alone is insufficient.
- An HTTP 200 health response and a live process do not replace route, header and
  failure-path tests.
- Proxy headers and browser Origin values must be normalized by meaning, not compared
  as arbitrary strings.
- A security control should not be weakened merely to satisfy a restricted test tool.
- Marketing claims must reflect the deployed architecture and current features.


## September 13, 2026 — Free public-beta preparation

Added a visible free-beta status, responsible-use guide, temporary-data notice and
safe feedback route. GitHub's beta feedback form explicitly prohibits credentials,
private targets and confidential results. The portfolio copy now distinguishes the
live native-Python Render service from the repository's optional Docker deployment.

Created a factual public-beta launch checklist, portfolio case study and social-media
draft pack. No customer accounts, permanent database, payment system, testimonials,
AI model or paid plan is claimed. Those remain potential later phases after genuine
tester feedback.
