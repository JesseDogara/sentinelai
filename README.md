# SentinelAI

A local security assessment dashboard for learning, inspection and evidence-based
reporting. Four independent modules keep each assessment's scope understandable.

| Module | What it does | What it does not establish |
| --- | --- | --- |
| Website | GET with redirects, HTTPS and common security-header checklist, existing score | Comprehensive application security or exploitability |
| API | One unauthenticated GET; status, content type, HTTPS, security/CORS/rate-limit headers and authentication-response observations | Correct authentication, CORS or rate-limit enforcement |
| Domain | Exact-name A, AAAA, CNAME, MX, NS, TXT and CAA DNS queries | Subdomain inventory, ownership, reputation, DNSSEC or effective email/CAA policy |
| IP Address | Local IPv4/IPv6 normalization and range flags; optional PTR lookup | Reachability, open ports, service security or ownership |

Only assess systems you own or have permission to test. No exploitation,
credential guessing, port sweeps or smart-contract scanning is included.
This is a local learning product, not a certified or production-hardened scanner.

## Start on macOS

Open the project folder in Terminal or VS Code. For a clone named `sentinelai`:

```bash
cd sentinelai
./run_mac.sh
```

The startup script creates `.venv` if needed and installs the pinned requirements.
Keep the terminal open. Visit `http://127.0.0.1:5000`.

If packages are already installed, an offline startup is:

```bash
.venv/bin/python app.py
```

DNS lookup uses macOS `/usr/bin/dig`; no new Python dependency is required. The
local Flask development server binds to loopback. Do not expose it to a network:
it has no user authentication or deployment hardening. Debug mode is off by default;
set `SENTINELAI_DEBUG=1` only for development. The session key is random per process
unless `SENTINELAI_SECRET_KEY` is supplied through the environment.
The current Python 3.9/LibreSSL environment emits an urllib3 compatibility warning;
local checks can pass despite this. A supported Python/OpenSSL environment is a
separate maintenance milestone, not something this release silently fixes.

## Use the dashboard

1. Choose Website, API, Domain or IP Address. Input guidance changes with the type.
2. Enter the exact target. Domains take `example.com`, not a URL. IP takes one
   address such as `127.0.0.1` or `::1`, not a subnet, URL or zone identifier.
3. For IP, optionally enable reverse DNS. With it disabled, classification sends
   no network traffic. With it enabled, one PTR query goes to the configured resolver.
4. Run the assessment, then read both evidence and interpretation.
5. Search/filter saved history. Reopen results or download Markdown reports and
   JSON evidence. New results have UTC timestamps, duration and scanner version.

Website keeps its existing checklist score. Other modules show observations,
not a numeric security rating. DNS lookup errors appear as lookup outcomes, not
as vulnerabilities. Refreshing a saved result does not launch another assessment.

## Request limits and evidence

- **API:** one GET; 5-second connect and 10-second read timeouts, verified TLS,
  no redirects, retries, response-body inspection, implicit `.netrc` credentials
  or environment proxies. URL credentials are rejected. Query values are sent as
  entered but redacted in saved results. Do not put secrets in URL paths.
- **Domain:** at most seven query invocations, one attempt per type, no search
  suffixes, zone transfers or explicit subdomain enumeration. Each invocation is
  bounded to 3 seconds with a 15-second overall query budget. NXDOMAIN skips the
  remaining types. Truncated UDP replies are reported without a TCP retry.
  Recursive resolvers may make their own upstream requests or return CNAME chains.
- **DNS:** uses the resolver available to `dig`; it may differ from application
  resolution on a macOS split-DNS/VPN setup. No custom resolver or resolver secrets
  are collected. Responses are capped at 100 records per query and 2,048 characters
  per record value. Long values may be clipped; exports contain the same snapshot.
- **IP:** Python `ipaddress` flags are descriptive and can vary by runtime version.
  Private/special-use is broader than private LAN space; global does not imply safe
  or reachable. Multiple flags can apply, including to multicast and mapped IPv6.
- **Reports:** saved selected headers and DNS records are untrusted observations,
  escaped in the UI and contained in a fenced evidence block in Markdown. Exports
  are local downloads, not submissions to any bounty platform.

A 200 API response without credentials can be intentional. Missing rate-limit
headers do not mean no rate limit exists. GET headers without Origin do not verify
CORS. A missing DNS record, PTR record or browser header is not automatically a
vulnerability. CAA inheritance and SPF/DKIM/DMARC validation are not implemented.

## Persistence and compatibility

`sentinelai.db` stores all types in one `scans` table. Additive migration introduces
`scan_type` and `result_json`; old rows remain Website records. Legacy rows keep
summary/findings data and lack the newer full-detail export. No existing rows are
removed. The original NOT NULL score column uses an internal zero for observations;
the saved result JSON uses null and the UI displays “Observations.” Old timestamps
remain local time; newly stored result metadata explicitly uses UTC.

## Verify changes

```bash
.venv/bin/python -m unittest discover -v
```

Tests use isolated databases, local HTTP fixtures and mocked DNS responses. They
cover all four routes, migration, parsing, malformed input, 401/403/302/429/500,
timeouts, NXDOMAIN/SERVFAIL/refused/truncated DNS, query limits, optional PTR,
HTML/Markdown escaping, report downloads, filters and refresh without duplicate
scans. Automated DNS fixtures are deterministic; a separate real resolver smoke
check verifies the installed `dig` path and output format when network is available.

## Repository workflow

See [the Git and GitHub guide](docs/github-workflow.md), [contribution guide](CONTRIBUTING.md),
and [security notes](SECURITY.md). Scan databases, secrets, reports and virtual
environments are excluded from version control. Automated tests run on macOS
with Python 3.12; Dependabot proposes dependency updates monthly.

## Code map

- `app.py`: module routing, persistence, filters, report downloads.
- `scanner.py`: existing Website checks.
- `api_scanner.py`: bounded API observations.
- `network_scanner.py`: input validation, bounded DNS, IP metadata.
- `reporting.py`: original Markdown report generation.
- `templates/`, `static/`: dashboard, results, accessible controls and progress.
- `test_*.py`: regression checks.
- `docs/learning-journal.md`: milestones and concepts to study.
- `docs/product-roadmap.md`: quality priorities and future milestones.

No AI model is connected yet. Future additions should earn their place through
clear scope, real evidence and regression tests.
