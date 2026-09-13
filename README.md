# SentinelAI

A security assessment dashboard for learning, inspection and evidence-based
reporting. It runs privately on your computer and has a restricted public mode for
portfolio deployment. Four assessment modules and a separate local training lab
keep each workflow's scope understandable.

- **Public beta:** https://sentinelai-vn61.onrender.com
- **Portfolio case study:** https://sentinelai-vn61.onrender.com/project

The public beta is free and has no accounts or paid plans. Its SQLite scan history
is temporary and can reset when the free Render service restarts, redeploys or
spins down. See the in-app beta guide before testing an authorized target.

| Module | What it does | What it does not establish |
| --- | --- | --- |
| Website | GET with redirects, HTTPS and common security-header checklist, existing score | Comprehensive application security or exploitability |
| API | One unauthenticated GET; status, content type, HTTPS, security/CORS/rate-limit headers and authentication-response observations | Correct authentication, CORS or rate-limit enforcement |
| Domain | Exact-name A, AAAA, CNAME, MX, NS, TXT and CAA DNS queries | Subdomain inventory, ownership, reputation, DNSSEC or effective email/CAA policy |
| IP Address | Local IPv4/IPv6 normalization and range flags; optional PTR lookup | Reachability, open ports, service security or ownership |

Only assess systems you own or have permission to test. No exploitation,
credential guessing, port sweeps or smart-contract scanning is included.
This is a learning product, not a penetration test or security certification.

## Setup: macOS, Linux and Windows

Use Python 3.12 where possible (the version used by CI), and Git if you want a
clone. Install Python from [python.org](https://www.python.org/downloads/) or your
operating system's package manager. Keep each operating system's `.venv` separate;
a Windows virtual environment cannot be reused inside WSL or Linux.

| Environment | Website / API / local IP information | Domain / reverse DNS |
| --- | --- | --- |
| macOS | Available | Requires `/usr/bin/dig` (normally included) |
| Linux | Available | Install `dig` at `/usr/bin/dig` |
| Windows PowerShell (native) | Available | Not supported by the current DNS backend; use WSL |
| Windows with WSL Ubuntu | Use the Linux setup below | Install `dnsutils` inside WSL |

The portable Website/API, IP/reporting and local-lab tests run on macOS, Linux and
Windows in CI. DNS regression tests currently run on macOS only. Native Windows
DNS remains unsupported: that implementation uses a fixed Unix path.

### Get the code

Clone the public repository:

```text
git clone https://github.com/JesseDogara/sentinelai.git
cd sentinelai
```

Alternatively, sign in on GitHub and use **Code → Download ZIP**, extract it, then
open the extracted project folder in your terminal. Replace `cd sentinelai` below
with that folder's actual name if it differs. Never put a token in the clone URL.

### Start on macOS

From the project folder, the existing convenience script creates the environment,
installs dependencies and starts the app:

```bash
./run_mac.sh
```

Or choose Python 3.12 explicitly and set up manually:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

If `python3.12` is unavailable, install it first. If the script reports permission
denied after a ZIP download, run `chmod +x run_mac.sh` or use the manual commands.

### Start on Linux

On Ubuntu/Debian, install Python environment support and the DNS utility:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip dnsutils git
```

On Fedora, the equivalent packages are:

```bash
sudo dnf install python3 python3-pip bind-utils git
```

Then, from the project folder:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

Check `python3 --version` before setup; use `python3.12` to create the environment
if you installed that version separately. Confirm DNS availability with
`/usr/bin/dig -v`. On other distributions, install the package providing that path.
Use the virtual environment for Python packages rather than `sudo pip`.

### Start on Windows (PowerShell)

Install Python 3.12, then open PowerShell in the project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

If the `py` launcher is unavailable, use `python -m venv .venv` after confirming
`python --version` selects the Python installation you intend to use. These
commands call the environment's interpreter directly, so activating a PowerShell
script or changing the execution policy is unnecessary.

Native Windows supports Website, API and local IP classification. Leave **Look up
reverse DNS** unchecked. Domain and reverse-DNS lookups require the WSL setup
below; installing Python alone does not provide the current `/usr/bin/dig` backend.

### Windows: use all four modules through WSL

Follow [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).
On a supported Windows system, open PowerShell **as Administrator** and run:

```powershell
wsl --install -d Ubuntu
```

Restart if prompted, launch Ubuntu and complete its first-run user setup. In the
**Ubuntu terminal**, follow the Ubuntu/Debian Linux instructions above. Clone or
extract the project inside WSL and create a fresh Linux `.venv`; do not reuse the
Windows `.venv`. You can open the app from your Windows browser at the address below.

### Open, stop and restart

On every platform, open **http://127.0.0.1:5000** and keep the server terminal open.
Press **Ctrl+C** in that terminal to stop it. After the first installation, restart
from the project folder without reinstalling dependencies:

macOS / Linux / WSL:

```bash
.venv/bin/python app.py
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe app.py
```

If port 5000 is busy, choose another local port. On macOS/Linux/WSL:

```bash
SENTINELAI_PORT=5001 .venv/bin/python app.py
```

On PowerShell:

```powershell
$env:SENTINELAI_PORT = "5001"
.\.venv\Scripts\python.exe app.py
```

Then open `http://127.0.0.1:5001`. Do not run a second server on the same port.

### Local configuration

`python app.py` starts the production-quality Waitress WSGI server on loopback;
it is reachable only from your computer. It does not use Flask's development
server. The session key is random per process unless `SENTINELAI_SECRET_KEY` is
supplied through the environment. `.env.example` is a reference; the app does not
automatically load `.env` files.

## Deploy publicly on Render

The included `Dockerfile` runs Gunicorn as a non-root user and installs `dig` for
the DNS module. `render.yaml` selects Render's free web-service plan, generates a
session secret, enables proxy awareness and public safety mode, waits for GitHub
checks to pass before automatic deploys, and checks `/healthz`.

In Render, create a **Blueprint**, connect this repository, and select its
`render.yaml`. No real secret belongs in GitHub. A custom domain must also be added
to `SENTINELAI_TRUSTED_HOSTS` as an exact hostname.

Public mode adds safeguards that are intentionally different from local mode:

- only HTTP/HTTPS standard ports are allowed and local, private, reserved and
  special-use destinations are rejected before outbound web requests;
- every website redirect is revalidated, URL queries are redacted in saved data,
  request bodies are not read, and outbound proxies or implicit credentials are
  disabled;
- each browser session sees only its own saved results; scan submissions are
  limited to 10 per 10 minutes per client address and four concurrent scans;
- the deliberately vulnerable access-control training lab is disabled;
- trusted-host, CSRF, secure-cookie, browser-header, request-size and timeout
  protections remain enabled.

The free Render filesystem is ephemeral, so scan history can reset after a deploy,
restart or service replacement. This avoids committing visitor data and avoids
silently creating a paid resource. Add a persistent datastore later only after
defining retention, deletion and privacy requirements.

Older macOS system Python builds may emit an urllib3/LibreSSL compatibility warning.
Use a modern Python installation with OpenSSL and create a new virtual environment
with that interpreter. Passing local tests on an older interpreter does not resolve
its TLS compatibility warning. See [Python's virtual-environment documentation](https://docs.python.org/3.12/library/venv.html)
for the platform-specific directory layout and environment setup.

## Local two-account training lab

Open **Access-control lab** from the dashboard to compare a deliberately broken
API with its fixed version. SentinelAI creates two temporary accounts, makes eight
bounded GET requests to its own loopback server, and checks whether Account B can
read Account A's exact synthetic private record. No target URL or real credentials
are accepted. The server stops after the run; tokens and response bodies are not
saved. Results are clearly labeled as synthetic training evidence.

The lab works without `dig` on macOS, Linux and native Windows. Read the
[step-by-step lesson](docs/access-control-lab.md) for expected results, request
limits, redaction guarantees and the code to study.

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

`sentinelai.db` stores all types in one `scans` table locally. In public mode,
records include an opaque browser-session owner token and queries return only that
session's records. Additive migration introduces `scan_type`, `result_json` and
`owner_token`; old rows remain Website records. Legacy rows keep
summary/findings data and lack the newer full-detail export. No existing rows are
removed. The original NOT NULL score column uses an internal zero for observations;
the saved result JSON uses null and the UI displays “Observations.” Old timestamps
remain local time; newly stored result metadata explicitly uses UTC.

## Verify changes

macOS / Linux / WSL (with `/usr/bin/dig` installed):

```bash
.venv/bin/python -m unittest discover -v
```

Native Windows: run the Website/API, local IP and reporting regression tests:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_api test_reporting test_access_lab
```

The full DNS test suite currently requires the Unix DNS utility to be present,
even though responses are mocked. Run the full suite inside WSL for that coverage.

Tests use isolated databases, local HTTP fixtures and mocked DNS responses. They
cover all four routes, migration, parsing, malformed input, 401/403/302/429/500,
timeouts, NXDOMAIN/SERVFAIL/refused/truncated DNS, query limits, optional PTR,
HTML/Markdown escaping, report downloads, filters and refresh without duplicate
scans. Automated DNS fixtures are deterministic; a separate real resolver smoke
check verifies the installed `dig` path and output format when network is available.

## Repository workflow

See [the Git and GitHub guide](docs/github-workflow.md), [contribution guide](CONTRIBUTING.md),
and [security notes](SECURITY.md). Scan databases, secrets, reports and virtual
environments are excluded from version control. Portable tests run on macOS, Linux
and Windows with Python 3.12; DNS tests run on macOS and Linux, the production
container builds on Linux, and Dependabot proposes dependency updates monthly.

## Code map

- `app.py`: module routing, safety controls, persistence, filters and report downloads.
- `target_safety.py`: public destination validation and URL query redaction.
- `Dockerfile`, `render.yaml`: production Gunicorn container and Render Blueprint.
- `scanner.py`: existing Website checks.
- `api_scanner.py`: bounded API observations.
- `network_scanner.py`: input validation, bounded DNS, IP metadata.
- `reporting.py`: original Markdown report generation.
- `access_lab.py`: ephemeral training API, strict lab request scope and evidence comparison.
- `docs/access-control-lab.md`: the two-account lesson and its limits.
- `templates/`, `static/`: dashboard, results, accessible controls and progress.
- `test_*.py`: regression checks.
- `docs/learning-journal.md`: milestones and concepts to study.
- `docs/product-roadmap.md`: quality priorities and future milestones.

No AI model is connected yet. Future additions should earn their place through
clear scope, real evidence and regression tests.
