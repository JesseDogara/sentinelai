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

Automated platform verification currently runs on macOS only. Linux and Windows
instructions are documented setup paths; they are not claims of native Windows
or Linux CI coverage. The DNS implementation currently uses a fixed Unix path.

### Get the code

The repository is private, so your GitHub account needs access. Authenticate Git
with GitHub CLI, GitHub Desktop or your credential manager before cloning:

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

The Flask development server binds to loopback. It has no user authentication or
production deployment hardening. Debug mode is off by default; set
`SENTINELAI_DEBUG=1` only for development. The session key is random per process
unless `SENTINELAI_SECRET_KEY` is supplied through the environment. `.env.example`
is a reference; the app does not automatically load `.env` files.

Older macOS system Python builds may emit an urllib3/LibreSSL compatibility warning.
Use a modern Python installation with OpenSSL and create a new virtual environment
with that interpreter. Passing local tests on an older interpreter does not resolve
its TLS compatibility warning. See [Python's virtual-environment documentation](https://docs.python.org/3.12/library/venv.html)
for the platform-specific directory layout and environment setup.

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

macOS / Linux / WSL (with `/usr/bin/dig` installed):

```bash
.venv/bin/python -m unittest discover -v
```

Native Windows: run the Website/API, local IP and reporting regression tests:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_api test_reporting
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
