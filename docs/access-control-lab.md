# Local two-account access-control lab

## Run the lesson

Start SentinelAI using the commands in the README for your platform. Open the
dashboard and select **Open access-control lab**, or visit `/lab`. Click
**Compare broken and fixed APIs**. No second terminal, target URL, API key or real
user data is needed. The lab uses only Flask, Requests and Python's standard library;
it does not depend on `dig`, so it works with native Windows as well as macOS/Linux.

Each run creates two random account credentials and two synthetic private records,
starts a temporary API on an OS-assigned loopback port, performs the comparison,
and stops the API. Credentials are held in memory and are not shown in the browser,
written to files or included in exports. Python does not guarantee secure memory
erasure; process memory is outside the report-redaction guarantee.

## Expected observations

| Request | Broken version | Fixed version |
| --- | --- | --- |
| A reads A's record | 200, exact A record | 200, exact A record |
| B reads B's record | 200, exact B record | 200, exact B record |
| Anonymous reads A's record | 401 | 401 |
| B reads A's record | 200, exact A record: unintended access | 403: access denied |

The intentionally broken version verifies the bearer token but skips the ownership
condition. The fixed version checks that the record owner matches the authenticated
account. This is a controlled example of broken object-level authorization.

The detector does not decide based on the scenario name. It first validates the
owner and anonymous controls, then compares the exact record ID, owner ID and
random synthetic private marker. A 200 response with an error message, an unrelated
record, a failed baseline or an unexpected response is **inconclusive**. A denied
read verifies only this case; it does not certify the whole API.

## Scope and request limits

- The workflow accepts no arbitrary URL, port, endpoint or credential from the UI.
- It contacts only the exact `http://127.0.0.1:<allocated-port>` origin it starts.
- Only the four known broken/fixed record paths are allowed, using GET.
- Eight requests maximum per run, spaced at least 0.2 seconds apart; redirects,
  retries, inherited proxy settings and automatic `.netrc` credentials are disabled.
- Twenty-second request budget, up to three seconds per network operation and
  16 KiB per response. Only one lab run is allowed at a time per application process.
- If setup/request processing fails, the temporary server is closed and no result
  is saved. Complete but unexpected evidence is saved as inconclusive.

These are **lab-specific controls**, not a scope allowlist for the existing
Website/API/Domain/IP modules. Do not assume the other modules enforce a bounty
program's scope. External authenticated comparisons are not implemented.

## What gets saved

History and Markdown/JSON exports include the training label, UTC timestamp,
elapsed time, scanner version, four HTTP status codes per scenario, baseline-check
outcomes and whether the private record matched. No bearer token, raw response body,
private marker, cookie or actual account data is saved. Training reports are visibly
marked as synthetic local evidence, not live-target findings.

All dashboard POST forms now require a session-bound CSRF token. Cross-origin POST
requests are rejected, form bodies are limited to 16 KiB, and local hostnames are
validated. Browser sessions use HttpOnly/SameSite=Strict cookies. Refreshing a saved
result still does not send another request. Scripted callers must load the form and
preserve its session cookie and CSRF token before submitting.

## Learn by inspecting the implementation

1. Open `create_training_api()` in `access_lab.py`. Find the token check and the
   ownership condition. Explain why the first does not replace the second.
2. Read `evaluate_access()`. Explain what the baseline controls establish and why
   HTTP status alone is insufficient evidence of private data access.
3. Run the lesson and compare both result tables. Reopen the result from history
   and download it; note that no private marker or credential is present.
4. Run `test_access_lab.py`. Its negative cases cover unrelated 200 responses,
   failed baselines, redirects, scope escape, budgets, cleanup, redaction and CSRF.
5. In a separate learning branch, change the fixed ownership condition, predict
   the outcome, and rerun tests. Do not publish or deploy the training API publicly.

This lesson is a foundation for understanding and testing authorization. Using
similar techniques in a bounty program requires explicit scope, permitted test
accounts and a separate external-credential design.
