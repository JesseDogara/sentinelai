"""One unauthenticated GET; no redirects, retries, body inspection or probing."""
from urllib.parse import urlsplit, urlunsplit
import requests
from scanner import SECURITY_HEADERS

CORS_HEADERS = ("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
                "Access-Control-Expose-Headers", "Access-Control-Max-Age", "Vary")
RATE_HEADERS = ("RateLimit", "RateLimit-Policy", "RateLimit-Limit", "RateLimit-Remaining",
                "RateLimit-Reset", "X-RateLimit-Limit", "X-RateLimit-Remaining",
                "X-RateLimit-Reset", "Retry-After")


def normalize_api_target(target):
    target = target.strip()
    if not target or any(c.isspace() or ord(c) < 32 for c in target):
        raise ValueError("Enter an API URL without spaces or control characters.")
    if "://" not in target:
        target = "https://" + target
    try:
        parsed = urlsplit(target)
        port = parsed.port
        if parsed.scheme not in ("http", "https") or not parsed.hostname or port == 0:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
    except ValueError:
        raise ValueError("Enter a valid HTTP or HTTPS API URL without embedded credentials.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def scan_api(target):
    target = normalize_api_target(target)
    parsed = urlsplit(target)
    # Query values may contain secrets: send as entered, but never persist/display them.
    display_target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                "[redacted]" if parsed.query else "", ""))
    try:
        with requests.Session() as session:
            session.trust_env = False  # Avoid implicit .netrc credentials and environment proxies.
            with session.get(target, timeout=(5, 10), allow_redirects=False, stream=True,
                             headers={"User-Agent": "SentinelAI-Learning-Project/0.2",
                                      "Accept": "application/json, */*"}) as response:
                status = response.status_code
                headers = response.headers
                content_type = headers.get("Content-Type", "Not observed")
                groups = {"Security headers": {h: headers.get(h, "Not observed") for h in SECURITY_HEADERS},
                          "CORS response headers": {h: headers.get(h, "Not observed") for h in CORS_HEADERS},
                          "Rate-limit response headers": {h: headers.get(h, "Not observed") for h in RATE_HEADERS}}
                challenge = "Present" if "WWW-Authenticate" in headers else "Not observed"
    except requests.RequestException:
        raise ValueError("API request failed: check the URL, connection and TLS certificate. No result was saved.") from None
    if status == 401:
        auth = "401 Unauthorized: this request was rejected as unauthenticated. This does not verify authentication correctness."
    elif status == 403:
        auth = "403 Forbidden: access was refused; the reason may be authorization, a gateway or another policy."
    elif 200 <= status < 300:
        auth = "A successful response was returned without supplied credentials. Public endpoints may intentionally allow this; it is not proof of an authentication flaw."
    elif 300 <= status < 400:
        auth = "Redirect observed and not followed. Authentication at the destination was not assessed."
    else:
        auth = "This status does not establish whether authentication is required or effective."
    findings = []
    def observe(name, description, advice):
        findings.append(dict(name=name, severity="Info", status="Observed", description=description, remediation=advice))
    observe("HTTPS usage", "HTTPS is used with certificate verification." if parsed.scheme == "https" else "The request used unencrypted HTTP.", "Use HTTPS for deployed APIs.")
    observe("Authentication response", auth + " WWW-Authenticate: " + challenge + ".", "Compare with the endpoint's documented access policy.")
    observe("CORS", "Headers below describe this GET response only. No Origin header or preflight request was sent.", "Review intended browser origins. Missing headers or a wildcard alone do not prove a vulnerability.")
    observe("Rate limiting", "Header presence is an indicator only. Missing headers do not mean limits are absent." + (" HTTP 429 indicates this request was rate limited." if status == 429 else ""), "Review server configuration; enforcement was not tested.")
    observe("Security headers", "Header presence does not validate its policy. Browser-specific headers may be less relevant to a JSON-only API.", "Interpret headers in the context of content type and browser use.")
    return dict(scan_type="api", target=display_target, final_url=display_target, status_code=status,
                content_type=content_type, server="Not collected", score=None, rating="Observations only",
                header_groups=groups, findings=findings)
