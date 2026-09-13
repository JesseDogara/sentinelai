from urllib.parse import urljoin, urlparse
import requests
from target_safety import bounded_observation, redact_query, validate_outbound_url

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Helps reduce the impact of content injection attacks such as cross-site scripting."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Tells browsers to use HTTPS for future requests."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Helps prevent MIME type sniffing."
    },
    "X-Frame-Options": {
        "severity": "Low",
        "description": "Helps reduce clickjacking risk."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information the browser sends."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Restricts access to selected browser features."
    },
}

SEVERITY_WEIGHT = {
    "Low": 5,
    "Medium": 10,
    "High": 20,
}


def normalize_target(target):
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    try:
        validate_outbound_url(target)
    except ValueError as exc:
        raise ValueError(str(exc)) from None

    return target


def scan_target(target):
    target = normalize_target(target)
    current = target
    response = None
    try:
        with requests.Session() as session:
            session.trust_env = False
            for redirect_count in range(4):
                validate_outbound_url(current)
                response = session.get(
                    current,
                    timeout=(5, 10),
                    allow_redirects=False,
                    stream=True,
                    headers={"User-Agent": "SentinelAI-Learning-Project/0.5"},
                )
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")
                    response.close()
                    if not location:
                        break
                    if redirect_count == 3:
                        raise ValueError("The website redirected too many times. No result was saved.")
                    current = urljoin(current, location)
                    continue
                break
            if response is None:
                raise ValueError("The website did not return a response. No result was saved.")
            status_code = response.status_code
            response_headers = response.headers.copy()
            final_url = current
            response.close()
    except requests.RequestException:
        raise ValueError("Website request failed: check the URL, connection and TLS certificate. No result was saved.") from None

    findings = []
    score = 100

    parsed = urlparse(final_url)

    if parsed.scheme != "https":
        findings.append({
            "name": "HTTPS not enabled",
            "severity": "High",
            "status": "Missing",
            "description": "The final page was delivered over HTTP rather than HTTPS.",
            "remediation": "Configure HTTPS using a valid TLS certificate and redirect HTTP traffic to HTTPS."
        })
        score -= SEVERITY_WEIGHT["High"]
    else:
        findings.append({
            "name": "HTTPS enabled",
            "severity": "Info",
            "status": "Passed",
            "description": "The final page is delivered over HTTPS.",
            "remediation": "No action required."
        })

    for header, metadata in SECURITY_HEADERS.items():
        value = response_headers.get(header)

        if value:
            findings.append({
                "name": header,
                "severity": "Info",
                "status": "Passed",
                "description": f"{header} is present.",
                "remediation": "No action required."
            })
        else:
            severity = metadata["severity"]
            findings.append({
                "name": f"Missing {header}",
                "severity": severity,
                "status": "Missing",
                "description": metadata["description"],
                "remediation": f"Configure the {header} response header with an appropriate policy for the application."
            })
            score -= SEVERITY_WEIGHT[severity]

    score = max(0, min(100, score))

    if score >= 85:
        rating = "Good"
    elif score >= 65:
        rating = "Needs Improvement"
    else:
        rating = "Weak"

    return {
        "target": redact_query(target),
        "final_url": redact_query(final_url),
        "status_code": status_code,
        "server": bounded_observation(response_headers.get("Server", "Not disclosed"), 256),
        "score": score,
        "rating": rating,
        "findings": findings,
    }
