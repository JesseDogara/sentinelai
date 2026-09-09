from urllib.parse import urlparse
import requests

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

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    return target


def scan_target(target):
    target = normalize_target(target)

    response = requests.get(
        target,
        timeout=10,
        allow_redirects=True,
        headers={"User-Agent": "SentinelAI-Learning-Project/0.1"},
    )

    findings = []
    score = 100

    final_url = response.url
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
        value = response.headers.get(header)

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
        "target": target,
        "final_url": final_url,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "Not disclosed"),
        "score": score,
        "rating": rating,
        "findings": findings,
    }
