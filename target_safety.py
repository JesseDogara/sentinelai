"""Public-hosting guardrails for outbound HTTP and DNS assessment targets."""
import ipaddress
import os
import socket
from urllib.parse import urlsplit, urlunsplit


BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home", ".lan")
STANDARD_PORTS = {("http", 80), ("https", 443)}


def public_mode():
    return os.environ.get("SENTINELAI_PUBLIC_MODE") == "1"


def _hostname_is_local(name):
    hostname = name.lower().rstrip(".")
    return hostname == "localhost" or hostname.endswith(BLOCKED_HOST_SUFFIXES)


def validate_public_hostname(hostname, port):
    """Resolve immediately before a request and reject any non-global answer."""
    if _hostname_is_local(hostname):
        raise ValueError("Local and private network targets are blocked on the public service.")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise ValueError("Private, reserved and local IP addresses are blocked on the public service.")
        return
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The target hostname could not be resolved.") from None
    addresses = {item[4][0].split("%", 1)[0] for item in answers}
    if not addresses:
        raise ValueError("The target hostname did not resolve to an address.")
    try:
        parsed = [ipaddress.ip_address(address) for address in addresses]
    except ValueError:
        raise ValueError("The target resolved to an invalid address.") from None
    if any(not address.is_global for address in parsed):
        raise ValueError("The target resolves to a private, reserved or local address and is blocked.")


def validate_outbound_url(target):
    """Validate an HTTP(S) destination; enforce SSRF controls in public mode."""
    if len(target) > 2048:
        raise ValueError("Enter a URL no longer than 2,048 characters.")
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError:
        raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials.") from None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials.")
    if any(character.isspace() or ord(character) < 32 for character in target):
        raise ValueError("Enter a URL without spaces or control characters.")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    if public_mode():
        if (parsed.scheme, effective_port) not in STANDARD_PORTS:
            raise ValueError("Only standard HTTP and HTTPS ports are allowed on the public service.")
        validate_public_hostname(parsed.hostname, effective_port)
    return parsed


def redact_query(target):
    parsed = urlsplit(target)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       "[redacted]" if parsed.query else "", ""))


def bounded_observation(value, limit=2048):
    """Keep untrusted response metadata small enough for reports and storage."""
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "… [clipped]"


def validate_public_domain(name):
    if public_mode() and _hostname_is_local(name):
        raise ValueError("Local and private DNS names are blocked on the public service.")


def validate_public_reverse_dns(address):
    if public_mode() and not address.is_global:
        raise ValueError("Reverse DNS for private, reserved and local addresses is blocked on the public service.")
