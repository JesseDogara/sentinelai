"""Bounded DNS observations and local IP metadata; never connect to target services."""
import ipaddress
from pathlib import Path
import re
# Required for the fixed-path, fixed-option dig invocation below.
import subprocess  # nosec B404
import time
from target_safety import validate_public_domain, validate_public_reverse_dns

DIG_PATH = Path('/usr/bin/dig')
RECORD_TYPES = ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA')
MAX_SCAN_SECONDS = 15


def normalize_domain(target):
    text = target.strip()
    if text.endswith('.'):
        text = text[:-1]
    if not text or any(c.isspace() for c in text) or any(c in text for c in '/:@?#\\'):
        raise ValueError('Enter a domain name only, such as example.com; no URL, port or path.')
    try:
        name = text.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Enter a valid domain name.') from None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError('Choose IP Address for an IP literal.')
    labels = name.split('.')
    if (len(name) > 253 or len(labels) < 2 or all(c in '0123456789.' for c in name)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        raise ValueError('Enter a valid domain name with at least two labels, such as example.com.')
    validate_public_domain(name)
    return name


def normalize_ip(target):
    text = target.strip()
    if '%' in text or '/' in text:
        raise ValueError('Enter one IPv4 or IPv6 address without a zone ID, subnet or URL.')
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ValueError('Enter one valid IPv4 or IPv6 address, such as 127.0.0.1 or ::1.') from None


def query_dns(name, record_type, timeout=3):
    """Only call with a validated absolute name and a fixed record type."""
    if not DIG_PATH.is_file():
        raise ValueError('DNS lookup needs the /usr/bin/dig utility, which was not found.')
    args = [str(DIG_PATH), name + '.', record_type,
            '+time=2', '+tries=1', '+nosearch', '+notcp', '+ignore',
            '+notrace', '+nonssearch', '+fail', '+nomultiline', '+ttlid', '+cl',
            '+noall', '+comments', '+answer']
    try:
        # Executable, record type and options are fixed; `name` passed strict validation.
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout,  # nosec B603
                                   check=False, encoding='utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return dict(query_type=record_type, status='Timeout', records=[])
    except OSError:
        raise ValueError('The local DNS lookup utility could not be started.') from None
    if completed.returncode == 1:
        raise ValueError('The DNS utility rejected its options. Check dig compatibility.')
    output = completed.stdout
    match = re.search(r'\bstatus: ([A-Z0-9]+)', output)
    if not match:
        return dict(query_type=record_type, status='Resolver unavailable', records=[])
    status = match.group(1)
    truncated = bool(re.search(r';; flags: [^;]*\btc\b', output))
    records = []
    for line in output.splitlines():
        if not line or line.startswith(';'):
            continue
        fields = line.split(None, 4)
        if len(fields) == 5 and fields[1].isdigit() and fields[2] == 'IN':
            records.append(dict(name=fields[0], ttl=fields[1], type=fields[3], value=fields[4][:2048]))
    if truncated:
        status = 'Truncated — partial response; no TCP retry'
    elif status == 'NOERROR':
        status = 'Answer received' if records else 'No records returned'
    return dict(query_type=record_type, status=status, records=records[:100])


def observation(name, description, advice):
    return dict(name=name, severity='Info', status='Observed', description=description, remediation=advice)


def scan_domain(target):
    name = normalize_domain(target)
    started = time.monotonic()
    queries = []
    nonexistent = False
    for record_type in RECORD_TYPES:
        remaining = MAX_SCAN_SECONDS - (time.monotonic() - started)
        if nonexistent:
            answer = dict(query_type=record_type, status='Skipped after NXDOMAIN', records=[])
        elif remaining <= 0:
            answer = dict(query_type=record_type, status='Skipped — scan time limit reached', records=[])
        else:
            answer = query_dns(name, record_type, timeout=min(3, remaining))
        queries.append(answer)
        nonexistent = nonexistent or answer['status'] == 'NXDOMAIN'
    return dict(scan_type='domain', target=name, score=None, rating='DNS observations only',
                summary={'Domain (ASCII)': name, 'Lookup scope': 'Exact name only',
                         'Record types': ', '.join(RECORD_TYPES), 'Resolver': 'System-configured DNS resolver'},
                dns_queries=queries, findings=[
                    observation('DNS records', 'These are resolver answers for the exact entered name. CNAME chains may appear in answers. TTL is the returned cache lifetime in seconds.',
                                'Compare A/AAAA addresses, mail (MX), nameservers (NS), text (TXT) and certificate-authority (CAA) records with your intended configuration.'),
                    observation('Interpreting missing answers', 'No records returned, NXDOMAIN (name does not exist), SERVFAIL, timeout and truncated answers are different outcomes. A missing record alone is not a vulnerability.',
                                'Check the resolver and authoritative configuration before drawing conclusions. CAA inheritance and email policies are not evaluated.'),
                    observation('Assessment limits', 'No subdomains were guessed, no zone transfers were attempted, and no target ports or services were contacted. DNSSEC, ownership and reputation were not verified.',
                                'Treat these results as an inventory snapshot, not a security rating.')])


def scan_ip(target, reverse_dns=False):
    address = normalize_ip(target)
    if reverse_dns:
        validate_public_reverse_dns(address)
    flags = [('Loopback', address.is_loopback), ('Link-local', address.is_link_local),
             ('Multicast', address.is_multicast), ('Unspecified', address.is_unspecified),
             ('Reserved (Python flag)', address.is_reserved),
             ('Private / special-use (Python flag)', address.is_private),
             ('Global (Python flag)', address.is_global)]
    summary = {'Normalized address': str(address), 'IP version': 'IPv' + str(address.version),
               'Address flags': ', '.join(label for label, value in flags if value) or 'No listed flags',
               'Reverse DNS': 'Requested' if reverse_dns else 'Not requested — no network traffic'}
    if address.version == 6 and address.ipv4_mapped:
        summary['IPv4-mapped address'] = str(address.ipv4_mapped)
    queries = [query_dns(address.reverse_pointer, 'PTR')] if reverse_dns else []
    return dict(scan_type='ip', target=str(address), score=None, rating='Address observations only',
                summary=summary, dns_queries=queries, findings=[
                    observation('IP classification', 'Flags describe address ranges using this Python runtime. Multiple flags can apply. Private / special-use includes more than private LAN space, and flags may vary across Python versions.',
                                'Do not infer reachability, safety, ownership or reputation from these flags.'),
                    observation('Reverse DNS', 'A PTR lookup maps an address to a DNS name when configured. The name is not proof of identity or ownership. No forward-confirmation lookup is performed.',
                                'An absent PTR record is not a vulnerability. Compare a returned name with your own DNS configuration.'),
                    observation('Assessment limits', 'No ping, port scan, HTTP request or TLS probe was sent to this address.',
                                'Use this module to understand the address and optional DNS metadata; service security is not assessed.')])
