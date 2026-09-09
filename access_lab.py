"""Ephemeral, loopback-only access-control training with synthetic accounts/data."""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hmac
import json
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, jsonify, request
import requests
from werkzeug.serving import WSGIRequestHandler, make_server

MAX_REQUESTS = 8
MAX_BODY_BYTES = 16_384
MAX_SECONDS = 20
REQUEST_INTERVAL = 0.2


@dataclass(repr=False)
class Fixture:
    tokens: dict = field(repr=False)
    records: dict = field(repr=False)


def make_fixture():
    return Fixture(
        tokens={account: secrets.token_urlsafe(32) for account in ('account-a', 'account-b')},
        records={f'record-{suffix}': {'id': f'record-{suffix}', 'owner_id': f'account-{suffix}',
                                    'private_note': 'synthetic-' + secrets.token_hex(16)}
                 for suffix in ('a', 'b')})


def create_training_api(fixture):
    lab = Flask('sentinelai_training_api')

    @lab.get('/<mode>/records/<record_id>')
    def record(mode, record_id):
        if mode not in ('broken', 'fixed') or record_id not in fixture.records:
            return jsonify(error='not_found'), 404
        supplied = request.headers.get('Authorization', '')
        account = next((account for account, token in fixture.tokens.items()
                        if hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode())), None)
        if account is None:
            return jsonify(error='authentication_required'), 401
        owned_record = fixture.records[record_id]
        # Intentional training flaw: broken mode authenticates but omits ownership.
        if mode == 'fixed' and owned_record['owner_id'] != account:
            return jsonify(error='access_denied'), 403
        return jsonify(owned_record)

    @lab.after_request
    def no_cache(response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    return lab


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


@contextmanager
def running_lab():
    fixture = make_fixture()
    server = make_server('127.0.0.1', 0, create_training_api(fixture), request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', fixture
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        fixture.tokens.clear()
        fixture.records.clear()


class LabClient:
    """An exact-origin/path allowlist; no arbitrary target, redirect or retry path."""
    def __init__(self, origin):
        parsed = urlsplit(origin)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or
                parsed.port is None or parsed.port < 1 or parsed.username is not None or
                parsed.path or parsed.query or parsed.fragment):
            raise ValueError('The training client requires its exact loopback lab origin.')
        self.origin = origin
        self.allowed_paths = {f'/{mode}/records/record-{suffix}'
                              for mode in ('broken', 'fixed') for suffix in ('a', 'b')}
        self.sent = 0
        self.started = time.monotonic()
        self.last_request = None
        self.session = requests.Session()
        self.session.trust_env = False

    def close(self):
        self.session.close()

    def get(self, path, token=None):
        if path not in self.allowed_paths or self.sent >= MAX_REQUESTS:
            raise ValueError('The local training scope or request budget was exceeded.')
        if self.last_request is not None:
            time.sleep(max(0, REQUEST_INTERVAL - (time.monotonic() - self.last_request)))
        remaining = MAX_SECONDS - (time.monotonic() - self.started)
        if remaining <= 0:
            raise ValueError('The local training time budget was exceeded.')
        self.sent += 1
        self.last_request = time.monotonic()
        headers = {'Accept': 'application/json', 'User-Agent': 'SentinelAI-Local-Training/0.4'}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + token
        self.session.cookies.clear()
        try:
            with self.session.get(self.origin + path, headers=headers, allow_redirects=False,
                                  stream=True, timeout=min(3, remaining)) as response:
                status = response.status_code
                if 300 <= status < 400:
                    raise ValueError('Training stopped: redirects are outside the allowed scope.')
                raw = bytearray()
                for chunk in response.iter_content(1024):
                    raw.extend(chunk)
                    if len(raw) > MAX_BODY_BYTES or time.monotonic() - self.started > MAX_SECONDS:
                        raise ValueError('Training stopped: response size or time limit reached.')
                is_json = response.headers.get('Content-Type', '').split(';')[0].strip() == 'application/json'
                try:
                    payload = json.loads(raw) if is_json else None
                except (ValueError, UnicodeError):
                    payload = None
                return status, payload
        except requests.RequestException:
            raise ValueError('The local training request failed. No credentials or response body were saved.') from None
        finally:
            self.session.cookies.clear()


def evaluate_access(owner_a, owner_b, anonymous, cross_account, records):
    """Check the control evidence before classifying a cross-account result."""
    controls_valid = (owner_a == (200, records['record-a']) and
                      owner_b == (200, records['record-b']) and anonymous[0] == 401)
    leaked = (cross_account[0] == 200 and isinstance(cross_account[1], dict) and
              all(cross_account[1].get(key) == records['record-a'][key]
                  for key in ('id', 'owner_id', 'private_note')))
    denied = (cross_account[0] in (403, 404) and isinstance(cross_account[1], dict) and
              cross_account[1].get('error') in ('access_denied', 'not_found') and
              'private_note' not in cross_account[1])
    if not controls_valid:
        outcome = 'Inconclusive: baseline controls did not match'
    elif leaked:
        outcome = 'Confirmed cross-account access in the local lab'
    elif denied:
        outcome = 'Cross-account read denied in this test'
    else:
        outcome = 'Inconclusive: response does not prove access or denial'
    return dict(outcome=outcome, controls_valid=controls_valid, private_record_matched=leaked,
                owner_a_status=owner_a[0], owner_b_status=owner_b[0],
                anonymous_status=anonymous[0], cross_account_status=cross_account[0])


_RUN_LOCK = threading.Lock()


def run_access_lab():
    if not _RUN_LOCK.acquire(blocking=False):
        raise ValueError('A training run is already in progress. Wait for it to finish.')
    try:
        comparisons = []
        with running_lab() as (origin, fixture):
            client = LabClient(origin)
            try:
                for mode in ('broken', 'fixed'):
                    path = f'/{mode}/records/'
                    owner_a = client.get(path + 'record-a', fixture.tokens['account-a'])
                    owner_b = client.get(path + 'record-b', fixture.tokens['account-b'])
                    anonymous = client.get(path + 'record-a')
                    cross_account = client.get(path + 'record-a', fixture.tokens['account-b'])
                    comparisons.append(dict(scenario=mode.title(), **evaluate_access(
                        owner_a, owner_b, anonymous, cross_account, fixture.records)))
                sent = client.sent
            finally:
                client.close()
        return dict(scan_type='access_lab', target='Local two-account training lab', score=None,
                    rating='Synthetic training evidence — not a live-target finding',
                    summary={'Environment': 'Temporary server bound to 127.0.0.1; stopped after the run',
                             'Accounts': 'A and B; randomly generated credentials held in memory',
                             'Requests': f'{sent} of {MAX_REQUESTS} allowed GET requests',
                             'Saved data': 'Status codes, control checks and synthetic record comparison outcomes'},
                    access_comparisons=comparisons, findings=[
                        dict(name='Authentication versus authorization', severity='Info', status='Training',
                             description='Both versions authenticate the caller. Broken mode omits the ownership check; fixed mode requires the record owner to match the authenticated account.',
                             remediation='Read create_training_api() and locate the ownership condition. Authentication identifies the caller; authorization decides what the caller may access.'),
                        dict(name='Evidence needed to confirm access', severity='Info', status='Training',
                             description='A 200 status alone is insufficient. The comparison requires valid owner and anonymous controls, plus the exact synthetic record ID, owner and private marker returned to Account B.',
                             remediation='Compare all four observations. Unexpected errors or unrelated content remain inconclusive.'),
                        dict(name='Assessment scope', severity='Info', status='Training',
                             description='This workflow accepts no target URLs or real credentials. It only contacts the temporary training API it starts. Credentials and raw response bodies are never included in results.',
                             remediation='Use the lab to learn and verify the detector. Applying this workflow to external programs requires a separately designed scope and credential system.')])
    finally:
        _RUN_LOCK.release()
