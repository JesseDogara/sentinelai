from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response, session
from collections import deque
from scanner import scan_target
from api_scanner import scan_api
from network_scanner import scan_domain, scan_ip
from access_lab import run_access_lab
import hmac
from urllib.parse import urlsplit
import os
import secrets
import sqlite3
import json
from datetime import datetime, timezone
from time import monotonic
from reporting import markdown_report
from pathlib import Path
from contextlib import closing
from threading import BoundedSemaphore, Lock
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
PUBLIC_MODE = os.environ.get("SENTINELAI_PUBLIC_MODE") == "1"
configured_secret = os.environ.get("SENTINELAI_SECRET_KEY")
if PUBLIC_MODE and not configured_secret:
    raise RuntimeError("SENTINELAI_SECRET_KEY is required in public mode.")
app.secret_key = configured_secret or secrets.token_hex(32)
SCANNER_VERSION = "0.5.0"
trusted_hosts = ["localhost", "127.0.0.1", "[::1]"]
if PUBLIC_MODE:
    trusted_hosts.append(".onrender.com")
trusted_hosts.extend(host.strip() for host in os.environ.get("SENTINELAI_TRUSTED_HOSTS", "").split(",")
                     if host.strip())
app.config.update(MAX_CONTENT_LENGTH=16_384, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=PUBLIC_MODE,
                  TRUSTED_HOSTS=trusted_hosts)
if os.environ.get("SENTINELAI_PROXY_FIX") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SCAN_LABELS = {"website": "Website", "api": "API", "domain": "Domain", "ip": "IP Address", "access_lab": "Access-control lab"}
SCANNERS = {"website": scan_target, "api": scan_api, "domain": scan_domain, "ip": scan_ip}
VISIBLE_SCAN_LABELS = {key: value for key, value in SCAN_LABELS.items()
                       if not PUBLIC_MODE or key != "access_lab"}
app.jinja_env.globals["scan_labels"] = VISIBLE_SCAN_LABELS
app.jinja_env.globals["scan_types"] = {key: SCAN_LABELS[key] for key in SCANNERS}
app.jinja_env.globals["public_mode"] = PUBLIC_MODE

DB_PATH = Path(os.environ.get("SENTINELAI_DB_PATH", Path(__file__).parent / "sentinelai.db"))
_RATE_LOCK = Lock()
_RATE_BUCKETS = {}
_SCAN_SLOTS = BoundedSemaphore(4)
RATE_LIMIT_COUNT = 10
RATE_LIMIT_WINDOW_SECONDS = 600


def connect_db():
    return sqlite3.connect(DB_PATH, timeout=10)


def current_owner_token():
    if not PUBLIC_MODE:
        return None
    if "owner_token" not in session:
        session["owner_token"] = secrets.token_urlsafe(24)
    return session["owner_token"]


def scan_rate_allowed(client_address):
    if not PUBLIC_MODE:
        return True
    now = datetime.now(timezone.utc).timestamp()
    with _RATE_LOCK:
        recent = deque(timestamp for timestamp in _RATE_BUCKETS.get(client_address, ())
                       if now - timestamp < RATE_LIMIT_WINDOW_SECONDS)
        if len(recent) >= RATE_LIMIT_COUNT:
            _RATE_BUCKETS[client_address] = recent
            return False
        recent.append(now)
        _RATE_BUCKETS[client_address] = recent
        if len(_RATE_BUCKETS) > 5_000:
            stale = [key for key, timestamps in _RATE_BUCKETS.items()
                     if not timestamps or now - timestamps[-1] >= RATE_LIMIT_WINDOW_SECONDS]
            for key in stale[:1_000]:
                _RATE_BUCKETS.pop(key, None)
        return True


@app.context_processor
def csrf_context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


def origin_matches_request(origin):
    """Compare browser Origin with the externally visible request origin."""
    parsed = urlsplit(origin)
    expected_scheme = "https" if PUBLIC_MODE else request.scheme
    request_authority = urlsplit("//" + request.host)
    if parsed.scheme != expected_scheme or not parsed.hostname or not request_authority.hostname:
        return False
    try:
        origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        request_port = request_authority.port or (443 if expected_scheme == "https" else 80)
    except ValueError:
        return False
    return parsed.hostname.casefold() == request_authority.hostname.casefold() and origin_port == request_port


@app.before_request
def protect_submissions():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected.encode(), supplied.encode()):
            abort(400, description="The form expired or could not be verified. Reload the page and try again.")
        origin = request.headers.get("Origin")
        if origin and not origin_matches_request(origin):
            app.logger.warning(
                "Rejected POST origin=%r scheme=%r host=%r forwarded_host=%r forwarded_proto=%r",
                origin, request.scheme, request.host,
                request.headers.get("X-Forwarded-Host"), request.headers.get("X-Forwarded-Proto"),
            )
            abort(403, description="Cross-origin submissions are not allowed.")
        if request.path == "/scan" and not scan_rate_allowed(request.remote_addr or "unknown"):
            abort(429, description="Scan limit reached. Try again in a few minutes.")


@app.after_request
def protect_local_pages(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'"
    )
    if PUBLIC_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            findings_json TEXT NOT NULL
        )
    """)
    columns = {row[1] for row in cur.execute("PRAGMA table_info(scans)")}
    if "scan_type" not in columns:
        cur.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'website'")
    if "result_json" not in columns:
        cur.execute("ALTER TABLE scans ADD COLUMN result_json TEXT")
    if "owner_token" not in columns:
        cur.execute("ALTER TABLE scans ADD COLUMN owner_token TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner_id ON scans(owner_token, id)")
    conn.commit()
    conn.close()


def save_scan(result, owner_token=None):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, scanned_at, score, findings_json, scan_type, result_json, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            result["target"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result["score"] if result["score"] is not None else 0,
            json.dumps(result["findings"]),
            result.get("scan_type", "website"),
            json.dumps(result),
            owner_token,
        ),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_history(limit=50, scan_type="", query="", owner_token=None):
    conn = connect_db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    select = "SELECT id, target, scanned_at, score, scan_type, result_json FROM scans"
    order = " ORDER BY id DESC LIMIT ?"
    if owner_token is not None and scan_type and query:
        rows = cur.execute(select + " WHERE owner_token = ? AND scan_type = ? AND instr(lower(target), lower(?)) > 0" + order,
                           (owner_token, scan_type, query, limit)).fetchall()
    elif owner_token is not None and scan_type:
        rows = cur.execute(select + " WHERE owner_token = ? AND scan_type = ?" + order,
                           (owner_token, scan_type, limit)).fetchall()
    elif owner_token is not None and query:
        rows = cur.execute(select + " WHERE owner_token = ? AND instr(lower(target), lower(?)) > 0" + order,
                           (owner_token, query, limit)).fetchall()
    elif owner_token is not None:
        rows = cur.execute(select + " WHERE owner_token = ?" + order,
                           (owner_token, limit)).fetchall()
    elif scan_type and query:
        rows = cur.execute(select + " WHERE scan_type = ? AND instr(lower(target), lower(?)) > 0" + order,
                           (scan_type, query, limit)).fetchall()
    elif scan_type:
        rows = cur.execute(select + " WHERE scan_type = ?" + order,
                           (scan_type, limit)).fetchall()
    elif query:
        rows = cur.execute(select + " WHERE instr(lower(target), lower(?)) > 0" + order,
                           (query, limit)).fetchall()
    else:
        rows = cur.execute(select + order, (limit,)).fetchall()
    conn.close()
    return rows


def dashboard(selected_type="website", target="", filter_type="", query=""):
    owner_token = current_owner_token()
    with closing(connect_db()) as conn:
        if owner_token is None:
            counts = dict(conn.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type"))
        else:
            counts = dict(conn.execute(
                "SELECT scan_type, COUNT(*) FROM scans WHERE owner_token = ? GROUP BY scan_type",
                (owner_token,)))
    return render_template("index.html", history=get_history(scan_type=filter_type, query=query,
                                                            owner_token=owner_token),
                           selected_type=selected_type, target=target, filter_type=filter_type,
                           query=query, counts=counts, total_scans=sum(counts.values()))


@app.route("/", methods=["GET"])
def index():
    filter_type = request.args.get("type", "")
    query = request.args.get("q", "").strip()[:200]
    if filter_type and filter_type not in VISIBLE_SCAN_LABELS:
        abort(400, description="Unknown scan type filter.")
    return dashboard(filter_type=filter_type, query=query)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "scanner_version": SCANNER_VERSION}


@app.get("/project")
def project_page():
    return render_template("project.html", scanner_version=SCANNER_VERSION)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not target:
        flash("Please enter a target.")
        return redirect(url_for("index"))

    if PUBLIC_MODE and request.form.get("authorized") != "on":
        flash("Confirm that you own the target or have explicit permission to assess it.")
        return dashboard(target=target), 400

    scan_type = request.form.get("scan_type", "website")
    if scan_type not in SCANNERS:
        flash("Choose Website, API, Domain or IP Address.")
        return redirect(url_for("index"))
    slot_acquired = not PUBLIC_MODE or _SCAN_SLOTS.acquire(blocking=False)
    if not slot_acquired:
        abort(503, description="The scanner is busy. Try again shortly.")
    try:
        started = monotonic()
        result = (scan_ip(target, reverse_dns=request.form.get("reverse_dns") == "on")
                  if scan_type == "ip" else SCANNERS[scan_type](target))
        result["scan_type"] = scan_type
        result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result["duration_ms"] = round((monotonic() - started) * 1000)
        result["scanner_version"] = SCANNER_VERSION
        scan_id = save_scan(result, owner_token=current_owner_token())
        return redirect(url_for("scan_detail", scan_id=scan_id), code=303)
    except ValueError as exc:
        flash(str(exc))
        return dashboard(selected_type=scan_type, target=target if scan_type in ("domain", "ip") else ""), 400
    except Exception:
        flash("The assessment could not be completed. Check your target and connection, then try again.")
        return dashboard(selected_type=scan_type), 500
    finally:
        if PUBLIC_MODE:
            _SCAN_SLOTS.release()


@app.get("/lab")
def lab_index():
    if PUBLIC_MODE:
        abort(404)
    return render_template("lab.html")


@app.post("/lab/run")
def lab_run():
    if PUBLIC_MODE:
        abort(404)
    try:
        started = monotonic()
        result = run_access_lab()
        result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result["duration_ms"] = round((monotonic() - started) * 1000)
        result["scanner_version"] = SCANNER_VERSION
        return redirect(url_for("scan_detail", scan_id=save_scan(result)), code=303)
    except ValueError as exc:
        flash(str(exc))
        return render_template("lab.html"), 400
    except Exception:
        flash("The local training run could not complete. No result was saved. Check whether this environment allows a loopback server.")
        return render_template("lab.html"), 500


def load_scan(scan_id, owner_token=None):
    with closing(connect_db()) as conn:
        if owner_token is None:
            row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        else:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE id = ? AND owner_token = ?",
                (scan_id, owner_token)).fetchone()
    if not row or not row[0]:
        abort(404, description="Detailed results are available for scans made after the API upgrade.")
    return json.loads(row[0])


@app.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    return render_template("results.html", result=load_scan(scan_id, current_owner_token()), scan_id=scan_id)


@app.get("/scans/<int:scan_id>/export/<format_name>")
def export_scan(scan_id, format_name):
    if format_name not in ("json", "md"):
        abort(404)
    result = load_scan(scan_id, current_owner_token())
    if format_name == "json":
        content, mime = json.dumps(result, ensure_ascii=False, indent=2), "application/json"
    else:
        content, mime = markdown_report(result, scan_id), "text/markdown"
    return Response(content, mimetype=mime, headers={
        "Content-Disposition": f'attachment; filename="sentinelai-assessment-{scan_id}.{format_name}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


init_db()

if __name__ == "__main__":
    from waitress import serve

    port = int(os.environ.get("SENTINELAI_PORT", "5000"))
    print(f"SentinelAI is available at http://127.0.0.1:{port}")
    serve(app, host="127.0.0.1", port=port, threads=4,
          channel_timeout=35, clear_untrusted_proxy_headers=True)
