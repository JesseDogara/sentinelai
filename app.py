from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response, session
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

app = Flask(__name__)
app.secret_key = os.environ.get("SENTINELAI_SECRET_KEY") or secrets.token_hex(32)
SCANNER_VERSION = "0.4.0"
app.config.update(MAX_CONTENT_LENGTH=16_384, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_HTTPONLY=True, TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"])
SCAN_LABELS = {"website": "Website", "api": "API", "domain": "Domain", "ip": "IP Address", "access_lab": "Access-control lab"}
SCANNERS = {"website": scan_target, "api": scan_api, "domain": scan_domain, "ip": scan_ip}
app.jinja_env.globals["scan_labels"] = SCAN_LABELS
app.jinja_env.globals["scan_types"] = {key: SCAN_LABELS[key] for key in SCANNERS}

DB_PATH = Path(__file__).parent / "sentinelai.db"


@app.context_processor
def csrf_context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


@app.before_request
def protect_submissions():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected.encode(), supplied.encode()):
            abort(400, description="The form expired or could not be verified. Reload the page and try again.")
        origin = request.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.scheme != request.scheme or parsed.netloc != request.host:
                abort(403, description="Cross-origin submissions are not allowed.")


@app.after_request
def protect_local_pages(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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
    conn.commit()
    conn.close()


def save_scan(result):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, scanned_at, score, findings_json, scan_type, result_json) VALUES (?, ?, ?, ?, ?, ?)",
        (
            result["target"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result["score"] if result["score"] is not None else 0,
            json.dumps(result["findings"]),
            result.get("scan_type", "website"),
            json.dumps(result),
        ),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_history(limit=50, scan_type="", query=""):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    clauses, parameters = [], []
    if scan_type:
        clauses.append("scan_type = ?")
        parameters.append(scan_type)
    if query:
        clauses.append("instr(lower(target), lower(?)) > 0")
        parameters.append(query)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = cur.execute(
        "SELECT id, target, scanned_at, score, scan_type, result_json FROM scans" + where + " ORDER BY id DESC LIMIT ?",
        (*parameters, limit),
    ).fetchall()
    conn.close()
    return rows


def dashboard(selected_type="website", target="", filter_type="", query=""):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        counts = dict(conn.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type"))
    return render_template("index.html", history=get_history(scan_type=filter_type, query=query),
                           selected_type=selected_type, target=target, filter_type=filter_type,
                           query=query, counts=counts, total_scans=sum(counts.values()))


@app.route("/", methods=["GET"])
def index():
    filter_type = request.args.get("type", "")
    query = request.args.get("q", "").strip()[:200]
    if filter_type and filter_type not in SCAN_LABELS:
        abort(400, description="Unknown scan type filter.")
    return dashboard(filter_type=filter_type, query=query)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not target:
        flash("Please enter a target.")
        return redirect(url_for("index"))

    scan_type = request.form.get("scan_type", "website")
    if scan_type not in SCANNERS:
        flash("Choose Website, API, Domain or IP Address.")
        return redirect(url_for("index"))
    try:
        started = monotonic()
        result = (scan_ip(target, reverse_dns=request.form.get("reverse_dns") == "on")
                  if scan_type == "ip" else SCANNERS[scan_type](target))
        result["scan_type"] = scan_type
        result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result["duration_ms"] = round((monotonic() - started) * 1000)
        result["scanner_version"] = SCANNER_VERSION
        scan_id = save_scan(result)
        return redirect(url_for("scan_detail", scan_id=scan_id), code=303)
    except ValueError as exc:
        flash(str(exc))
        return dashboard(selected_type=scan_type, target=target if scan_type in ("domain", "ip") else ""), 400
    except Exception:
        flash("The assessment could not be completed. Check your target and connection, then try again.")
        return dashboard(selected_type=scan_type), 500


@app.get("/lab")
def lab_index():
    return render_template("lab.html")


@app.post("/lab/run")
def lab_run():
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


def load_scan(scan_id):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row or not row[0]:
        abort(404, description="Detailed results are available for scans made after the API upgrade.")
    return json.loads(row[0])


@app.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    return render_template("results.html", result=load_scan(scan_id), scan_id=scan_id)


@app.get("/scans/<int:scan_id>/export/<format_name>")
def export_scan(scan_id, format_name):
    if format_name not in ("json", "md"):
        abort(404)
    result = load_scan(scan_id)
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
    app.run(host="127.0.0.1", port=int(os.environ.get("SENTINELAI_PORT", "5000")),
            debug=os.environ.get("SENTINELAI_DEBUG") == "1")
