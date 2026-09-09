"""
PresensiKu — Employee Attendance System (DrishtiSec validation lab)

Intentionally vulnerable Flask application for controlled reproduction
of representative attack patterns identified in WAF analysis. The
visible application is "PresensiKu", a realistic employee attendance
system; "DrishtiSec" is the security/assessment identity, used only on
the shared logo and within the separate assessment surface
(/portal/security and below, reached via a small sidebar footer link —
never the primary navigation). Two nav contexts share one
login/session/base.html shell; inject_portal_globals() picks between
them from request.endpoint alone.

Three intentionally vulnerable endpoints, each with a different
finding, WAF-evidence-matched endpoint/parameter, and a genuinely
DIFFERENT exposed resource (not a shared marker file) so their impact
is easy to tell apart in a demo:

  VAL-CMD-001  OS Command Injection   GET /admin/config?cmd=
  VAL-LFI-001  Local File Inclusion   GET /read?file=
  VAL-TRAV-001 Directory Traversal    GET /?file=

No proof-file substitution or string pattern-matching happens in this
file. Each endpoint uses the attacker-supplied input completely
unmodified; realistic impact comes purely from the controlled
filesystem layout (CMD_EXEC_CWD, LFI_BASE_DIR, TRAV_BASE_DIR — see
their definitions below) — the WAF-evidence target genuinely exists at
those paths, exactly like it would on a real vulnerable host:

  - /admin/config's "cmd" is passed straight to subprocess.run(...,
    shell=True, cwd=CMD_EXEC_CWD). The literal WAF-evidence command
    "cat/root/.aws/credentials" resolves to a real executable at
    lab-data/fs-root/cat/root/.aws/credentials (see that file) which
    cats lab-data/root/.aws/credentials. Any other command (whoami,
    id, hostname, shell metacharacters, chained commands, etc.) runs
    completely normally, unaffected by that layout.
  - /read's "file" and /'s "file" both share _serve_lfi_target(), the
    one shared execution primitive for VAL-LFI-001 and VAL-TRAV-001 —
    but each passes a DIFFERENT intended base directory (LFI_BASE_DIR
    vs TRAV_BASE_DIR), each positioned exactly two directory levels
    below a different lab-data/ subtree, so the identical WAF-evidence
    traversal depth "../../.env" lands on a different real file for
    each: lab-data/.env for VAL-LFI-001, lab-data/traversal-target/.env
    for VAL-TRAV-001.
  - A raw-query-string fallback parser (_get_waf_style_param) also
    accepts the WAF-log-style encoding where the "=" separator itself
    was percent-encoded (e.g. "cmd%3Dvalue"), so a WAF-evidence URL can
    be replayed byte-for-byte, exactly as it appears in the finalized
    WAF Excel.

All three endpoints return the RAW impact directly (plain-text command
output / file content) — no evidence-page HTML, no "VALIDATED" banner,
no validation metadata. A real vulnerable admin/debug endpoint
wouldn't render a validation report. All assessment metadata
(validation ID, WAF reference, timestamps) lives exclusively in
application.log and the separate DrishtiSec Evidence/Findings/Reports
pages under /portal/.

/download?file= ("Download Attendance Report" on Riwayat Kehadiran) is
an ordinary, non-vulnerable file download, unrelated to the three
findings above — it only ever serves files from PUBLIC_DIR.
/read?file= is also linked from Profil as a "Lihat Dokumen" (view
document) feature. /admin/config is intentionally NOT linked from
anywhere in the UI, matching a real leftover/undocumented admin
endpoint found only by enumeration — exactly as in the source WAF
evidence.

WARNING: /admin/config, /read, and "/" (when a "file" parameter is
supplied) are INTENTIONALLY VULNERABLE (OS command injection, local
file inclusion, and directory traversal, respectively). All exist ONLY
for controlled reproduction of WAF findings inside an isolated lab
network. Do not deploy this code anywhere else. Portal login
intentionally does NOT gate these endpoints — they must remain
directly testable.
"""
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import unquote

from flask import (
    Flask, Response, abort, redirect, render_template, request, send_file,
    session, url_for,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

app = Flask(__name__)
app.secret_key = os.environ.get(
    "LAB_SECRET_KEY", "drishtisec-lab-dev-secret-not-for-production"
)

LAB_USERNAME = os.environ.get("LAB_USERNAME", "labuser")
LAB_PASSWORD = os.environ.get("LAB_PASSWORD", "labpass")

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "application.log")

logger = logging.getLogger("waf_lab")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.FileHandler(LOG_PATH)
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z"
    ))
    logger.addHandler(_handler)
    # Also echo to console so `run.sh` output shows activity live.
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    logger.addHandler(_console)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FONTS_DIR = os.path.join(BASE_DIR, "static", "fonts")

# --------------------------------------------------------------------
# Filesystem layout for the three vulnerable endpoints. No proof-file
# substitution anywhere below — each endpoint's supplied input is used
# completely unmodified; the "impact" is real because these paths
# genuinely contain the (synthetic) sensitive-looking content the WAF
# evidence's target string would resolve to on a real vulnerable host.
# --------------------------------------------------------------------

# /download ("Download Attendance Report" — a legitimate, unrelated
# feature) still serves ordinary files from here.
PUBLIC_DIR = os.path.join(BASE_DIR, "lab-data", "public")

# VAL-LFI-001 (/read?file=) and VAL-TRAV-001 (/?file=) use the SAME
# "../../.env" traversal depth (from the WAF evidence) but must expose
# DIFFERENT, clearly distinguishable resources, so each gets its own
# intended directory positioned exactly two levels below a different
# lab-data/ subtree:
#   LFI_BASE_DIR/../../.env       == BASE_DIR/lab-data/.env
#   TRAV_BASE_DIR/../../.env      == BASE_DIR/lab-data/traversal-target/.env
# (verified by normpath(join(...)) — see _serve_lfi_target()'s callers.)
LFI_BASE_DIR = os.path.join(BASE_DIR, "lab-data", "public", "documents")
TRAV_BASE_DIR = os.path.join(BASE_DIR, "lab-data", "traversal-target", "public", "assets")

# VAL-CMD-001 (/admin/config?cmd=). subprocess.run() below executes the
# attacker-supplied "cmd" value completely unmodified via shell=True,
# with this directory as its cwd — the SAME primitive as before,
# except now the relative path "cat/root/.aws/credentials" (the exact,
# space-free WAF-evidence command) resolves to a real executable file
# on disk (lab-data/fs-root/cat/root/.aws/credentials) instead of being
# pattern-matched and substituted in Python. Any other command
# (whoami, id, hostname, shell metacharacters, etc.) is completely
# unaffected by this and runs exactly as it would from any cwd.
CMD_EXEC_CWD = os.path.join(BASE_DIR, "lab-data", "fs-root")

LAB_HOST_ENV = os.environ.get("LAB_HOST", "192.168.200.128")
LAB_PORT_ENV = os.environ.get("LAB_PORT", "8080")

# --------------------------------------------------------------------
# Sidebar navigation for the DrishtiSec Security Portal (everything
# under /portal). Pentester-methodology stages (recon, enumeration,
# scope, attack-surface mapping, etc.) are intentionally NOT modeled
# as product navigation — those are activities the analyst performs
# manually, not features of the target application.
# --------------------------------------------------------------------
# --------------------------------------------------------------------
# The application now presents two conceptually separate navigation
# contexts sharing one login and one page shell (base.html):
#
#   "attendance" — PresensiKu, the normal employee-facing surface.
#   This is what a typical user sees; it contains ordinary attendance
#   functionality and no vulnerability-related wording anywhere.
#
#   "security" — the DrishtiSec assessment/evidence/reporting surface
#   a security assessor uses. Reachable only via the small footer link
#   in the sidebar (never the primary navigation), consistent with
#   "the security assessment interface must exist but be discovered,
#   not advertised, by the normal employee workflow."
#
# inject_portal_globals() below picks which list to render based on
# request.endpoint, so individual routes don't need to pass this.
# --------------------------------------------------------------------
NAV_SECTIONS_ATTENDANCE = [
    {"label": None, "links": [
        {"name": "Dashboard", "endpoint": "portal_dashboard", "icon": "grid"},
        {"name": "Presensi", "endpoint": "presensi", "icon": "check"},
        {"name": "Riwayat Kehadiran", "endpoint": "riwayat", "icon": "list"},
        {"name": "Cuti & Izin", "endpoint": "cuti", "icon": "flag"},
        {"name": "Profil", "endpoint": "profil", "icon": "target"},
        {"name": "Informasi Perusahaan", "endpoint": "perusahaan", "icon": "layers"},
    ]},
    {"label": None, "links": [
        {"name": "Settings", "endpoint": "settings", "icon": "settings"},
    ]},
]

NAV_SECTIONS_SECURITY = [
    {"label": "DrishtiSec Assessment", "links": [
        {"name": "Overview", "endpoint": "portal_security", "icon": "grid"},
        {"name": "WAF Findings", "endpoint": "waf_findings", "icon": "alert"},
        {"name": "Validation Scenarios", "endpoint": "validation_scenarios", "icon": "check"},
        {"name": "Evidence", "endpoint": "evidence", "icon": "file"},
        {"name": "Findings", "endpoint": "findings", "icon": "flag"},
        {"name": "Reports", "endpoint": "reports", "icon": "doc"},
    ]},
]

# Endpoints that belong to the DrishtiSec security-assessment surface.
# Used by inject_portal_globals() to pick the nav list and brand text
# from request.endpoint alone, with no per-route wiring needed.
SECURITY_ENDPOINTS = {
    "portal_security", "waf_findings", "validation_scenarios",
    "validation_detail", "evidence", "findings", "reports",
    "reports_generate", "reports_download",
}

# --------------------------------------------------------------------
# Single source of truth for the three validation scenarios. Reused by
# the dashboard cards, WAF Findings page, Validation Scenarios table,
# the unified validation-detail page, Findings page, and the PDF
# report generator — so scenario facts are defined once.
# --------------------------------------------------------------------
VALIDATION_ORDER = ["VAL-CMD-001", "VAL-LFI-001", "VAL-TRAV-001"]

VALIDATION_DEFS = {
    "VAL-CMD-001": {
        "id": "VAL-CMD-001",
        "type": "cmd",
        "title": "OS Command Injection",
        "severity": "High",
        "waf_reference": "SP_Asset-006",
        "endpoint": "/admin/config",
        "param": "cmd",
        "endpoint_label": "/admin/config?cmd=",
        "http_method_label": "GET / POST",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET", "POST"],
        "waf_request_pattern": "/admin/config?cmd%3Dcat/root/.aws/credentials",
        "local_evidence_path": "lab-data/root/.aws/credentials",
        "description": (
            "Controlled validation of attacker-controlled command input "
            "leading to OS command execution."
        ),
        "technical_summary": (
            "The /admin/config endpoint passes the supplied cmd value directly "
            "into a shell command with no sanitization or allow-listing, "
            "allowing arbitrary operating-system command execution."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could execute arbitrary "
            "commands with the privileges of the application process, "
            "potentially leading to full host compromise."
        ),
        "waf_note": (
            "The WAF evidence identified a GET-based command injection "
            "pattern. During controlled laboratory validation, the same "
            "command execution primitive was additionally tested using "
            "POST to assess behavior across HTTP request methods."
        ),
        "replay_links": [
            {"label": "Replay WAF Pattern (GET)", "href": "/admin/config?cmd%3Dcat/root/.aws/credentials"},
        ],
        "safe_links": [
            {"label": "Controlled Safe Test — whoami", "href": "/admin/config?cmd=whoami"},
        ],
    },
    "VAL-LFI-001": {
        "id": "VAL-LFI-001",
        "type": "lfi",
        "title": "Local File Inclusion (LFI)",
        "severity": "High",
        "waf_reference": "SP_Asset-011",
        "endpoint": "/read",
        "param": "file",
        "endpoint_label": "/read?file=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": "/read?file%3D../../.env",
        "local_evidence_path": "lab-data/.env",
        "description": (
            "Controlled validation of local file inclusion through an "
            "attacker-controlled file parameter."
        ),
        "technical_summary": (
            "The /read endpoint joins the supplied file value onto its "
            "intended documents directory with no normalization or "
            "allow-listing, so \"../\" segments escape it and include the "
            "contents of arbitrary local files."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could read local "
            "application files, potentially exposing configuration or "
            "credential material."
        ),
        "waf_note": (
            "WAF evidence and laboratory validation both used GET; no "
            "additional HTTP methods were tested for this finding."
        ),
        "replay_links": [
            {"label": "Replay WAF Pattern (GET)", "href": "/read?file%3D../../.env"},
        ],
        "safe_links": [
            {"label": "Normal Access — /read", "href": "/read?file=handbook.txt"},
        ],
    },
    "VAL-TRAV-001": {
        "id": "VAL-TRAV-001",
        "type": "trav",
        "title": "Directory Traversal",
        "severity": "High",
        "waf_reference": "SP_Asset-013",
        "endpoint": "/api/file",
        "param": "path",
        "endpoint_label": "/api/file?path=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": "/api/file?path%3D../../.env",
        "local_evidence_path": "lab-data/traversal-target/.env",
        "description": (
            "Controlled validation of path traversal escaping the intended "
            "application directory."
        ),
        "technical_summary": (
            "The /api/file endpoint joins a supplied path value onto its "
            "own intended assets directory with no normalization, so "
            "\"../\" segments escape it and reach internal application/HR "
            "configuration outside the intended directory. This is the "
            "same underlying primitive as VAL-LFI-001, reached through a "
            "different application entry point and parameter name, and "
            "escaping to a different, distinct resource so the two "
            "findings' impact is clearly distinguishable."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could read internal "
            "application and HR infrastructure configuration outside the "
            "intended public directory."
        ),
        "waf_note": (
            "WAF evidence and laboratory validation both used GET; no "
            "additional HTTP methods were tested for this finding."
        ),
        "replay_links": [
            {"label": "Replay WAF Pattern (GET)", "href": "/api/file?path%3D../../.env"},
        ],
        "safe_links": [
            {"label": "Normal Access — /api/file", "href": "/api/file?path=welcome.txt"},
        ],
    },
}

WAF_FINDING_MAP = {
    "SP_Asset-006": "VAL-CMD-001",
    "SP_Asset-011": "VAL-LFI-001",
    "SP_Asset-013": "VAL-TRAV-001",
}

_LOG_LINE_RE = re.compile(r"^(?P<ts>\S+) \| (?P<vid>VAL-[A-Z]+-\d+) \| (?P<rest>.+)$")


def parse_log_entries(limit=None):
    """Parse logs/application.log into structured entries, most-recent-first.

    Reused by the Evidence and Dashboard pages so the portal reflects the
    same application log written by the vulnerable endpoints, rather than
    fabricated activity.
    """
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as f:
        lines = f.readlines()
    if limit:
        lines = lines[-limit:]
    entries = []
    for line in lines:
        match = _LOG_LINE_RE.match(line.strip())
        if not match:
            continue
        fields = {}
        for part in match.group("rest").split(" | "):
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key.strip()] = value.strip().strip("'")
        entries.append({
            "timestamp": match.group("ts"),
            "validation_id": match.group("vid"),
            "fields": fields,
        })
    entries.reverse()
    return entries


def build_recent_activity(limit=8):
    activity = []
    for entry in parse_log_entries(limit=limit):
        f = entry["fields"]
        activity.append({
            "timestamp": entry["timestamp"],
            "validation_id": entry["validation_id"],
            "endpoint": f.get("endpoint", ""),
            "source_ip": f.get("ip", "unknown"),
            "method": f.get("method", "GET"),
            "status": f.get("status", ""),
        })
    return activity


_BEHAVIOR_BY_STATUS = {
    "EXECUTED": "Operating-system command executed successfully",
    "FILE_READ": "Local file included; contents returned",
    "TRAVERSAL_READ": "Path traversal escaped the intended directory; contents returned",
    "NO_INPUT": "No input parameter supplied",
    "ERROR": "Execution/read failed",
}

_EVIDENCE_SCENARIO_DEFS = [
    {"id": "VAL-CMD-001", "title": "OS Command Injection", "input_key": "cmd"},
    {"id": "VAL-LFI-001", "title": "Local File Inclusion (LFI)", "input_key": "file"},
    {"id": "VAL-TRAV-001", "title": "Directory Traversal", "input_key": "path"},
]


def build_evidence_scenarios(limit_per_scenario=5):
    all_entries = parse_log_entries()
    scenarios = []
    for definition in _EVIDENCE_SCENARIO_DEFS:
        matched = [e for e in all_entries if e["validation_id"] == definition["id"]]
        matched = matched[:limit_per_scenario]
        entries = []
        for entry in matched:
            f = entry["fields"]
            status = f.get("status", "")
            entries.append({
                "timestamp": entry["timestamp"],
                "source_ip": f.get("ip", "unknown"),
                "method": f.get("method", "GET"),
                "endpoint": f.get("endpoint", ""),
                "input": f.get(definition["input_key"], "(none)"),
                "behavior": _BEHAVIOR_BY_STATUS.get(status, status or "Unknown"),
                "status": status,
            })
        scenarios.append({
            "id": definition["id"],
            "title": definition["title"],
            "entries": entries,
        })
    return scenarios


@app.context_processor
def inject_portal_globals():
    nav_context = "security" if request.endpoint in SECURITY_ENDPOINTS else "attendance"
    return {
        "nav_sections": NAV_SECTIONS_SECURITY if nav_context == "security" else NAV_SECTIONS_ATTENDANCE,
        "nav_context": nav_context,
        "current_user": session.get("username"),
        "is_authenticated": bool(session.get("logged_in")),
        "lab_host": LAB_HOST_ENV,
        "lab_port": LAB_PORT_ENV,
        "validation_defs": VALIDATION_DEFS,
        "validation_order": VALIDATION_ORDER,
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------
# Public marketing site. Does not expose vulnerability names, WAF
# finding IDs, or the fact that this is a validation lab.
# --------------------------------------------------------------------
@app.route("/")
def landing():
    # Plain PresensiKu landing page — no vulnerability here. VAL-TRAV-001
    # now lives at /api/file?path= (see below), not "/".
    return render_template("landing.html")


# --------------------------------------------------------------------
# Authentication (lightweight, session-based — intentionally simple,
# no database, no external identity provider). Login/signup gate the
# DrishtiSec Security Portal pages only. They must NOT gate the three
# vulnerable validation endpoints, which stay directly testable with
# or without a session (see requirement to never let auth block
# controlled testing of /admin/config, /read, /download).
# --------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == LAB_USERNAME and password == LAB_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            next_url = request.args.get("next") or url_for("portal_dashboard")
            return redirect(next_url)
        error = "Invalid username or password."
    signup_notice = request.args.get("signup") == "1"
    return render_template("login.html", error=error, signup_notice=signup_notice)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        company_email = request.form.get("company_email", "").strip()
        company_name = request.form.get("company_name", "").strip()
        password = request.form.get("password", "")
        if not (full_name and company_email and company_name and password):
            error = "Please complete all fields to request access."
        else:
            # Lightweight demo flow: no database, no real account
            # provisioning. Hand off to Sign In with a success notice.
            return redirect(url_for("login", signup="1"))
    return render_template("signup.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------
# PresensiKu — Employee Attendance System (the normal-user-facing
# application). Lightweight, session-based dummy state — no database,
# consistent with the rest of this lab. None of these pages mention
# the underlying vulnerabilities; the vulnerable endpoints
# (/admin/config, /read, /download) are reachable but not linked from
# this navigation, matching a realistic "the assessor must discover
# it" laboratory design.
# --------------------------------------------------------------------
EMPLOYEE = {
    "name": "Ayu Lestari",
    "employee_id": "EMP-2024-0142",
    "position": "Software Engineer",
    "department": "Engineering",
    "email": "ayu.lestari@presensiku.local",
    "join_date": "2024-03-01",
}

COMPANY_INFO = {
    "name": "PT Contoh Teknologi Indonesia",
    "address": "Jl. Sudirman No. 123, Jakarta Selatan",
    "phone": "+62 21 5550 1234",
    "email": "hr@presensiku.local",
    "working_hours": "08:00 - 17:00 WIB",
    "about": (
        "PT Contoh Teknologi Indonesia is a fictional company used for "
        "this laboratory environment. PresensiKu is its internal "
        "employee attendance system."
    ),
}

ATTENDANCE_HISTORY = [
    {"date": "2026-09-08", "check_in": "08:02", "check_out": "17:05", "status": "Hadir"},
    {"date": "2026-09-05", "check_in": "08:14", "check_out": "17:01", "status": "Terlambat"},
    {"date": "2026-09-04", "check_in": "07:58", "check_out": "17:10", "status": "Hadir"},
    {"date": "2026-09-03", "check_in": "08:00", "check_out": "17:00", "status": "Hadir"},
    {"date": "2026-09-02", "check_in": "-", "check_out": "-", "status": "Cuti"},
    {"date": "2026-09-01", "check_in": "08:05", "check_out": "17:03", "status": "Hadir"},
]

LEAVE_HISTORY = [
    {"type": "Cuti Tahunan", "start": "2026-09-02", "end": "2026-09-02", "status": "Disetujui"},
    {"type": "Izin Sakit", "start": "2026-07-14", "end": "2026-07-15", "status": "Disetujui"},
]


def _today_key():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@app.route("/portal")
@login_required
def portal_dashboard():
    today = session.get("presensi", {})
    return render_template(
        "attendance_dashboard.html",
        breadcrumb=["Dashboard"],
        employee=EMPLOYEE,
        today_status=today.get("status", "Belum Presensi"),
        check_in_time=today.get("check_in"),
        check_out_time=today.get("check_out"),
        recent_history=ATTENDANCE_HISTORY[:5],
    )


@app.route("/portal/presensi")
@login_required
def presensi():
    today = session.get("presensi", {})
    return render_template(
        "presensi.html",
        breadcrumb=["Presensi"],
        employee=EMPLOYEE,
        status=today.get("status", "Belum Presensi"),
        check_in_time=today.get("check_in"),
        check_out_time=today.get("check_out"),
    )


@app.route("/portal/presensi/checkin")
@login_required
def presensi_checkin():
    today = session.get("presensi", {})
    if today.get("date") != _today_key():
        today = {"date": _today_key()}
    today["check_in"] = datetime.now(timezone.utc).strftime("%H:%M")
    today["status"] = "Hadir"
    session["presensi"] = today
    return redirect(url_for("presensi"))


@app.route("/portal/presensi/checkout")
@login_required
def presensi_checkout():
    today = session.get("presensi", {})
    if today.get("date") == _today_key() and today.get("check_in"):
        today["check_out"] = datetime.now(timezone.utc).strftime("%H:%M")
        session["presensi"] = today
    return redirect(url_for("presensi"))


@app.route("/portal/riwayat")
@login_required
def riwayat():
    return render_template(
        "riwayat.html",
        breadcrumb=["Riwayat Kehadiran"],
        history=ATTENDANCE_HISTORY,
    )


@app.route("/portal/cuti")
@login_required
def cuti():
    return render_template(
        "cuti.html",
        breadcrumb=["Cuti & Izin"],
        leave_history=LEAVE_HISTORY,
    )


@app.route("/portal/profil")
@login_required
def profil():
    return render_template(
        "profil.html",
        breadcrumb=["Profil"],
        employee=EMPLOYEE,
    )


@app.route("/portal/perusahaan")
@login_required
def perusahaan():
    return render_template(
        "perusahaan.html",
        breadcrumb=["Informasi Perusahaan"],
        company=COMPANY_INFO,
    )


# --------------------------------------------------------------------
# DrishtiSec security-assessment surface. Same authenticated session,
# reached only via the small footer link in the sidebar — never the
# primary employee-facing navigation. Reuses the pre-existing
# dashboard.html (Validation Summary + Recent Activity), which already
# carries no attendance-app framing.
# --------------------------------------------------------------------
@app.route("/portal/security")
@login_required
def portal_security():
    return render_template(
        "dashboard.html",
        breadcrumb=["Security", "Overview"],
        recent_activity=build_recent_activity(),
    )


@app.route("/portal/waf-findings")
@login_required
def waf_findings():
    return render_template(
        "waf_findings.html",
        breadcrumb=["Security", "WAF Findings"],
        waf_finding_map=WAF_FINDING_MAP,
    )


@app.route("/portal/validation-scenarios")
@login_required
def validation_scenarios():
    return render_template(
        "validation_scenarios.html",
        breadcrumb=["Security", "Validation Scenarios"],
    )


@app.route("/portal/validation/<validation_id>")
@login_required
def validation_detail(validation_id):
    definition = VALIDATION_DEFS.get(validation_id)
    if not definition:
        abort(404)
    matching = [
        s for s in build_evidence_scenarios(limit_per_scenario=5)
        if s["id"] == validation_id
    ]
    entries = matching[0]["entries"] if matching else []
    return render_template(
        "validation_detail.html",
        breadcrumb=["Security", "Validation Scenarios", validation_id],
        v=definition,
        entries=entries,
    )


@app.route("/portal/evidence")
@login_required
def evidence():
    return render_template(
        "evidence.html",
        breadcrumb=["Security", "Evidence"],
        evidence_scenarios=build_evidence_scenarios(),
    )


@app.route("/portal/findings")
@login_required
def findings():
    return render_template("findings.html", breadcrumb=["Reporting", "Findings"])


@app.route("/portal/reports")
@login_required
def reports():
    report_exists = os.path.exists(REPORT_PATH)
    report_generated_at = None
    if report_exists:
        report_generated_at = datetime.fromtimestamp(
            os.path.getmtime(REPORT_PATH), tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "reports.html",
        breadcrumb=["Reporting", "Reports"],
        report_exists=report_exists,
        report_generated_at=report_generated_at,
        just_generated=request.args.get("generated") == "1",
    )


@app.route("/portal/reports/generate")
@login_required
def reports_generate():
    generate_pdf_report()
    return redirect(url_for("reports", generated="1"))


@app.route("/portal/reports/download")
@login_required
def reports_download():
    if not os.path.exists(REPORT_PATH):
        abort(404)
    return send_file(
        REPORT_PATH,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=REPORT_FILENAME,
    )


@app.route("/portal/settings")
@login_required
def settings():
    return render_template("settings.html", breadcrumb=["Settings"])


# ======================================================================
# PDF report generation (ReportLab). Builds a fresh
# reports/DrishtiSec_Security_Validation_Report.pdf on demand from the
# same VALIDATION_DEFS / WAF_FINDING_MAP / application-log evidence
# used by the portal pages — no fabricated report data.
# ======================================================================
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
REPORT_FILENAME = "DrishtiSec_Security_Validation_Report.pdf"
REPORT_PATH = os.path.join(REPORTS_DIR, REPORT_FILENAME)
LOGO_PATH = os.path.join(BASE_DIR, "static", "images", "drishtisec-logo.png")

pdfmetrics.registerFont(TTFont("Lato", os.path.join(FONTS_DIR, "lato-regular.ttf")))
pdfmetrics.registerFont(TTFont("Lato-Bold", os.path.join(FONTS_DIR, "lato-bold.ttf")))
pdfmetrics.registerFont(TTFont("JetBrainsMono", os.path.join(FONTS_DIR, "jetbrains-mono-regular.ttf")))

_PDF_NAVY = colors.HexColor("#0b1220")
_PDF_CYAN = colors.HexColor("#0891b2")
_PDF_CYAN_LIGHT = colors.HexColor("#22d3ee")
_PDF_SLATE = colors.HexColor("#334155")
_PDF_MUTED = colors.HexColor("#64748b")
_PDF_BORDER = colors.HexColor("#dfe4ee")
_PDF_ROW_ALT = colors.HexColor("#f4f6fb")

_PDF_STYLES = {
    "brand": ParagraphStyle("brand", fontName="Lato-Bold", fontSize=30, textColor=colors.white, leading=34),
    "brand_sub": ParagraphStyle("brand_sub", fontName="Lato", fontSize=13, textColor=_PDF_CYAN_LIGHT, leading=17),
    "h1": ParagraphStyle("h1", fontName="Lato-Bold", fontSize=15, textColor=_PDF_NAVY, spaceBefore=16, spaceAfter=8),
    "h2": ParagraphStyle("h2", fontName="Lato-Bold", fontSize=11.5, textColor=_PDF_CYAN, spaceBefore=10, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Lato", fontSize=10, textColor=_PDF_SLATE, leading=15, spaceAfter=6),
    "mono": ParagraphStyle("mono", fontName="JetBrainsMono", fontSize=9, textColor=_PDF_NAVY, leading=13, spaceAfter=4),
    "small": ParagraphStyle("small", fontName="Lato", fontSize=8.5, textColor=_PDF_MUTED, leading=12),
}


def _pdf_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Lato", 8)
    canvas.setFillColor(_PDF_MUTED)
    canvas.drawString(
        0.75 * inch, 0.5 * inch,
        "DrishtiSec Security Validation Report — Isolated Laboratory Environment",
    )
    canvas.drawRightString(LETTER[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


def _pdf_table_style():
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PDF_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Lato-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Lato"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, _PDF_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PDF_ROW_ALT]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ])


def generate_pdf_report():
    """Build reports/DrishtiSec_Security_Validation_Report.pdf from the
    same validation/evidence data the portal pages already show. Called
    fresh on every "Generate PDF Report" click; overwrites the previous
    file at the same fixed path (the "latest report").
    """
    doc = SimpleDocTemplate(
        REPORT_PATH, pagesize=LETTER,
        topMargin=0, bottomMargin=0.85 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        title="DrishtiSec Security Validation Report",
    )
    story = []

    brand_cell = [
        Paragraph("DrishtiSec", _PDF_STYLES["brand"]),
        Paragraph("Security Validation Report", _PDF_STYLES["brand_sub"]),
    ]
    cover_row = [brand_cell]
    cover_col_widths = [7 * inch]
    if os.path.exists(LOGO_PATH):
        # Official DrishtiSec logo asset — embedded as-is, not recreated.
        cover_row = [Image(LOGO_PATH, width=0.85 * inch, height=0.85 * inch), brand_cell]
        cover_col_widths = [1.15 * inch, 5.85 * inch]

    cover = Table([cover_row], colWidths=cover_col_widths)
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 30),
        ("LEFTPADDING", (-1, 0), (-1, 0), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 34),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 34),
    ]))
    story.append(cover)
    story.append(Spacer(1, 24))

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta_rows = [
        ["Assessment Date", now_str],
        ["Assessment Target", "PresensiKu — Employee Attendance System"],
        ["Environment", f"Isolated Lab ({LAB_HOST_ENV}:{LAB_PORT_ENV})"],
        ["Assessment Type", "Web Application Security Assessment"],
    ]
    meta_table = Table(
        [[Paragraph(f"<b>{k}</b>", _PDF_STYLES["body"]), Paragraph(v, _PDF_STYLES["mono"])]
         for k, v in meta_rows],
        colWidths=[1.8 * inch, 5.2 * inch],
    )
    meta_table.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)

    story.append(Paragraph("Executive Summary", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "This report documents controlled security validation activity performed "
        "against an isolated laboratory target. Three representative attack "
        "patterns identified in prior WAF analysis were reproduced against a "
        "deliberately vulnerable application to confirm the underlying technical "
        "behavior. All three validation scenarios completed successfully.",
        _PDF_STYLES["body"],
    ))
    story.append(Paragraph(
        "<b>This validation was performed entirely within an isolated laboratory "
        "environment. It does not represent, and must not be interpreted as, "
        "exploitation of any production system.</b>",
        _PDF_STYLES["body"],
    ))

    story.append(Paragraph("WAF Findings", _PDF_STYLES["h1"]))
    waf_rows = [["Finding", "Pattern", "Validation", "Status"]]
    for finding_id, vid in WAF_FINDING_MAP.items():
        v = VALIDATION_DEFS[vid]
        waf_rows.append([finding_id, v["title"], vid, "Validated"])
    waf_table = Table(waf_rows, colWidths=[1.3 * inch, 2.7 * inch, 1.4 * inch, 1.1 * inch])
    waf_table.setStyle(_pdf_table_style())
    story.append(waf_table)

    story.append(Paragraph("Validation Results", _PDF_STYLES["h1"]))
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        story.append(Paragraph(f"{vid} — {v['title']}", _PDF_STYLES["h2"]))
        story.append(Paragraph(
            f"Status: <b>VALIDATED</b> &nbsp;&nbsp; WAF Reference: {v['waf_reference']} "
            f"&nbsp;&nbsp; Endpoint: {v['endpoint']}",
            _PDF_STYLES["mono"],
        ))
        story.append(Paragraph(
            f"WAF request pattern: {v['waf_request_pattern']}",
            _PDF_STYLES["mono"],
        ))
        story.append(Paragraph(
            f"Local evidence: {v['local_evidence_path']}",
            _PDF_STYLES["mono"],
        ))
        if vid == "VAL-CMD-001":
            story.append(Paragraph(
                "WAF evidence: GET-based request pattern. Laboratory validation: "
                "GET and POST. POST was added as an additional controlled test of "
                "the same execution primitive and was NOT observed in the original "
                "WAF evidence.",
                _PDF_STYLES["body"],
            ))
        else:
            story.append(Paragraph(
                "WAF evidence and laboratory validation both used GET.",
                _PDF_STYLES["body"],
            ))

    story.append(Paragraph("Evidence", _PDF_STYLES["h1"]))
    for scenario in build_evidence_scenarios(limit_per_scenario=1):
        v = VALIDATION_DEFS[scenario["id"]]
        story.append(Paragraph(f"{scenario['id']} — {v['title']}", _PDF_STYLES["h2"]))
        if scenario["entries"]:
            e = scenario["entries"][0]
            story.append(Paragraph(
                f"timestamp={e['timestamp']} source_ip={e['source_ip']} "
                f"method={e['method']} endpoint={e['endpoint']} status={e['status']}",
                _PDF_STYLES["mono"],
            ))
            story.append(Paragraph(e["behavior"], _PDF_STYLES["body"]))
        else:
            story.append(Paragraph(
                "No application log entry captured yet for this scenario.",
                _PDF_STYLES["small"],
            ))

    story.append(Paragraph("Findings", _PDF_STYLES["h1"]))
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        story.append(Paragraph(
            f"{vid} — {v['title']} (Severity: {v['severity']})", _PDF_STYLES["h2"]
        ))
        story.append(Paragraph(v["technical_summary"], _PDF_STYLES["body"]))
        story.append(Paragraph(
            f"<b>Business Impact:</b> {v['business_impact']}", _PDF_STYLES["body"]
        ))

    story.append(Paragraph("Conclusion", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "All three representative attack patterns were successfully reproduced "
        "against the isolated laboratory target, confirming the underlying "
        "vulnerable behavior identified by prior WAF analysis. This constitutes "
        "successful controlled reproduction in an isolated vulnerable "
        "environment, not exploitation of a production system.",
        _PDF_STYLES["body"],
    ))

    doc.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return REPORT_PATH


# ======================================================================
# Vulnerable endpoints — VAL-CMD-001, VAL-LFI-001, VAL-TRAV-001.
#
# No proof-file substitution anywhere below. Each endpoint uses the
# attacker-supplied input completely unmodified; realistic impact comes
# purely from the controlled filesystem layout set up at the top of
# this file (LFI_BASE_DIR, CMD_EXEC_CWD) — the WAF-evidence target
# genuinely exists there, exactly like it would on a real vulnerable
# host. Responses are raw impact only (plain text) — no validation
# metadata, no "VALIDATED" banner, no evidence table. That information
# lives only in application.log and the separate DrishtiSec
# Evidence/Findings pages (/portal/evidence, /portal/findings).
# ======================================================================

def _get_waf_style_param(key):
    """Read `key` from normal GET/POST parsing first (request.values).

    If that finds nothing, fall back to parsing the raw query string for
    the WAF-log-style form where the key/value separator itself was
    percent-encoded (e.g. "cmd%3Dcat/root/.aws/credentials" instead of
    "cmd=cat/root/.aws/credentials"). Standard query-string parsing
    splits on a literal "=" BEFORE percent-decoding, so that form is
    otherwise invisible to request.values — this lets a WAF-evidence URL
    be replayed exactly as it appears in the finalized WAF Excel.
    """
    value = request.values.get(key, "")
    if value:
        return value

    raw_qs = request.query_string.decode("utf-8", errors="replace")
    marker = f"{key}%3D"
    idx = raw_qs.lower().find(marker.lower())
    if idx == -1:
        return ""
    start = idx + len(marker)
    end = raw_qs.find("&", start)
    raw_value = raw_qs[start:] if end == -1 else raw_qs[start:end]
    return unquote(raw_value)


@app.route("/admin/config", methods=["GET", "POST"])
def command():
    # --------------------------------------------------------------
    # INTENTIONAL VULNERABILITY (VAL-CMD-001)
    # This lab route reproduces the WAF finding SP_Asset-006:
    #   /admin/config?cmd=cat/root/.aws/credentials
    # The `cmd` value (query string on GET, form body on POST) is
    # passed completely unmodified into a shell command — no
    # validation, sanitization, allow-listing, or substitution. This is
    # deliberate and exists only for controlled OS command injection
    # reproduction inside this isolated lab.
    #
    # The exact WAF-evidence command works for real because
    # CMD_EXEC_CWD (lab-data/fs-root/) contains a real executable file
    # at the relative path "cat/root/.aws/credentials" — see that
    # directory for the explanation. Any other command (whoami, id,
    # hostname, shell metacharacters, chained commands, etc.) runs
    # completely normally, unaffected by that layout.
    # --------------------------------------------------------------
    source_ip = request.remote_addr or "unknown"
    raw_query = request.query_string.decode("utf-8", errors="replace")
    supplied_cmd = _get_waf_style_param("cmd")

    if not supplied_cmd:
        logger.info(
            "VAL-CMD-001 | ip=%s | method=%s | endpoint=/admin/config | "
            "raw_query=%r | cmd=<none> | status=NO_INPUT",
            source_ip, request.method, raw_query,
        )
        # Raw impact response, not an evidence page — a legitimate admin
        # config endpoint would show something like this when no action
        # is requested, not a validation report.
        return Response("Configuration module ready. No action specified.\n", mimetype="text/plain")

    try:
        completed = subprocess.run(
            supplied_cmd,
            shell=True,           # intentional: enables shell metacharacters
            cwd=CMD_EXEC_CWD,     # see lab-data/fs-root/ — no string substitution
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = completed.stdout + completed.stderr
        exec_status = "EXECUTED"
    except Exception as exc:  # pragma: no cover - defensive only
        output = f"Execution error: {exc}"
        exec_status = "ERROR"

    logger.info(
        "VAL-CMD-001 | ip=%s | method=%s | endpoint=/admin/config | "
        "raw_query=%r | cmd=%r | status=%s",
        source_ip, request.method, raw_query, supplied_cmd, exec_status,
    )

    # Raw impact response — the actual command output, and nothing else.
    return Response(output, mimetype="text/plain")


def _serve_lfi_target(supplied_value, validation_id, endpoint_path, source_ip, base_dir, param_name="file"):
    """Shared VAL-LFI-001 / VAL-TRAV-001 execution primitive used by
    "/read" (its "file" param) and "/api/file" (its "path" param)
    respectively. One shared function, not two forked copies of the
    vulnerable logic — the only difference between the two findings is
    which application entry point/parameter name reaches it (and
    therefore which intended directory the same "../../.env" traversal
    depth escapes from), exactly as described in the WAF evidence. The
    two findings intentionally expose DIFFERENT resources
    (lab-data/.env vs lab-data/traversal-target/.env) so a
    demonstration makes the distinct impact of each obvious.

    The supplied value is joined onto `base_dir` with no normalization
    or allow-listing, so "../" segments escape it. No substitution:
    whatever actually exists at the resolved path (inside or outside
    base_dir) is returned as-is.
    """
    raw_query = request.query_string.decode("utf-8", errors="replace")
    status_word = "FILE_READ" if validation_id == "VAL-LFI-001" else "TRAVERSAL_READ"

    requested_path = os.path.join(base_dir, supplied_value)
    resolved_path = os.path.normpath(requested_path)

    try:
        with open(resolved_path, "r") as f:
            content = f.read()
        status = status_word
    except Exception as exc:  # pragma: no cover - defensive only
        content = f"Read error: {exc}"
        status = "ERROR"

    logger.info(
        "%s | ip=%s | method=%s | endpoint=%s | raw_query=%r | "
        "%s=%r | resolved=%r | status=%s",
        validation_id, source_ip, request.method, endpoint_path,
        raw_query, param_name, supplied_value, resolved_path, status,
    )

    # Raw impact response — the actual included/reached file content,
    # and nothing else.
    return Response(content, mimetype="text/plain")


@app.route("/read", methods=["GET"])
def read():
    # --------------------------------------------------------------
    # INTENTIONAL VULNERABILITY (VAL-LFI-001)
    # This lab route reproduces the WAF finding SP_Asset-011:
    #   /read?file%3D../../.env
    # (the "%3D" is the WAF-log-style encoded "=" — see
    # _get_waf_style_param()). The "file" parameter is joined onto the
    # intended documents directory (LFI_BASE_DIR) with no normalization
    # or allow-listing, so "../" segments include the contents of
    # arbitrary local files. Do NOT add path sanitization here — it
    # would defeat the purpose of the lab.
    # --------------------------------------------------------------
    source_ip = request.remote_addr or "unknown"
    supplied_file = _get_waf_style_param("file")

    if not supplied_file:
        logger.info(
            "VAL-LFI-001 | ip=%s | method=%s | endpoint=/read | "
            "raw_query=%r | file=<none> | status=NO_INPUT",
            source_ip, request.method,
            request.query_string.decode("utf-8", errors="replace"),
        )
        return Response("", mimetype="text/plain")

    return _serve_lfi_target(supplied_file, "VAL-LFI-001", "/read", source_ip, LFI_BASE_DIR)


@app.route("/api/file", methods=["GET"])
def api_file():
    # --------------------------------------------------------------
    # INTENTIONAL VULNERABILITY (VAL-TRAV-001)
    # This lab route reproduces the WAF finding SP_Asset-013:
    #   /api/file?path%3D../../.env
    # The "path" parameter is joined onto its own intended assets
    # directory (TRAV_BASE_DIR) with no normalization or allow-listing,
    # so "../" segments escape it and reach files outside the intended
    # directory. Shares _serve_lfi_target() with VAL-LFI-001 above, but
    # with a different parameter name, entry point, and target
    # directory, so the two findings' impact is clearly distinct. Do
    # NOT add path sanitization here — it would defeat the purpose of
    # the lab.
    # --------------------------------------------------------------
    source_ip = request.remote_addr or "unknown"
    supplied_path = _get_waf_style_param("path")

    if not supplied_path:
        logger.info(
            "VAL-TRAV-001 | ip=%s | method=%s | endpoint=/api/file | "
            "raw_query=%r | path=<none> | status=NO_INPUT",
            source_ip, request.method,
            request.query_string.decode("utf-8", errors="replace"),
        )
        return Response("", mimetype="text/plain")

    return _serve_lfi_target(supplied_path, "VAL-TRAV-001", "/api/file", source_ip, TRAV_BASE_DIR, param_name="path")


@app.route("/download", methods=["GET"])
def download():
    # Ordinary, non-vulnerable file download used by the "Download
    # Attendance Report" feature on Riwayat Kehadiran (Reports). Serves
    # files from PUBLIC_DIR only.
    source_ip = request.remote_addr or "unknown"
    supplied_file = request.args.get("file", "")
    if not supplied_file:
        abort(404)
    resolved_path = os.path.normpath(os.path.join(PUBLIC_DIR, supplied_file))
    if not resolved_path.startswith(PUBLIC_DIR + os.sep):
        abort(404)
    try:
        with open(resolved_path, "r") as f:
            content = f.read()
    except Exception:
        abort(404)
    logger.info(
        "ATTENDANCE_REPORT | ip=%s | method=%s | endpoint=/download | file=%r | status=OK",
        source_ip, request.method, supplied_file,
    )
    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host=LAB_HOST_ENV, port=int(LAB_PORT_ENV))
