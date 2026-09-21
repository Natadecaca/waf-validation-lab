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

Six intentionally vulnerable endpoints, each with a different
finding, WAF-evidence-matched endpoint/parameter, and a genuinely
DIFFERENT exposed resource (not a shared marker file) so their impact
is easy to tell apart in a demo:

  VAL-CMD-001    OS Command Injection            GET  /admin/config?cmd=
  VAL-LFI-001    Local File Inclusion             GET  /read?file=
  VAL-TRAV-001   Directory Traversal              GET  /?file=
  VAL-SQLI-001   SQL Injection (UNION-based)      GET  /search/members/?id=
  VAL-SSRF-001   Server-Side Request Forgery      GET  /CookieAuth.dll?url=
  VAL-UPLOAD-001 Unrestricted File Upload/Shell   POST /defaultroot/upload/fileUpload.controller

The three newer findings (SQLI/SSRF/UPLOAD) follow the same rules as
the original three: no proof-marker files, no "if input looks like an
attack, return canned output" branching. VAL-SQLI-001 runs the
attacker-supplied value in a real SQL statement against a real
in-process SQLite database (MEMBERS_DB). VAL-SSRF-001 performs a real
server-side HTTP fetch (urllib.request) of the attacker-supplied URL;
a second, genuinely separate Werkzeug service bound only to
127.0.0.1:INTERNAL_SSRF_PORT stands in for an "internal-only" backend
service, unreachable except through the vulnerable server's own
outbound request. VAL-UPLOAD-001 saves the uploaded file with no
extension allow-list and, for .py/.sh uploads, genuinely executes them
via subprocess.run (same real-execution pattern as VAL-CMD-001) — the
returned output is the real stdout/stderr of that execution.

No proof-file substitution or string pattern-matching happens in this
file. Each endpoint uses the attacker-supplied input completely
unmodified; realistic impact comes purely from the controlled
filesystem layout (CMD_EXEC_CWD, LFI_BASE_DIR, TRAV_BASE_DIR — see
their definitions below) — the WAF-evidence target genuinely exists at
those paths, exactly like it would on a real vulnerable host:

  - /admin/config's "cmd" is passed straight to subprocess.run(...,
    shell=True, cwd=CMD_EXEC_CWD). CMD_EXEC_CWD (lab-data/cmd-root/)
    contains symlinks back to the real project tree, so ordinary
    commands (ls, pwd, whoami, cat <realfile>, etc.) genuinely execute
    and reflect the real lab filesystem. The literal WAF-evidence
    command "cat/root/.aws/credentials" additionally resolves to a real
    executable at lab-data/cmd-root/cat/root/.aws/credentials (see that
    file) which cats lab-data/root/.aws/credentials. No command-specific
    branching exists in Python — every command genuinely executes.
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

WARNING: /, /admin/config, /read, /api/file, /search/members/,
/CookieAuth.dll, and /defaultroot/upload/fileUpload.controller are
INTENTIONALLY VULNERABLE (reflected XSS, OS command injection, local
file inclusion, directory traversal, SQL injection, SSRF, and
unrestricted file upload, respectively). All exist ONLY for
controlled reproduction of WAF findings inside an isolated lab
network. Do not deploy this code anywhere else. Portal login
intentionally does NOT gate any of these seven endpoints — they must
remain directly testable, even though each is discovered through a
login-gated PresensiKu feature first (except / itself, which is
public, matching the original WAF finding).
"""
import ast
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import unquote
from xml.sax.saxutils import escape as _xml_escape

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
# with this directory as its cwd. lab-data/cmd-root/ contains:
#   - symlinks back to the real project directories (app.py, lab-data,
#     logs, reports, static, templates, validation, venv), so ordinary
#     commands (ls, pwd, cat <realfile>, find, etc.) reflect the real
#     lab filesystem — NOT an artificially empty sandbox. (An earlier
#     revision pointed this at an otherwise-empty directory, which made
#     "ls" appear to return a hardcoded "cat" — it was actually a
#     genuine, if misleading, listing of that near-empty cwd. Symlinking
#     the real tree in fixes that without any command-specific
#     branching in Python.)
#   - cat/root/.aws/credentials, a real executable file at that exact
#     relative path, so the literal space-free WAF-evidence command
#     "cat/root/.aws/credentials" resolves to something real via normal
#     shell path lookup — no string pattern-matching/substitution in
#     application code.
# Every other command (whoami, id, hostname, shell metacharacters,
# pipelines, etc.) is unaffected and executes for real.
CMD_EXEC_CWD = os.path.join(BASE_DIR, "lab-data", "cmd-root")

LAB_HOST_ENV = os.environ.get("LAB_HOST", "192.168.200.128")
LAB_PORT_ENV = os.environ.get("LAB_PORT", "8080")

# --------------------------------------------------------------------
# Company identity — single source of truth. Used throughout
# COMPANY_INFO, employee seed data, templates (via
# inject_portal_globals()), and the report/PDF generators, so the
# normal-facing application never has to repeat these literals.
# "DrishtiSec" (without "PT") remains the distinct security/assessment
# brand used only on the shared logo and within /portal/security and
# below — see the module docstring above.
# --------------------------------------------------------------------
COMPANY_NAME = "PT DrishtiSec"
PRODUCT_NAME = "PresensiKu"
COMPANY_DOMAIN = "drishtisec.corp"
HR_EMAIL = f"hr@{COMPANY_DOMAIN}"

# --------------------------------------------------------------------
# VAL-SQLI-001 (/search/members/?id=). A real, in-process SQLite
# database — not a mock and not string substitution.
#
# Two clearly separate tables:
#
#   "members" — the ordinary Direktori Karyawan feature's data (6
#   realistic columns). Used ONLY by /portal/direktori's own listing
#   query. Untouched by the vulnerable query layer below.
#
#   "sqli_members" — the DEDICATED table backing the vulnerable
#   /search/members/ query layer, with exactly 32 realistic employee
#   columns (contact/org/attendance/payroll fields), so SP_PAM-047's
#   32-expression UNION SELECT lines up column-for-column against a
#   real schema — no NULL padding, no forcing "members" into an
#   unrealistic 32-column shape. Same synthetic 8-person roster as
#   "members", just with the fuller HR-record shape a real employee
#   search/profile endpoint would plausibly select from.
#
#   "admin_credentials" — a 6-column table never exposed by the
#   intended query. Not linked from any pre-built test in this lab, but
#   genuinely reachable via a hand-crafted 32-expression UNION SELECT
#   (padding its 6 real columns with 26 literal NULLs) — the same
#   unrestricted injection point SP_PAM-047 exercises, demonstrating
#   the vulnerability isn't limited to the literal WAF payload alone.
# --------------------------------------------------------------------
MEMBERS_DB = sqlite3.connect(":memory:", check_same_thread=False)

_MEMBERS_SEED = [
    (1, "EMP-2024-0142", "Ayu Lestari", "Software Engineer", "Engineering", f"ayu.lestari@{COMPANY_DOMAIN}"),
    (2, "EMP-2023-0087", "Bima Nugraha", "HR Business Partner", "Human Resources", f"bima.nugraha@{COMPANY_DOMAIN}"),
    (3, "EMP-2022-0154", "Citra Wulandari", "Finance Analyst", "Finance", f"citra.wulandari@{COMPANY_DOMAIN}"),
    (4, "EMP-2024-0201", "Dedi Purnomo", "QA Engineer", "Engineering", f"dedi.purnomo@{COMPANY_DOMAIN}"),
    (5, "EMP-2021-0033", "Eka Pratiwi", "Office Manager", "General Affairs", f"eka.pratiwi@{COMPANY_DOMAIN}"),
    (6, "EMP-2023-0119", "Fajar Ramadhan", "DevOps Engineer", "Engineering", f"fajar.ramadhan@{COMPANY_DOMAIN}"),
    (7, "EMP-2022-0076", "Gita Anindya", "Talent Acquisition", "Human Resources", f"gita.anindya@{COMPANY_DOMAIN}"),
    (8, "EMP-2024-0058", "Hendra Saputra", "IT Support", "Information Technology", f"hendra.saputra@{COMPANY_DOMAIN}"),
]

# 32 realistic HR-record columns — the schema the vulnerable query
# layer actually selects from. Column order matches the SP_PAM-047
# UNION payload's 32 expression positions exactly (see
# _SQLI_MEMBERS_COLUMNS / _SQLI_MEMBERS_LABELS below).
_SQLI_MEMBERS_SEED = [
    (1, "EMP-2024-0142", "Ayu Lestari", "Software Engineer", "Engineering", f"ayu.lestari@{COMPANY_DOMAIN}",
     "+62 812-3456-7001", "Jakarta HQ", "2024-03-01", "Active",
     "Fajar Ramadhan", "No active investigations.", "2024-03-01 09:00:00", "2026-09-01 10:00:00",
     "Product Engineering", "Staff", "Permanent", f"ayu.lestari@{COMPANY_DOMAIN}", "1142",
     "CC-ENG-01", "PR-10142", 9, "Hadir",
     "08:02", "17:05", "Permanent", 6,
     "Engineering Division", "Tower A", "5", "BADGE-00142", "ACTIVE"),
    (2, "EMP-2023-0087", "Bima Nugraha", "HR Business Partner", "Human Resources", f"bima.nugraha@{COMPANY_DOMAIN}",
     "+62 812-3456-7002", "Jakarta HQ", "2023-06-15", "Active",
     "Gita Anindya", "No active investigations.", "2023-06-15 09:00:00", "2026-08-20 14:00:00",
     "People & Culture", "Senior Staff", "Permanent", f"bima.nugraha@{COMPANY_DOMAIN}", "1087",
     "CC-HR-01", "PR-10087", 12, "Hadir",
     "08:10", "17:02", "Permanent", 7,
     "Human Resources Division", "Tower A", "3", "BADGE-00087", "ACTIVE"),
    (3, "EMP-2022-0154", "Citra Wulandari", "Finance Analyst", "Finance", f"citra.wulandari@{COMPANY_DOMAIN}",
     "+62 812-3456-7003", "Jakarta HQ", "2022-01-10", "Active",
     "Eka Pratiwi", "No active investigations.", "2022-01-10 09:00:00", "2026-07-15 11:30:00",
     "Corporate Finance", "Staff", "Permanent", f"citra.wulandari@{COMPANY_DOMAIN}", "1154",
     "CC-FIN-01", "PR-10154", 6, "Cuti",
     "-", "-", "Permanent", 5,
     "Finance Division", "Tower A", "4", "BADGE-00154", "ACTIVE"),
    (4, "EMP-2024-0201", "Dedi Purnomo", "QA Engineer", "Engineering", f"dedi.purnomo@{COMPANY_DOMAIN}",
     "+62 812-3456-7004", "Jakarta HQ", "2024-05-20", "Active",
     "Fajar Ramadhan", "No active investigations.", "2024-05-20 09:00:00", "2026-09-10 09:00:00",
     "Product Engineering", "Staff", "Contract", f"dedi.purnomo@{COMPANY_DOMAIN}", "1201",
     "CC-ENG-01", "PR-10201", 4, "Hadir",
     "08:05", "17:00", "Contract", 6,
     "Engineering Division", "Tower A", "5", "BADGE-00201", "ACTIVE"),
    (5, "EMP-2021-0033", "Eka Pratiwi", "Office Manager", "General Affairs", f"eka.pratiwi@{COMPANY_DOMAIN}",
     "+62 812-3456-7005", "Jakarta HQ", "2021-02-01", "Active",
     "Bima Nugraha", "No active investigations.", "2021-02-01 09:00:00", "2026-06-01 08:00:00",
     "Corporate Services", "Manager", "Permanent", f"eka.pratiwi@{COMPANY_DOMAIN}", "1033",
     "CC-GA-01", "PR-10033", 15, "Hadir",
     "07:58", "17:10", "Permanent", 2,
     "General Affairs Division", "Tower A", "2", "BADGE-00033", "ACTIVE"),
    (6, "EMP-2023-0119", "Fajar Ramadhan", "DevOps Engineer", "Engineering", f"fajar.ramadhan@{COMPANY_DOMAIN}",
     "+62 812-3456-7006", "Jakarta HQ", "2023-09-01", "Active",
     "Eka Pratiwi", "No active investigations.", "2023-09-01 09:00:00", "2026-09-15 16:00:00",
     "Product Engineering", "Senior Staff", "Permanent", f"fajar.ramadhan@{COMPANY_DOMAIN}", "1119",
     "CC-ENG-01", "PR-10119", 10, "Hadir",
     "08:00", "17:00", "Permanent", 5,
     "Engineering Division", "Tower A", "5", "BADGE-00119", "ACTIVE"),
    (7, "EMP-2022-0076", "Gita Anindya", "Talent Acquisition", "Human Resources", f"gita.anindya@{COMPANY_DOMAIN}",
     "+62 812-3456-7007", "Jakarta HQ", "2022-04-11", "Active",
     "Bima Nugraha", "No active investigations.", "2022-04-11 09:00:00", "2026-05-22 13:00:00",
     "People & Culture", "Staff", "Permanent", f"gita.anindya@{COMPANY_DOMAIN}", "1076",
     "CC-HR-01", "PR-10076", 8, "Hadir",
     "08:12", "17:03", "Permanent", 2,
     "Human Resources Division", "Tower A", "3", "BADGE-00076", "ACTIVE"),
    (8, "EMP-2024-0058", "Hendra Saputra", "IT Support", "Information Technology", f"hendra.saputra@{COMPANY_DOMAIN}",
     "+62 812-3456-7008", "Jakarta HQ", "2024-01-08", "Active",
     "Fajar Ramadhan", "No active investigations.", "2024-01-08 09:00:00", "2026-09-18 10:00:00",
     "Infrastructure & Support", "Staff", "Permanent", f"hendra.saputra@{COMPANY_DOMAIN}", "1058",
     "CC-IT-01", "PR-10058", 11, "Hadir",
     "08:03", "17:01", "Permanent", 6,
     "Information Technology Division", "Tower B", "1", "BADGE-00058", "ACTIVE"),
]

# A 6-column table, same shape as the OLD members schema — the
# "Laboratory UNION Test" replay link (VALIDATION_DEFS) pads its
# SELECT list with 26 literal NULLs to reach the 32 expressions
# sqli_members now requires, rather than the table itself needing 32
# columns. Synthetic/lab-only, never real credentials.
_ADMIN_CREDENTIALS_SEED = [
    (1, "svc-backup", "$2b$12$LABSYNTHETICb4ckup0nlyD0N0tUseXXXXXXXXXXXXXXX", "service", "LAB-API-7f3e9c2a1b6d4f80", "Automated nightly backup service account (synthetic lab credential)"),
    (2, "svc-monitoring", "$2b$12$LABSYNTHETICm0n1t0rXXXXXXXXXXXXXXXXXXXXXXXX", "service", "LAB-API-4c1d8e6b2a9f0731", "Monitoring/alerting integration account (synthetic lab credential)"),
    (3, "hr-admin", "$2b$12$LABSYNTHETIChr4dm1nXXXXXXXXXXXXXXXXXXXXXXXXX", "admin", "LAB-API-91a2b3c4d5e6f708", "HR system administrator account (synthetic lab credential)"),
]

# 32 realistic HR-record columns, in the exact order SP_PAM-047's
# UNION payload expects (see module docstring / VALIDATION_DEFS).
_SQLI_MEMBERS_COLUMNS = [
    "id", "employee_id", "full_name", "position", "department", "email",
    "phone", "office_location", "join_date", "employment_status",
    "manager_name", "notes", "created_at", "updated_at", "division",
    "job_level", "employee_type", "work_email", "extension",
    "cost_center", "payroll_code", "leave_balance", "attendance_status",
    "last_checkin", "last_checkout", "contract_type", "supervisor_id",
    "organization_unit", "building", "floor", "badge_id", "record_status",
]
_SQLI_MEMBERS_LABELS = [
    "ID", "Employee ID", "Nama", "Jabatan", "Departemen", "Email",
    "Telepon", "Lokasi", "Tanggal Masuk", "Status", "Manager", "Catatan",
    "Created", "Updated", "Divisi", "Level", "Tipe Karyawan", "Work Email",
    "Ext", "Cost Center", "Payroll Code", "Leave Balance", "Attendance",
    "Last Check-In", "Last Check-Out", "Contract Type", "Supervisor",
    "Org Unit", "Building", "Floor", "Badge ID", "Record Status",
]
_SQLI_SELECT_COLUMNS = ", ".join(_SQLI_MEMBERS_COLUMNS)
_SQLI_MEMBERS_PLACEHOLDERS = ", ".join(["?"] * len(_SQLI_MEMBERS_COLUMNS))


def _init_members_db():
    cur = MEMBERS_DB.cursor()
    cur.execute(
        "CREATE TABLE members (id INTEGER PRIMARY KEY, employee_id TEXT, "
        "full_name TEXT, position TEXT, department TEXT, email TEXT)"
    )
    cur.execute(
        "CREATE TABLE sqli_members ("
        "id INTEGER PRIMARY KEY, employee_id TEXT, full_name TEXT, "
        "position TEXT, department TEXT, email TEXT, phone TEXT, "
        "office_location TEXT, join_date TEXT, employment_status TEXT, "
        "manager_name TEXT, notes TEXT, created_at TEXT, updated_at TEXT, "
        "division TEXT, job_level TEXT, employee_type TEXT, work_email TEXT, "
        "extension TEXT, cost_center TEXT, payroll_code TEXT, "
        "leave_balance INTEGER, attendance_status TEXT, last_checkin TEXT, "
        "last_checkout TEXT, contract_type TEXT, supervisor_id INTEGER, "
        "organization_unit TEXT, building TEXT, floor TEXT, badge_id TEXT, "
        "record_status TEXT)"
    )
    cur.execute(
        "CREATE TABLE admin_credentials (id INTEGER PRIMARY KEY, username TEXT, "
        "password_hash TEXT, role TEXT, api_token TEXT, notes TEXT)"
    )
    cur.executemany("INSERT INTO members VALUES (?,?,?,?,?,?)", _MEMBERS_SEED)
    cur.executemany(
        f"INSERT INTO sqli_members VALUES ({_SQLI_MEMBERS_PLACEHOLDERS})",
        _SQLI_MEMBERS_SEED,
    )
    cur.executemany("INSERT INTO admin_credentials VALUES (?,?,?,?,?,?)", _ADMIN_CREDENTIALS_SEED)
    MEMBERS_DB.commit()


_init_members_db()


def _sqli_unhex(hex_string):
    """Custom SQLite UNHEX(), registered on MEMBERS_DB below.

    SQLite has no built-in UNHEX() (it's a MySQL/MariaDB function — the
    origin of SP_PAM-047's payload); without registering one, the exact
    WAF payload's unhex('66636f756d') call would fail with "no such
    function: unhex" instead of genuinely evaluating. Registering it
    here makes that call real, native SQLite execution — the resulting
    'fcoum' in query output comes from this function actually running,
    not from string substitution anywhere in this file.
    """
    try:
        return bytes.fromhex(hex_string).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None


MEMBERS_DB.create_function("unhex", 1, _sqli_unhex)


def _balance_sqli_parens(supplied):
    """Generic parenthesis balancer for the "id IN (...)" clause built
    by search_members() below — applied identically to every request,
    not attack-specific.

    The clause opens with a literal "(" before `supplied`; this closes
    it with exactly enough ")" to balance whatever `supplied` itself
    already opened/closed. For ordinary numeric input (no parens of its
    own) that's just one closing paren, e.g. "id IN (1)". For the
    SP_PAM-047 payload — whose own "520)" and balanced "unhex('...')"
    already net to zero — nothing extra is appended, so the payload's
    UNION SELECT attaches directly onto a syntactically complete
    "id IN (520)" clause, exactly as it would have against the original
    production query.
    """
    net_open = 1 + supplied.count("(") - supplied.count(")")
    return supplied + (")" * max(net_open, 0))


# --------------------------------------------------------------------
# VAL-SSRF-001 (/CookieAuth.dll?url=). A genuinely separate service,
# bound only to 127.0.0.1, standing in for an "internal-only" backend
# system a real Exchange/OWA-style host would have behind it. It is
# NOT reachable from the lab's host-only network interface — only the
# vulnerable app itself (running on the same machine) can reach it,
# which is exactly the real-world SSRF impact this reproduces. Content
# is synthetic and clearly labeled as lab-only; no real infrastructure
# or credentials.
# --------------------------------------------------------------------
INTERNAL_SSRF_HOST = "127.0.0.1"
INTERNAL_SSRF_PORT = int(os.environ.get("LAB_INTERNAL_SSRF_PORT", "8180"))

_internal_service = Flask("presensiku_internal_service")

_INTERNAL_SERVICE_BODY = (
    "PT DrishtiSec\n"
    "Corporate Service Directory\n"
    "\n"
    "Service Name              Host                 Status\n"
    "------------------------------------------------------------\n"
    "Presensi Database         127.0.0.1:5432       HEALTHY\n"
    "Backup Service            127.0.0.1:9001       HEALTHY\n"
    "HR Payroll Service        127.0.0.1:9100       DEGRADED\n"
    "\n"
    "Environment\n"
    "------------------------------------------------------------\n"
    "Service                  attendance-api\n"
    "Database                 presensi-production\n"
    "Region                   Jakarta\n"
    "Status                   Operational\n"
)


@_internal_service.route("/", defaults={"_path": ""})
@_internal_service.route("/<path:_path>")
def _internal_service_root(_path):
    return Response(_INTERNAL_SERVICE_BODY, mimetype="text/plain")


def _run_internal_ssrf_service():
    from werkzeug.serving import make_server
    srv = make_server(INTERNAL_SSRF_HOST, INTERNAL_SSRF_PORT, _internal_service)
    srv.serve_forever()


threading.Thread(target=_run_internal_ssrf_service, daemon=True).start()

# --------------------------------------------------------------------
# VAL-UPLOAD-001. The live route is the exact WAF-evidence endpoint
# (SP_IprocVendor-015): POST /defaultroot/upload/fileUpload.controller
# — not a renamed lab-only path. Uploaded documents are saved here
# verbatim, with no extension or content-type allow-list.
# --------------------------------------------------------------------
UPLOAD_ENDPOINT_PATH = "/defaultroot/upload/fileUpload.controller"
CUTI_UPLOAD_DIR = os.path.join(BASE_DIR, "lab-data", "uploads", "cuti")
os.makedirs(CUTI_UPLOAD_DIR, exist_ok=True)

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
        {"name": "Direktori Karyawan", "endpoint": "direktori", "icon": "search"},
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
VALIDATION_ORDER = [
    "VAL-CMD-001", "VAL-LFI-001", "VAL-TRAV-001",
    "VAL-SQLI-001", "VAL-SSRF-001", "VAL-UPLOAD-001", "VAL-XSS-001",
]

VALIDATION_DEFS = {
    "VAL-XSS-001": {
        "id": "VAL-XSS-001",
        "type": "xss",
        "title": "Reflected Cross-Site Scripting (XSS)",
        "severity": "High",
        "waf_reference": "SP_LMS-Frontend-015",
        "waf_host": "114.7.158.168",
        "matched_pattern": "<script>",
        "signature_id": "010000057",
        "waf_action": "Alert_Deny",
        "waf_severity": "High",
        "threat_level": "Severe",
        "attack_category": "Reflected Cross-Site Scripting (XSS)",
        "owasp_primary": "A03:2021-Injection",
        "objective": (
            "Demonstrate reflected input reaching the HTTP response without "
            "proper output encoding."
        ),
        "recon": (
            "The tester opens the PresensiKu homepage (/) unauthenticated "
            "and views the page source, as with any initial recon of a "
            "public-facing page, before touching any parameter."
        ),
        "impact_note": (
            "The reflected value is placed into the response with no HTML "
            "encoding. Supplying a <script> payload causes the browser to "
            "parse and execute it as real page script — genuine "
            "client-side code execution in the victim's browser session, "
            "not a simulated result."
        ),
        "lab_result": (
            "Reproduced — the wapiskqm value is reflected byte-for-byte and "
            "unescaped; a <script>alert(\"XSS\")</script> payload executes "
            "in the browser when the response is rendered."
        ),
        "endpoint": "/",
        "param": "wapiskqm",
        "endpoint_label": "/?wapiskqm=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": (
            "/?wapiskqm%3D<script>alert(%22XSS%22);</script>"
        ),
        "local_evidence_path": (
            "landing.html response body — campaign_banner reflected via "
            "Jinja's `| safe` filter (autoescaping deliberately bypassed)"
        ),
        "discovery_source": (
            "An HTML comment left in the PresensiKu homepage source "
            "(\"marketing: append ?wapiskqm=<code> to preview an onboarding "
            "campaign banner before launch\") reveals both the parameter "
            "name and its purpose through ordinary View Source recon — "
            "found before any WAF data was consulted."
        ),
        "description": (
            "Controlled validation of reflected XSS via an undocumented "
            "campaign-preview parameter on the public homepage."
        ),
        "technical_summary": (
            "The / (landing) route reads the wapiskqm query parameter and "
            "renders it into a campaign-preview banner using Jinja's "
            "`| safe` filter, which disables Jinja's normal automatic HTML "
            "escaping for that value. Any HTML or JavaScript supplied in "
            "wapiskqm is reflected into the response completely unescaped."
        ),
        "business_impact": (
            "An attacker able to get a victim to open a crafted link could "
            "execute arbitrary JavaScript in that victim's browser session "
            "against the PresensiKu origin — e.g. actions performed as the "
            "logged-in victim, or further client-side attacks."
        ),
        "waf_note": (
            "WAF evidence and laboratory validation both used GET, and the "
            "exact WAF payload (a harmless alert(\"XSS\") proof-of-concept) "
            "reproduces cleanly against the lab — no payload adaptation was "
            "needed for this finding."
        ),
        "replay_links": [
            {
                "label": "3. Controlled XSS PoC — alert(\"XSS\")",
                "href": "/?wapiskqm=%3Cscript%3Ealert(%22XSS%22)%3C%2Fscript%3E",
            },
        ],
        "safe_links": [
            {"label": "1. Normal Request — wapiskqm=test", "href": "/?wapiskqm=test"},
        ],
        "boolean_links": [
            {"label": "2. HTML-Oriented Input — wapiskqm=<b>test</b>", "href": "/?wapiskqm=%3Cb%3Etest%3C%2Fb%3E"},
        ],
        "remediation": {
            "title": "HTML-encode all reflected output",
            "priority": "Immediate",
            "dedup_key": "reflected-xss",
            "component": "/ (wapiskqm parameter)",
            "description": (
                "The landing page reflects the wapiskqm parameter into the "
                "response using Jinja's `| safe` filter, bypassing "
                "Jinja's automatic HTML escaping and allowing arbitrary "
                "HTML/JavaScript injection into the page."
            ),
            "immediate_action": (
                "Remove the `| safe` filter and let Jinja's default "
                "autoescaping encode the value, or remove the "
                "campaign-preview feature entirely."
            ),
            "long_term": (
                "Never disable autoescaping for request-influenced values. "
                "Where rich HTML genuinely must be rendered, sanitize it "
                "through an allow-list HTML sanitizer, never a raw `| safe` "
                "pass-through of user input."
            ),
            "verification": (
                "Confirm /?wapiskqm=<script>...</script> and equivalent "
                "payloads are rendered as inert, visible text rather than "
                "executed as HTML/JavaScript."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF signatures "
                "blocking <script>, event-handler attributes, and "
                "javascript: URIs in query parameters. This reduces "
                "exposure but does not fix the missing output encoding."
            ),
        },
    },
    "VAL-CMD-001": {
        "id": "VAL-CMD-001",
        "type": "cmd",
        "title": "OS Command Injection",
        "severity": "High",
        "waf_reference": "SP_Asset-006",
        "objective": (
            "Demonstrate that attacker-controlled input reaches an OS shell "
            "with no sanitization."
        ),
        "recon": (
            "Content/endpoint enumeration against the PresensiKu host "
            "surfaces an /admin path distinct from the normal employee "
            "navigation — a leftover internal ops panel worth inspecting "
            "further."
        ),
        "endpoint": "/admin/config",
        "param": "cmd",
        "endpoint_label": "/admin/config?cmd=",
        "http_method_label": "GET / POST",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET", "POST"],
        "waf_request_pattern": "/admin/config?cmd%3Dcat/root/.aws/credentials",
        "local_evidence_path": "lab-data/root/.aws/credentials",
        "discovery_source": (
            "Content enumeration under /admin surfaced an internal ops "
            "panel; its \"Configuration Diagnostics\" link and page-source "
            "comment led to /admin/config and its cmd parameter — found "
            "before any WAF data was consulted."
        ),
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
        "remediation": {
            "title": "Eliminate shell execution of user-controlled input",
            "priority": "Immediate",
            "dedup_key": "cmd-exec",
            "component": "/admin/config (cmd parameter)",
            "description": (
                "The /admin/config endpoint passes the cmd parameter to an OS "
                "shell. No request-influenced value should reach a shell "
                "interpreter; the command-execution capability must be removed "
                "or hard-restricted."
            ),
            "immediate_action": (
                "Disable the diagnostic command feature, or hard-restrict it to "
                "a fixed allowlist of non-parameterised operations and reject "
                "any cmd value outside that allowlist."
            ),
            "long_term": (
                "Replace shell invocation with direct OS/library APIs. Where an "
                "external process is unavoidable, execute it without a shell "
                "(argument vector, shell=False) and never interpolate request "
                "input into the command string."
            ),
            "verification": (
                "Replay /admin/config?cmd=... with whoami, id, and shell "
                "metacharacters and confirm no command executes — the endpoint "
                "must return an error or only the fixed allowlisted output."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF signatures "
                "that block command-injection patterns on the cmd parameter "
                "(shell metacharacters, common binary names). This reduces "
                "exposure but does not remove the underlying flaw."
            ),
        },
    },
    "VAL-LFI-001": {
        "id": "VAL-LFI-001",
        "type": "lfi",
        "title": "Local File Inclusion (LFI)",
        "severity": "High",
        "waf_reference": "SP_Asset-011",
        "objective": (
            "Demonstrate that a document-viewing feature can be made to "
            "read arbitrary local files."
        ),
        "recon": (
            "The tester signs in and browses ordinary employee pages — "
            "Profil offers a \"Lihat Dokumen\" (view document) feature, a "
            "natural place to look for a file-serving parameter."
        ),
        "endpoint": "/read",
        "param": "file",
        "endpoint_label": "/read?file=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": "/read?file%3D../../.env",
        "local_evidence_path": "lab-data/.env",
        "discovery_source": (
            "The /read endpoint was found during application enumeration; "
            "its \"Lihat Dokumen\" (view document) feature on the Profil "
            "page exposes the \"file\" parameter directly in an HTML form "
            "— found before any WAF data was consulted."
        ),
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
        "remediation": {
            "title": "Restrict local file access to an allowlisted resource set",
            "priority": "Immediate",
            "dedup_key": "path-access",
            "component": "/read (file parameter)",
            "description": (
                "The /read endpoint builds a filesystem path directly from the "
                "file parameter, so traversal sequences escape the intended "
                "documents directory and include arbitrary local files "
                "(the exposed .env carried database and session secrets)."
            ),
            "immediate_action": (
                "Reject file values containing path separators or traversal "
                "sequences; serve only from a fixed allowlist of known "
                "document names."
            ),
            "long_term": (
                "Never construct filesystem paths from request input. Map a "
                "supplied identifier to a server-side path via an allowlist or "
                "lookup table, canonicalize the result, and confirm it remains "
                "within the intended base directory before opening it."
            ),
            "verification": (
                "Confirm /read?file=../../.env and equivalent encoded forms no "
                "longer return files outside the intended documents directory."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF rules that "
                "block traversal sequences (../ and encoded variants) on the "
                "file parameter. This limits exposure but does not fix the path "
                "handling itself."
            ),
        },
    },
    "VAL-TRAV-001": {
        "id": "VAL-TRAV-001",
        "type": "trav",
        "title": "Directory Traversal",
        "severity": "High",
        "waf_reference": "SP_Asset-013",
        "objective": (
            "Demonstrate that a company-document link can be made to escape "
            "its intended directory and read internal files."
        ),
        "recon": (
            "The tester notices PresensiKu's document viewer (/dokumen/...) "
            "renders company documents without exposing a filename "
            "parameter, so enumeration turns to the application's other "
            "surfaces — an /api root distinct from the normal page "
            "namespace is a natural next place to probe, the same way "
            "/admin was probed before finding /admin/config."
        ),
        "endpoint": "/api/file",
        "param": "path",
        "endpoint_label": "/api/file?path=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": "/api/file?path%3D../../.env",
        "local_evidence_path": "lab-data/traversal-target/.env",
        "discovery_source": (
            "The /api root returns a minimal internal-API banner; "
            "enumerating beneath it (e.g. gobuster/ffuf, or guessing common "
            "sub-paths) surfaces /api/file and its \"path\" parameter — "
            "found through application/endpoint enumeration, mirroring how "
            "/admin/config was found beneath /admin, before any WAF data "
            "was consulted."
        ),
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
    "VAL-SQLI-001": {
        "id": "VAL-SQLI-001",
        "type": "sqli",
        "title": "SQL Injection (UNION-based)",
        "severity": "High",
        "waf_reference": "SP_PAM-047",
        "waf_host": "pam.patra-jasa.com:8282",
        "matched_pattern": "unhex(",
        "signature_id": "030000165",
        "waf_action": "Alert_Deny",
        "waf_severity": "High",
        "threat_level": "Severe",
        "attack_category": "SQL Injection",
        "owasp_primary": "A03:2021-Injection",
        "objective": (
            "Demonstrate that attacker-controlled input reaches a database "
            "query without appropriate parameterization."
        ),
        "recon": (
            "Before touching any parameter, the tester signs in to "
            "PresensiKu as an ordinary employee and looks for a "
            "people-search feature — a near-universal function in HR/"
            "attendance systems — rather than starting from a known "
            "endpoint or payload."
        ),
        "endpoint": "/search/members/",
        "param": "id",
        "endpoint_label": "/search/members/?id=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": (
            "/search/members/?id`%3D520)/**/union/**/select/**/1,2,3,4,5,6,7,8,9,"
            "10,11,unhex('66636f756d'),13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
            "27,28,29,30,31,32#sqli%3D1"
        ),
        "local_evidence_path": (
            "MEMBERS_DB (in-process SQLite) — dedicated sqli_members table "
            "(32 real HR-record columns; the ordinary Direktori Karyawan "
            "feature's \"members\" table is untouched, 6 columns) with a "
            "custom-registered unhex() SQLite function, so the exact "
            "32-expression SP_PAM-047 UNION payload executes natively "
            "against a real schema, not a scaled-down substitute"
        ),
        "discovery_source": (
            "The Direktori Karyawan page lists employees with \"Lihat Detail\" "
            "links of the form /search/members/?id=1, /search/members/?id=2, "
            "etc., revealing the numeric \"id\" parameter and its search "
            "endpoint through ordinary application use — found before any WAF "
            "data was consulted."
        ),
        "description": (
            "Controlled validation of UNION-based SQL injection in the "
            "employee search endpoint."
        ),
        "technical_summary": (
            "The /search/members/ endpoint's vulnerable query layer selects "
            "all 32 columns of the dedicated sqli_members table (a real "
            "32-field HR record — contact, org, attendance and payroll "
            "data — not the 6-column \"members\" table Direktori Karyawan "
            "uses) and interpolates the supplied id value into a WHERE id "
            "IN (...) clause with no parameter binding, escaping, or type "
            "validation — closing that clause with a generic parenthesis "
            "balancer applied identically to every request, not "
            "attack-specific logic. Appending a boolean condition "
            "(AND 1=1 / AND 1=2) changes the result set predictably. "
            "Because the query layer already selects exactly 32 columns, "
            "the SP_PAM-047 payload's 32-expression UNION SELECT — "
            "including its unhex('66636f756d') call, evaluated by a "
            "custom-registered SQLite function — executes natively and "
            "controls every value in the returned row, with no payload "
            "adaptation required."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could enumerate and "
            "extract arbitrary data from the application database, "
            "including from other tables, and fully control the values "
            "returned in the result set."
        ),
        "impact_note": (
            "The boolean-based test changes only whether a row is returned "
            "(true vs. false condition). The exact SP_PAM-047 UNION payload "
            "escalates that same primitive to full control over the "
            "returned row's values — the response contains the literal "
            "integers 1-32 the attacker supplied, with position 12 showing "
            "'fcoum', the real output of unhex('66636f756d') evaluated by "
            "SQLite at query time. Because sqli_members has 32 real "
            "columns, /search/members/ renders the full result directly in "
            "the browser (same renderer for every request, no branching on "
            "whether input looks malicious) — the separate, unrelated "
            "/portal/direktori listing still shows only the ordinary "
            "6-field \"members\" table."
        ),
        "lab_result": (
            "Reproduced — the exact, unmodified SP_PAM-047 payload (32 "
            "expressions, unhex() included) executes successfully against "
            "the vulnerable query layer; position 12 of the returned row is "
            "'fcoum', genuinely computed by SQLite, not hardcoded."
        ),
        "waf_note": (
            "The WAF evidence's 32-expression UNION payload is used "
            "unmodified as the lab's primary test — no scaled-down "
            "substitute. The lab's dedicated sqli_members table (32 real "
            "HR-record columns) plus a custom unhex() function exist "
            "specifically so this exact payload executes natively rather "
            "than erroring on a column-count mismatch."
        ),
        "replay_links": [
            {
                "label": "4. Exact SP_PAM-047 UNION Payload (unmodified, 32 expressions)",
                "href": (
                    "/search/members/?id`%3D520)/**/union/**/select/**/1,2,3,4,5,6,7,8,9,"
                    "10,11,unhex('66636f756d'),13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
                    "27,28,29,30,31,32"
                ),
            },
        ],
        "safe_links": [
            {"label": "1. Normal Request — id=1", "href": "/search/members/?id=1"},
        ],
        "boolean_links": [
            {"label": "2. Boolean TRUE — id=1 AND 1=1 (same record)", "href": "/search/members/?id=1%20AND%201=1"},
            {"label": "3. Boolean FALSE — id=1 AND 1=2 (no record)", "href": "/search/members/?id=1%20AND%201=2"},
        ],
        "remediation": {
            "title": "Use parameterized queries for all database access",
            "priority": "Immediate",
            "dedup_key": "sql-injection",
            "component": "/search/members/ (id parameter)",
            "description": (
                "The /search/members/ endpoint concatenates the id parameter "
                "directly into a SQL string, allowing arbitrary query "
                "structure changes including UNION-based data extraction from "
                "unrelated tables."
            ),
            "immediate_action": (
                "Restrict the id parameter to a validated integer before it "
                "reaches any query, and reject non-numeric input outright."
            ),
            "long_term": (
                "Rewrite all database access to use parameterized queries or "
                "an ORM's bound-parameter interface; never build SQL strings "
                "from request input, including via string formatting."
            ),
            "verification": (
                "Confirm /search/members/?id=1)/**/UNION/**/SELECT... and "
                "equivalent payloads no longer alter the query's result set "
                "beyond the single requested member."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF signatures "
                "blocking UNION/SELECT keywords and SQL comment sequences on "
                "the id parameter. This reduces exposure but does not fix the "
                "underlying query construction."
            ),
        },
    },
    "VAL-SSRF-001": {
        "id": "VAL-SSRF-001",
        "type": "ssrf",
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "waf_reference": "SP_PAM-004",
        "waf_host": "Not recorded in the WAF dataset provided for this finding",
        "matched_pattern": "Not recorded in the WAF dataset provided for this finding",
        "signature_id": "Not recorded in the WAF dataset provided for this finding",
        "waf_action": "Not recorded in the WAF dataset provided for this finding",
        "waf_severity": "Not recorded in the WAF dataset provided for this finding",
        "threat_level": "Not recorded in the WAF dataset provided for this finding",
        "attack_category": "Server-Side Request Forgery (SSRF)",
        "owasp_primary": "A10:2021-Server-Side Request Forgery (SSRF)",
        "objective": (
            "Demonstrate that a server-side connectivity/preview feature "
            "makes an outbound HTTP request to a caller-supplied URL with no "
            "destination restriction."
        ),
        "recon": (
            "The tester signs in and looks for any feature that connects "
            "PresensiKu to an external or company-internal system — "
            "integrations, sync, and \"test connection\" style features are "
            "common places a server performs outbound requests on a user's "
            "behalf."
        ),
        "impact_note": (
            "Pointing the connection test at the loopback-only internal "
            "service returns that service's own response content — content "
            "the tester's own machine cannot reach directly, proving the "
            "request was made by the PresensiKu server itself, not the "
            "tester's browser."
        ),
        "lab_result": (
            "Reproduced — genuine server-side fetch confirmed against a "
            "loopback-only internal target unreachable from the tester's own "
            "network position."
        ),
        "endpoint": "/CookieAuth.dll",
        "param": "url",
        "endpoint_label": "/CookieAuth.dll?url=",
        "http_method_label": "GET",
        "waf_evidence_methods": ["GET"],
        "lab_methods": ["GET"],
        "waf_request_pattern": (
            "/CookieAuth.dll?GetLogon?url=/exchweb/bin/redir.asp?"
            "URL=https://interact.sh&reason=0"
        ),
        "local_evidence_path": (
            f"http://{INTERNAL_SSRF_HOST}:{INTERNAL_SSRF_PORT}/ "
            "(loopback-only internal service, unreachable except via SSRF)"
        ),
        "discovery_source": (
            "The Settings page's \"Integrasi Webmail Kantor (OWA)\" section "
            "exposes a \"Uji Koneksi Webmail\" (test webmail connection) form "
            "with a plain \"url\" field, plus the full SSO-handoff link it "
            "generates — both reveal the /CookieAuth.dll endpoint and its "
            "URL input through ordinary application use, before any WAF data "
            "was consulted."
        ),
        "description": (
            "Controlled validation of server-side request forgery via a "
            "webmail connection-test feature."
        ),
        "technical_summary": (
            "The /CookieAuth.dll endpoint accepts a URL from either a "
            "simplified \"url\" parameter or the WAF-evidence-style nested "
            "GetLogon?url=...redir.asp?URL=... form, then performs a genuine "
            "server-side HTTP request to that URL and returns the fetched "
            "response. No allow-list restricts the target host, so the "
            "server can be made to request internal-only resources on the "
            "attacker's behalf."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could make the "
            "application server issue requests to internal-only "
            "infrastructure not reachable from the attacker's own network "
            "position, potentially exposing internal services and data."
        ),
        "waf_note": (
            "WAF evidence and laboratory validation both used GET. The WAF "
            "evidence's target (interact.sh) was an external out-of-band "
            "collaborator server; the isolated lab instead targets a "
            "loopback-only internal service so the same SSRF primitive can "
            "be demonstrated without contacting any real external "
            "infrastructure."
        ),
        "replay_links": [
            {
                "label": "SSRF to internal-only service",
                "href": f"/CookieAuth.dll?url=http://{INTERNAL_SSRF_HOST}:{INTERNAL_SSRF_PORT}/",
            },
        ],
        "safe_links": [
            {
                "label": "Normal Access — self-check",
                "href": "/CookieAuth.dll?url=/portal",
            },
        ],
        "remediation": {
            "title": "Restrict outbound requests to an allow-listed destination set",
            "priority": "Immediate",
            "dedup_key": "ssrf",
            "component": "/CookieAuth.dll (url parameter)",
            "description": (
                "The /CookieAuth.dll endpoint performs a server-side HTTP "
                "request to a caller-supplied URL with no destination "
                "restriction, allowing the server to be used as a proxy "
                "against internal-only network resources."
            ),
            "immediate_action": (
                "Disable the connection-test feature, or hard-restrict it to "
                "a fixed allow-list of known, external webmail hostnames."
            ),
            "long_term": (
                "Validate and allow-list destination hosts before any "
                "server-side fetch; deny requests to loopback, "
                "link-local, and private address ranges; do not follow "
                "redirects to non-allow-listed hosts."
            ),
            "verification": (
                "Confirm /CookieAuth.dll?url=... pointed at loopback or "
                "internal addresses no longer results in a server-side fetch "
                "of that target."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF rules "
                "blocking loopback/private-range hosts and known SSRF "
                "collaborator domains in the url parameter. This reduces "
                "exposure but does not fix the missing destination "
                "validation."
            ),
        },
    },
    "VAL-UPLOAD-001": {
        "id": "VAL-UPLOAD-001",
        "type": "upload",
        "title": "Unrestricted File Upload / Web Shell",
        "severity": "Critical",
        "waf_reference": "SP_IprocVendor-015",
        "waf_host": "iprocvendor.patra-jasa.com",
        "matched_pattern": "MD5 hash match against known web shell database",
        "signature_id": "Not recorded in the WAF dataset provided for this finding",
        "waf_action": "Alert_Deny",
        "waf_severity": "Medium",
        "threat_level": "Severe",
        "attack_category": "Unrestricted File Upload - Web Shell Confirmed (MD5 Hash Match)",
        "owasp_primary": "A03:2021-Injection",
        "owasp_secondary": "A05:2021-Security Misconfiguration",
        "waf_detected_file": "3JLMMQGPjALvurxUhLwy9IzXSCF.jsp",
        "waf_detected_md5": "4fc95b693c53487fbb2edf0c22acf8d3",
        "waf_message": (
            "File [3JLMMQGPjALvurxUhLwy9IzXSCF.jsp] MD5 "
            "[4fc95b693c53487fbb2edf0c22acf8d3] matched web shell [JSP]"
        ),
        "objective": (
            "Demonstrate insufficient file-upload validation and controlled "
            "server-side execution behavior."
        ),
        "recon": (
            "The tester signs in and uses ordinary attendance functionality "
            "— leave/permission requests commonly require a supporting "
            "document attachment (doctor's note, approval letter), a "
            "natural place to look for a file-upload feature."
        ),
        "impact_note": (
            "The original detection was an exact MD5 hash match against a "
            "known JSP web shell on a Java/JSP-based vendor stack. This lab "
            "runs on Python/Flask, so the reproduction targets the same "
            "vulnerability class — unrestricted extension + server-side "
            "execution of uploaded content — using a Python script instead "
            "of a byte-identical JSP file; matching the exact MD5 would only "
            "be possible by uploading that same known-malicious binary, "
            "which this lab intentionally does not do."
        ),
        "lab_result": (
            "Reproduced — a .py upload with no legitimate document content "
            "is accepted with no extension/type restriction and its "
            "contents genuinely execute server-side (real subprocess "
            "output returned, not simulated)."
        ),
        "endpoint": "/defaultroot/upload/fileUpload.controller",
        "param": "document",
        "endpoint_label": "/defaultroot/upload/fileUpload.controller (multipart: document)",
        "http_method_label": "POST",
        "waf_evidence_methods": ["POST"],
        "lab_methods": ["POST"],
        "waf_request_pattern": "POST /defaultroot/upload/fileUpload.controller",
        "local_evidence_path": (
            "lab-data/uploads/cuti/ — uploaded file saved verbatim; "
            ".py/.sh uploads executed server-side"
        ),
        "discovery_source": (
            "The Cuti & Izin page's \"Ajukan Cuti Baru\" form includes an "
            "\"Upload Surat Keterangan\" file attachment; submitting it and "
            "inspecting the POST request (browser DevTools/Burp) reveals it "
            "targets /defaultroot/upload/fileUpload.controller — found "
            "through ordinary application use, before any WAF data was "
            "consulted."
        ),
        "description": (
            "Controlled validation of unrestricted file upload leading to "
            "server-side code execution."
        ),
        "technical_summary": (
            "The /defaultroot/upload/fileUpload.controller endpoint accepts "
            "any uploaded filename and extension with no allow-list or "
            "content inspection, saving "
            "it as-is. Its document-preview step then executes .py uploads "
            "via python3 and .sh uploads via bash, so an uploaded script "
            "runs with the application's own privileges — a functioning web "
            "shell."
        ),
        "business_impact": (
            "An attacker able to reach this endpoint could execute arbitrary "
            "code with the privileges of the application process, "
            "potentially leading to full host compromise."
        ),
        "waf_note": (
            "WAF evidence and laboratory validation both used POST. The "
            "original WAF detection confirmed an exact MD5 hash match "
            "against a known JSP web shell signature; the lab reproduces "
            "the same underlying vulnerability class (unrestricted upload "
            "leading to server-side script execution) with a Python script "
            "instead, since this lab's stack is Flask/Python, not JSP."
        ),
        "replay_links": [],
        "safe_links": [],
        "remediation": {
            "title": "Enforce a strict upload allow-list and never execute uploaded content",
            "priority": "Immediate",
            "dedup_key": "unrestricted-upload",
            "component": "/defaultroot/upload/fileUpload.controller (document parameter)",
            "description": (
                "The /defaultroot/upload/fileUpload.controller endpoint accepts any file extension "
                "and its preview step executes recognized script extensions "
                "directly, turning an ordinary document-attachment feature "
                "into a remote code execution primitive."
            ),
            "immediate_action": (
                "Disable automatic processing of uploaded documents, or "
                "restrict it to a fixed allow-list of safe document types "
                "(PDF, JPG, PNG) validated by content, not filename."
            ),
            "long_term": (
                "Never execute or interpret uploaded file content. Store "
                "uploads outside the web root with randomized names, "
                "validate content type by inspection rather than extension, "
                "and serve them back with a fixed, non-executable content "
                "type."
            ),
            "verification": (
                "Confirm uploading a .py or .sh file no longer results in "
                "server-side execution of its contents."
            ),
            "waf_mitigation": (
                "As a temporary compensating control, deploy WAF rules "
                "blocking uploads with executable-script extensions "
                "(.py, .sh, .php, .jsp, etc.). This reduces exposure but "
                "does not remove the underlying execution behavior."
            ),
        },
    },
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
    "QUERY_EXECUTED": "SQL query executed against the members database; result rows returned",
    "FETCHED": "Server-side request issued to the supplied URL; response returned",
    "SCRIPT_EXECUTED": "Uploaded script executed server-side; process output returned",
    "ACCEPTED": "Uploaded file accepted and stored with no type validation",
    "REFLECTED": "Supplied value reflected into the response with no output encoding",
    "NO_INPUT": "No input parameter supplied",
    "NO_MATCH": "Query executed; no matching rows",
    "ERROR": "Execution/read failed",
}

_EVIDENCE_SCENARIO_DEFS = [
    {"id": "VAL-CMD-001", "title": "OS Command Injection", "input_key": "cmd"},
    {"id": "VAL-LFI-001", "title": "Local File Inclusion (LFI)", "input_key": "file"},
    {"id": "VAL-TRAV-001", "title": "Directory Traversal", "input_key": "path"},
    {"id": "VAL-SQLI-001", "title": "SQL Injection (UNION-based)", "input_key": "id"},
    {"id": "VAL-SSRF-001", "title": "Server-Side Request Forgery (SSRF)", "input_key": "url"},
    {"id": "VAL-UPLOAD-001", "title": "Unrestricted File Upload / Web Shell", "input_key": "filename"},
    {"id": "VAL-XSS-001", "title": "Reflected Cross-Site Scripting (XSS)", "input_key": "value"},
]


def _parse_result_columns(result_sample_repr):
    """Turn a logged result_sample repr (e.g. "(1, 2, ..., 'fcoum', ...)")
    back into a [(column_number, value), ...] list for display.

    Never fabricates a value -- this only re-parses what search_members()
    already logged as the real SQLite row via %r, using ast.literal_eval
    (safe: it evaluates literals only, no code execution) against a
    string this application generated itself, not request input. Column
    12 shows 'fcoum' here if and only if that is what the real
    unhex('66636f756d') call actually returned to SQLite for that
    request.
    """
    if not result_sample_repr:
        return []
    try:
        row = ast.literal_eval(result_sample_repr)
    except (ValueError, SyntaxError):
        return []
    if not isinstance(row, tuple):
        return []
    return list(enumerate(row, start=1))


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
            sql_text = f.get("sql", "")
            result_columns = _parse_result_columns(f.get("result_sample", ""))
            # Derived, not hardcoded: "union detected" reflects whether the
            # SQL actually sent to SQLite (sql_text) contains a UNION
            # clause AND that query actually executed successfully
            # (status) -- both facts already captured from the real
            # request, never asserted independently of them.
            union_detected = bool(result_columns) and status == "QUERY_EXECUTED" and "union" in sql_text.lower()
            result_json = ""
            if result_columns:
                result_json = json.dumps(
                    {
                        "column_count": len(result_columns),
                        "values": [v for _, v in result_columns],
                    },
                    indent=2,
                )
            entries.append({
                "timestamp": entry["timestamp"],
                "source_ip": f.get("ip", "unknown"),
                "method": f.get("method", "GET"),
                "endpoint": f.get("endpoint", ""),
                "input": f.get(definition["input_key"], "(none)"),
                "behavior": _BEHAVIOR_BY_STATUS.get(status, status or "Unknown"),
                "status": status,
                # Only populated for VAL-SQLI-001 log lines (see
                # search_members()) -- the actual constructed SQL, the
                # actual SQLite result row, and the actual SQLite error
                # (if any), all generic pass-throughs of whatever was
                # logged, never fabricated here.
                "raw_query": f.get("raw_query", ""),
                "sql": sql_text,
                "result_sample": f.get("result_sample", ""),
                "result_columns": result_columns,
                "result_column_count": len(result_columns),
                "union_detected": union_detected,
                "result_json": result_json,
                "sqlite_error": f.get("sqlite_error", ""),
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
        "company_name": COMPANY_NAME,
        "product_name": PRODUCT_NAME,
        "company_domain": COMPANY_DOMAIN,
        "hr_email": HR_EMAIL,
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
    # --------------------------------------------------------------
    # INTENTIONAL VULNERABILITY (VAL-XSS-001) — Reflected XSS
    # This lab route reproduces the WAF finding SP_LMS-Frontend-015:
    #   /?wapiskqm%3D<script>alert("XSS");</script>
    # The "wapiskqm" campaign-preview parameter is a real, if obscure,
    # piece of application behavior (see the HTML comment in
    # landing.html) — a leftover marketing preview feature that echoes
    # its value into the page with NO output encoding (rendered via
    # Jinja's `| safe` filter, which deliberately disables Jinja's
    # normal autoescaping — this is the genuine, real mechanism by
    # which the reflection happens, not a simulation of one). Whatever
    # HTML/JS the caller supplies is reflected byte-for-byte and, if
    # opened in a real browser, genuinely parses and executes.
    # _get_waf_style_param() (shared with VAL-CMD-001/LFI/TRAV) lets the
    # exact WAF-evidence URL be replayed byte-for-byte — its "=" is
    # itself percent-encoded ("wapiskqm%3D..."), which plain
    # request.args parsing cannot see.
    # --------------------------------------------------------------
    campaign_code = _get_waf_style_param("wapiskqm")
    campaign_banner = ""
    if campaign_code:
        campaign_banner = f"Campaign preview: {campaign_code}"
        source_ip = request.remote_addr or "unknown"
        logger.info(
            "VAL-XSS-001 | ip=%s | method=%s | endpoint=/ | scenario=reflected-xss | "
            "parameter=wapiskqm | raw_query=%r | value=%r | test_stage=reflection-validation | "
            "result=REFLECTED | evidence_reference=landing-response-body",
            source_ip, request.method,
            request.query_string.decode("utf-8", errors="replace"), campaign_code,
        )
    return render_template("landing.html", campaign_banner=campaign_banner)


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
    "email": f"ayu.lestari@{COMPANY_DOMAIN}",
    "join_date": "2024-03-01",
}

COMPANY_INFO = {
    "name": COMPANY_NAME,
    "address": "Jl. Sudirman No. 123, Jakarta Selatan",
    "phone": "+62 21 5550 1234",
    "email": HR_EMAIL,
    "working_hours": "08:00 - 17:00 WIB, Senin - Jumat",
    "about": (
        f"{COMPANY_NAME} merupakan perusahaan yang menyediakan solusi "
        f"teknologi dan layanan keamanan informasi. {PRODUCT_NAME} "
        "merupakan sistem internal perusahaan untuk mendukung "
        "pengelolaan kehadiran karyawan."
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


COMPANY_DOCUMENTS = [
    {
        "slug": "peraturan-perusahaan",
        "label": "Peraturan Perusahaan",
        "filename": "peraturan-perusahaan.txt",
        "category": "Kebijakan Perusahaan",
        "version": "v1.0",
        "status": "Berlaku",
        "updated_at": "12 September 2026",
        "summary": "Ketentuan umum yang berlaku bagi seluruh karyawan PT DrishtiSec.",
        "tagline": "Kebijakan dan ketentuan umum perusahaan",
        "section_titles": ["Jam Kerja", "Kehadiran", "Keterlambatan", "Cuti Tahunan"],
        "closing_title": "Dokumen Internal",
    },
    {
        "slug": "panduan-presensi",
        "label": "Panduan Presensi",
        "filename": "panduan-presensi.txt",
        "category": "Panduan Penggunaan",
        "version": "v1.0",
        "status": "Aktif",
        "updated_at": "12 September 2026",
        "summary": "Panduan penggunaan aplikasi PresensiKu untuk pencatatan kehadiran karyawan.",
        "tagline": "Panduan penggunaan aplikasi PresensiKu",
        "section_titles": ["Membuka Menu Presensi", "Check In", "Check Out", "Riwayat Kehadiran", "Pengajuan Cuti"],
        "closing_title": "Butuh Bantuan?",
    },
]
COMPANY_DOCUMENTS_BY_SLUG = {doc["slug"]: doc for doc in COMPANY_DOCUMENTS}


def _extract_document_parts(raw_text):
    """Split a source document into (numbered items, closing note).

    Ordinary presentation helper for the /dokumen/<slug> viewer — not
    part of the vulnerability surface. Input always comes from a fixed,
    developer-controlled filename (via COMPANY_DOCUMENTS_BY_SLUG), never
    from request input, so this has nothing to do with VAL-TRAV-001.

    Blank lines separate blocks; divider lines of "=" or "-" are
    dropped. The first block (company/document letterhead) is skipped —
    the template renders its own letterhead. Any block where every line
    starts with "N. " contributes its items, in order, to the numbered
    section list (paired with COMPANY_DOCUMENTS' section_titles by the
    caller). The last remaining block becomes the closing note. Content
    itself is never altered, only split apart for layout.
    """
    blocks = []
    current = []

    def flush():
        lines = [ln.strip() for ln in current if not re.fullmatch(r"[=\-]{3,}", ln.strip())]
        current.clear()
        if lines:
            blocks.append(lines)

    for line in raw_text.splitlines():
        if line.strip() == "":
            flush()
        else:
            current.append(line)
    flush()

    numbered_items = []
    closing_lines = []
    for block in blocks[1:]:
        if all(re.match(r"^\d+\.\s", ln) for ln in block):
            numbered_items.extend(re.sub(r"^\d+\.\s*", "", ln) for ln in block)
        else:
            closing_lines = block
    return numbered_items, " ".join(closing_lines)


def _document_pdf_footer(canvas, pdf_doc):
    canvas.saveState()
    canvas.setFont("Lato", 8)
    canvas.setFillColor(_PDF_MUTED)
    canvas.drawString(0.75 * inch, 0.5 * inch, f"{COMPANY_NAME} — Dokumen Internal")
    canvas.drawRightString(LETTER[0] - 0.75 * inch, 0.5 * inch, f"Page {pdf_doc.page}")
    canvas.restoreState()


def generate_document_pdf(doc, sections, closing_note):
    """Render a real, populated PDF for a /dokumen/<slug> document —
    reuses the same ReportLab setup (fonts, styles, PT DrishtiSec cover
    treatment) already registered for the security validation report,
    per a completely separate, non-empty document each time this is
    called. Never cached across requests, so it always reflects the
    current section content.
    """
    path = os.path.join(REPORTS_DIR, f"dokumen-{doc['slug']}.pdf")
    pdf_doc = SimpleDocTemplate(
        path, pagesize=LETTER,
        topMargin=0, bottomMargin=0.85 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        title=doc["label"],
    )
    story = []

    brand_cell = [
        Paragraph(COMPANY_NAME, _PDF_STYLES["brand"]),
        Paragraph(doc["label"], _PDF_STYLES["brand_sub"]),
    ]
    cover_row = [brand_cell]
    cover_col_widths = [7 * inch]
    if os.path.exists(LOGO_PATH):
        cover_row = [Image(LOGO_PATH, width=0.85 * inch, height=0.85 * inch), brand_cell]
        cover_col_widths = [1.15 * inch, 5.85 * inch]
    cover = Table([cover_row], colWidths=cover_col_widths)
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 30),
        ("LEFTPADDING", (-1, 0), (-1, 0), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 28),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
    ]))
    story.append(cover)
    story.append(Spacer(1, 20))

    meta_rows = [
        ["Kategori", doc["category"]],
        ["Terakhir Diperbarui", doc["updated_at"]],
        ["Versi", doc["version"]],
        ["Status", doc["status"]],
    ]
    meta_table = Table(
        [[Paragraph(f"<b>{k}</b>", _PDF_STYLES["body"]), Paragraph(v, _PDF_STYLES["body"])]
         for k, v in meta_rows],
        colWidths=[1.8 * inch, 5.2 * inch],
    )
    meta_table.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    for i, (title, body) in enumerate(sections, start=1):
        story.append(Paragraph(f"{i:02d}. {title}", _PDF_STYLES["h2"]))
        story.append(Paragraph(body, _PDF_STYLES["body"]))

    if closing_note:
        story.append(Spacer(1, 10))
        story.append(Paragraph(closing_note, _PDF_STYLES["small"]))

    pdf_doc.build(story, onFirstPage=_document_pdf_footer, onLaterPages=_document_pdf_footer)
    return path


@app.route("/portal/direktori")
@login_required
def direktori():
    cur = MEMBERS_DB.cursor()
    cur.execute(
        "SELECT id, employee_id, full_name, position, department FROM members ORDER BY id"
    )
    members = cur.fetchall()
    return render_template(
        "direktori.html",
        breadcrumb=["Direktori Karyawan"],
        members=members,
    )


@app.route("/portal/perusahaan")
@login_required
def perusahaan():
    return render_template(
        "perusahaan.html",
        breadcrumb=["Informasi Perusahaan"],
        company=COMPANY_INFO,
        documents=COMPANY_DOCUMENTS,
    )


# ----------------------------------------------------------------------
# /dokumen/<slug> — the normal, user-facing document viewer for the
# "Dokumen Perusahaan" card on Informasi Perusahaan. This is an
# ordinary authenticated presentation feature, unrelated to the
# VAL-TRAV-001 vulnerability surface: `slug` is only ever looked up
# against the fixed COMPANY_DOCUMENTS_BY_SLUG dict below, never used to
# build a filesystem path, so no request input reaches the filesystem
# here. /api/file (the actual vulnerable endpoint) is untouched and
# stays reachable for security validation — it is simply no longer
# linked from this normal page.
# ----------------------------------------------------------------------
@app.route("/dokumen/<slug>")
@login_required
def dokumen_viewer(slug):
    doc = COMPANY_DOCUMENTS_BY_SLUG.get(slug)
    if not doc:
        abort(404)
    file_path = os.path.join(TRAV_BASE_DIR, doc["filename"])
    try:
        with open(file_path, "r") as f:
            raw_text = f.read()
    except OSError:
        abort(404)
    items, closing_note = _extract_document_parts(raw_text)
    sections = list(zip(doc["section_titles"], items))
    other_documents = [d for d in COMPANY_DOCUMENTS if d["slug"] != slug]
    return render_template(
        "dokumen_viewer.html",
        breadcrumb=["Informasi Perusahaan", doc["label"]],
        doc=doc,
        sections=sections,
        closing_note=closing_note,
        other_documents=other_documents,
    )


@app.route("/dokumen/<slug>/unduh")
@login_required
def dokumen_download(slug):
    doc = COMPANY_DOCUMENTS_BY_SLUG.get(slug)
    if not doc:
        abort(404)
    file_path = os.path.join(TRAV_BASE_DIR, doc["filename"])
    try:
        with open(file_path, "r") as f:
            raw_text = f.read()
    except OSError:
        abort(404)
    items, closing_note = _extract_document_parts(raw_text)
    sections = list(zip(doc["section_titles"], items))
    pdf_path = generate_document_pdf(doc, sections, closing_note)
    return send_file(
        pdf_path, mimetype="application/pdf", as_attachment=True,
        download_name=f"{doc['slug']}.pdf",
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
# same VALIDATION_DEFS / application-log evidence and live route
# enumeration used by the portal pages — no fabricated report data.
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


def _pdf_esc(value):
    """Escape a value for safe inclusion in a ReportLab Paragraph/Table
    cell. Several finding fields (e.g. VAL-XSS-001's WAF request pattern
    and matched pattern) genuinely contain raw "<", ">", "&" — ReportLab's
    Paragraph mini-markup parser treats those as tags and raises a syntax
    error unless escaped first.
    """
    return _xml_escape("" if value is None else str(value))


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
        Paragraph(COMPANY_NAME, _PDF_STYLES["brand"]),
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
        "This report documents a controlled black-box web application security "
        "assessment performed against an isolated laboratory target (PresensiKu). "
        "Seven vulnerabilities — OS Command Injection, Local File Inclusion, "
        "Directory Traversal, SQL Injection (UNION-based), Server-Side "
        "Request Forgery, Unrestricted File Upload / Web Shell, and Reflected "
        "Cross-Site Scripting — were independently discovered through "
        "application enumeration, endpoint discovery, and parameter testing, "
        "then validated for impact. Each validated finding was subsequently "
        "correlated against prior WAF analysis, which recorded matching "
        "request patterns as observed production traffic. All seven findings "
        "were successfully validated.",
        _PDF_STYLES["body"],
    ))
    story.append(Paragraph(
        "<b>This assessment was performed entirely within an isolated laboratory "
        "environment. It does not represent, and must not be interpreted as, "
        "exploitation of any production system.</b>",
        _PDF_STYLES["body"],
    ))

    story.append(Paragraph("Scope", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        f"Target application: PresensiKu — Employee Attendance System, running "
        f"at {LAB_HOST_ENV}:{LAB_PORT_ENV} inside an isolated laboratory network. "
        "Testing was limited to this application and host; no external systems "
        "were in scope or contacted.",
        _PDF_STYLES["body"],
    ))

    story.append(Paragraph("Methodology", _PDF_STYLES["h1"]))
    for step in (
        "Reconnaissance — identify the target application, technology stack, "
        "and normal functionality.",
        "Enumeration — discover reachable endpoints through direct browsing "
        "and content/directory enumeration.",
        "Application Discovery — map discovered endpoints to the application "
        "features and parameters that reach them.",
        "Manual Testing — probe discovered parameters for injection and "
        "path-handling weaknesses.",
        "Vulnerability Validation — confirm real, observable impact for each "
        "candidate weakness in the isolated lab.",
        "WAF Correlation — cross-reference each validated finding against "
        "prior WAF analysis to confirm the same pattern was observed in "
        "production traffic.",
        "Evidence & Reporting — capture request/response evidence and local "
        "artifacts, then compile this report.",
    ):
        story.append(Paragraph(f"&bull; {step}", _PDF_STYLES["body"]))

    story.append(Paragraph("Reconnaissance", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        f"Target: {LAB_HOST_ENV}:{LAB_PORT_ENV}  |  Server: Werkzeug (Flask "
        "development server)  |  Application: PresensiKu, an employee "
        "attendance system presenting a normal login-gated business "
        "application with no vulnerability information disclosed on its "
        "public-facing pages.",
        _PDF_STYLES["mono"],
    ))

    story.append(Paragraph("Enumeration", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "Endpoints reachable on the target, as registered by the application "
        "at the time this report was generated:",
        _PDF_STYLES["body"],
    ))
    enum_rows = [["Method", "Endpoint"]]
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if rule.endpoint == "static":
            continue
        methods = ", ".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
        enum_rows.append([methods, rule.rule])
    enum_table = Table(enum_rows, colWidths=[1.3 * inch, 5.9 * inch])
    enum_table.setStyle(_pdf_table_style())
    story.append(enum_table)
    story.append(Paragraph(
        "The /admin path returned a distinct response from unregistered paths, "
        "indicating an internal panel; enumerating beneath it surfaced "
        "/admin/config.",
        _PDF_STYLES["small"],
    ))

    story.append(Paragraph("Application Discovery", _PDF_STYLES["h1"]))
    disc_rows = [["Endpoint", "Parameter", "How It Was Found"]]
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        disc_rows.append([_pdf_esc(v["endpoint"]), _pdf_esc(v["param"]), _pdf_esc(v["discovery_source"])])
    disc_table = Table(disc_rows, colWidths=[1.3 * inch, 0.9 * inch, 5 * inch])
    disc_table.setStyle(_pdf_table_style())
    story.append(disc_table)

    story.append(Paragraph("Findings", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "Each finding below follows the same pipeline: Objective, Recon, "
        "Discovery, Baseline Request, Security Testing, Validation, "
        "Controlled Impact — all performed independently in this isolated "
        "lab before any WAF data was consulted (see WAF Correlation, below).",
        _PDF_STYLES["small"],
    ))
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        story.append(Paragraph(
            f"{_pdf_esc(vid)} — {_pdf_esc(v['title'])} (Severity: {_pdf_esc(v['severity'])})", _PDF_STYLES["h2"]
        ))
        if v.get("objective"):
            story.append(Paragraph(f"<b>Objective:</b> {_pdf_esc(v['objective'])}", _PDF_STYLES["body"]))
        if v.get("recon"):
            story.append(Paragraph(f"<b>Recon:</b> {_pdf_esc(v['recon'])}", _PDF_STYLES["body"]))
        story.append(Paragraph(f"<b>Discovery:</b> {_pdf_esc(v['discovery_source'])}", _PDF_STYLES["body"]))
        story.append(Paragraph(
            f"<b>Baseline / Testing / Validation:</b> {_pdf_esc(v['technical_summary'])}",
            _PDF_STYLES["body"],
        ))
        story.append(Paragraph(
            f"<b>Controlled Impact:</b> {_pdf_esc(v['business_impact'])}", _PDF_STYLES["body"]
        ))
        if v.get("impact_note"):
            story.append(Paragraph(_pdf_esc(v["impact_note"]), _PDF_STYLES["small"]))

    story.append(Paragraph("Validation Results", _PDF_STYLES["h1"]))
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        story.append(Paragraph(f"{_pdf_esc(vid)} — {_pdf_esc(v['title'])}", _PDF_STYLES["h2"]))
        story.append(Paragraph(
            f"Status: <b>VALIDATED</b> &nbsp;&nbsp; WAF Reference: {_pdf_esc(v['waf_reference'])} "
            f"&nbsp;&nbsp; Endpoint: {_pdf_esc(v['endpoint'])}",
            _PDF_STYLES["mono"],
        ))
        story.append(Paragraph(
            f"Exact WAF Request Replay: {_pdf_esc(v['waf_request_pattern'])}",
            _PDF_STYLES["mono"],
        ))
        story.append(Paragraph(
            f"Local evidence: {_pdf_esc(v['local_evidence_path'])}",
            _PDF_STYLES["mono"],
        ))
        if v.get("waf_message"):
            story.append(Paragraph(f"WAF message: {_pdf_esc(v['waf_message'])}", _PDF_STYLES["mono"]))
        if v.get("lab_result"):
            story.append(Paragraph(f"Laboratory result: {_pdf_esc(v['lab_result'])}", _PDF_STYLES["mono"]))
        if vid == "VAL-CMD-001":
            story.append(Paragraph(
                "WAF evidence: GET-based request pattern. Laboratory validation: "
                "GET and POST. POST was added as an additional controlled test of "
                "the same execution primitive and was NOT observed in the original "
                "WAF evidence.",
                _PDF_STYLES["body"],
            ))
        else:
            story.append(Paragraph(_pdf_esc(v["waf_note"]), _PDF_STYLES["body"]))

    story.append(Paragraph("Evidence", _PDF_STYLES["h1"]))
    for scenario in build_evidence_scenarios(limit_per_scenario=1):
        v = VALIDATION_DEFS[scenario["id"]]
        story.append(Paragraph(f"{_pdf_esc(scenario['id'])} — {_pdf_esc(v['title'])}", _PDF_STYLES["h2"]))
        if scenario["entries"]:
            e = scenario["entries"][0]
            story.append(Paragraph(
                f"timestamp={_pdf_esc(e['timestamp'])} source_ip={_pdf_esc(e['source_ip'])} "
                f"method={_pdf_esc(e['method'])} endpoint={_pdf_esc(e['endpoint'])} status={_pdf_esc(e['status'])}",
                _PDF_STYLES["mono"],
            ))
            story.append(Paragraph(_pdf_esc(e["behavior"]), _PDF_STYLES["body"]))
        else:
            story.append(Paragraph(
                "No application log entry captured yet for this scenario.",
                _PDF_STYLES["small"],
            ))

    story.append(Paragraph("Impact", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "Combined, these findings would allow an attacker to execute arbitrary "
        "operating-system commands (directly, and via an uploaded script), to "
        "read arbitrary files readable by the application process — including "
        "application configuration, database credentials, and cloud/service "
        "credentials — to extract arbitrary application-database records "
        "including internal service credentials, and to make the server issue "
        "requests to internal-only infrastructure, and to execute arbitrary "
        "JavaScript in a victim's browser session against the application "
        "origin. Any one of these findings, if present in a production "
        "deployment, would be sufficient for significant data exposure or "
        "full host compromise; together they indicate a systemic lack of "
        "input validation and output encoding across the application's "
        "file-, command-, query-, upload-, and output-handling parameters.",
        _PDF_STYLES["body"],
    ))

    story.append(Paragraph("Recommendations", _PDF_STYLES["h1"]))
    for rec in (
        "Never pass user-supplied input to a shell or subprocess call. If "
        "external command execution is required, use a fixed allow-list of "
        "commands and pass arguments without shell interpretation "
        "(e.g. shell=False with an argument list).",
        "Never build filesystem paths by concatenating user input. Resolve the "
        "requested path and verify it remains within the intended directory "
        "before opening it (canonicalize and prefix-check, or use a "
        "framework-provided safe-join helper).",
        "Apply the same path-handling fix consistently across every endpoint "
        "that accepts a file or path parameter (this assessment found the "
        "same class of issue on two independent endpoints).",
        "Do not expose internal/administrative endpoints without "
        "authentication and network-level restriction; remove or properly "
        "gate legacy admin panels before deployment.",
        "Add automated regression tests asserting that traversal sequences "
        "and shell metacharacters are rejected by these parameters.",
        "Use parameterized queries or an ORM's bound-parameter interface for "
        "all database access; never build SQL strings from request input.",
        "Validate and allow-list destination hosts before any server-side "
        "HTTP fetch; deny requests to loopback, link-local, and private "
        "address ranges.",
        "Enforce a strict file-type allow-list (validated by content, not "
        "extension) on all upload endpoints, and never execute or interpret "
        "uploaded file content.",
        "Never disable a templating engine's automatic output escaping "
        "(e.g. Jinja's `| safe` filter) for request-influenced values; where "
        "rich HTML must be rendered, pass it through an allow-list HTML "
        "sanitizer instead.",
    ):
        story.append(Paragraph(f"&bull; {rec}", _PDF_STYLES["body"]))

    story.append(Paragraph("WAF Correlation", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "Each finding below was discovered and validated independently, before "
        "its matching WAF reference was consulted. The WAF reference confirms "
        "that the same request pattern was previously observed as production "
        "traffic — it is corroborating evidence, not the source of discovery.",
        _PDF_STYLES["body"],
    ))
    corr_rows = [["Validation", "Discovery Source", "WAF Reference", "Status"]]
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        corr_rows.append([_pdf_esc(vid), _pdf_esc(v["discovery_source"]), _pdf_esc(v["waf_reference"]), "Validated"])
    corr_table = Table(corr_rows, colWidths=[1.1 * inch, 4.3 * inch, 1.1 * inch, 0.7 * inch])
    corr_table.setStyle(_pdf_table_style())
    story.append(corr_table)

    story.append(Paragraph(
        "WAF-reported detail for each event, preserved verbatim from the "
        "source WAF dataset:",
        _PDF_STYLES["small"],
    ))
    waf_rows = [["Validation", "Host", "Matched Pattern / Signature", "Action", "Category"]]
    for vid in VALIDATION_ORDER:
        v = VALIDATION_DEFS[vid]
        waf_rows.append([
            _pdf_esc(vid),
            _pdf_esc(v.get("waf_host", "N/A")),
            _pdf_esc(f"{v.get('matched_pattern', 'N/A')} ({v.get('signature_id', 'N/A')})"),
            _pdf_esc(v.get("waf_action", "N/A")),
            _pdf_esc(v.get("attack_category", "N/A")),
        ])
    waf_table = Table(waf_rows, colWidths=[1.0 * inch, 1.5 * inch, 2.1 * inch, 0.9 * inch, 1.7 * inch])
    waf_table.setStyle(_pdf_table_style())
    story.append(waf_table)

    story.append(Paragraph("Conclusion", _PDF_STYLES["h1"]))
    story.append(Paragraph(
        "All seven findings — OS Command Injection, Local File Inclusion, "
        "Directory Traversal, SQL Injection (UNION-based), Server-Side "
        "Request Forgery, Unrestricted File Upload / Web Shell, and Reflected "
        "Cross-Site Scripting — were independently discovered through "
        "application assessment and "
        "successfully validated with observable impact against the isolated "
        "laboratory target. Each finding's request pattern was subsequently "
        "corroborated by prior WAF analysis. This constitutes successful "
        "controlled reproduction in an isolated vulnerable environment, not "
        "exploitation of a production system.",
        _PDF_STYLES["body"],
    ))

    doc.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return REPORT_PATH


# ======================================================================
# Discovery surface for VAL-CMD-001.
#
# /admin is a leftover internal ops panel — NOT linked from PresensiKu's
# navigation, but reachable directly and by content/endpoint enumeration
# (e.g. gobuster finding "admin" from a common wordlist). It has no real
# authentication (submitting the login form always reports invalid
# credentials); its purpose is purely to be a plausible surface a tester
# would enumerate and inspect, from which /admin/config's "cmd" parameter
# can be discovered via an on-page link and HTML-source comment — WITHOUT
# needing to already know the WAF finding.
# ======================================================================
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    error = None
    if request.method == "POST":
        error = "Invalid credentials."
    return render_template("admin.html", error=error)


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

_WAF_STYLE_PARAM_CACHE = {}


def _get_waf_style_param(key):
    """Read `key` from normal GET/POST parsing first (request.values).

    If that finds nothing, fall back to parsing the raw query string for
    the WAF-log-style form where the key/value separator itself was
    percent-encoded (e.g. "cmd%3Dcat/root/.aws/credentials" instead of
    "cmd=cat/root/.aws/credentials"). Standard query-string parsing
    splits on a literal "=" BEFORE percent-decoding, so that form is
    otherwise invisible to request.values — this lets a WAF-evidence URL
    be replayed exactly as it appears in the finalized WAF Excel.

    Also tolerates a single stray backtick between the key and the
    encoded "=" (e.g. "id`%3D520)..."), exactly as recorded in the
    SP_PAM-047 WAF event for VAL-SQLI-001 — some WAF export tooling
    appends this artifact to the raw request line. Matching is
    case-insensitive, mirroring how WAF signature matching itself is
    typically case-insensitive.
    """
    value = request.values.get(key, "")
    if value:
        return value

    raw_qs = request.query_string.decode("utf-8", errors="replace")
    pattern = _WAF_STYLE_PARAM_CACHE.get(key)
    if pattern is None:
        pattern = re.compile(re.escape(key) + r"`?%3[dD]")
        _WAF_STYLE_PARAM_CACHE[key] = pattern
    match = pattern.search(raw_qs)
    if not match:
        return ""
    start = match.end()
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
    # CMD_EXEC_CWD (lab-data/cmd-root/) symlinks back to the real
    # project tree, so ls/pwd/whoami/cat <realfile>/etc. genuinely
    # execute against the real lab filesystem. The exact WAF-evidence
    # command additionally works for real because that directory also
    # contains a real executable file at the relative path
    # "cat/root/.aws/credentials" — see that file for the explanation.
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
            cwd=CMD_EXEC_CWD,     # see lab-data/cmd-root/ — no string substitution
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
        # Realistic missing-parameter error — reveals the "file" param
        # through ordinary endpoint behavior, not through WAF evidence.
        return Response("Error: missing required parameter 'file'.\n", mimetype="text/plain")

    return _serve_lfi_target(supplied_file, "VAL-LFI-001", "/read", source_ip, LFI_BASE_DIR)


@app.route("/api", methods=["GET"])
def api_root():
    # Minimal API root so that content/endpoint enumeration under /api
    # is possible before finding /api/file — mirrors the same
    # discoverability pattern as /admin before /admin/config.
    return Response("PresensiKu internal API.\n", mimetype="text/plain")


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
        # Realistic missing-parameter error — reveals the "path" param
        # through ordinary endpoint behavior, not through WAF evidence.
        return Response("Error: missing required parameter 'path'.\n", mimetype="text/plain")

    return _serve_lfi_target(supplied_path, "VAL-TRAV-001", "/api/file", source_ip, TRAV_BASE_DIR, param_name="path")


# ======================================================================
# VAL-SQLI-001. /search/members/ is the backend for the "Direktori
# Karyawan" page's per-employee "Lihat Detail" links (?id=1, ?id=2,
# ...) — that is how the "id" parameter is discovered, without any WAF
# knowledge. The supplied value is formatted directly into the SQL
# string with no parameter binding and executed as-is against the real
# MEMBERS_DB SQLite connection, via the vulnerable query layer defined
# above (_SQLI_SELECT_COLUMNS, _balance_sqli_parens, _sqli_unhex) —
# built specifically so the exact, unmodified SP_PAM-047 payload (32
# expressions, unhex() included) executes natively. Do NOT add input
# validation/binding here — it would defeat the purpose of the lab.
# ======================================================================
@app.route("/search/members/", methods=["GET"])
def search_members():
    # _get_waf_style_param() lets the exact WAF-evidence URL for
    # SP_PAM-047 be replayed byte-for-byte: its "id" key is followed by
    # a stray backtick and its "=" is itself percent-encoded
    # ("id`%3D520)..."), which plain request.args parsing cannot see.
    source_ip = request.remote_addr or "unknown"
    raw_query = request.query_string.decode("utf-8", errors="replace")
    supplied_id = _get_waf_style_param("id")

    if not supplied_id:
        logger.info(
            "VAL-SQLI-001 | ip=%s | method=%s | endpoint=/search/members/ | "
            "raw_query=%r | id=<none> | status=NO_INPUT",
            source_ip, request.method, raw_query,
        )
        return render_template(
            "search_results.html", query_id="", columns=[],
            rows=[], error=None, no_input=True,
        )

    # Vulnerable query layer: SELECT from the dedicated sqli_members
    # table, which has exactly the 32 real, realistic HR-record columns
    # (_SQLI_MEMBERS_COLUMNS) SP_PAM-047's 32-expression UNION SELECT
    # expects — no NULL padding, no forcing the ordinary "members" table
    # into an unrealistic shape (that table is untouched, used only by
    # /portal/direktori). Plus generic paren-balancing (applied to every
    # request, not attack-specific) on the "IN (...)" clause.
    sql = (
        f"SELECT {_SQLI_SELECT_COLUMNS} FROM sqli_members "
        f"WHERE id IN ({_balance_sqli_parens(supplied_id)}"
    )
    raw_rows, error = [], None
    try:
        cur = MEMBERS_DB.cursor()
        cur.execute(sql)
        raw_rows = cur.fetchall()
        status = "QUERY_EXECUTED" if raw_rows else "NO_MATCH"
    except Exception as exc:  # pragma: no cover - defensive only
        error = f"Query error: {exc}"
        status = "ERROR"

    # The renderer always shows exactly what the query layer returned —
    # all 32 real columns for a normal lookup (a legitimate full-profile
    # employee search result), and whatever the UNION SELECT actually
    # produced for the exact WAF payload. No branching on "is this an
    # attack" anywhere here; same code path, same template, either way.
    result_sample = raw_rows[0] if raw_rows else ()

    logger.info(
        "VAL-SQLI-001 | ip=%s | method=%s | endpoint=/search/members/ | "
        "raw_query=%r | id=%r | sql=%r | rows=%d | result_sample=%r | "
        "sqlite_error=%r | status=%s",
        source_ip, request.method, raw_query, supplied_id, sql,
        len(raw_rows), result_sample, error or "", status,
    )
    return render_template(
        "search_results.html", query_id=supplied_id,
        columns=_SQLI_MEMBERS_LABELS, rows=raw_rows, error=error, no_input=False,
    )


# ======================================================================
# VAL-SSRF-001. /CookieAuth.dll is discovered via the Settings page's
# "Integrasi Webmail Kantor (OWA)" connection-test feature. It accepts
# either the simplified "url" parameter that feature's form submits, or
# the raw WAF-evidence-style nested "GetLogon?url=...redir.asp?URL=..."
# shape (also linked from that same Settings section), then performs a
# genuine server-side HTTP fetch of the resolved target with
# urllib.request — no destination allow-list. Do NOT add host
# validation here — it would defeat the purpose of the lab.
# ======================================================================
def _resolve_ssrf_target():
    raw_qs = request.query_string.decode("utf-8", errors="replace")
    marker = "GetLogon?url="
    idx = raw_qs.find(marker)
    if idx != -1:
        start = idx + len(marker)
        end = raw_qs.find("&", start)
        nested = unquote(raw_qs[start:] if end == -1 else raw_qs[start:end])
        if "URL=" in nested:
            return unquote(nested.split("URL=", 1)[1])
        return nested
    return request.args.get("url", "")


@app.route("/CookieAuth.dll", methods=["GET"])
def cookie_auth():
    source_ip = request.remote_addr or "unknown"
    raw_query = request.query_string.decode("utf-8", errors="replace")
    target_url = _resolve_ssrf_target()

    if not target_url:
        logger.info(
            "VAL-SSRF-001 | ip=%s | method=%s | endpoint=/CookieAuth.dll | "
            "raw_query=%r | url=<none> | status=NO_INPUT",
            source_ip, request.method, raw_query,
        )
        return render_template(
            "ssrf_result.html", target_url="", status_code=None, body=None,
            error=None, no_input=True,
        )

    if target_url.startswith("/"):
        target_url = f"http://{LAB_HOST_ENV}:{LAB_PORT_ENV}{target_url}"

    status_code, body, error = None, None, None
    try:
        req = urllib.request.Request(
            target_url, headers={"User-Agent": "PresensiKu-WebmailSync/1.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            status_code = resp.status
            body = resp.read(4096).decode("utf-8", errors="replace")
        status = "FETCHED"
    except Exception as exc:  # pragma: no cover - defensive only
        error = f"Connection error: {exc}"
        status = "ERROR"

    logger.info(
        "VAL-SSRF-001 | ip=%s | method=%s | endpoint=/CookieAuth.dll | "
        "raw_query=%r | url=%r | resp_status=%s | status=%s",
        source_ip, request.method, raw_query, target_url, status_code, status,
    )
    return render_template(
        "ssrf_result.html", target_url=target_url, status_code=status_code,
        body=body, error=error, no_input=False,
    )


# ======================================================================
# VAL-UPLOAD-001. The endpoint is the exact WAF-evidence path
# (UPLOAD_ENDPOINT_PATH, "/defaultroot/upload/fileUpload.controller"),
# discovered via the Cuti & Izin page's "Ajukan Cuti Baru" form's
# "Upload Surat Keterangan" file input (its <form action> points here).
# No extension/content-type allow-list is applied when saving the
# file; recognized script extensions (.py, .sh) are then genuinely
# executed via subprocess.run (same real-execution pattern as
# VAL-CMD-001), framed in-app as an automatic document-preview step.
# Do NOT add extension validation here — it would defeat the purpose
# of the lab.
# ======================================================================
@app.route(UPLOAD_ENDPOINT_PATH, methods=["POST"])
def cuti_upload():
    source_ip = request.remote_addr or "unknown"
    leave_type = request.form.get("leave_type", "")
    uploaded = request.files.get("document")

    if not uploaded or not uploaded.filename:
        logger.info(
            "VAL-UPLOAD-001 | ip=%s | method=%s | endpoint=%s | "
            "filename=<none> | status=NO_INPUT",
            source_ip, request.method, UPLOAD_ENDPOINT_PATH,
        )
        return Response("Error: no document uploaded.\n", mimetype="text/plain")

    filename = os.path.basename(uploaded.filename)
    saved_path = os.path.join(CUTI_UPLOAD_DIR, filename)
    uploaded.save(saved_path)

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    output_lines = [
        f"Dokumen '{filename}' diterima untuk pengajuan '{leave_type}'.",
        f"Tersimpan di: {saved_path}",
    ]

    if ext in ("py", "sh"):
        interpreter = "python3" if ext == "py" else "bash"
        try:
            completed = subprocess.run(
                [interpreter, saved_path], capture_output=True, text=True, timeout=5,
            )
            output_lines.append("Auto-preview processor output:")
            output_lines.append(completed.stdout + completed.stderr)
            status = "SCRIPT_EXECUTED"
        except Exception as exc:  # pragma: no cover - defensive only
            output_lines.append(f"Execution error: {exc}")
            status = "ERROR"
    else:
        output_lines.append("(No preview processor registered for this extension.)")
        status = "ACCEPTED"

    logger.info(
        "VAL-UPLOAD-001 | ip=%s | method=%s | endpoint=%s | "
        "filename=%r | ext=%r | status=%s",
        source_ip, request.method, UPLOAD_ENDPOINT_PATH, filename, ext, status,
    )
    return Response("\n".join(output_lines) + "\n", mimetype="text/plain")


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
