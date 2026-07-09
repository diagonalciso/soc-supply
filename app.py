#!/usr/bin/env python3
"""soc-supply — third-party / supply-chain exposure monitor (:8109).

Keeps a private register of the organisations you depend on (clients, suppliers,
vendors, partners) and checks each one's domain for breach exposure.

PRIVACY — the whole point of this module:
  * The party register NEVER leaves this host. There is no upload path: this
    service does not POST to soc-intel /intel/bulk, does not create cases, and
    does not ship the list anywhere. `tests` in CI assert that.
  * By default the only thing contacted is your own self-hosted soc-intel, whose
    darkweb store already holds the breach corpus. Nothing about your party list
    reaches a third party.
  * EXTERNAL_LOOKUPS=1 additionally performs a live Hudson Rock infostealer query
    per domain (proxied by soc-intel, but the domain does reach Hudson Rock).
    Opt-in only — same idiom as soc-osint's ACTIVE_PROBES.

Sources (self-hosted soc-intel darkweb store):
  credential-exposure · stealer-log · iab-listing · ransomware-leak · tg-message
Source (external, opt-in): Hudson Rock Cavalier via soc-intel /enrich/hudsonrock.

Register management: add / edit / delete in the UI, bulk import from CSV or JSON,
export back out to CSV or JSON. Import is idempotent on `domain`.

Deps: none (stdlib). Run: cp .env.example .env && python3 app.py
"""
import csv
import io
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import Request, urlopen

PORT = int(os.getenv("SUPPLY_PORT", "8109"))
# Network-reachable so analysts can open the register from the SOC LAN, like every
# other stdlib module. Privacy here means no OUTBOUND upload of the register (see the
# module docstring + CI guard), not inbound auth. Bind loopback for local-only access.
HOST = os.getenv("SUPPLY_HOST", "0.0.0.0")
DB_PATH = os.getenv("SUPPLY_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "supply.db"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))

# Opt-in: live third-party lookup. Off => nothing but self-hosted soc-intel is queried.
EXTERNAL_LOOKUPS = os.getenv("EXTERNAL_LOOKUPS", "0") == "1"

# Background rescan of the whole register. 0 disables.
SCAN_INTERVAL_H = int(os.getenv("SCAN_INTERVAL_H", "24"))

SOCINT_API_URL = os.getenv("SOCINT_API_URL", "http://localhost:8000/api").rstrip("/")
SOCINT_USER = os.getenv("SOCINT_USER", "admin@socint.internal")
SOCINT_PASS = os.getenv("SOCINT_PASS", "changeme123!")

_UA = "soc-supply/1.0 (+private third-party monitor)"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

CATEGORIES = ("client", "supplier", "vendor", "partner", "subsidiary", "other")
CRITICALITIES = ("low", "medium", "high", "critical")

# soc-intel darkweb types queried with ?q=<domain>, then post-filtered.
_Q_TYPES = ("stealer-log", "iab-listing", "ransomware-leak")

# finding kind -> severity
_SEVERITY = {
    "ransomware-leak": "critical",
    "credential-exposure": "high",
    "stealer-log": "high",
    "infostealer": "high",
    "iab-listing": "high",
    "tg-message": "medium",
}

_scan_lock = threading.Lock()
_running = set()          # domains with an in-flight scan


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS parties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL DEFAULT 'supplier',
    criticality TEXT NOT NULL DEFAULT 'medium',
    contact TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    added TEXT NOT NULL,
    last_scan TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    party_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    severity TEXT NOT NULL,
    breach_date TEXT,
    detail TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(party_id, kind, ref)
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    party_id INTEGER,
    domain TEXT,
    total INTEGER DEFAULT 0,
    new INTEGER DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_find_party ON findings(party_id);
CREATE INDEX IF NOT EXISTS idx_scan_party ON scans(party_id);
"""


def _db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def _init_db():
    c = _db()
    c.executescript(SCHEMA)
    c.commit()
    c.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# register CRUD
# --------------------------------------------------------------------------- #
def _clean_party(p):
    """Validate + normalise an inbound party dict. Returns (dict, error)."""
    # CSV rows with short lines hand us None, so coalesce every field.
    name = str(p.get("name") or "").strip()
    domain = str(p.get("domain") or "").strip().lower().lstrip("*.")
    if domain.startswith("http"):
        domain = urlparse(domain).netloc or domain
    if not name:
        return None, "name is required"
    if not _DOMAIN_RE.match(domain):
        return None, f"invalid domain: {domain or '(empty)'}"
    cat = str(p.get("category") or "supplier").strip().lower()
    crit = str(p.get("criticality") or "medium").strip().lower()
    return {
        "name": name,
        "domain": domain,
        "category": cat if cat in CATEGORIES else "other",
        "criticality": crit if crit in CRITICALITIES else "medium",
        "contact": str(p.get("contact", "") or "").strip(),
        "notes": str(p.get("notes", "") or "").strip(),
    }, None


def add_party(p):
    row, err = _clean_party(p)
    if err:
        return {"error": err}
    c = _db()
    try:
        cur = c.execute(
            "INSERT INTO parties (name,domain,category,criticality,contact,notes,added) "
            "VALUES (:name,:domain,:category,:criticality,:contact,:notes,:added)",
            {**row, "added": _now()})
        c.commit()
        return {"id": cur.lastrowid, **row}
    except sqlite3.IntegrityError:
        return {"error": f"{row['domain']} is already in the register"}
    finally:
        c.close()


def update_party(pid, p):
    row, err = _clean_party(p)
    if err:
        return {"error": err}
    c = _db()
    try:
        cur = c.execute(
            "UPDATE parties SET name=:name, domain=:domain, category=:category, "
            "criticality=:criticality, contact=:contact, notes=:notes WHERE id=:id",
            {**row, "id": pid})
        c.commit()
        if cur.rowcount == 0:
            return {"error": "no such party"}
        # domain may have changed: findings keyed on party_id stay, refresh their domain
        c.execute("UPDATE findings SET domain=? WHERE party_id=?", (row["domain"], pid))
        c.commit()
        return {"id": pid, **row}
    except sqlite3.IntegrityError:
        return {"error": f"{row['domain']} belongs to another party"}
    finally:
        c.close()


def delete_party(pid):
    c = _db()
    c.execute("DELETE FROM findings WHERE party_id=?", (pid,))
    c.execute("DELETE FROM scans WHERE party_id=?", (pid,))
    cur = c.execute("DELETE FROM parties WHERE id=?", (pid,))
    c.commit()
    c.close()
    return {"deleted": cur.rowcount}


def list_parties():
    c = _db()
    rows = c.execute("""
        SELECT p.*,
               (SELECT COUNT(*) FROM findings f WHERE f.party_id = p.id) AS findings,
               (SELECT COUNT(*) FROM findings f WHERE f.party_id = p.id
                                              AND f.severity IN ('critical','high')) AS serious
        FROM parties p ORDER BY p.name COLLATE NOCASE""").fetchall()
    c.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# import / export — local files only, never the network
# --------------------------------------------------------------------------- #
_CSV_FIELDS = ["name", "domain", "category", "criticality", "contact", "notes"]


def import_rows(rows):
    """Idempotent on domain: existing entries are updated, new ones inserted."""
    added = updated = skipped = 0
    errors = []
    existing = {p["domain"]: p["id"] for p in list_parties()}
    for raw in rows:
        row, err = _clean_party(raw)
        if err:
            errors.append(err)
            skipped += 1
            continue
        pid = existing.get(row["domain"])
        if pid:
            res = update_party(pid, row)
            updated += 0 if res.get("error") else 1
        else:
            res = add_party(row)
            if res.get("error"):
                errors.append(res["error"])
                skipped += 1
            else:
                existing[row["domain"]] = res["id"]
                added += 1
    return {"added": added, "updated": updated, "skipped": skipped, "errors": errors[:20]}


def parse_import(body, ctype):
    """Accept a JSON list, a JSON {parties:[...]} envelope, or CSV text."""
    text = body.decode("utf-8", "replace").strip()
    if not text:
        return [], "empty payload"
    if text[0] in "[{" or "json" in (ctype or ""):
        try:
            doc = json.loads(text)
        except ValueError as e:
            return [], f"bad JSON: {e}"
        rows = doc.get("parties") if isinstance(doc, dict) else doc
        if not isinstance(rows, list):
            return [], "JSON must be a list of parties"
        return rows, None
    # CSV — with or without a header row
    sample = text.splitlines()[0].lower()
    has_header = "domain" in sample and "name" in sample
    reader = csv.DictReader(io.StringIO(text)) if has_header else \
        csv.DictReader(io.StringIO(text), fieldnames=_CSV_FIELDS)
    return [dict(r) for r in reader], None


def export_csv():
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for p in list_parties():
        w.writerow(p)
    return out.getvalue()


# --------------------------------------------------------------------------- #
# soc-intel queries  (read-only — this module never writes to soc-intel)
# --------------------------------------------------------------------------- #
class Intel:
    """Read-only soc-intel client. Deliberately has no push/create method."""

    def __init__(self):
        self.token = None

    def login(self):
        try:
            payload = json.dumps({"email": SOCINT_USER, "password": SOCINT_PASS}).encode()
            req = Request(f"{SOCINT_API_URL}/auth/login", data=payload,
                          headers={"Content-Type": "application/json", "User-Agent": _UA})
            with urlopen(req, timeout=HTTP_TIMEOUT) as r:
                self.token = json.loads(r.read()).get("access_token")
        except Exception:
            self.token = None
        return self.token

    def get(self, path):
        if not self.token and not self.login():
            return {}
        try:
            req = Request(f"{SOCINT_API_URL}{path}",
                          headers={"Authorization": f"Bearer {self.token}", "User-Agent": _UA})
            with urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return json.loads(r.read())
        except Exception:
            return {}


_intel = Intel()


def _domain_matches(obj, domain):
    """Guard against soc-intel's multi_match over-matching on ?q=."""
    d = domain.lower()
    for f in ("domain", "victim_domain"):
        if str(obj.get(f, "")).lower() == d:
            return True
    for f in ("domains", "affected_domains"):
        vals = obj.get(f) or []
        if isinstance(vals, list) and d in [str(x).lower() for x in vals]:
            return True
    return False


def collect_exposure(domain):
    """Return list[{kind,ref,severity,breach_date,detail}] for one domain."""
    d = quote(domain, safe="")
    found = []

    def emit(kind, ref, breach_date=None, **detail):
        found.append({"kind": kind, "ref": str(ref),
                      "severity": _SEVERITY.get(kind, "medium"),
                      "breach_date": breach_date, "detail": detail})

    # 1. credential-exposure — soc-intel term-filters server-side, trust it
    for obj in _intel.get(f"/darkweb/credentials?domain={d}").get("objects", []):
        emit("credential-exposure",
             obj.get("id") or obj.get("source", "unknown"),
             obj.get("date_discovered") or obj.get("created"),
             source=obj.get("source", ""))

    # 2. q-searched darkweb types — post-filter, ?q= is a fuzzy multi_match
    for t in _Q_TYPES:
        for obj in _intel.get(f"/darkweb/objects?type={t}&q={d}").get("objects", []):
            if not _domain_matches(obj, domain):
                continue
            emit(t, obj.get("id") or f"{t}:{obj.get('source', 'unknown')}",
                 obj.get("date_discovered") or obj.get("date") or obj.get("created"),
                 source=obj.get("source", ""), group=obj.get("group", ""))

    # 3. Telegram breach channels — no structured domain field, match the free text
    for obj in _intel.get(f"/darkweb/objects?type=tg-message&q={d}").get("objects", []):
        if domain.lower() not in str(obj.get("text", "")).lower():
            continue
        emit("tg-message", obj.get("id") or f"tg:{obj.get('channel', 'unknown')}",
             obj.get("created") or obj.get("date_discovered"),
             channel=obj.get("channel", ""))

    # 4. EXTERNAL, opt-in: the domain reaches Hudson Rock. Stable ref so repeat
    #    scans don't churn dedup; live counts live in detail.
    if EXTERNAL_LOOKUPS:
        hr = _intel.get(f"/enrich/hudsonrock/domain/{d}").get("result") or {}
        if hr.get("hudsonrock_exposed"):
            emit("infostealer", "hudsonrock:infostealer",
                 hr.get("last_employee_compromised") or hr.get("last_user_compromised"),
                 corporate_credentials=hr.get("corporate_credentials_exposed", 0) or 0,
                 user_credentials=hr.get("user_credentials_exposed", 0) or 0,
                 malware_families=hr.get("malware_families", []))
    return found


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def scan_party(pid):
    c = _db()
    p = c.execute("SELECT * FROM parties WHERE id=?", (pid,)).fetchone()
    c.close()
    if not p:
        return {"error": "no such party"}
    domain = p["domain"]

    with _scan_lock:
        if domain in _running:
            return {"error": "scan already running for this domain"}
        _running.add(domain)
    try:
        results = collect_exposure(domain)
    except Exception as e:                                    # never let a source kill a scan
        c = _db()
        c.execute("INSERT INTO scans (ts,party_id,domain,error) VALUES (?,?,?,?)",
                  (_now(), pid, domain, str(e)))
        c.commit()
        c.close()
        return {"error": f"scan failed: {e}"}
    finally:
        with _scan_lock:
            _running.discard(domain)

    ts = _now()
    new = 0
    c = _db()
    for f in results:
        known = c.execute("SELECT 1 FROM findings WHERE party_id=? AND kind=? AND ref=?",
                          (pid, f["kind"], f["ref"])).fetchone()
        if not known:
            new += 1
        c.execute(
            "INSERT INTO findings (party_id,domain,kind,ref,severity,breach_date,detail,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(party_id,kind,ref) DO UPDATE SET last_seen=excluded.last_seen, "
            "detail=excluded.detail, severity=excluded.severity",
            (pid, domain, f["kind"], f["ref"], f["severity"], f["breach_date"],
             json.dumps(f["detail"]), ts, ts))
    c.execute("INSERT INTO scans (ts,party_id,domain,total,new) VALUES (?,?,?,?,?)",
              (ts, pid, domain, len(results), new))
    c.execute("UPDATE parties SET last_scan=? WHERE id=?", (ts, pid))
    c.commit()
    c.close()
    return {"party_id": pid, "domain": domain, "total": len(results), "new": new,
            "findings": results}


def scan_all():
    out = []
    for p in list_parties():
        out.append(scan_party(p["id"]))
    return {"scanned": len(out), "results": out}


def _background_scanner():
    if SCAN_INTERVAL_H <= 0:
        return
    time.sleep(30)                     # let soc-intel finish booting
    while True:
        try:
            scan_all()
        except Exception as e:
            print(f"background scan error: {e}")
        time.sleep(SCAN_INTERVAL_H * 3600)


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #
def findings_for(pid=None, limit=500):
    c = _db()
    if pid:
        rows = c.execute("SELECT f.*, p.name FROM findings f JOIN parties p ON p.id=f.party_id "
                         "WHERE f.party_id=? ORDER BY f.last_seen DESC LIMIT ?",
                         (pid, limit)).fetchall()
    else:
        rows = c.execute("SELECT f.*, p.name FROM findings f JOIN parties p ON p.id=f.party_id "
                         "ORDER BY f.last_seen DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d["detail"] or "{}")
        except ValueError:
            d["detail"] = {}
        out.append(d)
    return out


def stats():
    c = _db()
    parties = c.execute("SELECT COUNT(*) FROM parties").fetchone()[0]
    exposed = c.execute("SELECT COUNT(DISTINCT party_id) FROM findings").fetchone()[0]
    serious = c.execute("SELECT COUNT(*) FROM findings WHERE severity IN ('critical','high')").fetchone()[0]
    total = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    by_kind = dict(c.execute("SELECT kind, COUNT(*) FROM findings GROUP BY kind").fetchall())
    by_cat = dict(c.execute("SELECT category, COUNT(*) FROM parties GROUP BY category").fetchall())
    last = c.execute("SELECT MAX(ts) FROM scans").fetchone()[0]
    c.close()
    return {"parties": parties, "exposed": exposed, "findings": total, "serious": serious,
            "by_kind": by_kind, "by_category": by_cat, "last_scan": last,
            "external_lookups": EXTERNAL_LOOKUPS, "scan_interval_h": SCAN_INTERVAL_H,
            "socint": SOCINT_API_URL, "uploads": False}


# --------------------------------------------------------------------------- #
# web
# --------------------------------------------------------------------------- #
PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Supply — Third-Party Exposure</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔗</text></svg>"><style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--txt:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box}body{margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid var(--bd);background:var(--panel)}
h1{margin:0;font-size:18px;letter-spacing:1px;color:var(--accent)}h1 small{font-weight:400;opacity:.55;font-size:.6em;color:var(--txt)}
.meta{font-size:12px;color:var(--dim);text-align:right}
.wrap{max-width:1280px;margin:0 auto;padding:18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:12px}
.kpi .n{font-size:23px;font-weight:700;color:var(--accent)}.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase}
.kpi .n.bad{color:var(--bad)}
.warn{background:#0a1a10;border:1px solid #1d4b30;color:var(--ok);padding:9px 12px;border-radius:8px;margin-bottom:12px;font-size:12px}
.warn.ext{background:#2a1a00;border-color:#5a3a00;color:var(--warn)}
.bar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
input,select,textarea{background:#0a1020;border:1px solid var(--bd);color:var(--txt);padding:8px 10px;border-radius:6px;font-family:inherit}
input{flex:1;min-width:120px}
button{background:var(--accent);color:#04121a;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-family:inherit;font-weight:700}
button.sec{background:transparent;color:var(--accent);border:1px solid var(--bd)}
button.del{background:transparent;color:var(--bad);border:1px solid var(--bd);padding:2px 8px;font-size:11px}
button.edit{background:transparent;color:var(--dim);border:1px solid var(--bd);padding:2px 8px;font-size:11px}
button:disabled{opacity:.5;cursor:wait}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd)}
th{color:var(--dim);font-weight:400;text-transform:uppercase;font-size:10px}
.pill{font-size:10px;padding:1px 6px;border-radius:10px;border:1px solid var(--bd)}
.critical{color:var(--bad);border-color:var(--bad)}.high{color:var(--bad);border-color:var(--bad);opacity:.85}
.medium{color:var(--warn);border-color:var(--warn)}.low{color:var(--dim)}
.clean{color:var(--ok);border-color:var(--ok)}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-top:14px}
h3{margin:0 0 8px;font-size:13px;color:var(--accent)}
.cols{display:grid;grid-template-columns:1.15fr 1fr;gap:16px}
textarea{width:100%;min-height:110px;font-size:11px}
.msg{font-size:12px;margin-top:6px}.err{color:var(--bad)}.good{color:var(--ok)}
@media(max-width:900px){.cols{grid-template-columns:1fr}}
</style></head><body><a href="/manual" target="_blank" title="Manual / Help" style="position:fixed;top:12px;right:14px;z-index:99999;width:30px;height:30px;border-radius:50%;background:#161b22;border:1px solid #30363d;color:#58a6ff;font:700 16px/30px system-ui,sans-serif;text-align:center;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.4)" onmouseover="this.style.borderColor='#58a6ff'" onmouseout="this.style.borderColor='#30363d'">?</a>
<header><h1>SOC Supply <small>third-party exposure · private register</small></h1>
<div class="meta" id="meta">loading…</div></header>
<div class="wrap">
  <div id="mode"></div>
  <div class="kpis">
    <div class="kpi"><div class="n" id="k-parties">--</div><div class="l">Parties</div></div>
    <div class="kpi"><div class="n bad" id="k-exposed">--</div><div class="l">Exposed</div></div>
    <div class="kpi"><div class="n bad" id="k-serious">--</div><div class="l">High/Critical</div></div>
    <div class="kpi"><div class="n" id="k-find">--</div><div class="l">Findings</div></div>
  </div>

  <div class="panel">
    <h3 id="formTitle">Add party</h3>
    <div class="bar">
      <input id="f-name" placeholder="name (e.g. Acme Logistics)">
      <input id="f-domain" placeholder="domain (acme-logistics.com)">
      <select id="f-cat"></select>
      <select id="f-crit"></select>
      <input id="f-contact" placeholder="contact (optional)">
      <input id="f-notes" placeholder="notes (optional)">
      <button id="f-save" onclick="save()">Add</button>
      <button class="sec" id="f-cancel" style="display:none" onclick="resetForm()">Cancel</button>
    </div>
    <div class="msg" id="f-msg"></div>
  </div>

  <div class="cols">
    <div class="panel">
      <h3>Register <button class="sec" style="float:right;padding:3px 10px;font-size:11px" onclick="scanAll()" id="scanBtn">Scan all</button></h3>
      <table><thead><tr><th>name</th><th>domain</th><th>cat</th><th>crit</th><th>exposure</th><th>last scan</th><th></th></tr></thead>
      <tbody id="parties"></tbody></table>
    </div>
    <div class="panel">
      <h3>Findings</h3>
      <table><thead><tr><th>party</th><th>kind</th><th>sev</th><th>ref</th><th>seen</th></tr></thead>
      <tbody id="findings"></tbody></table>
    </div>
  </div>

  <div class="panel">
    <h3>Import / export <span style="color:var(--dim);font-weight:400;font-size:11px">— stays on this host</span></h3>
    <textarea id="imp" placeholder="Paste CSV (name,domain,category,criticality,contact,notes) or a JSON list of objects. Existing domains are updated, not duplicated."></textarea>
    <div class="bar" style="margin-top:8px">
      <button onclick="doImport()">Import</button>
      <button class="sec" onclick="location='/api/export?fmt=csv'">Export CSV</button>
      <button class="sec" onclick="location='/api/export?fmt=json'">Export JSON</button>
      <span class="msg" id="i-msg"></span>
    </div>
  </div>
</div>
<script>
const $=s=>document.querySelector(s);
const CATS=%%CATS%%, CRITS=%%CRITS%%;
let editing=null;
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
CATS.forEach(c=>$('#f-cat').add(new Option(c,c)));
CRITS.forEach(c=>$('#f-crit').add(new Option(c,c)));
$('#f-crit').value='medium';

async function stats(){
  const s=await (await fetch('/api/stats')).json();
  $('#k-parties').textContent=s.parties;$('#k-exposed').textContent=s.exposed;
  $('#k-serious').textContent=s.serious;$('#k-find').textContent=s.findings;
  $('#meta').innerHTML='soc-intel: '+esc(s.socint)+'<br>last scan: '+esc(s.last_scan||'never');
  $('#mode').innerHTML = s.external_lookups
    ? '<div class="warn ext">⚠ EXTERNAL_LOOKUPS=1 — each scan also sends the party domain to Hudson Rock (via soc-intel). The register itself is still never uploaded.</div>'
    : '<div class="warn">Private mode: only your self-hosted soc-intel is queried. No party data leaves this host. Set EXTERNAL_LOOKUPS=1 to add live Hudson Rock lookups.</div>';
}
async function parties(){
  const rows=await (await fetch('/api/parties')).json();
  $('#parties').innerHTML=rows.map(p=>`<tr>
    <td>${esc(p.name)}</td><td style="color:var(--dim)">${esc(p.domain)}</td>
    <td><span class="pill">${esc(p.category)}</span></td>
    <td><span class="pill ${esc(p.criticality)}">${esc(p.criticality)}</span></td>
    <td>${p.findings ? `<span class="pill ${p.serious?'critical':'medium'}">${p.findings} finding(s)</span>` : '<span class="pill clean">clean</span>'}</td>
    <td style="color:var(--dim)">${esc((p.last_scan||'never').replace('T',' ').replace('+00:00','Z'))}</td>
    <td style="white-space:nowrap">
      <button class="edit" onclick='scanOne(${p.id})'>scan</button>
      <button class="edit" onclick='edit(${JSON.stringify(p).replace(/'/g,"&#39;")})'>edit</button>
      <button class="del" onclick="del(${p.id},'${esc(p.name)}')">del</button></td></tr>`).join('')
    || '<tr><td colspan=7 style="color:var(--dim)">register is empty — add a party or import a list</td></tr>';
}
async function findings(){
  const rows=await (await fetch('/api/findings')).json();
  $('#findings').innerHTML=rows.slice(0,60).map(f=>`<tr>
    <td>${esc(f.name)}</td><td>${esc(f.kind)}</td>
    <td><span class="pill ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td style="color:var(--dim);max-width:220px;overflow:hidden;text-overflow:ellipsis">${esc(f.ref)}</td>
    <td style="color:var(--dim)">${esc((f.last_seen||'').slice(0,10))}</td></tr>`).join('')
    || '<tr><td colspan=5 style="color:var(--dim)">no exposure found</td></tr>';
}
function refresh(){stats();parties();findings();}

function resetForm(){
  editing=null;
  ['f-name','f-domain','f-contact','f-notes'].forEach(i=>$('#'+i).value='');
  $('#f-cat').value='supplier';$('#f-crit').value='medium';
  $('#formTitle').textContent='Add party';$('#f-save').textContent='Add';
  $('#f-cancel').style.display='none';$('#f-msg').textContent='';
}
function edit(p){
  editing=p.id;
  $('#f-name').value=p.name;$('#f-domain').value=p.domain;
  $('#f-cat').value=p.category;$('#f-crit').value=p.criticality;
  $('#f-contact').value=p.contact||'';$('#f-notes').value=p.notes||'';
  $('#formTitle').textContent='Edit party #'+p.id;$('#f-save').textContent='Save';
  $('#f-cancel').style.display='';window.scrollTo(0,0);
}
async function save(){
  const body={name:$('#f-name').value,domain:$('#f-domain').value,category:$('#f-cat').value,
    criticality:$('#f-crit').value,contact:$('#f-contact').value,notes:$('#f-notes').value};
  const url = editing ? '/api/party/update?id='+editing : '/api/party/add';
  const r=await (await fetch(url,{method:'POST',body:JSON.stringify(body)})).json();
  if(r.error){$('#f-msg').className='msg err';$('#f-msg').textContent=r.error;return;}
  resetForm();$('#f-msg').className='msg good';$('#f-msg').textContent='saved';refresh();
}
async function del(id,name){
  if(!confirm('Remove '+name+' from the register? Its findings are deleted too.'))return;
  await fetch('/api/party/delete?id='+id,{method:'POST'});refresh();
}
async function scanOne(id){
  const r=await (await fetch('/api/scan?id='+id,{method:'POST'})).json();
  if(r.error)alert(r.error); else alert(r.domain+': '+r.total+' finding(s), '+r.new+' new');
  refresh();
}
async function scanAll(){
  $('#scanBtn').disabled=true;$('#scanBtn').textContent='scanning…';
  try{await fetch('/api/scan?all=1',{method:'POST'});}catch(e){}
  $('#scanBtn').disabled=false;$('#scanBtn').textContent='Scan all';refresh();
}
async function doImport(){
  const t=$('#imp').value.trim();if(!t)return;
  const r=await (await fetch('/api/import',{method:'POST',body:t})).json();
  if(r.error){$('#i-msg').className='msg err';$('#i-msg').textContent=r.error;return;}
  $('#i-msg').className='msg good';
  $('#i-msg').textContent=`added ${r.added}, updated ${r.updated}, skipped ${r.skipped}`
    +(r.errors&&r.errors.length?' — '+r.errors.join('; '):'');
  $('#imp').value='';refresh();
}
refresh();
</script></body></html>"""


def _page():
    return PAGE.replace("%%CATS%%", json.dumps(list(CATEGORIES))) \
               .replace("%%CRITS%%", json.dumps(list(CRITICALITIES)))


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        if path == "/health":
            return self._json({"status": "ok", "external_lookups": EXTERNAL_LOOKUPS,
                               "uploads": False})
        if path == "/manual":
            return _serve_manual(self)
        if path in ("/", "/index.html"):
            return self._send(200, "text/html; charset=utf-8", _page())
        if path == "/api/stats":
            return self._json(stats())
        if path == "/api/parties":
            return self._json(list_parties())
        if path == "/api/findings":
            pid = int(q.get("party_id", ["0"])[0] or 0)
            return self._json(findings_for(pid or None))
        if path == "/api/export":
            if q.get("fmt", ["json"])[0] == "csv":
                return self._send(200, "text/csv; charset=utf-8", export_csv(),
                                  {"Content-Disposition": 'attachment; filename="soc-supply-register.csv"'})
            return self._send(200, "application/json", json.dumps(list_parties(), indent=2),
                              {"Content-Disposition": 'attachment; filename="soc-supply-register.json"'})
        self._send(404, "text/plain", "not found")

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        pid = int(q.get("id", ["0"])[0] or 0)
        try:
            if path == "/api/party/add":
                return self._json(add_party(json.loads(self._body() or b"{}")))
            if path == "/api/party/update":
                return self._json(update_party(pid, json.loads(self._body() or b"{}")))
            if path == "/api/party/delete":
                return self._json(delete_party(pid))
            if path == "/api/import":
                rows, err = parse_import(self._body(), self.headers.get("Content-Type"))
                return self._json({"error": err} if err else import_rows(rows))
            if path == "/api/scan":
                if q.get("all", ["0"])[0] == "1":
                    return self._json(scan_all())
                return self._json(scan_party(pid))
        except ValueError as e:
            return self._json({"error": f"bad request: {e}"}, 400)
        self._send(404, "text/plain", "not found")

    def log_message(self, *a):
        pass


# ---- injected: /manual help page (stdlib markdown renderer) ----------------
def _md_to_html(md):
    import html, re as _re
    lines = md.split("\n")
    out = []; i = 0; n = len(lines)
    def inline(t):
        t = html.escape(t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        t = _re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                    r'<a href="\2" target="_blank" rel="noopener">\1</a>', t)
        return t
    while i < n:
        ln = lines[i]
        if ln.startswith("```"):
            i += 1; buf = []
            while i < n and not lines[i].startswith("```"):
                buf.append(html.escape(lines[i])); i += 1
            i += 1
            out.append("<pre><code>" + "\n".join(buf) + "</code></pre>"); continue
        m = _re.match(r"(#{1,6})\s+(.*)", ln)
        if m:
            lv = len(m.group(1)); out.append("<h%d>%s</h%d>" % (lv, inline(m.group(2)), lv)); i += 1; continue
        if _re.match(r"\s*[-*]\s+", ln):
            out.append("<ul>")
            while i < n and _re.match(r"\s*[-*]\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*[-*]\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ul>"); continue
        if _re.match(r"\s*\d+\.\s+", ln):
            out.append("<ol>")
            while i < n and _re.match(r"\s*\d+\.\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*\d+\.\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ol>"); continue
        if ln.strip().startswith("|") and i + 1 < n and _re.match(r"^\s*\|[-:\s|]+\|\s*$", lines[i+1]):
            hdr = [c.strip() for c in ln.strip().strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join("<th>%s</th>" % inline(c) for c in hdr) + "</tr></thead><tbody>")
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in cells) + "</tr>"); i += 1
            out.append("</tbody></table>"); continue
        if _re.match(r"^\s*---+\s*$", ln):
            out.append("<hr>"); i += 1; continue
        if ln.strip() == "":
            i += 1; continue
        para = [ln]; i += 1
        while i < n and lines[i].strip() and not _re.match(r"(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s|\|)", lines[i]):
            para.append(lines[i]); i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")
    return "\n".join(out)


def _manual_page(inner):
    return ("""<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Manual</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔗</text></svg>"><style>
:root{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--ac:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:15px/1.65 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 22px 80px}
.top{position:sticky;top:0;background:rgba(13,17,23,.92);backdrop-filter:blur(6px);
border-bottom:1px solid var(--bd);margin:-32px -22px 24px;padding:12px 22px;display:flex;
align-items:center;gap:12px}
.top a{color:var(--ac);text-decoration:none;font-size:13px}
h1,h2,h3,h4{color:#fff;line-height:1.25;margin:1.5em 0 .5em}
h1{font-size:26px;border-bottom:1px solid var(--bd);padding-bottom:.3em}
h2{font-size:20px;border-bottom:1px solid var(--bd);padding-bottom:.25em}
h3{font-size:16px}a{color:var(--ac)}
code{background:var(--sf);border:1px solid var(--bd);border-radius:4px;padding:1px 5px;
font:13px/1.4 ui-monospace,Menlo,monospace}
pre{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;
overflow:auto}pre code{background:none;border:0;padding:0}
ul,ol{padding-left:1.4em}li{margin:.25em 0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:14px}
th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left}
th{background:var(--sf)}hr{border:0;border-top:1px solid var(--bd);margin:2em 0}
.mut{color:var(--mut)}
</style></head><body><div class=wrap>
<div class=top><a href="/">&larr; Back to app</a><span class=mut>&middot; Manual</span></div>
""" + inner + "\n</div></body></html>")


def _serve_manual(handler):
    import os as _os
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "MANUAL.md")
    try:
        with open(p, encoding="utf-8") as _fh:
            md = _fh.read()
    except OSError:
        md = "# Manual\n\nMANUAL.md not found next to the application."
    body = _manual_page(_md_to_html(md)).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
# ---- end injected block -----------------------------------------------------


if __name__ == "__main__":
    _init_db()
    threading.Thread(target=_background_scanner, daemon=True).start()
    print(f"soc-supply on http://{HOST}:{PORT}  "
          f"(external_lookups={'ON' if EXTERNAL_LOOKUPS else 'OFF'}, "
          f"rescan={SCAN_INTERVAL_H}h, uploads=NEVER)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
