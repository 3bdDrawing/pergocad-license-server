from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
import time
import requests
import psycopg
from psycopg.rows import dict_row

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
PERGOCAD_API_SECRET = os.environ.get("PERGOCAD_API_SECRET", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
LICENSE_FILE = "licenses.json"
DATE_FMT = "%Y-%m-%d"


def db_connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    license_key TEXT PRIMARY KEY,
                    type TEXT NOT NULL DEFAULT 'paid',
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    max_devices INTEGER NOT NULL DEFAULT 1,
                    demo_days INTEGER,
                    expiry DATE,
                    sold_to TEXT,
                    sold_by TEXT,
                    sold_date DATE,
                    expected_country TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)
            cur.execute("""
                ALTER TABLE licenses
                ADD COLUMN IF NOT EXISTS notes TEXT;
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id BIGSERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL REFERENCES licenses(license_key) ON DELETE CASCADE,
                    pc_id TEXT NOT NULL,
                    company_name TEXT,
                    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ip_address TEXT,
                    country TEXT,
                    city TEXT,
                    check_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE (license_key, pc_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS activation_logs (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    license_key TEXT,
                    company TEXT,
                    pc_id_short TEXT,
                    ip TEXT,
                    country TEXT,
                    city TEXT,
                    success BOOLEAN NOT NULL DEFAULT FALSE,
                    message TEXT
                );
            """)
            conn.commit()


def import_json_if_empty():
    if not os.path.exists(LICENSE_FILE):
        return
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM licenses")
            if cur.fetchone()["c"] > 0:
                return
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                licenses = json.load(f)
            for key, data in licenses.items():
                expiry = data.get("expiry")
                if expiry == "null" or expiry == "":
                    expiry = None
                sold_date = data.get("sold_date")
                if sold_date == "null" or sold_date == "":
                    sold_date = None
                cur.execute("""
                    INSERT INTO licenses (
                        license_key, type, active, max_devices, demo_days,
                        expiry, sold_to, sold_by, sold_date, expected_country, notes
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (license_key) DO NOTHING
                """, (
                    key, data.get("type", "paid"), bool(data.get("active", True)),
                    int(data.get("max_devices", 1)), data.get("demo_days"), expiry,
                    data.get("sold_to"), data.get("sold_by"), sold_date,
                    data.get("expected_country"), data.get("notes")
                ))
                for d in data.get("devices", []):
                    device_pc = d.get("pc_id") or d.get("pc")
                    if not device_pc:
                        continue
                    cur.execute("""
                        INSERT INTO devices (
                            license_key, pc_id, company_name, activated_at,
                            last_seen, ip_address, country, city, check_count
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (license_key, pc_id) DO NOTHING
                    """, (
                        key, device_pc, d.get("company_name") or d.get("company"),
                        d.get("activated_at") or datetime.utcnow(),
                        d.get("last_seen") or d.get("last_check") or datetime.utcnow(),
                        d.get("ip_address"), d.get("country"), d.get("city"),
                        int(d.get("check_count", 1))
                    ))
            conn.commit()


def verify_hmac_request():
    secret = request.headers.get("X-PergoCAD-Secret", "")
    timestamp = request.headers.get("X-Timestamp", "")
    signature = request.headers.get("X-Signature", "")
    if not PERGOCAD_API_SECRET:
        return False, "Server secret is not configured"
    if secret != PERGOCAD_API_SECRET:
        return False, "Unauthorized"
    if not timestamp or not signature:
        return False, "Missing request signature"
    try:
        timestamp_int = int(timestamp)
    except Exception:
        return False, "Invalid timestamp"
    if abs(int(time.time()) - timestamp_int) > 300:
        return False, "Request expired"
    data = request.get_json(silent=True) or {}
    body_str = json.dumps(data, separators=(",", ":"))
    msg = f"{timestamp}:{body_str}".encode("utf-8")
    expected = hmac.new(PERGOCAD_API_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "Invalid request signature"
    return True, "OK"


def verify_admin():
    admin_token = request.headers.get("X-Admin-Token", "")
    return bool(ADMIN_PASSWORD) and hmac.compare_digest(admin_token, ADMIN_PASSWORD)

def is_private_ip(ip):
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except Exception:
        return False



def get_client_ip():
    """
    Get the best public client IP from Render/proxy headers.
    """
    possible_headers = [
        "CF-Connecting-IP",
        "X-Real-IP",
        "X-Forwarded-For",
        "Forwarded",
    ]

    for header in possible_headers:
        value = request.headers.get(header)
        if not value:
            continue

        # X-Forwarded-For can be: client, proxy1, proxy2
        if header == "X-Forwarded-For":
            parts = [p.strip() for p in value.split(",") if p.strip()]
            for ip in parts:
                if ip and not is_private_ip(ip):
                    return ip

        # Forwarded can be: for=1.2.3.4;proto=https
        if header == "Forwarded":
            parts = value.split(";")
            for part in parts:
                part = part.strip()
                if part.lower().startswith("for="):
                    ip = part.split("=", 1)[1].strip().strip('"')
                    if ip and not is_private_ip(ip):
                        return ip

        ip = value.strip()
        if ip and not is_private_ip(ip):
            return ip

    ip = request.remote_addr or "Unknown"
    return ip


def get_location_from_ip(ip_address):
    """
    Get country and city from IP address.
    Tries ipapi.co first, then ipwho.is as fallback.
    """

    if not ip_address or ip_address == "Unknown" or is_private_ip(ip_address):
        return {
            "country": "Unknown",
            "city": "Unknown",
            "ip": ip_address or "Unknown"
        }

    # Provider 1: ipapi.co
    try:
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=8,
            headers={"User-Agent": "PergoCAD-License-Server/1.0"}
        )

        data = response.json()

        if not data.get("error"):
            country = data.get("country_name") or data.get("country")
            city = data.get("city")

            if country or city:
                return {
                    "country": country or "Unknown",
                    "city": city or "Unknown",
                    "ip": ip_address
                }

    except Exception as e:
        print(f"ipapi geolocation error for {ip_address}: {e}")

    # Provider 2: ipwho.is fallback
    try:
        response = requests.get(
            f"https://ipwho.is/{ip_address}",
            timeout=8,
            headers={"User-Agent": "PergoCAD-License-Server/1.0"}
        )

        data = response.json()

        if data.get("success", False):
            return {
                "country": data.get("country") or "Unknown",
                "city": data.get("city") or "Unknown",
                "ip": ip_address
            }

    except Exception as e:
        print(f"ipwho.is geolocation error for {ip_address}: {e}")

    return {
        "country": "Unknown",
        "city": "Unknown",
        "ip": ip_address
    }


def log_activation(key, company, pc_id, location, success, message=""):
    pc_short = (pc_id[:8] + "...") if pc_id else ""
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO activation_logs (
                    license_key, company, pc_id_short, ip, country, city, success, message
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (key, company, pc_short, location.get("ip"), location.get("country"), location.get("city"), bool(success), message))
            conn.commit()


def normalize_country(value):
    if not value:
        return ""
    v = value.strip().lower()
    aliases = {"turkey": "turkiye", "türkiye": "turkiye", "turkiye": "turkiye"}
    return aliases.get(v, v)


def detect_fraud(license_data, company_name, location, existing_countries):
    alerts = []
    sold_to = (license_data.get("sold_to") or "").lower().strip()
    entered_company = (company_name or "").lower().strip()
    if sold_to and entered_company and sold_to != entered_company:
        alerts.append(f"⚠️ FRAUD WARNING: License sold to '{license_data.get('sold_to')}' but activated with company name '{company_name}'")
    expected_country = normalize_country(license_data.get("expected_country"))
    actual_country = normalize_country(location.get("country"))
    if expected_country and actual_country and actual_country != "unknown" and expected_country != actual_country:
        alerts.append(f"⚠️ LOCATION WARNING: Expected {license_data.get('expected_country')}, but activated from {location.get('country')}")
    countries = set([c for c in existing_countries if c and c != "Unknown"])
    countries.add(location.get("country", "Unknown"))
    countries.discard("Unknown")
    if len(countries) > 1:
        alerts.append(f"🚨 MULTIPLE COUNTRIES: License used in {', '.join(sorted(countries))}")
    return alerts


def license_row_to_dict(row):
    return {
        "key": row["license_key"],
        "type": row["type"],
        "active": row["active"],
        "max_devices": row["max_devices"],
        "demo_days": row["demo_days"],
        "expiry": row["expiry"].strftime(DATE_FMT) if row["expiry"] else None,
        "sold_to": row["sold_to"],
        "sold_by": row["sold_by"],
        "sold_date": row["sold_date"].strftime(DATE_FMT) if row["sold_date"] else None,
        "expected_country": row["expected_country"],
        "notes": row.get("notes"),
    }


@app.route("/activate", methods=["POST"])
def activate():
    ok_sig, sig_message = verify_hmac_request()
    if not ok_sig:
        return jsonify({"ok": False, "message": sig_message}), 401
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip()
    company = data.get("company", "").strip()
    pc_id = data.get("pc_id", "").strip()
    ip_address = get_client_ip()
    location = get_location_from_ip(ip_address)
    if not key or not pc_id:
        log_activation(key, company, pc_id, location, False, "Missing key or pc_id")
        return jsonify({"ok": False, "message": "Missing license key or computer ID"})
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key=%s", (key,))
            lic_row = cur.fetchone()
            if not lic_row:
                log_activation(key, company, pc_id, location, False, "Invalid license key")
                return jsonify({"ok": False, "message": "Invalid license key"})
            license_data = license_row_to_dict(lic_row)
            if not lic_row["active"]:
                log_activation(key, company, pc_id, location, False, "License deactivated")
                return jsonify({"ok": False, "message": "This license has been deactivated"})
            if lic_row["type"] == "paid" and lic_row["expiry"] and datetime.utcnow().date() > lic_row["expiry"]:
                log_activation(key, company, pc_id, location, False, "License expired")
                return jsonify({"ok": False, "message": "License expired"})
            if lic_row["type"] == "demo":
                if not lic_row["expiry"]:
                    expiry_date = datetime.utcnow().date() + timedelta(days=int(lic_row["demo_days"] or 1))
                    cur.execute("UPDATE licenses SET expiry=%s, updated_at=NOW() WHERE license_key=%s", (expiry_date, key))
                    lic_row["expiry"] = expiry_date
                    license_data["expiry"] = expiry_date.strftime(DATE_FMT)
                if lic_row["expiry"] and datetime.utcnow().date() > lic_row["expiry"]:
                    log_activation(key, company, pc_id, location, False, "Demo expired")
                    return jsonify({"ok": False, "message": "Demo license expired"})
            cur.execute("SELECT * FROM devices WHERE license_key=%s AND pc_id=%s", (key, pc_id))
            device = cur.fetchone()
            if device:
                cur.execute("""
                    UPDATE devices SET last_seen=NOW(), check_count=check_count + 1,
                        ip_address=%s, country=%s, city=%s, company_name=%s
                    WHERE license_key=%s AND pc_id=%s
                """, (ip_address, location["country"], location["city"], company, key, pc_id))
                message = "License verified"
            else:
                cur.execute("SELECT COUNT(*) AS c FROM devices WHERE license_key=%s", (key,))
                device_count = cur.fetchone()["c"]
                max_devices = int(lic_row["max_devices"] or 1)
                if device_count >= max_devices:
                    log_activation(key, company, pc_id, location, False, f"Max devices ({max_devices}) already activated")
                    return jsonify({"ok": False, "message": f"Maximum devices ({max_devices}) already activated for this license"})
                cur.execute("""
                    INSERT INTO devices (license_key, pc_id, company_name, ip_address, country, city)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (key, pc_id, company, ip_address, location["country"], location["city"]))
                message = "New device activated successfully"
            cur.execute("SELECT DISTINCT country FROM devices WHERE license_key=%s", (key,))
            existing_countries = [r["country"] for r in cur.fetchall()]
            fraud_alerts = detect_fraud(license_data, company, location, existing_countries)
            conn.commit()
    for alert in fraud_alerts:
        log_activation(key, company, pc_id, location, True, alert)
    log_activation(key, company, pc_id, location, True, message)
    return jsonify({"ok": True, "type": license_data.get("type", "paid"), "expiry": license_data.get("expiry"), "message": message})


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not verify_admin():
        return jsonify({"error": "Unauthorized"}), 401
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses ORDER BY created_at DESC, license_key ASC")
            license_rows = cur.fetchall()
            summary = []
            for row in license_rows:
                key = row["license_key"]
                cur.execute("SELECT * FROM devices WHERE license_key=%s ORDER BY activated_at ASC", (key,))
                devices = cur.fetchall()
                device_list = [{
                    "pc_id": d["pc_id"], "company_name": d["company_name"],
                    "activated_at": d["activated_at"].isoformat(), "last_seen": d["last_seen"].isoformat(),
                    "ip_address": d["ip_address"], "country": d["country"], "city": d["city"], "check_count": d["check_count"]
                } for d in devices]
                countries = sorted(list(set([d["country"] or "Unknown" for d in devices])))
                companies = sorted(list(set([d["company_name"] or "Unknown" for d in devices])))
                issues = []
                if len(devices) > row["max_devices"]:
                    issues.append(f"🚨 OVER-ACTIVATED: {len(devices)}/{row['max_devices']} devices")
                clean_countries = [c for c in countries if c != "Unknown"]
                if len(clean_countries) > 1:
                    issues.append(f"⚠️ Multiple countries: {', '.join(clean_countries)}")
                clean_companies = [c for c in companies if c != "Unknown"]
                if len(clean_companies) > 1:
                    issues.append(f"⚠️ Multiple companies: {', '.join(clean_companies)}")
                sold_to = (row["sold_to"] or "").lower().strip()
                if sold_to:
                    for comp in clean_companies:
                        if comp.lower().strip() != sold_to:
                            issues.append(f"⚠️ Wrong company: expected '{row['sold_to']}', got '{comp}'")
                summary.append({
                    "key": key, "sold_to": row["sold_to"], "sold_by": row["sold_by"],
                    "sold_date": row["sold_date"].strftime(DATE_FMT) if row["sold_date"] else None,
                    "active": row["active"], "type": row["type"],
                    "expiry": row["expiry"].strftime(DATE_FMT) if row["expiry"] else None,
                    "demo_days": row["demo_days"], "notes": row.get("notes"),
                    "devices_used": len(devices), "max_devices": row["max_devices"],
                    "countries": countries, "companies_entered": companies, "issues": issues, "devices": device_list
                })
            cur.execute("SELECT * FROM activation_logs ORDER BY timestamp DESC LIMIT 100")
            logs = cur.fetchall()
            recent = [{
                "timestamp": l["timestamp"].isoformat(), "key": l["license_key"], "company": l["company"],
                "pc_id": l["pc_id_short"], "ip": l["ip"], "country": l["country"], "city": l["city"],
                "success": l["success"], "message": l["message"]
            } for l in logs]
    return jsonify({"total_licenses": len(summary), "licenses": summary, "recent_activations": recent})


@app.route("/admin/license/upsert", methods=["POST"])
def admin_license_upsert():
    if not verify_admin():
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "message": "License key is required"}), 400
    expiry = data.get("expiry") or None
    sold_date = data.get("sold_date") or None
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (license_key, type, active, max_devices, demo_days, expiry, sold_to, sold_by, sold_date, expected_country, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (license_key) DO UPDATE SET
                    type=EXCLUDED.type, active=EXCLUDED.active, max_devices=EXCLUDED.max_devices,
                    demo_days=EXCLUDED.demo_days, expiry=EXCLUDED.expiry, sold_to=EXCLUDED.sold_to,
                    sold_by=EXCLUDED.sold_by, sold_date=EXCLUDED.sold_date,
                    expected_country=EXCLUDED.expected_country, notes=EXCLUDED.notes, updated_at=NOW()
            """, (
                key, data.get("type", "paid"), bool(data.get("active", True)), int(data.get("max_devices", 1)),
                data.get("demo_days"), expiry, data.get("sold_to"), data.get("sold_by"), sold_date,
                data.get("expected_country"), data.get("notes")
            ))
            conn.commit()
    return jsonify({"ok": True, "message": "License saved", "key": key})


@app.route("/admin/license/set-active", methods=["POST"])
def admin_license_set_active():
    if not verify_admin():
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    active = bool(data.get("active", False))
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET active=%s, updated_at=NOW() WHERE license_key=%s", (active, key))
            changed = cur.rowcount
            conn.commit()
    if changed == 0:
        return jsonify({"ok": False, "message": "License not found"}), 404
    return jsonify({"ok": True, "message": "License active status changed", "key": key, "active": active})


@app.route("/admin/license/delete", methods=["POST"])
def admin_license_delete():
    if not verify_admin():
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM licenses WHERE license_key=%s", (key,))
            changed = cur.rowcount
            conn.commit()
    if changed == 0:
        return jsonify({"ok": False, "message": "License not found"}), 404
    return jsonify({"ok": True, "message": "License deleted", "key": key})


@app.route("/admin/license/reset-devices", methods=["POST"])
def admin_license_reset_devices():
    if not verify_admin():
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE license_key=%s", (key,))
            deleted = cur.rowcount
            conn.commit()
    return jsonify({"ok": True, "message": "Devices reset", "key": key, "deleted_devices": deleted})



# ============================================================
# SIMPLE WEB ADMIN PANEL
# ============================================================

@app.route("/admin", methods=["GET"])
def admin_page():
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PergoCAD License Admin</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background:#f6f7fb; color:#222; }
    h1 { margin-bottom: 8px; }
    .card { background:white; border:1px solid #ddd; border-radius:12px; padding:18px; margin:14px 0; box-shadow:0 2px 8px rgba(0,0,0,.05); }
    label { display:block; font-weight:bold; margin-top:10px; }
    input, select { width:100%; padding:9px; box-sizing:border-box; margin-top:4px; border:1px solid #bbb; border-radius:8px; }
    button { padding:9px 12px; border:0; border-radius:8px; cursor:pointer; margin:4px; background:#2457d6; color:white; font-weight:bold; }
    button.danger { background:#b00020; }
    button.warn { background:#d68100; }
    button.gray { background:#666; }
    table { border-collapse:collapse; width:100%; background:white; }
    th, td { border:1px solid #ddd; padding:8px; text-align:left; vertical-align:top; font-size:14px; }
    th { background:#eee; }
    .row { display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; }
    .small { font-size:12px; color:#666; }
    .active { color:green; font-weight:bold; }
    .inactive { color:#b00020; font-weight:bold; }
    pre { white-space:pre-wrap; background:#111; color:#eee; padding:12px; border-radius:8px; max-height:300px; overflow:auto; }
    @media (max-width:900px) { .row { grid-template-columns: 1fr; } table { font-size:12px; } }
  </style>
</head>
<body>
  <h1>PergoCAD License Admin</h1>
  <p class="small">Use this page to add/edit/deactivate/delete licenses and reset devices. Keep your admin token private.</p>

  <div class="card">
    <label>Admin Password / Token</label>
    <input id="token" type="password" placeholder="Enter ADMIN_PASSWORD">
    <button onclick="saveToken()">Save Token in this browser</button>
    <button class="gray" onclick="loadDashboard()">Refresh Dashboard</button>
    <span id="status" class="small"></span>
  </div>

  <div class="card">
    <h2>Add / Edit License</h2>
    <div class="row">
      <div><label>License Key</label><input id="key" placeholder="VER-TEST-0001"></div>
      <div><label>Type</label><select id="type"><option value="paid">paid</option><option value="demo">demo</option></select></div>
      <div><label>Active</label><select id="active"><option value="true">true</option><option value="false">false</option></select></div>
      <div><label>Max Devices</label><input id="max_devices" type="number" value="1"></div>
    </div>
    <div class="row">
      <div><label>Demo Days</label><input id="demo_days" type="number" placeholder="3"></div>
      <div><label>Expiry</label><input id="expiry" placeholder="2026-12-31 or empty"></div>
      <div><label>Sold To</label><input id="sold_to" placeholder="Customer company"></div>
      <div><label>Sold By</label><input id="sold_by" placeholder="Salesman / You"></div>
    </div>
    <div class="row">
      <div><label>Sold Date</label><input id="sold_date" placeholder="2026-05-15"></div>
      <div><label>Expected Country</label><input id="expected_country" placeholder="Türkiye"></div>
    </div>
    
    <label>Notes</label>
    <textarea id="notes" rows="4" placeholder="Price, special edits, customer requests, payment notes..." style="width:100%; padding:9px; box-sizing:border-box; margin-top:4px; border:1px solid #bbb; border-radius:8px;"></textarea>
    
    <button onclick="saveLicense()">Save License</button>
    <button class="gray" onclick="clearForm()">Clear Form</button>
  </div>

  <div class="card">
    <h2>Licenses</h2>
    <div id="licenses">Click Refresh Dashboard.</div>
  </div>

  <div class="card">
    <h2>Recent Activations</h2>
    <pre id="logs">Click Refresh Dashboard.</pre>
  </div>

<script>
function setStatus(msg) { document.getElementById('status').textContent = msg; }
function token() { return document.getElementById('token').value.trim(); }
function saveToken() { localStorage.setItem('pergocad_admin_token', token()); setStatus('Token saved.'); }
function loadToken() { document.getElementById('token').value = localStorage.getItem('pergocad_admin_token') || ''; }

async function api(path, method='GET', body=null) {
  const headers = {'X-Admin-Token': token()};
  if (body !== null) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {method, headers, body: body ? JSON.stringify(body) : null});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || data.error || ('HTTP ' + res.status));
  return data;
}

function getFormData() {
  const demoDaysText = document.getElementById('demo_days').value.trim();
  return {
    key: document.getElementById('key').value.trim(),
    type: document.getElementById('type').value,
    active: document.getElementById('active').value === 'true',
    max_devices: parseInt(document.getElementById('max_devices').value || '1'),
    demo_days: demoDaysText ? parseInt(demoDaysText) : null,
    expiry: document.getElementById('expiry').value.trim() || null,
    sold_to: document.getElementById('sold_to').value.trim() || null,
    sold_by: document.getElementById('sold_by').value.trim() || null,
    sold_date: document.getElementById('sold_date').value.trim() || null,
    expected_country: document.getElementById('expected_country').value.trim() || null,
    notes: document.getElementById('notes').value.trim() || null
  };
}

async function saveLicense() {
  try {
    const data = await api('/admin/license/upsert', 'POST', getFormData());
    setStatus(data.message || 'Saved');
    await loadDashboard();
  } catch (e) { alert(e.message); }
}

function clearForm() {
  for (const id of ['key','demo_days','expiry','sold_to','sold_by','sold_date','expected_country','notes']) document.getElementById(id).value = '';
  document.getElementById('type').value = 'paid';
  document.getElementById('active').value = 'true';
  document.getElementById('max_devices').value = '1';
}

function editLicense(l) {
  document.getElementById('key').value = l.key || '';
  document.getElementById('type').value = l.type || 'paid';
  document.getElementById('active').value = String(!!l.active);
  document.getElementById('max_devices').value = l.max_devices || 1;
  document.getElementById('demo_days').value = l.demo_days || '';
  document.getElementById('expiry').value = l.expiry || '';
  document.getElementById('sold_to').value = l.sold_to || '';
  document.getElementById('sold_by').value = l.sold_by || '';
  document.getElementById('sold_date').value = l.sold_date || '';
  document.getElementById('expected_country').value = (l.expected_country || '');
  document.getElementById('notes').value = (l.notes || '');
  window.scrollTo({top:0, behavior:'smooth'});
}

async function setActive(key, active) {
  if (!confirm((active ? 'Activate ' : 'Deactivate ') + key + '?')) return;
  try {
    await api('/admin/license/set-active', 'POST', {key, active});
    await loadDashboard();
  } catch (e) { alert(e.message); }
}

async function resetDevices(key) {
  if (!confirm('Reset all activated devices for ' + key + '?')) return;
  try {
    await api('/admin/license/reset-devices', 'POST', {key});
    await loadDashboard();
  } catch (e) { alert(e.message); }
}

async function deleteLicense(key) {
  if (!confirm('DELETE license ' + key + '? This cannot be undone.')) return;
  try {
    await api('/admin/license/delete', 'POST', {key});
    await loadDashboard();
  } catch (e) { alert(e.message); }
}

function formatDateTime(value) {
  if (!value) return '';

  try {
    const date = new Date(value);

    if (isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString('en-GB', {
      timeZone: 'Europe/Istanbul',
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }) + ' GMT+3';
  } catch (e) {
    return String(value);
  }
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>'"]/g, function(c) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[c];
  });
}

function formatDateTime(value) {
  if (!value) return '';

  try {
    const date = new Date(value);

    if (isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString('en-GB', {
      timeZone: 'Europe/Istanbul',
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }) + ' GMT+3';
  } catch (e) {
    return String(value);
  }
}

function renderDashboard(data) {
  let html = '<table><thead><tr><th>Key</th><th>Status</th><th>Customer</th><th>Devices</th><th>Expiry</th><th>Issues</th><th>Actions</th></tr></thead><tbody>';
  for (const l of data.licenses || []) {
    const issues = (l.issues || []).map(escapeHtml).join('<br>');
    const devices = (l.devices || []).map((d, index) => `
      <b>Device ${index + 1}</b><br>
      Company: ${escapeHtml(d.company_name)}<br>
      Location: ${escapeHtml(d.country)} / ${escapeHtml(d.city)}<br>
      IP: ${escapeHtml(d.ip_address)}<br>
      PC ID: ${escapeHtml(d.pc_id)}<br>
      Activated: ${escapeHtml(formatDateTime(d.activated_at))}<br>
      Last seen: ${escapeHtml(formatDateTime(d.last_seen))}<br>
      Checks: ${escapeHtml(d.check_count)}
    `).join('<hr>');
    html += `<tr>
      <td><b>${escapeHtml(l.key)}</b><br><span class="small">${escapeHtml(l.type)}</span></td>
      <td class="${l.active ? 'active' : 'inactive'}">${l.active ? 'ACTIVE' : 'INACTIVE'}</td>
      <td>${escapeHtml(l.sold_to)}<br><span class="small">Sold by: ${escapeHtml(l.sold_by)}<br>Country: ${escapeHtml(l.expected_country || '')}<br><b>Notes:</b><br>${escapeHtml(l.notes || '')}</span></td>      <td>${l.devices_used}/${l.max_devices}<br>${devices}</td>
      <td>${escapeHtml(l.expiry || '')}<br><span class="small">demo days: ${escapeHtml(l.demo_days || '')}</span></td>
      <td>${issues}</td>
      <td>
        <button onclick='editLicense(${JSON.stringify(l).replace(/'/g, "&#39;")})'>Edit</button>
        <button class="${l.active ? 'warn' : ''}" onclick="setActive('${escapeHtml(l.key)}', ${!l.active})">${l.active ? 'Deactivate' : 'Activate'}</button>
        <button class="gray" onclick="resetDevices('${escapeHtml(l.key)}')">Reset Devices</button>
        <button class="danger" onclick="deleteLicense('${escapeHtml(l.key)}')">Delete</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table>';
  document.getElementById('licenses').innerHTML = html;
  document.getElementById('logs').textContent = JSON.stringify(data.recent_activations || [], null, 2);
}

async function loadDashboard() {
  try {
    setStatus('Loading...');
    const data = await api('/admin/dashboard');
    renderDashboard(data);
    setStatus('Loaded. Total licenses: ' + data.total_licenses);
  } catch (e) { alert(e.message); setStatus('Error: ' + e.message); }
}

loadToken();
</script>
</body>
</html>
    """


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "message": "License server running"})


try:
    init_db()
    import_json_if_empty()
except Exception as e:
    print(f"Database startup error: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
