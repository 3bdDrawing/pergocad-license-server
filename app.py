import base64
import json
import os
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

GITHUB_USER = "3bdDrawing"
GITHUB_REPO = "pergola-licenses"
GITHUB_FILE = "licenses.json"

TOKEN_ENV_NAME = "PERGOLA_LICENSE_TOKEN"
API_SECRET_ENV_NAME = "PERGOCAD_API_SECRET"

REQUEST_TIMEOUT = 12
DATE_FMT = "%Y-%m-%d"


def utc_today():
    return datetime.now(timezone.utc)


def today_str():
    return utc_today().strftime(DATE_FMT)


def parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, DATE_FMT).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def get_token():
    token = os.getenv(TOKEN_ENV_NAME, "").strip()
    if not token:
        raise RuntimeError("Missing GitHub token on server.")
    return token


def check_api_secret(req):
    expected = os.getenv(API_SECRET_ENV_NAME, "").strip()

    # If no API secret is set on Render, allow request.
    # Later we will set it, so the app needs the same secret.
    if not expected:
        return True

    received = req.headers.get("X-PergoCAD-Secret", "").strip()
    return received == expected


def github_get():
    url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{GITHUB_FILE}"
    headers = {
        "Authorization": f"token {get_token()}",
        "Accept": "application/vnd.github+json",
    }

    r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()

    data = r.json()
    content = base64.b64decode(data["content"]).decode("utf-8")

    return json.loads(content), data["sha"]


def github_update(db, sha):
    url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{GITHUB_FILE}"
    headers = {
        "Authorization": f"token {get_token()}",
        "Accept": "application/vnd.github+json",
    }

    content = base64.b64encode(json.dumps(db, indent=2).encode("utf-8")).decode("utf-8")

    payload = {
        "message": "update license activation",
        "content": content,
        "sha": sha,
    }

    r = requests.put(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()


def is_demo_license(lic):
    return str(lic.get("type", "paid")).lower() in ("demo", "trial")


def calculate_demo_expiry(lic):
    days = int(lic.get("demo_days", 1) or 1)
    return (utc_today() + timedelta(days=days)).strftime(DATE_FMT)


def check_expiry(lic):
    expiry = parse_date(lic.get("expiry"))
    if expiry and utc_today() > expiry:
        return "License expired."
    return None


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "ok": True,
        "service": "PergoCAD License Server"
    })


@app.route("/activate", methods=["POST"])
def activate():
    if not check_api_secret(request):
        return jsonify({
            "ok": False,
            "message": "Unauthorized."
        }), 401

    data = request.get_json(force=True) or {}

    key = str(data.get("key", "")).strip()
    company = str(data.get("company", "")).strip()
    pc_id = str(data.get("pc_id", "")).strip()

    if not key:
        return jsonify({
            "ok": False,
            "message": "Missing license key."
        }), 400

    if not pc_id:
        return jsonify({
            "ok": False,
            "message": "Missing PC ID."
        }), 400

    try:
        db, sha = github_get()
    except Exception:
        return jsonify({
            "ok": False,
            "message": "Cannot reach license database."
        }), 500

    if key not in db:
        return jsonify({
            "ok": False,
            "message": "License key not found."
        }), 404

    lic = db[key]

    if not lic.get("active", False):
        return jsonify({
            "ok": False,
            "message": "License is deactivated."
        }), 403

    expiry_error = check_expiry(lic)
    if expiry_error:
        return jsonify({
            "ok": False,
            "message": expiry_error
        }), 403

    devices = lic.setdefault("devices", [])
    max_devices = int(lic.get("max_devices", 1) or 1)

    # Existing device
    for d in devices:
        if d.get("pc") == pc_id:
            d["company"] = company or d.get("company", "")
            d["last_check"] = today_str()

            db[key] = lic
            github_update(db, sha)

            return jsonify({
                "ok": True,
                "message": "License verified.",
                "type": lic.get("type", "paid"),
                "expiry": lic.get("expiry"),
            })

    # New device
    if len(devices) >= max_devices:
        return jsonify({
            "ok": False,
            "message": "Device limit reached."
        }), 403

    # Demo first activation
    if is_demo_license(lic) and not lic.get("expiry"):
        lic["expiry"] = calculate_demo_expiry(lic)

    expiry_error = check_expiry(lic)
    if expiry_error:
        return jsonify({
            "ok": False,
            "message": expiry_error
        }), 403

    devices.append({
        "pc": pc_id,
        "company": company,
        "activated_at": today_str(),
        "last_check": today_str(),
    })

    db[key] = lic
    db[key]["devices"] = devices
    github_update(db, sha)

    return jsonify({
        "ok": True,
        "message": "License activated.",
        "type": lic.get("type", "paid"),
        "expiry": lic.get("expiry"),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)