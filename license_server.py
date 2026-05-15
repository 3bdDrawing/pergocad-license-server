from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import requests

app = Flask(__name__)

# Your secret key (same as in customer app)
PERGOCAD_API_SECRET = "PergoCAD-Secret-2026"

LICENSE_FILE = "licenses.json"
LOG_FILE = "activation_log.json"

# ============================================================
# GEOLOCATION - Detect Country from IP
# ============================================================

def get_location_from_ip(ip_address):
    """Get country and city from IP address."""
    try:
        # Using ipapi.co - free, no API key needed, 1000 requests/day
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=5
        )
        data = response.json()
        
        return {
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ip": ip_address
        }
    except Exception as e:
        print(f"Geolocation error: {e}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "ip": ip_address
        }

# ============================================================
# LOAD/SAVE LICENSE DATA
# ============================================================

def load_licenses():
    """Load all licenses from JSON file."""
    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_licenses(licenses):
    """Save licenses to JSON file."""
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(licenses, f, indent=2, ensure_ascii=False)

# ============================================================
# LOGGING - Track Every Activation
# ============================================================

def log_activation(key, company, pc_id, location, success, message=""):
    """Log every activation attempt for audit trail."""
    try:
        # Load existing logs
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except:
            logs = []
        
        # Add new log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "key": key,
            "company": company,
            "pc_id": pc_id[:8] + "...",  # Only partial ID for privacy
            "ip": location["ip"],
            "country": location["country"],
            "city": location["city"],
            "success": success,
            "message": message
        }
        
        logs.append(log_entry)
        
        # Keep only last 10,000 logs
        if len(logs) > 10000:
            logs = logs[-10000:]
        
        # Save
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
            
    except Exception as e:
        print(f"Logging error: {e}")

# ============================================================
# FRAUD DETECTION
# ============================================================

def detect_fraud(key, license_data, company_name, location):
    """Detect suspicious activity."""
    alerts = []
    
    # Check 1: Company name mismatch
    sold_to = license_data.get("sold_to", "").lower().strip()
    entered_company = company_name.lower().strip()
    
    if sold_to and entered_company and sold_to != entered_company:
        alerts.append(
            f"⚠️ FRAUD WARNING: License sold to '{license_data['sold_to']}' "
            f"but activated with company name '{company_name}'"
        )
    
    # Check 2: Wrong country
    expected_country = license_data.get("expected_country", "").lower()
    actual_country = location.get("country", "").lower()
    
    if expected_country and actual_country != "unknown":
        if expected_country not in actual_country and actual_country not in expected_country:
            alerts.append(
                f"⚠️ LOCATION WARNING: Expected {license_data['expected_country']}, "
                f"but activated from {location['country']}"
            )
    
    # Check 3: Multiple countries on same license
    devices = license_data.get("devices", [])
    countries = set([d.get("country", "Unknown") for d in devices])
    countries.add(location["country"])
    
    if len(countries) > 1 and "Unknown" in countries:
        countries.remove("Unknown")
    
    if len(countries) > 1:
        alerts.append(
            f"🚨 MULTIPLE COUNTRIES: License used in {', '.join(countries)}"
        )
    
    return alerts

# ============================================================
# ACTIVATION ENDPOINT
# ============================================================

@app.route('/activate', methods=['POST'])
def activate():
    # Verify secret
    secret = request.headers.get('X-PergoCAD-Secret')
    if secret != PERGOCAD_API_SECRET:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    # Get request data
    data = request.json
    key = data.get('key', '').strip()
    company = data.get('company', '').strip()
    pc_id = data.get('pc_id', '').strip()
    
    # Get IP address
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    # Get location from IP
    location = get_location_from_ip(ip_address)
    
    # Load licenses
    licenses = load_licenses()
    
    # Check if license exists
    if key not in licenses:
        log_activation(key, company, pc_id, location, False, "Invalid license key")
        return jsonify({"ok": False, "message": "Invalid license key"})
    
    license_data = licenses[key]
    
    # Check if license is active
    if not license_data.get("active", False):
        log_activation(key, company, pc_id, location, False, "License deactivated")
        return jsonify({"ok": False, "message": "This license has been deactivated"})
    
    # Check expiry for paid licenses
    if license_data.get("type") == "paid":
        expiry_str = license_data.get("expiry")
        if expiry_str:
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
                if datetime.utcnow() > expiry_date:
                    log_activation(key, company, pc_id, location, False, "License expired")
                    return jsonify({"ok": False, "message": "License expired"})
            except:
                pass
    
    # Handle demo licenses
    if license_data.get("type") == "demo":
        demo_days = license_data.get("demo_days", 1)
        
        # Check if already activated (demo expiry was set)
        if not license_data.get("expiry"):
            # First activation - set expiry
            from datetime import timedelta
            expiry_date = datetime.utcnow() + timedelta(days=demo_days)
            license_data["expiry"] = expiry_date.strftime("%Y-%m-%d")
            licenses[key] = license_data
            save_licenses(licenses)
        
        # Check if demo expired
        expiry_str = license_data.get("expiry")
        if expiry_str:
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
                if datetime.utcnow() > expiry_date:
                    log_activation(key, company, pc_id, location, False, "Demo expired")
                    return jsonify({"ok": False, "message": "Demo license expired"})
            except:
                pass
    
    # Get devices list
    devices = license_data.get("devices", [])
    
    # Check if this PC already activated
    device_entry = None
    for d in devices:
        if d["pc_id"] == pc_id:
            device_entry = d
            break
    
    if device_entry:
        # UPDATE existing device
        device_entry["last_seen"] = datetime.utcnow().isoformat() + "Z"
        device_entry["check_count"] = device_entry.get("check_count", 0) + 1
        device_entry["ip_address"] = ip_address
        device_entry["country"] = location["country"]
        device_entry["city"] = location["city"]
        
        message = "License verified"
    else:
        # NEW device activation
        max_devices = license_data.get("max_devices", 1)
        
        if len(devices) >= max_devices:
            log_activation(key, company, pc_id, location, False, 
                         f"Max devices ({max_devices}) already activated")
            return jsonify({
                "ok": False, 
                "message": f"Maximum devices ({max_devices}) already activated for this license"
            })
        
        # Add new device
        new_device = {
            "pc_id": pc_id,
            "company_name": company,
            "activated_at": datetime.utcnow().isoformat() + "Z",
            "last_seen": datetime.utcnow().isoformat() + "Z",
            "ip_address": ip_address,
            "country": location["country"],
            "city": location["city"],
            "check_count": 1
        }
        
        devices.append(new_device)
        message = "New device activated successfully"
    
    # Detect fraud
    fraud_alerts = detect_fraud(key, license_data, company, location)
    if fraud_alerts:
        # Log fraud but still allow activation (so you can track it)
        for alert in fraud_alerts:
            log_activation(key, company, pc_id, location, True, alert)
    
    # Save updated license
    license_data["devices"] = devices
    licenses[key] = license_data
    save_licenses(licenses)
    
    # Log successful activation
    log_activation(key, company, pc_id, location, True, message)
    
    # Return success
    return jsonify({
        "ok": True,
        "type": license_data.get("type", "paid"),
        "expiry": license_data.get("expiry"),
        "message": message
    })

# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    """Admin endpoint to view all license activity."""
    
    # Simple password protection
    admin_token = request.headers.get('X-Admin-Token')
    ADMIN_PASSWORD = "PergoCAD2025Secret!Admin"  # CHANGE THIS!
    
    if admin_token != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Load data
    licenses = load_licenses()
    
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except:
        logs = []
    
    # Build summary
    summary = []
    
    for key, data in licenses.items():
        devices = data.get("devices", [])
        max_devices = data.get("max_devices", 1)
        
        # Get unique countries
        countries = list(set([d.get("country", "Unknown") for d in devices]))
        
        # Get unique company names entered
        companies = list(set([d.get("company_name", "Unknown") for d in devices]))
        
        # Detect issues
        issues = []
        
        # Issue 1: Over-activated
        if len(devices) > max_devices:
            issues.append(f"🚨 OVER-ACTIVATED: {len(devices)}/{max_devices} devices")
        
        # Issue 2: Multiple countries
        if len(countries) > 1 and "Unknown" in countries:
            countries.remove("Unknown")
        if len(countries) > 1:
            issues.append(f"⚠️ Multiple countries: {', '.join(countries)}")
        
        # Issue 3: Multiple company names
        if len(companies) > 1 and "Unknown" in companies:
            companies.remove("Unknown")
        if len(companies) > 1:
            issues.append(f"⚠️ Multiple companies: {', '.join(companies)}")
        
        # Issue 4: Company name mismatch
        sold_to = data.get("sold_to", "").lower()
        if sold_to:
            for comp in companies:
                if comp.lower() != sold_to:
                    issues.append(f"⚠️ Wrong company: expected '{data['sold_to']}', got '{comp}'")
        
        summary.append({
            "key": key,
            "sold_to": data.get("sold_to", "Unknown"),
            "sold_by": data.get("sold_by", "Unknown"),
            "sold_date": data.get("sold_date", "Unknown"),
            "active": data.get("active", True),
            "type": data.get("type", "paid"),
            "expiry": data.get("expiry"),
            "devices_used": len(devices),
            "max_devices": max_devices,
            "countries": countries,
            "companies_entered": companies,
            "issues": issues,
            "devices": devices
        })
    
    return jsonify({
        "total_licenses": len(licenses),
        "licenses": summary,
        "recent_activations": logs[-100:]  # Last 100 activations
    })

# ============================================================
# START SERVER
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
