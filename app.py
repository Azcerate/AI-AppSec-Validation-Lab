from flask import Flask, render_template, abort, request, redirect, url_for
import json
from datetime import datetime

app = Flask(__name__)


def load_findings():
    with open("findings.json", "r", encoding="utf-8") as file:
        return json.load(file)


def save_findings(findings):
    with open("findings.json", "w", encoding="utf-8") as file:
        json.dump(findings, file, indent=4)


def load_assets():
    with open("assets.json", "r", encoding="utf-8") as file:
        return json.load(file)


def save_assets(assets):
    with open("assets.json", "w", encoding="utf-8") as file:
        json.dump(assets, file, indent=4)


def load_discovery_results():
    with open("discovery_results.json", "r", encoding="utf-8") as file:
        return json.load(file)


def load_audit_logs():
    with open("audit_log.json", "r", encoding="utf-8") as file:
        return json.load(file)


def save_audit_logs(logs):
    with open("audit_log.json", "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)


def write_audit_log(action, obj, details, severity="Info", user="Anthony Saunders"):
    logs = load_audit_logs()

    new_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "action": action,
        "object": obj,
        "details": details,
        "severity": severity
    }

    logs.insert(0, new_log)
    save_audit_logs(logs)


def get_asset_by_id(asset_id):
    assets = load_assets()
    return next((asset for asset in assets if asset["id"] == asset_id), None)


def calculate_risk(finding, asset):
    score = 0

    severity_scores = {
        "Critical": 40,
        "High": 30,
        "Medium": 20,
        "Low": 10
    }

    exposure_scores = {
        "Internet-facing": 20,
        "Internal": 10
    }

    environment_scores = {
        "Production": 20,
        "Development": 5,
        "Staging": 10
    }

    sensitivity_scores = {
        "High": 15,
        "Medium": 10,
        "Low": 5
    }

    criticality_scores = {
        "High": 15,
        "Medium": 10,
        "Low": 5
    }

    score += severity_scores.get(finding["severity"], 0)
    score += exposure_scores.get(asset.get("exposure", "Internal"), 0)
    score += environment_scores.get(asset.get("environment", "Development"), 0)
    score += sensitivity_scores.get(asset.get("data_sensitivity", "Low"), 0)
    score += criticality_scores.get(asset.get("criticality", "Low"), 0)
    score += len(asset.get("regulations", [])) * 5

    if score >= 90:
        priority = "Critical"
    elif score >= 70:
        priority = "High"
    elif score >= 50:
        priority = "Medium"
    else:
        priority = "Low"

    return score, priority


def classify_asset_type(hostname, services):
    hostname = (hostname or "").lower()
    services = [s.lower() for s in services]

    if "mssql" in services or "mysql" in services or "postgres" in services:
        return "Database"
    if "api" in hostname:
        return "API"
    if "http" in services or "https" in services or "http-alt" in services:
        return "Application"
    return "Server"


def infer_exposure(services):
    services = [s.lower() for s in services]
    if "http" in services or "https" in services or "http-alt" in services:
        return "Internet-facing"
    return "Internal"


def infer_environment(hostname):
    hostname = (hostname or "").lower()
    if "prod" in hostname:
        return "Production"
    if "staging" in hostname or "stage" in hostname:
        return "Staging"
    if "dev" in hostname:
        return "Development"
    return "Development"


def infer_owner(asset_type):
    if asset_type in ["Application", "API"]:
        return "Engineering"
    if asset_type == "Database":
        return "IT"
    return "IT"


def normalize_discovered_asset(result, next_id):
    asset_type = classify_asset_type(result.get("hostname", ""), result.get("services", []))
    exposure = infer_exposure(result.get("services", []))
    environment = infer_environment(result.get("hostname", ""))

    if asset_type == "Application":
        name = result.get("hostname", "Unknown App")
        data_sensitivity = "High"
        criticality = "High" if environment == "Production" else "Medium"
        regulations = ["NIST", "ISO27001"] if environment == "Production" else ["OWASP"]
    elif asset_type == "API":
        name = result.get("hostname", "Unknown API")
        data_sensitivity = "Medium"
        criticality = "Medium"
        regulations = ["OWASP"]
    elif asset_type == "Database":
        name = result.get("hostname", "Unknown Database")
        data_sensitivity = "High"
        criticality = "High"
        regulations = ["NIST"]
        exposure = "Internal"
    else:
        name = result.get("hostname", "Unknown Server")
        data_sensitivity = "Low"
        criticality = "Low"
        regulations = []

    return {
        "id": next_id,
        "name": name,
        "type": asset_type,
        "owner": infer_owner(asset_type),
        "exposure": exposure,
        "data_sensitivity": data_sensitivity,
        "environment": environment,
        "criticality": criticality,
        "data_type": "Internal" if data_sensitivity != "High" else "Sensitive",
        "regulations": regulations,
        "ip_address": result.get("ip_address", ""),
        "hostname": result.get("hostname", ""),
        "open_ports": result.get("open_ports", []),
        "services": result.get("services", []),
        "discovery_source": result.get("source", "Discovery"),
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Discovered"
    }


def sync_discovery_to_assets():
    assets = load_assets()
    discovery_results = load_discovery_results()

    existing_by_ip = {asset.get("ip_address"): asset for asset in assets}
    next_id = max([asset["id"] for asset in assets], default=0) + 1

    new_count = 0
    updated_count = 0

    for result in discovery_results:
        ip = result.get("ip_address")

        if ip in existing_by_ip:
            asset = existing_by_ip[ip]
            asset["hostname"] = result.get("hostname", asset.get("hostname"))
            asset["open_ports"] = result.get("open_ports", asset.get("open_ports", []))
            asset["services"] = result.get("services", asset.get("services", []))
            asset["discovery_source"] = result.get("source", asset.get("discovery_source", "Discovery"))
            asset["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            asset["status"] = "Known"
            updated_count += 1
        else:
            new_asset = normalize_discovered_asset(result, next_id)
            assets.append(new_asset)
            next_id += 1
            new_count += 1

    save_assets(assets)

    write_audit_log(
        action="Discovery Sync Completed",
        obj="Asset Inventory",
        details=f"Discovery sync completed: {new_count} new assets added, {updated_count} existing assets updated",
        severity="Medium"
    )

    return new_count, updated_count


@app.route("/")
def home():
    write_audit_log(
        action="Platform Accessed",
        obj="Dashboard",
        details="User opened the dashboard",
        severity="Info"
    )
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    findings = load_findings()
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if f["severity"] == "Critical")
    high_count = sum(1 for f in findings if f["severity"] == "High")

    status = "Blocked" if critical_count > 0 or high_count > 0 else "Ready"

    return render_template(
        "dashboard.html",
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        status=status
    )


@app.route("/findings")
def findings_page():
    findings = load_findings()

    for finding in findings:
        asset = get_asset_by_id(finding["asset_id"])
        finding["asset_name"] = asset["name"] if asset else "Unknown"

        if asset:
            risk_score, priority = calculate_risk(finding, asset)
            finding["risk_score"] = risk_score
            finding["priority"] = priority
        else:
            finding["risk_score"] = 0
            finding["priority"] = "Unknown"

    return render_template("findings.html", findings=findings)


@app.route("/threat-model")
def threat_model():
    return render_template("threat_model.html")


@app.route("/reports")
def reports():
    write_audit_log(
        action="Reports Viewed",
        obj="Reports Module",
        details="User opened the reports page",
        severity="Info"
    )
    return render_template("reports.html")


@app.route("/compliance")
def compliance():
    write_audit_log(
        action="Compliance Reviewed",
        obj="Compliance Module",
        details="User opened the compliance page",
        severity="Info"
    )
    return render_template("compliance.html")


@app.route("/settings")
def settings():
    write_audit_log(
        action="Settings Viewed",
        obj="Settings Module",
        details="User opened the settings page",
        severity="Info"
    )
    return render_template("settings.html")


@app.route("/assets")
def assets_page():
    assets = load_assets()
    return render_template("assets.html", assets=assets)


@app.route("/audit")
def audit_page():
    logs = load_audit_logs()
    return render_template("audit.html", logs=logs)


@app.route("/finding/<int:finding_id>")
def finding_detail(finding_id):
    findings = load_findings()

    finding = next((f for f in findings if f["id"] == finding_id), None)

    if finding is None:
        abort(404)

    asset = get_asset_by_id(finding["asset_id"])

    finding["asset_name"] = asset["name"] if asset else "Unknown"
    finding["asset_exposure"] = asset["exposure"] if asset else "Unknown"
    finding["asset_environment"] = asset["environment"] if asset else "Unknown"
    finding["asset_data_sensitivity"] = asset["data_sensitivity"] if asset else "Unknown"
    finding["asset_criticality"] = asset["criticality"] if asset else "Unknown"
    finding["asset_regulations"] = ", ".join(asset["regulations"]) if asset else "None"

    if asset:
        risk_score, priority = calculate_risk(finding, asset)
        finding["risk_score"] = risk_score
        finding["priority"] = priority
    else:
        finding["risk_score"] = 0
        finding["priority"] = "Unknown"

    write_audit_log(
        action="Finding Viewed",
        obj=finding["title"],
        details=f"User opened finding detail for {finding['title']}",
        severity="Info"
    )

    return render_template("finding_detail.html", finding=finding)


@app.route("/finding/<int:finding_id>/status", methods=["POST"])
def update_finding_status(finding_id):
    findings = load_findings()
    new_status = request.form.get("status")

    finding = next((f for f in findings if f["id"] == finding_id), None)

    if finding is None:
        abort(404)

    old_status = finding["status"]
    finding["status"] = new_status
    save_findings(findings)

    severity = "High" if new_status in ["Resolved", "Accepted Risk"] else "Medium"

    write_audit_log(
        action="Finding Status Changed",
        obj=finding["title"],
        details=f"Status changed from {old_status} to {new_status}",
        severity=severity
    )

    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/discovery")
def discovery_page():
    discovery_results = load_discovery_results()
    return render_template("discovery.html", results=discovery_results)


@app.route("/discovery/run", methods=["POST"])
def run_discovery():
    write_audit_log(
        action="Discovery Scan Started",
        obj="Approved Scope",
        details="Automated discovery scan initiated from platform dashboard",
        severity="Medium"
    )

    new_count, updated_count = sync_discovery_to_assets()

    write_audit_log(
        action="Discovery Scan Finished",
        obj="Approved Scope",
        details=f"Discovery finished: {new_count} new assets, {updated_count} updated assets",
        severity="Medium"
    )

    return redirect(url_for("assets_page"))


if __name__ == "__main__":
    app.run(debug=True)