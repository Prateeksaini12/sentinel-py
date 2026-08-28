from flask import Flask, request, jsonify
from flask import send_from_directory, send_file
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
import tempfile

import psutil
import platform
import socket
import uuid
import datetime
import threading
import time
import os
import psutil
import queue
import subprocess
import re

try:
    import winreg
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False




app = Flask(__name__)
CORS(app)

file_events = []

# --- Threat alert feed (rolling list of security-relevant events) ---
threat_feed = []
threat_lock = threading.Lock()

def push_alert(severity, message):
    """severity: 'critical' | 'warning' | 'info'"""
    with threat_lock:
        threat_feed.insert(0, {
            "severity": severity,
            "message": message,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        del threat_feed[50:]  # keep last 50


# --- Global variables for Full Security Audit ---
audit_status = {"status": "idle", "results": {}}
audit_lock = threading.Lock()
global_last_scan_time = "Never" # <-- ADD THIS
global_security_score = 100



class FileMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        fname = os.path.basename(event.src_path)
        file_events.append({
            "file": fname,
            "type": "Created",
            "date": datetime.datetime.now().strftime("%Y-%m-%d")
        })
        if fname.lower().endswith(('.exe', '.scr', '.bat', '.vbs')):
            push_alert("warning", f"New executable-type file created: {fname}")

    def on_deleted(self, event):
        file_events.append({
            "file": os.path.basename(event.src_path),
            "type": "Deleted",
            "date": datetime.datetime.now().strftime("%Y-%m-%d")
        })

    def on_modified(self, event):
        if not event.is_directory:
            file_events.append({
                "file": os.path.basename(event.src_path),
                "type": "Modified",
                "date": datetime.datetime.now().strftime("%Y-%m-%d")
            })

def start_file_monitor(path='.'):
    observer = Observer()
    event_handler = FileMonitorHandler()
    observer.schedule(event_handler, path=path, recursive=True)
    observer.start()

    def keep_running():
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    thread = threading.Thread(target=keep_running, daemon=True)
    thread.start()

import sys

@app.route('/')
def home():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS  # When running from exe
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))  # When running as script
    return send_from_directory(base_path, "dash.html")



@app.route('/generate-report', methods=['POST'])
def generate_report():
    try:
        data = request.json or {}
        from_date = data.get('from')
        to_date = data.get('to')

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        uname = platform.uname()

        cpu_usage = psutil.cpu_percent(interval=0.2)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        process_count = len(psutil.pids())

        with audit_lock:
            last_audit = audit_status.get("results") or {}

        proc_scan = last_audit.get("processes", {"status": "success", "count": 0, "details": ["No audit run yet."]})
        persist_scan = last_audit.get("persistence", {"status": "success", "count": 0, "details": ["No audit run yet."]})
        net_scan = last_audit.get("network", {"status": "success", "count": 0, "details": ["No audit run yet."]})

        with threat_lock:
            recent_alerts = list(threat_feed[:15])

        from reportlab.lib import colors
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib.units import cm

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        pdf_path = temp_file.name
        temp_file.close()

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                 topMargin=2*cm, bottomMargin=2*cm,
                                 leftMargin=2*cm, rightMargin=2*cm)
        story = []

        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal = styles['Normal']

        def section_table(headers, rows, col_widths=None):
            table_data = [headers] + rows if rows else [headers, ["—"] * len(headers)]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111826')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7fa')]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            return t

        story.append(Paragraph("Sentinel Py — Security &amp; System Report", title_style))
        story.append(Paragraph(f"Generated: {now}", normal))
        story.append(Paragraph(f"Report window: {from_date or 'N/A'} &rarr; {to_date or 'N/A'}", normal))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Executive Summary", heading_style))
        story.append(section_table(
            ["Metric", "Value"],
            [
                ["Security Score", f"{global_security_score}/100"],
                ["Last Full Audit", global_last_scan_time],
                ["CPU Usage", f"{cpu_usage}%"],
                ["RAM Usage", f"{memory.percent}%"],
                ["Disk Usage", f"{disk.percent}%"],
                ["Running Processes", str(process_count)],
                ["System Uptime", str(uptime).split('.')[0]],
                ["OS", f"{uname.system} {uname.release}"],
            ],
            col_widths=[6*cm, 10*cm]
        ))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Recent Threat Alerts", heading_style))
        alert_rows = [[a["time"], a["severity"].upper(), a["message"]] for a in recent_alerts] if recent_alerts else []
        story.append(section_table(["Time", "Severity", "Message"], alert_rows, col_widths=[3.5*cm, 2.5*cm, 10*cm]))
        story.append(Spacer(1, 16))

        story.append(Paragraph(f"Process Scan — {proc_scan['status'].upper()} ({proc_scan['count']} found)", heading_style))
        for d in proc_scan.get("details", []):
            story.append(Paragraph(f"• {d}", normal))
        story.append(Spacer(1, 16))

        story.append(Paragraph(f"Startup / Persistence Scan — {persist_scan['status'].upper()} ({persist_scan['count']} found)", heading_style))
        for d in persist_scan.get("details", []):
            story.append(Paragraph(f"• {d}", normal))
        story.append(Spacer(1, 16))

        story.append(Paragraph(f"Network Exposure Scan — {net_scan['status'].upper()} ({net_scan['count']} found)", heading_style))
        for d in net_scan.get("details", []):
            story.append(Paragraph(f"• {d}", normal))

        doc.build(story)

        filename = f"SentinelPy_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(pdf_path, mimetype='application/pdf',
                          as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    

@app.route('/system-info')
def system_info():
    try:
        uname = platform.uname()
        memory = psutil.virtual_memory()
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())

        # Battery
        try:
            battery = psutil.sensors_battery()
            battery_info = {
                "percent": battery.percent,
                "charging": battery.power_plugged
            } if battery else None
        except Exception:
            battery_info = None

        # Disks
        disks = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "used": round(usage.used / (1024 ** 3), 1),
                    "total": round(usage.total / (1024 ** 3), 1),
                    "percent": usage.percent
                })
            except PermissionError:
                continue

        return jsonify({
            "os": f"{uname.system} {uname.release}",
            "cpu": uname.processor,
            "ram": f"{round(memory.total / (1024 ** 3), 1)} GB",
            "uptime": str(uptime).split('.')[0],
            "battery": battery_info,
            "disks": disks
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/file-events')
def get_file_events():
    return jsonify(file_events)

@app.route('/network-usage')
def network_usage():
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                connections.append({
                    "ip": conn.raddr.ip,
                    "port": conn.raddr.port,
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "status": conn.status
                })

        net_io = psutil.net_io_counters()
        return jsonify({
            "connections": connections[:15],  # Optional: limit to 15
            "sent": net_io.bytes_sent,
            "recv": net_io.bytes_recv
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Full Security Audit ---

def _scan_processes():
    """Helper function: Scans running processes for suspicious names."""
    keylogger_keywords = ["keylog", "logger", "hook", "keystroke"]
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name']):
        name = proc.info.get('name', '')
        if name and any(kw in name.lower() for kw in keylogger_keywords):
            suspicious.append(f"{name} (PID: {proc.info.get('pid')})")
    
    if suspicious:
        return {"status": "danger", "count": len(suspicious), "details": suspicious}
    return {"status": "success", "count": 0, "details": ["No suspicious processes found."]}

def _scan_hosts_file():
    """Checks the system hosts file for suspicious redirects of well-known domains."""
    sensitive_domains = [
        "google.com", "facebook.com", "microsoft.com", "apple.com",
        "paypal.com", "amazon.com", "bankofamerica.com", "chase.com",
        "gmail.com", "outlook.com", "github.com"
    ]
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if IS_WINDOWS else "/etc/hosts"
    suspicious = []

    try:
        if not os.path.exists(hosts_path):
            return {"status": "success", "count": 0, "details": ["Hosts file not found — skipped."]}

        with open(hosts_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, domain = parts[0], parts[1].lower()
                if any(sd in domain for sd in sensitive_domains) and not ip.startswith("127.") and ip != "::1":
                    suspicious.append(f"{domain} -> {ip} (unexpected redirect)")

        if suspicious:
            return {"status": "danger", "count": len(suspicious), "details": suspicious}
        return {"status": "success", "count": 0, "details": ["No suspicious domain redirects found in hosts file."]}

    except PermissionError:
        return {"status": "warning", "count": 0, "details": ["Permission denied reading hosts file — run with elevated privileges to scan."]}
    except Exception as e:
        return {"status": "warning", "count": 0, "details": [f"Could not read hosts file: {e}"]}


def _scan_persistence():
    """Helper function: Scans Windows Registry startup keys for persistence."""
    if not IS_WINDOWS:
        return {"status": "success", "count": 0,
                "details": ["Registry-based persistence scan is Windows-only. Skipped on this OS."]}

    suspicious = []
    # Registry keys to check
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    
    for hive, key_path in run_keys:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        suspicious.append(f"[{hive_to_str(hive)}] {name}: {value}")
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except Exception as e:
            suspicious.append(f"Error reading key {key_path}: {str(e)}")
            
    if suspicious:
        return {"status": "warning", "count": len(suspicious), "details": suspicious}
    return {"status": "success", "count": 0, "details": ["No suspicious startup items found."]}

def hive_to_str(hive):
    """Helper to make registry key names readable."""
    if hive == winreg.HKEY_CURRENT_USER: return "HKCU"
    if hive == winreg.HKEY_LOCAL_MACHINE: return "HKLM"
    return str(hive)

def _scan_network():
    """Helper function: Scans localhost for common open ports."""
    suspicious = []
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 
        445: "SMB", 1433: "MSSQL", 3306: "MySQL", 
        3389: "RDP (Remote Desktop)", 5900: "VNC"
    }

    for port, service in common_ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1) # <--- THE FIX (much faster)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    suspicious.append(f"Port {port} ({service}) is open")
        except socket.error:
            pass

    if suspicious:
        return {"status": "warning", "count": len(suspicious), "details": suspicious}
    return {"status": "success", "count": 0, "details": ["No common dangerous ports open."]}


def run_full_audit():
    """The main thread target function for the audit."""
    global audit_status, audit_lock, global_last_scan_time, global_security_score

    push_alert("info", "Full security audit started.")

    time.sleep(1)                 # simulate initialization
    proc_result = _scan_processes()

    time.sleep(1)                 # simulate deeper persistence check
    persist_result = _scan_persistence()

    time.sleep(1)                 # simulate network sweep
    net_result = _scan_network()

    time.sleep(1)                 # simulate hosts file / DNS integrity check
    hosts_result = _scan_hosts_file()

    time.sleep(1)                   # simulate final compilation

    results = {
        "processes": proc_result,
        "network": net_result,
        "hosts": hosts_result,
        "scanTime": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    global_last_scan_time = results["scanTime"]

    score = 100
    score -= proc_result["count"] * 20      # suspicious processes are severe
    score -= hosts_result["count"] * 25     # hijacked domain redirects are severe
    score -= net_result["count"] * 3        # each open risky port
    global_security_score = max(0, min(100, score))

    if proc_result["count"] > 0:
        push_alert("critical", f"{proc_result['count']} suspicious process(es) detected.")
    if hosts_result["count"] > 0:
        push_alert("critical", f"{hosts_result['count']} suspicious hosts file redirect(s) detected.")
    if net_result["count"] > 0:
        push_alert("warning", f"{net_result['count']} risky open port(s) detected.")
    if proc_result["count"] == 0 and net_result["count"] == 0 and hosts_result["count"] == 0:
        push_alert("info", "Full audit complete — no issues found.")

    with audit_lock:
        audit_status = {"status": "complete", "results": results}


@app.route('/scan/processes', methods=['POST'])
def scan_processes_only():
    result = _scan_processes()
    if result["count"] > 0:
        push_alert("critical", f"[Process Scan] {result['count']} suspicious process(es) detected.")
    else:
        push_alert("info", "[Process Scan] No suspicious processes found.")
    return jsonify(result)


@app.route('/scan/persistence', methods=['POST'])
def scan_persistence_only():
    result = _scan_persistence()
    if result["count"] > 0:
        push_alert("warning", f"[Startup Scan] {result['count']} persistence item(s) found.")
    else:
        push_alert("info", "[Startup Scan] No suspicious startup entries found.")
    return jsonify(result)


@app.route('/scan/network', methods=['POST'])
def scan_network_only():
    result = _scan_network()
    if result["count"] > 0:
        push_alert("warning", f"[Port Scan] {result['count']} risky open port(s) detected.")
    else:
        push_alert("info", "[Port Scan] No common dangerous ports open.")
    return jsonify(result)


@app.route('/start-full-audit', methods=['POST'])
def start_full_audit():
    global audit_status, audit_lock
    
    with audit_lock:
        if audit_status.get("status") == "running":
            return jsonify({"status": "error", "message": "Scan already in progress."}), 400
        
        audit_status = {"status": "running", "results": {}}
    
    # Run the full scan in a separate thread
    scan_thread = threading.Thread(target=run_full_audit, daemon=True)
    scan_thread.start()
    
    return jsonify({"status": "success", "message": "Full security audit started."}), 202

@app.route('/audit-status')
def get_audit_status():
    global audit_status, audit_lock
    with audit_lock:
        return jsonify(audit_status)
    

    
@app.route('/dashboard-data')
def dashboard_data():
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent # <-- ADDED DISK

    # Calculate Health: 40% CPU, 40% RAM, 20% Disk
    # Lower usage = higher health
    health_score_raw = (cpu * 0.4) + (ram * 0.4) + (disk * 0.2)
    health = 100 - health_score_raw # <-- ADDED HEALTH

    # This now uses the real global variable
    last_scan_time = global_last_scan_time # <-- MODIFIED

    data = {
        "cpu": round(cpu),
        "ram": round(ram),
        "health": round(health), # <-- REPLACED GPU
        "securityScore": global_security_score,
        "uptime": int(psutil.boot_time()),  # UNIX timestamp for frontend formatting
        "procCount": len(psutil.pids()),
        "date": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "lastScan": last_scan_time
    }
    return jsonify(data)


@app.route('/threat-feed')
def get_threat_feed():
    with threat_lock:
        return jsonify(list(threat_feed))


@app.route('/startup-items')
def get_startup_items():
    return jsonify(_scan_persistence())

@app.route('/patch-status')
def patch_status():
    """Real OS patch/update status check — no simulated data."""
    try:
        if IS_WINDOWS:
            ps_script = (
                "$s = New-Object -ComObject Microsoft.Update.Session;"
                "$r = $s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0\");"
                "$r.Updates.Count"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=45
            )
            text = out.stdout.strip()
            if text.isdigit():
                count = int(text)
                return jsonify({
                    "status": "success", "count": count, "platform": "windows",
                    "message": "System is fully patched." if count == 0 else f"{count} pending security update(s) found."
                })
            return jsonify({"status": "warning", "count": None, "platform": "windows",
                             "message": "Could not read Windows Update status."})

        elif platform.system() == "Linux":
            try:
                subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=25)
                out = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=15).stdout
                lines = [l for l in out.splitlines() if "/" in l and "Listing..." not in l]
                return jsonify({
                    "status": "success", "count": len(lines), "platform": "linux (apt)",
                    "message": "System is fully patched." if not lines else f"{len(lines)} package update(s) available."
                })
            except FileNotFoundError:
                out = subprocess.run(["dnf", "check-update"], capture_output=True, text=True, timeout=25)
                lines = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith(("Last metadata", "Repo"))]
                return jsonify({
                    "status": "success", "count": len(lines), "platform": "linux (dnf)",
                    "message": "System is fully patched." if not lines else f"{len(lines)} package update(s) available."
                })

        elif platform.system() == "Darwin":
            out = subprocess.run(["softwareupdate", "-l"], capture_output=True, text=True, timeout=30).stdout
            no_updates = "No new software available" in out
            count = out.count("* Label:")
            return jsonify({
                "status": "success", "count": 0 if no_updates else count, "platform": "macos",
                "message": "System is fully patched." if no_updates else f"{count} macOS update(s) available."
            })

        else:
            return jsonify({"status": "warning", "count": None, "platform": "unknown",
                             "message": "Unsupported OS for patch detection."})

    except subprocess.TimeoutExpired:
        return jsonify({"status": "warning", "count": None, "message": "Patch check timed out — try again."}), 200
    except Exception as e:
        return jsonify({"status": "error", "count": None, "message": str(e)}), 200
    

@app.route('/firewall-status')
def firewall_status():
    """Real cross-platform firewall detection — no simulated data."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            ).stdout
            profiles = re.findall(r"(\w+ Profile Settings):\s*\r?\n-+\r?\n\s*State\s+(\w+)", out)
            if not profiles:
                # fallback simpler parse
                states = re.findall(r"State\s+(ON|OFF)", out)
                enabled = any(s == "ON" for s in states) if states else None
            else:
                enabled = any(state.upper() == "ON" for _, state in profiles)
            return jsonify({"status": "success", "enabled": bool(enabled), "platform": "windows", "raw": out[:800]})

        elif platform.system() == "Linux":
            try:
                out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5).stdout
                enabled = "Status: active" in out
                return jsonify({"status": "success", "enabled": enabled, "platform": "linux (ufw)", "raw": out[:800]})
            except FileNotFoundError:
                out = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5).stdout
                enabled = "Chain INPUT (policy DROP)" in out or bool(re.search(r"\d+\s+.+\s+DROP|REJECT", out))
                return jsonify({"status": "success", "enabled": enabled, "platform": "linux (iptables)", "raw": out[:800]})

        elif platform.system() == "Darwin":
            out = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5
            ).stdout
            enabled = "enabled" in out.lower()
            return jsonify({"status": "success", "enabled": enabled, "platform": "macos", "raw": out[:800]})

        else:
            return jsonify({"status": "warning", "enabled": None, "platform": "unknown",
                             "raw": "Unsupported OS for firewall detection."})

    except subprocess.TimeoutExpired:
        return jsonify({"status": "warning", "enabled": None, "raw": "Firewall check timed out."}), 200
    except PermissionError:
        return jsonify({"status": "warning", "enabled": None, "raw": "Permission denied — try running with elevated privileges."}), 200
    except Exception as e:
        return jsonify({"status": "error", "enabled": None, "raw": str(e)}), 200

@app.route('/listening-ports')
def get_listening_ports():
    """Ports this machine itself has open/listening on — real attack-surface data."""
    risky = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900}
    ports = []
    try:
        seen = set()
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                key = (conn.laddr.port, conn.type)
                if key in seen:
                    continue
                seen.add(key)
                ports.append({
                    "port": conn.laddr.port,
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "risky": conn.laddr.port in risky
                })
        ports.sort(key=lambda p: p["port"])
        return jsonify({"ports": ports})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/processes")
def get_processes():
    try:
        # Get query params for pagination
        page = int(request.args.get("page", 1))  # Default page 1
        per_page = 6  # Show 6 processes at a time

        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                processes.append({
                    "name": info['name'],
                    "pid": info['pid'],
                    "cpu": round(info['cpu_percent'], 1),
                    "ram": round(info['memory_percent'], 1)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort by CPU usage (optional for top processes)
        processes.sort(key=lambda x: x["cpu"], reverse=True)

        # Pagination logic
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        paginated = processes[start_index:end_index]

        total_pages = (len(processes) + per_page - 1) // per_page  # ceil

        return jsonify({
            "page": page,
            "total_pages": total_pages,
            "processes": paginated
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/kill-process", methods=["POST"])
def kill_process():
    try:
        data = request.json
        pid = data.get("pid")

        if not pid:
            return jsonify({"status": "error", "message": "No PID provided"}), 400

        pid = int(pid)
        p = psutil.Process(pid)
        p.terminate()  # Try to terminate the process
        p.wait(timeout=3)  # Wait for termination

        return jsonify({"status": "success", "message": f"Process {pid} terminated successfully."}), 200

    except psutil.NoSuchProcess:
        return jsonify({"status": "error", "message": "Process not found."}), 404
    except psutil.AccessDenied:
        return jsonify({"status": "error", "message": "Access denied. Try running as Administrator."}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



if __name__ == "__main__":
    # Multiple folders to monitor
    paths_to_watch = [
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Documents"),
    ]

    for folder_path in paths_to_watch:
        if os.path.exists(folder_path):
            print(f"📂 Monitoring: {folder_path}")
            start_file_monitor(path=folder_path)
        else:
            print(f"⚠️ Folder not found: {folder_path}")

import threading, webbrowser
def open_browser():
    webbrowser.open("http://127.0.0.1:5001/")
threading.Timer(1, open_browser).start()
app.run(host="127.0.0.1", port=5001, debug=False)


#Port change to 5000 for exe version now i have changed to 5001 and also update time of html file to 1 second