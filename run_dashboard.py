import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import threading
import time
import webbrowser
from dashboard.server import run_server, add_alert, set_module_status

print("="*55)
print("  HIDS Dashboard")
print("="*55)
print()

# Start the web server in a background thread
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
print("[1/3] Web server started at http://127.0.0.1:5000")

# Wait a moment then open the browser automatically
time.sleep(1.5)
dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "dashboard.html")
webbrowser.open("file://" + os.path.abspath(dashboard_path))
print("[2/3] Dashboard opened in your browser")

# ── Send demo alerts so you can see the dashboard working ────────────
print("[3/3] Sending demo alerts...")
time.sleep(1)

demo_alerts = [
    ("network",   "PORT_SCAN",          "HIGH",     "Port scan detected: 24 ports probed from 192.168.1.5 in 10s"),
    ("integrity", "FILE_DELETED",       "CRITICAL", "File was DELETED: 'secrets.txt'"),
    ("log",       "BRUTE_FORCE",        "HIGH",     "6 failed login attempts in 60 seconds"),
    ("process",   "HIGH_CPU",           "HIGH",     "'cryptominer.exe' using 94.2% CPU"),
    ("network",   "SUSPICIOUS_DNS",     "MEDIUM",   "Suspicious DNS query 'xkqtbfzmprs.tk'"),
    ("log",       "DANGEROUS_KEYWORD",  "CRITICAL", "Keyword 'rootkit' found in system log"),
    ("integrity", "FILE_MODIFIED",      "HIGH",     "File was modified: 'config.txt'"),
    ("process",   "NEW_PROCESS",        "LOW",      "New process started: 'unknown_task.exe' (PID 9832)"),
    ("network",   "BANDWIDTH_SPIKE",    "MEDIUM",   "12.4 MB sent from 192.168.1.10 in 5 seconds"),
    ("integrity", "FILE_CREATED",       "MEDIUM",   "New file appeared: 'malware.exe'"),
]

# Set all modules as running
for mod in ["network", "process", "log", "integrity"]:
    set_module_status(mod, "running")

# Send alerts one by one with a gap so you see them appear live
for source, alert_type, severity, description in demo_alerts:
    add_alert(source, alert_type, severity, description)
    print(f"  -> [{severity}] {alert_type}")
    time.sleep(1.5)

print()
print("Dashboard is live! Alerts are appearing in real time.")
print("Keep this terminal running — press Ctrl+C to stop.\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDashboard stopped.")
    