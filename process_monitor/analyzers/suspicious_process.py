from process_monitor.alert import ProcessAlert

# Known suspicious process names — add more as you learn them
SUSPICIOUS_NAMES = {
    # Hacking / remote access tools
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "psexec.exe", "psexec64.exe", "wce.exe", "fgdump.exe",

    # Suspicious scripting
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",

    # Common trojan/rat names
    "rats.exe", "njrat.exe", "darkcomet.exe", "poisonivy.exe",
    "back_orifice.exe", "sub7.exe",

    # Linux equivalents
    "nc", "ncat", "netcat", "bash", "sh", "python3", "perl", "ruby",
}

# Suspicious keywords that might appear in a process path
SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "/tmp/", "/var/tmp/",
    "\\downloads\\",
]

class SuspiciousProcessDetector:
    def __init__(self):
        self._alerted_pids = set()

    def analyze(self, process: dict) -> ProcessAlert | None:
        pid = process["pid"]
        name = process["name"].lower()
        exe_path = process["exe"].lower()

        if pid in self._alerted_pids:
            return None  # already alerted about this one

        # Check against known suspicious names
        if name in SUSPICIOUS_NAMES:
            self._alerted_pids.add(pid)
            return ProcessAlert(
                alert_type="SUSPICIOUS_PROCESS_NAME",
                severity="HIGH",
                pid=pid,
                process_name=process["name"],
                description=f"Suspicious process detected: '{process['name']}' (PID {pid}) matches known dangerous tool list",
                extra={"exe": process["exe"], "cmdline": process["cmdline"]}
            )

        # Check if running from a suspicious location (e.g. Temp folder)
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in exe_path:
                self._alerted_pids.add(pid)
                return ProcessAlert(
                    alert_type="PROCESS_FROM_SUSPICIOUS_PATH",
                    severity="MEDIUM",
                    pid=pid,
                    process_name=process["name"],
                    description=f"'{process['name']}' (PID {pid}) is running from a suspicious location: {process['exe']}",
                    extra={"exe": process["exe"]}
                )

        return None