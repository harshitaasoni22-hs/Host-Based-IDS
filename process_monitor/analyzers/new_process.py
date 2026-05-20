from datetime import datetime
from process_monitor.alert import ProcessAlert

class NewProcessWatcher:
    def __init__(self):
        self._known_pids: set[int] = set()
        self._initialized = False

    def initialize(self, processes: list[dict]):
        """
        Call this once at startup with the initial list of processes.
        Everything in this list is considered 'normal' and will NOT be alerted.
        """
        self._known_pids = {p["pid"] for p in processes}
        self._initialized = True
        print(f"  [NewProcessWatcher] Learned {len(self._known_pids)} existing processes as baseline.")

    def analyze(self, process: dict) -> ProcessAlert | None:
        if not self._initialized:
            return None

        pid = process["pid"]

        # If we have never seen this PID before — it is a NEW process
        if pid not in self._known_pids:
            self._known_pids.add(pid)  # add it so we don't alert again
            name = process["name"]

            return ProcessAlert(
                alert_type="NEW_PROCESS",
                severity="LOW",
                pid=pid,
                process_name=name,
                description=f"New process started: '{name}' (PID {pid}) — appeared after monitor started",
                extra={
                    "exe": process["exe"],
                    "username": process["username"],
                    "cmdline": process["cmdline"]
                }
            )

        return None