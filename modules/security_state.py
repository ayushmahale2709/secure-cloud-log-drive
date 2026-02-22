# modules/security_state.py

class SecurityState:
    """
    Global security state shared across sessions.
    Tracks overall system threat level.
    """

    def __init__(self):
        self.search_count = 0
        self.view_count = 0
        self.anomaly_hits = 0
        self.threat_level = "LOW"  # LOW, MEDIUM, HIGH

    def record_search(self):
        self.search_count += 1

    def record_view(self):
        self.view_count += 1

    def record_anomaly(self):
        self.anomaly_hits += 1
        self._update_threat_level()

    def reset_anomaly(self):
        if self.anomaly_hits > 0:
            self.anomaly_hits -= 1
        self._update_threat_level()

    def _update_threat_level(self):
        if self.anomaly_hits >= 3:
            self.threat_level = "HIGH"
        elif self.anomaly_hits == 2:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"
