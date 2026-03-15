# modules/security_state.py

class SecurityState:
    """
    Global security state shared across sessions.
    Tracks overall system threat level and activity metrics.
    """

    def __init__(self):

        # Activity counters
        self.search_count = 0
        self.view_count = 0

        # Anomaly detection counter
        self.anomaly_hits = 0

        # System threat level
        self.threat_level = "LOW"   # LOW, MEDIUM, HIGH


    # -------------------------------------------------
    # RECORD USER ACTIONS
    # -------------------------------------------------

    def record_search(self):
        """Track search activity."""
        self.search_count += 1


    def record_view(self):
        """Track log view activity."""
        self.view_count += 1


    def record_anomaly(self):
        """Record suspicious behaviour."""
        self.anomaly_hits += 1
        self._update_threat_level()


    def reset_anomaly(self):
        """Reduce anomaly count when system stabilizes."""
        if self.anomaly_hits > 0:
            self.anomaly_hits -= 1

        self._update_threat_level()


    # -------------------------------------------------
    # THREAT LEVEL LOGIC
    # -------------------------------------------------

    def _update_threat_level(self):

        if self.anomaly_hits >= 3:
            self.threat_level = "HIGH"

        elif self.anomaly_hits == 2:
            self.threat_level = "MEDIUM"

        else:
            self.threat_level = "LOW"


    # -------------------------------------------------
    # SECURITY SCORE (FOR DASHBOARD)
    # -------------------------------------------------

    def get_security_score(self):
        """
        Returns a security score out of 100.
        Higher anomalies reduce score.
        """

        score = 100 - (self.anomaly_hits * 25)

        if score < 0:
            score = 0

        return score


    # -------------------------------------------------
    # SECURITY STATUS MESSAGE
    # -------------------------------------------------

    def get_status_message(self):

        if self.threat_level == "LOW":
            return "System secure. No abnormal activity detected."

        elif self.threat_level == "MEDIUM":
            return "Suspicious behaviour detected. Monitoring closely."

        else:
            return "High threat activity detected. Immediate attention required."


    # -------------------------------------------------
    # DASHBOARD SUMMARY
    # -------------------------------------------------

    def get_summary(self):
        """
        Returns all security metrics in one structure
        for dashboard display.
        """

        return {
            "searches": self.search_count,
            "views": self.view_count,
            "anomalies": self.anomaly_hits,
            "threat_level": self.threat_level,
            "security_score": self.get_security_score()
        }


    # -------------------------------------------------
    # RESET SYSTEM SECURITY
    # -------------------------------------------------

    def reset_security(self):
        """
        Reset security monitoring values.
        Useful for admin controls.
        """

        self.search_count = 0
        self.view_count = 0
        self.anomaly_hits = 0
        self.threat_level = "LOW"
