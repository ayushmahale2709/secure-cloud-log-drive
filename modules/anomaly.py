import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    ML-based anomaly detection using Isolation Forest.
    Produces risk levels instead of simple True/False.
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.2,
            random_state=42
        )
        self.data = []
        self.trained = False

    def record_activity(self, search_count, view_count, time_gap):
        """
        Record user behavior as feature vector:
        [search count, view count, time gap]
        """
        self.data.append([search_count, view_count, time_gap])

        if len(self.data) >= 10:
            self._train_model()

    def _train_model(self):
        X = np.array(self.data)
        self.model.fit(X)
        self.trained = True

    def evaluate_risk(self, search_count, view_count, time_gap) -> str:
        """
        Returns:
        - NORMAL
        - SUSPICIOUS
        - HIGH
        """
        if not self.trained:
            return "NORMAL"

        X = np.array([[search_count, view_count, time_gap]])
        prediction = self.model.predict(X)

        if prediction[0] == -1:
            if search_count >= 6 or time_gap < 1.5:
                return "HIGH"
            return "SUSPICIOUS"

        return "NORMAL"
