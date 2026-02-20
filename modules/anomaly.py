import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    ML-based anomaly detection using Isolation Forest.
    Detects abnormal user behavior in real time.
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
        Record user activity as a feature vector:
        [search frequency, log views, time gap]
        """
        feature_vector = [search_count, view_count, time_gap]
        self.data.append(feature_vector)

        # Train model after collecting baseline behavior
        if len(self.data) >= 10:
            self._train_model()

    def _train_model(self):
        X = np.array(self.data)
        self.model.fit(X)
        self.trained = True

    def is_anomalous(self, search_count, view_count, time_gap) -> bool:
        """
        Predict whether the current behavior is anomalous.
        """
        if not self.trained:
            return False

        X = np.array([[search_count, view_count, time_gap]])
        prediction = self.model.predict(X)

        # Isolation Forest: -1 = anomaly, 1 = normal
        return prediction[0] == -1
