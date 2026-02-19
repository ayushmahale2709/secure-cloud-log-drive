import time
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    ML-based anomaly detection using Isolation Forest.
    """

    def __init__(self):
        # Small model for real-time detection
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.2,
            random_state=42
        )
        self.data = []
        self.trained = False

    def record_activity(self, search_count, view_count, time_gap):
        """
        Record user activity as a feature vector.
        """
        feature_vector = [search_count, view_count, time_gap]
        self.data.append(feature_vector)

        # Train model after enough data
        if len(self.data) >= 10:
            self._train_model()

    def _train_model(self):
        """
        Train Isolation Forest on collected data.
        """
        X = np.array(self.data)
        self.model.fit(X)
        self.trained = True

    def is_anomalous(self, search_count, view_count, time_gap) -> bool:
        """
        Predict whether current behavior is anomalous.
        """
        if not self.trained:
            return False

        X = np.array([[search_count, view_count, time_gap]])
        prediction = self.model.predict(X)

        # -1 means anomaly, 1 means normal
        return prediction[0] == -1
