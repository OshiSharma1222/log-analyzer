import importlib
import math


class AnomalyDetector:
    def __init__(self, contamination=0.15, random_state=42):
        self.contamination = contamination
        self.random_state = random_state

    def _feature_vector(self, feature_row):
        return [
            float(feature_row.get("request_rate", 0.0)),
            float(feature_row.get("error_rate", 0.0)),
            float(feature_row.get("data_transfer_rate", 0.0)),
            float(feature_row.get("login_failures", 0.0)),
            float(feature_row.get("log_length", 0.0)),
        ]

    def _detect_with_sklearn(self, features):
        sklearn_ensemble = importlib.import_module("sklearn.ensemble")
        isolation_forest = sklearn_ensemble.IsolationForest

        matrix = [self._feature_vector(feature_row) for feature_row in features]
        model = isolation_forest(
            contamination=min(self.contamination, max(1 / len(features), 0.49)),
            random_state=self.random_state,
        )
        predictions = model.fit_predict(matrix)
        scores = model.decision_function(matrix)

        anomalies = []
        for index, prediction in enumerate(predictions):
            if prediction != -1:
                continue

            enriched_row = dict(features[index])
            enriched_row.update(
                {
                    "severity": "high" if scores[index] < -0.05 else "medium",
                    "anomaly_score": round(float(scores[index]), 4),
                }
            )
            anomalies.append(enriched_row)

        return anomalies

    def _detect_with_statistics(self, features):
        matrix = [self._feature_vector(feature_row) for feature_row in features]
        column_means = [sum(column) / len(column) for column in zip(*matrix)]

        distances = []
        for vector in matrix:
            distance = math.sqrt(
                sum((value - mean) ** 2 for value, mean in zip(vector, column_means))
            )
            distances.append(distance)

        mean_distance = sum(distances) / len(distances)
        variance = sum((distance - mean_distance) ** 2 for distance in distances) / len(distances)
        deviation = math.sqrt(variance)
        threshold = mean_distance + max(deviation, 0.5)

        anomalies = []
        for index, distance in enumerate(distances):
            if distance <= threshold:
                continue

            enriched_row = dict(features[index])
            enriched_row.update(
                {
                    "severity": "high" if distance > threshold * 1.25 else "medium",
                    "anomaly_score": round(distance, 4),
                }
            )
            anomalies.append(enriched_row)

        return anomalies

    def detect(self, features):
        if not features:
            return []

        if len(features) < 3:
            return []

        try:
            return self._detect_with_sklearn(features)
        except ModuleNotFoundError:
            return self._detect_with_statistics(features)