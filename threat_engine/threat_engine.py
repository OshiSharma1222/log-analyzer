from threat_engine.rule_engine import RuleEngine
from threat_engine.behavior_engine import BehaviourDetector
from threat_engine.anomaly_detector import AnomalyDetector
from threat_engine.log_clustering import LogClustering

class ThreatEngine:

    def analyze(self, logs, features):

        rule_engine = RuleEngine()
        behavior_detector = BehaviourDetector()
        anomaly_detector = AnomalyDetector()
        clustering = LogClustering()

        rule_alerts = rule_engine.detect(logs)

        behavior_alerts = behavior_detector.detect_bruteforce(logs)

        anomalies = anomaly_detector.detect(features)

        clusters = clustering.cluster(logs)

        return {
            "rule_alerts": rule_alerts,
            "behavior_alerts": behavior_alerts,
            "anomalies": anomalies,
            "clusters": clusters
        }