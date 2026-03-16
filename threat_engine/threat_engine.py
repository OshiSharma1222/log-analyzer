from collections import Counter, defaultdict

from threat_engine.anomaly_detector import AnomalyDetector
from threat_engine.behaviour_engine import BehaviourDetector
from threat_engine.log_clustering import LogClustering
from threat_engine.rule_engine import RuleEngine


class ThreatEngine:
    def __init__(self, rule_engine=None, behaviour_detector=None, anomaly_detector=None, clustering=None):
        self.rule_engine = rule_engine or RuleEngine()
        self.behaviour_detector = behaviour_detector or BehaviourDetector()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.clustering = clustering or LogClustering()

    def _normalise_logs(self, logs):
        normalised_logs = []
        for log in logs:
            if not isinstance(log, dict):
                continue

            normalised_logs.append(
                {
                    "timestamp": log.get("timestamp"),
                    "level": str(log.get("level", "INFO")).upper(),
                    "message": str(log.get("message", "")),
                    "ip": log.get("ip", "unknown"),
                    "source": log.get("source", "unknown"),
                }
            )
        return normalised_logs

    def _build_feature_rows(self, logs, provided_features=None):
        if provided_features:
            feature_rows = []
            for feature in provided_features:
                feature_rows.append(
                    {
                        "ip": feature.get("ip", "unknown"),
                        "request_rate": float(feature.get("request_rate", 0.0)),
                        "error_rate": float(feature.get("error_rate", 0.0)),
                        "data_transfer_rate": float(feature.get("data_transfer_rate", 0.0)),
                        "login_failures": float(feature.get("login_failures", feature.get("login failures", 0.0))),
                        "log_length": float(feature.get("log_length", 0.0)),
                    }
                )
            return feature_rows

        grouped_logs = defaultdict(list)
        for log in logs:
            grouped_logs[log.get("ip", "unknown")].append(log)

        feature_rows = []
        for ip_address, entries in grouped_logs.items():
            error_count = sum(1 for entry in entries if entry.get("level") in {"ERROR", "CRITICAL"})
            login_failures = sum(
                1
                for entry in entries
                if "login failed" in entry.get("message", "").lower()
                or "authentication failure" in entry.get("message", "").lower()
            )
            average_log_length = sum(len(entry.get("message", "")) for entry in entries) / len(entries)

            feature_rows.append(
                {
                    "ip": ip_address,
                    "request_rate": float(len(entries)),
                    "error_rate": round(error_count / len(entries), 4),
                    "data_transfer_rate": 0.0,
                    "login_failures": float(login_failures),
                    "log_length": round(average_log_length, 2),
                }
            )

        return feature_rows

    def _summarise(self, logs, rule_alerts, behaviour_alerts, anomalies):
        severity_counts = Counter()
        for alert in rule_alerts + behaviour_alerts + anomalies:
            severity_counts[alert.get("severity", "unknown")] += 1

        total_logs = len(logs)
        error_logs = sum(1 for log in logs if log.get("level") in {"ERROR", "CRITICAL"})
        suspicious_ips = sorted(
            {
                alert.get("ip")
                for alert in rule_alerts + behaviour_alerts + anomalies
                if alert.get("ip")
            }
        )

        if severity_counts.get("high"):
            risk_level = "high"
        elif severity_counts.get("medium"):
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "total_logs": total_logs,
            "error_logs": error_logs,
            "severity_breakdown": dict(severity_counts),
            "suspicious_ip_count": len(suspicious_ips),
            "suspicious_ips": suspicious_ips,
            "risk_level": risk_level,
        }

    def analyze(self, logs, features=None):
        normalised_logs = self._normalise_logs(logs)
        feature_rows = self._build_feature_rows(normalised_logs, provided_features=features)

        rule_alerts = self.rule_engine.detect(normalised_logs)
        behaviour_alerts = self.behaviour_detector.detect(normalised_logs)
        anomalies = self.anomaly_detector.detect(feature_rows)
        clusters = self.clustering.cluster(normalised_logs)
        summary = self._summarise(normalised_logs, rule_alerts, behaviour_alerts, anomalies)

        return {
            "summary": summary,
            "rule_alerts": rule_alerts,
            "behavior_alerts": behaviour_alerts,
            "anomalies": anomalies,
            "clusters": clusters,
            "derived_features": feature_rows,
        }