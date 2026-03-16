from collections import Counter, defaultdict
from datetime import datetime


class BehaviourDetector:
    def __init__(self, brute_force_threshold=3, burst_threshold=20):
        self.brute_force_threshold = brute_force_threshold
        self.burst_threshold = burst_threshold

    def _parse_timestamp(self, value):
        if not value:
            return None

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def detect_bruteforce(self, logs):
        login_failures = defaultdict(list)
        for log in logs:
            message = str(log.get("message", "")).lower()
            if "login failed" not in message and "authentication failure" not in message:
                continue

            ip_address = log.get("ip", "unknown")
            login_failures[ip_address].append(log)

        suspicious_ips = []
        for ip_address, failed_events in login_failures.items():
            if len(failed_events) <= self.brute_force_threshold:
                continue

            suspicious_ips.append(
                {
                    "type": "possible brute force",
                    "severity": "high",
                    "ip": ip_address,
                    "attempts": len(failed_events),
                    "first_seen": failed_events[0].get("timestamp"),
                    "last_seen": failed_events[-1].get("timestamp"),
                    "messages": [event.get("message") for event in failed_events[-3:]],
                }
            )

        return suspicious_ips

    def detect_request_burst(self, logs):
        per_minute = Counter()
        for log in logs:
            ip_address = log.get("ip") or "unknown"
            timestamp = self._parse_timestamp(log.get("timestamp"))
            if timestamp is None:
                continue

            bucket = timestamp.replace(second=0, microsecond=0).isoformat(sep=" ")
            per_minute[(ip_address, bucket)] += 1

        alerts = []
        for (ip_address, bucket), request_count in per_minute.items():
            if request_count <= self.burst_threshold:
                continue

            alerts.append(
                {
                    "type": "request burst",
                    "severity": "medium",
                    "ip": ip_address,
                    "time_window": bucket,
                    "request_count": request_count,
                }
            )

        return alerts

    def detect(self, logs):
        return self.detect_bruteforce(logs) + self.detect_request_burst(logs)