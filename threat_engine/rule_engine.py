import json
from pathlib import Path


class RuleEngine:
    def __init__(self, rules=None, rules_path=None):
        self.rules_path = Path(rules_path) if rules_path else self._default_rules_path()
        self.rules = self._normalise_rules(rules if rules is not None else self._load_rules())

    def _default_rules_path(self):
        return Path(__file__).resolve().parent.parent / "config" / "detection_rules.json"

    def _load_rules(self):
        with self.rules_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _normalise_rules(self, rules):
        normalised = []
        for rule in rules:
            if isinstance(rule, str):
                normalised.append(
                    {
                        "name": rule.upper(),
                        "category": "operational",
                        "severity": "medium",
                        "keywords": [rule.lower()],
                    }
                )
                continue

            keywords = [keyword.lower() for keyword in rule.get("keywords", [])]
            if not keywords and rule.get("name"):
                keywords = [rule["name"].lower()]

            normalised.append(
                {
                    "name": rule.get("name", "UNNAMED_RULE"),
                    "category": rule.get("category", "operational"),
                    "severity": rule.get("severity", "medium"),
                    "keywords": keywords,
                    "description": rule.get("description", ""),
                }
            )
        return normalised

    def detect(self, logs):
        alerts = []
        for log in logs:
            message = str(log.get("message", ""))
            message_lower = message.lower()
            for rule in self.rules:
                matched_keyword = next(
                    (keyword for keyword in rule["keywords"] if keyword in message_lower),
                    None,
                )
                if matched_keyword is None:
                    continue

                alerts.append(
                    {
                        "rule": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "matched_keyword": matched_keyword,
                        "timestamp": log.get("timestamp"),
                        "ip": log.get("ip"),
                        "level": log.get("level", "INFO"),
                        "message": message,
                        "description": rule.get("description", ""),
                    }
                )
        return alerts

