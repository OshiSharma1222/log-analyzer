import json
class RuleEngine:
    def __init__(self, rules):
        if rules is None:
            self.rules = rules
        else:
            with open("config/detection_rules.json") as f:
                self.rules = json.load(f)
    
    def detect(self, logs):
        alerts = []
        for log in logs:
            message = log["message"].lower()
            for rule in self.rules:
                if rule in message:
                    alerts.append({
                        "type": rule,
                        "ip": log.get("ip"),
                        "timestamp":log.get("timestamp"),
                        "message":log["message"]
                    })
        return alerts

