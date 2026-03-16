#this module will detect the suspicious user behaviour pattern like brute force attack
from collections import dedualtdict, defaultdict
from rule_engine import RuleEngine
class BehaviourDetector:
    def __init__bruteforce(self, logs):
        login_failures = defaultdict(int) #to count failed login attempts per IP
        for log in logs:
            message = log["message"].lower()
            if "login failed" in message or "authentication failure" in message:
                ip = log.get("ip")
                login_failures[ip]+=1
            suspicious_ips = []
            for ip, count in login_failures.items():
                
                if count > 3:
                    suspicious_ips.append({
                        "ip" : ip,
                        "attempts": count,
                        "type": "possible brute force"
                    })
        return suspicious_ips