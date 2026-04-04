import re
from typing import Dict, Any, List

# Regex patterns to detect specific security behaviors
LOGIN_PATTERNS = re.compile(r'login\s*failed|authentication\s*fail|auth\s*fail|401', re.IGNORECASE)

def extract_features(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract discrete atomic features from a single normalized log entry
    for downstream time-series analysis or ML modeling.
    """
    message = str(log.get("message", ""))
    level = str(log.get("level", "INFO")).upper()
    metadata = log.get("metadata", {})
    
    # Flag errors if specifically labeled ERROR/CRITICAL or if an Apache HTTP 4xx/5xx code is present
    status_code = metadata.get("status_code", "200")
    is_error = 1 if level in {"ERROR", "CRITICAL", "WARNING"} or not status_code.startswith(('2', '3')) else 0
    
    # Detect login failures based on message patterns or 401 code
    is_login_failed = 1 if LOGIN_PATTERNS.search(message) or status_code == "401" else 0
    
    return {
        "log_length": len(message),
        "error_flag": is_error,
        "is_login_failure": is_login_failed,
        "ip": log.get("ip", ""),
        "timestamp": log.get("timestamp", "")
    }

def aggregate_ip_features(features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggregate individual log features globally per IP address to compute
    risk metrics. Designed to generate the `features` object in the main ThreatEngine.
    """
    ip_stats = {}
    
    # 1st Pass: Aggregate raw metrics per IP
    for f in features_list:
        ip = f.get("ip")
        if not ip:
            continue
            
        if ip not in ip_stats:
            ip_stats[ip] = {
                "request_count": 0, 
                "error_count": 0, 
                "login_failure_count": 0, 
                "total_length": 0
            }
        
        stat = ip_stats[ip]
        stat["request_count"] += 1
        stat["error_count"] += f.get("error_flag", 0)
        stat["login_failure_count"] += f.get("is_login_failure", 0)
        stat["total_length"] += f.get("log_length", 0)
        
    results = []
    
    # 2nd Pass: Derive Rates and normalize bounds
    for ip, stat in ip_stats.items():
        requests = stat["request_count"]
        results.append({
            "ip": ip,
            "ip_request_count": requests,
            "error_rate": round(stat["error_count"] / requests, 4) if requests > 0 else 0.0,
            "login_failures": stat["login_failure_count"],
            "avg_log_length": round(stat["total_length"] / requests, 2) if requests > 0 else 0.0
        })
        
    return results
