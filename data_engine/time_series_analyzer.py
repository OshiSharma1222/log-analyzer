from typing import Dict, Any, List, Tuple
from collections import defaultdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class TimeSeriesAnalyzer:
    """
    Analyzes temporal trends using a sliding window across logs, extracting
    per-minute load, errors, and burst patterns.
    """
    
    def __init__(self, window_size_seconds: int = 60):
        """
        Args:
            window_size_seconds (int): Granularity of the time series window (default 1 min)
        """
        self.window_size_seconds = window_size_seconds
        
    def _parse_time(self, ts_str: str) -> float:
        """
        Best-effort parsing of various log timestamps into UNIX epoch seconds.
        """
        if not ts_str:
            return 0.0
            
        # Standard: 2026-03-14 12:20:01
        try:
            dt = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except ValueError:
            pass
        
        # Apache: 14/Mar/2026:12:20:01
        try:
            trimmed = ts_str.split()[0]
            dt = datetime.strptime(trimmed, "%d/%b/%Y:%H:%M:%S")
            return dt.timestamp()
        except ValueError:
            pass
            
        return 0.0

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Map a batch of normalized logs into discrete sliding windows 
        to capture temporal trends (like RPS and Error Bursts).
        """
        if not logs:
            return {}

        parsed_logs: List[Tuple[float, Dict[str, Any]]] = []
        for log in logs:
            ts = self._parse_time(log.get("timestamp", ""))
            if ts > 0:
                parsed_logs.append((ts, log))
                
        # Time-series analysis requires chronological sorting
        parsed_logs.sort(key=lambda x: x[0])
        
        return self._compute_metrics(parsed_logs)

    def _compute_metrics(self, sorted_logs: List[Tuple[float, Dict[str, Any]]]) -> Dict[str, Any]:
        """
        O(N) single-pass bucket aggregation for fast sliding window summaries.
        """
        if not sorted_logs:
            return {}
            
        start_time = sorted_logs[0][0]
        
        # buckets logic: map continuous sliding window logic into hashed buckets starting from index 0
        buckets = defaultdict(lambda: {"requests": 0, "errors": 0})
        ip_login_attempts = defaultdict(int)
        
        for ts, log in sorted_logs:
            # Shift continuous timestamp into discrete chunk offsets
            bucket_idx = int((ts - start_time) // self.window_size_seconds)
            
            buckets[bucket_idx]["requests"] += 1
            if log.get("level") in {"ERROR", "CRITICAL", "WARNING"}:
                buckets[bucket_idx]["errors"] += 1
                
            ip = log.get("ip")
            if ip and 'login' in str(log.get("message", "")).lower():
                ip_login_attempts[ip] += 1

        windows_requests = []
        windows_errors = []
        for b_idx in sorted(buckets.keys()):
            windows_requests.append(buckets[b_idx]["requests"])
            windows_errors.append(buckets[b_idx]["errors"])
            
        total_windows = len(windows_requests)
            
        return {
            "window_size_sec": self.window_size_seconds,
            "max_requests_per_window": max(windows_requests) if windows_requests else 0,
            "avg_requests_per_window": round(sum(windows_requests)/total_windows, 2) if total_windows else 0,
            "max_errors_per_window": max(windows_errors) if windows_errors else 0,
            "ip_login_attempts_overall": dict(ip_login_attempts)
        }
