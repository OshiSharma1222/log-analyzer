"""
IP Intelligence System
Builds a rich behavioral profile for each IP seen across log entries.
Detects: most-active IPs, login failure spikes, request bursts, and assigns
a threat flag (clean / suspicious / malicious) based on configurable thresholds.
"""

import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

LOGIN_FAILURE_RE = re.compile(
    r"login\s*fail|authentication\s*fail|auth\s*fail|invalid\s*password|invalid\s*credentials",
    re.IGNORECASE,
)

TIMESTAMP_FMTS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
)


def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
    """Best-effort timestamp parse across multiple known formats."""
    if not raw:
        return None
    # Trim timezone suffix so strptime does not choke
    trimmed = raw.split("+")[0].split(" +")[0].strip()
    for fmt in TIMESTAMP_FMTS:
        try:
            return datetime.strptime(trimmed[:19], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(trimmed)
    except ValueError:
        return None


class IPProfiler:
    """
    Builds structured intelligence profiles for every IP active in a log batch.

    Thresholds (all configurable via constructor):
    - failed_login_threshold  : logins at or above this → escalate flag
    - burst_rps_threshold     : requests/sec sustained above this → escalate
    - malicious_login_limit   : failed logins above this → flag = "malicious"
    """

    def __init__(
        self,
        failed_login_threshold: int = 5,
        burst_rps_threshold: float = 10.0,
        malicious_login_limit: int = 20,
    ) -> None:
        self.failed_login_threshold = failed_login_threshold
        self.burst_rps_threshold = burst_rps_threshold
        self.malicious_login_limit = malicious_login_limit

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def profile(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyse a normalised log batch and return one intelligence record per IP.

        Args:
            logs: List of normalised log dicts (output of ThreatEngine._normalise_logs).

        Returns:
            List of IP intelligence dicts, sorted by threat score descending.
        """
        raw: Dict[str, Dict[str, Any]] = defaultdict(self._empty_profile)

        for log in logs:
            ip = log.get("ip") or "unknown"
            ts = _parse_ts(log.get("timestamp"))
            msg = str(log.get("message", ""))
            level = str(log.get("level", "INFO")).upper()

            p = raw[ip]
            p["ip"] = ip
            p["_request_timestamps"].append(ts)
            p["total_requests"] += 1

            if level in {"ERROR", "CRITICAL"}:
                p["error_count"] += 1

            if LOGIN_FAILURE_RE.search(msg):
                p["failed_logins"] += 1
                if ts:
                    p["_failure_times"].append(ts)

        profiles = [self._finalise(p) for p in raw.values()]
        profiles.sort(key=lambda x: x["threat_score"], reverse=True)
        return profiles

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_profile() -> Dict[str, Any]:
        return {
            "ip": "unknown",
            "total_requests": 0,
            "failed_logins": 0,
            "error_count": 0,
            "_request_timestamps": [],
            "_failure_times": [],
        }

    def _compute_rps(self, timestamps: List[Optional[datetime]]) -> float:
        """
        Estimate requests-per-second from a list of timestamps.
        Uses total span / count — avoids nested loops.
        """
        valid = sorted(t for t in timestamps if t is not None)
        if len(valid) < 2:
            return 0.0
        span_seconds = (valid[-1] - valid[0]).total_seconds()
        if span_seconds <= 0:
            return float(len(valid))
        return round(len(valid) / span_seconds, 4)

    def _assign_flag(self, failed_logins: int, rps: float) -> str:
        """Classify an IP as clean / suspicious / malicious."""
        if failed_logins >= self.malicious_login_limit:
            return "malicious"
        if failed_logins >= self.failed_login_threshold or rps >= self.burst_rps_threshold:
            return "suspicious"
        return "clean"

    def _threat_score(self, failed_logins: int, rps: float, error_count: int) -> float:
        """
        Composite threat score (0–100) blending login failures, RPS spikes, and error rate.
        Weights: logins 50 %, RPS 30 %, errors 20 %.
        """
        login_score = min(failed_logins / max(self.malicious_login_limit, 1) * 50, 50)
        rps_score = min(rps / max(self.burst_rps_threshold, 1) * 30, 30)
        error_score = min(error_count / 10 * 20, 20)
        return round(login_score + rps_score + error_score, 2)

    def _finalise(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a raw accumulation dict into a clean intelligence record."""
        rps = self._compute_rps(raw["_request_timestamps"])
        failed = raw["failed_logins"]
        errors = raw["error_count"]
        flag = self._assign_flag(failed, rps)
        score = self._threat_score(failed, rps, errors)

        return {
            "ip": raw["ip"],
            "total_requests": raw["total_requests"],
            "failed_logins": failed,
            "error_count": errors,
            "requests_per_sec": rps,
            "flag": flag,
            "threat_score": score,
        }
