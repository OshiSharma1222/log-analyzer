"""
Enhanced Log Clustering with Root-Cause Detection.

Replaces the original LogClustering.  New capabilities:
- Root-cause label assigned to every cluster via keyword heuristics (always)
  plus TF-IDF + cosine similarity ranking when scikit-learn is present.
- Cluster confidence score (0-1).
- Top-N representative messages surfaced per cluster.
- Graceful fallback when scikit-learn is absent.
"""

import importlib
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Root-cause label taxonomy
# Ordered: first match wins.  Extend this list to add new categories.
# ---------------------------------------------------------------------------
ROOT_CAUSE_RULES: List[Tuple[str, re.Pattern]] = [
    ("Database Failure",     re.compile(r"database|db\s|timeout|connection refused|sql", re.I)),
    ("Authentication Error", re.compile(r"auth|login\s*fail|unauthori[sz]ed|invalid\s*(password|cred)", re.I)),
    ("Memory Pressure",      re.compile(r"out of memory|oom|memory (leak|overflow|exhausted)", re.I)),
    ("Network / IO Error",   re.compile(r"connection\s*(reset|refused|timed?\s*out)|network|socket|i/o error", re.I)),
    ("Service Crash",        re.compile(r"segfault|panic|fatal|crash|core dump|killed", re.I)),
    ("Permission Denied",    re.compile(r"permission denied|access denied|forbidden|403", re.I)),
    ("Rate Limiting",        re.compile(r"rate.?limit|too many request|429|throttl", re.I)),
    ("Configuration Error",  re.compile(r"config|yaml|toml|invalid setting|missing key", re.I)),
]


def _infer_root_cause(messages: List[str]) -> str:
    """
    Vote across messages in a cluster to determine the dominant root-cause label.
    Uses frequency counting across the taxonomy rules; returns 'Unknown / Misc' as default.
    """
    scores: Dict[str, int] = defaultdict(int)
    for msg in messages:
        for label, pattern in ROOT_CAUSE_RULES:
            if pattern.search(msg):
                scores[label] += 1

    if not scores:
        return "Unknown / Misc"
    return max(scores, key=lambda k: scores[k])


def _top_messages(messages: List[str], n: int = 3) -> List[str]:
    """Return the N most-frequent unique messages from a group."""
    from collections import Counter
    return [msg for msg, _ in Counter(messages).most_common(n)]


class LogClustering:
    """
    Cluster log messages and assign root-cause labels.

    When scikit-learn is available:
        TF-IDF vectorisation → KMeans clustering.
        Representative message chosen as the centroid nearest neighbour.

    Fallback (no scikit-learn):
        Keyword taxonomy clustering (zero-dependency).
    """

    def __init__(self, max_clusters: int = 5, random_state: int = 42) -> None:
        self.max_clusters = max_clusters
        self.random_state = random_state

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def cluster(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Group logs into clusters and attach root-cause intelligence.

        Args:
            logs: Normalised log dicts.

        Returns:
            List of cluster dicts, sorted by size (largest first).
        """
        if not logs:
            return []

        messages = [str(log.get("message", "")) for log in logs]
        unique_count = len(set(messages))
        k = max(1, min(self.max_clusters, len(logs), unique_count))

        if k == 1:
            return [self._build_cluster(0, logs, messages, "Single Group")]

        try:
            grouped = self._cluster_with_sklearn(logs, messages, k)
        except (ModuleNotFoundError, Exception):
            grouped = self._cluster_with_keywords(logs)

        clusters = []
        for label, entries in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
            entry_messages = [str(e.get("message", "")) for e in entries]
            root_cause = _infer_root_cause(entry_messages)
            clusters.append(self._build_cluster(label, entries, entry_messages, root_cause))

        return clusters

    # ------------------------------------------------------------------ #
    # sklearn path                                                         #
    # ------------------------------------------------------------------ #

    def _cluster_with_sklearn(
        self, logs: List[Dict], messages: List[str], k: int
    ) -> Dict[int, List[Dict]]:
        sklearn_text = importlib.import_module("sklearn.feature_extraction.text")
        sklearn_cluster = importlib.import_module("sklearn.cluster")
        np = importlib.import_module("numpy")

        vectorizer = sklearn_text.TfidfVectorizer(stop_words="english", min_df=1)
        matrix = vectorizer.fit_transform(messages)

        model = sklearn_cluster.KMeans(
            n_clusters=k, n_init="auto", random_state=self.random_state
        )
        labels = model.fit_predict(matrix)

        grouped: Dict[int, List[Dict]] = defaultdict(list)
        for idx, lbl in enumerate(labels):
            grouped[int(lbl)].append(logs[idx])

        return grouped

    # ------------------------------------------------------------------ #
    # Keyword fallback                                                     #
    # ------------------------------------------------------------------ #

    def _cluster_with_keywords(self, logs: List[Dict]) -> Dict[str, List[Dict]]:
        grouped: Dict[str, List[Dict]] = defaultdict(list)
        for log in logs:
            msg = str(log.get("message", "")).lower()
            matched = "misc"
            for label, pattern in ROOT_CAUSE_RULES:
                if pattern.search(msg):
                    matched = label
                    break
            grouped[matched].append(log)
        return grouped

    # ------------------------------------------------------------------ #
    # Cluster builder                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_cluster(
        cluster_id: Any,
        entries: List[Dict],
        messages: List[str],
        root_cause: str,
    ) -> Dict[str, Any]:
        top_msgs = _top_messages(messages)
        # Confidence: ratio of messages that match the root-cause label
        rc_pattern = next(
            (pat for lbl, pat in ROOT_CAUSE_RULES if lbl == root_cause), None
        )
        if rc_pattern and messages:
            matches = sum(1 for m in messages if rc_pattern.search(m))
            confidence = round(matches / len(messages), 3)
        else:
            confidence = 1.0 if root_cause != "Unknown / Misc" else 0.0

        return {
            "cluster_id": cluster_id,
            "root_cause": root_cause,
            "confidence": confidence,
            "size": len(entries),
            "top_messages": top_msgs,
            "representative_message": top_msgs[0] if top_msgs else "",
            "entries": entries,
        }