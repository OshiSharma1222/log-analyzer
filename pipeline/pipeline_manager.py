"""
Pipeline Manager
================
Central orchestrator for the AI Log Analyzer.

Batch mode  : process a complete snapshot of logs at once.
Streaming mode: process an iterable of pre-parsed log dicts (e.g., from a
                watchdog tail feed) and accumulate results incrementally.

Design principles:
- Single Responsibility: each stage is a distinct, replaceable component.
- Dependency Injection: all engines can be swapped via constructor.
- Fail-safe: every stage is wrapped; one broken entry never kills the run.
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from data_engine.feature_extractor import aggregate_ip_features, extract_features
from data_engine.log_parser import ingest_file, parse_log_line
from data_engine.time_series_analyzer import TimeSeriesAnalyzer
from threat_engine.anomaly_detector import AnomalyDetector
from threat_engine.behaviour_engine import BehaviourDetector
from threat_engine.ip_intelligence import IPProfiler
from threat_engine.log_clustering import LogClustering
from threat_engine.rule_engine import RuleEngine
from threat_engine.threat_engine import ThreatEngine

logger = logging.getLogger(__name__)


class PipelineResult:
    """
    Typed container for the full analysis result.
    Attributes mirror the ThreatEngine output dict and add pipeline metadata.
    """

    def __init__(self, raw: Dict[str, Any], elapsed_ms: float) -> None:
        self.summary: Dict[str, Any] = raw.get("summary", {})
        self.rule_alerts: List[Dict] = raw.get("rule_alerts", [])
        self.behavior_alerts: List[Dict] = raw.get("behavior_alerts", [])
        self.anomalies: List[Dict] = raw.get("anomalies", [])
        self.clusters: List[Dict] = raw.get("clusters", [])
        self.derived_features: List[Dict] = raw.get("derived_features", [])
        self.ip_profiles: List[Dict] = raw.get("ip_profiles", [])
        self.time_series: Dict[str, Any] = raw.get("time_series", {})
        self.elapsed_ms: float = elapsed_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "rule_alerts": self.rule_alerts,
            "behavior_alerts": self.behavior_alerts,
            "anomalies": self.anomalies,
            "clusters": self.clusters,
            "derived_features": self.derived_features,
            "ip_profiles": self.ip_profiles,
            "time_series": self.time_series,
            "meta": {"elapsed_ms": self.elapsed_ms},
        }


class PipelineManager:
    """
    Orchestrates the full analysis pipeline.

    Stages
    ------
    1. Ingest       – read lines from file or accept pre-parsed dicts.
    2. Parse        – format-detect + normalise every raw log line.
    3. Features     – extract per-log scalar features.
    4. ThreatEngine – rule, behaviour, anomaly, clustering passes.
    5. IP Intel     – build per-IP threat profiles.
    6. TimeSeries   – sliding-window velocity metrics.
    """

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        behaviour_detector: Optional[BehaviourDetector] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
        clustering: Optional[LogClustering] = None,
        ip_profiler: Optional[IPProfiler] = None,
        ts_window_seconds: int = 60,
    ) -> None:
        self._threat_engine = ThreatEngine(
            rule_engine=rule_engine or RuleEngine(),
            behaviour_detector=behaviour_detector or BehaviourDetector(),
            anomaly_detector=anomaly_detector or AnomalyDetector(),
            clustering=clustering or LogClustering(),
        )
        self._ip_profiler = ip_profiler or IPProfiler()
        self._ts_analyzer = TimeSeriesAnalyzer(window_size_seconds=ts_window_seconds)

    # ------------------------------------------------------------------ #
    # Batch mode                                                           #
    # ------------------------------------------------------------------ #

    def run_file(self, file_path: str) -> PipelineResult:
        """
        Process an entire log file in one shot.

        Args:
            file_path: Absolute or relative path to a supported log file.

        Returns:
            PipelineResult containing all analysis artefacts and timing.
        """
        logger.info("Pipeline: ingesting file %s", file_path)
        t0 = time.perf_counter()

        if not Path(file_path).is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Stage 1+2: lazy ingest — generator, never loads entire file into RAM
        logs: List[Dict[str, Any]] = list(ingest_file(file_path))
        logger.info("Pipeline: parsed %d log entries", len(logs))

        return self._run_stages(logs, t0)

    def run_payload(
        self,
        logs: List[Dict[str, Any]],
        features: Optional[List[Dict[str, Any]]] = None,
    ) -> PipelineResult:
        """
        Process a pre-assembled structured payload (used by the CLI --sample path).

        Args:
            logs:     Normalised or raw log dicts.
            features: Optional pre-computed feature rows (skips auto-derivation).

        Returns:
            PipelineResult.
        """
        t0 = time.perf_counter()
        return self._run_stages(logs, t0, provided_features=features)

    # ------------------------------------------------------------------ #
    # Streaming / incremental mode                                         #
    # ------------------------------------------------------------------ #

    def run_stream(
        self, line_iterator: Iterable[str]
    ) -> Iterator[Dict[str, Any]]:
        """
        Process log lines as they arrive (e.g., from a tail feed or watchdog).

        Yields a lightweight alert dict for every line that triggers at least
        one rule match.  Designed for low-latency, real-time paths.

        Args:
            line_iterator: Any iterable of raw log line strings.

        Yields:
            Dict with keys: log, alerts.
        """
        for raw_line in line_iterator:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            log = parse_log_line(raw_line)
            if not log:
                continue
            alerts = self._threat_engine.rule_engine.detect([log])
            if alerts:
                yield {"log": log, "alerts": alerts}

    # ------------------------------------------------------------------ #
    # Internal orchestration                                               #
    # ------------------------------------------------------------------ #

    def _run_stages(
        self,
        logs: List[Dict[str, Any]],
        t0: float,
        provided_features: Optional[List[Dict]] = None,
    ) -> PipelineResult:
        if not logs:
            logger.warning("Pipeline: received empty log list")
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            return PipelineResult({}, elapsed)

        # Stage 3 – ThreatEngine (rule + behaviour + anomaly + clustering)
        threat_result = self._threat_engine.analyze(
            logs, features=provided_features or []
        )

        # Stage 4 – IP Intelligence (runs on normalised logs)
        normalised = self._threat_engine._normalise_logs(logs)
        ip_profiles = self._ip_profiler.profile(normalised)

        # Stage 5 – Time-series velocity metrics
        ts_metrics = self._ts_analyzer.analyze(normalised)

        threat_result["ip_profiles"] = ip_profiles
        threat_result["time_series"] = ts_metrics

        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        logger.info("Pipeline: completed in %.1f ms", elapsed)
        return PipelineResult(threat_result, elapsed)
