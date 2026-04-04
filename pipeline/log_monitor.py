"""
Real-Time Log Monitor
=====================
Watches a directory (or single file) for new log lines using watchdog.
New content is fed through the PipelineManager streaming path and any
rule-triggered alerts are surfaced immediately via the Rich console.

Usage (internal — invoked by cli.py --watch):
    monitor = LogMonitor(path="logs/", pipeline=PipelineManager())
    monitor.start()          # blocks; Ctrl-C to stop
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from rich.console import Console
from rich.text import Text

logger = logging.getLogger(__name__)
console = Console()


class _FileTailHandler:
    """
    Tracks the byte offset of a file so only NEW content is read on each poll.
    Thread-safe via a per-file lock.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._offset: int = os.path.getsize(path)
        self._lock = threading.Lock()

    def readnew(self):
        """Yield new lines added since the last call."""
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(self._offset)
                    new_data = fh.read()
                    self._offset = fh.tell()
                if new_data:
                    for line in new_data.splitlines():
                        line = line.strip()
                        if line:
                            yield line
            except OSError as exc:
                logger.warning("Tail error on %s: %s", self.path, exc)


class LogMonitor:
    """
    Monitors a path for log updates and streams new entries through the pipeline.

    Args:
        watch_path : Directory or file to watch.
        pipeline   : A PipelineManager instance (must expose run_stream()).
        poll_interval: Seconds between file-stat polls (default 1 s).
        extensions : File extensions to watch inside a directory.
    """

    def __init__(
        self,
        watch_path: str,
        pipeline,  # PipelineManager — avoid circular import with string hint
        poll_interval: float = 1.0,
        extensions: tuple = (".log", ".txt", ".jsonl"),
    ) -> None:
        self._watch_path = Path(watch_path)
        self._pipeline = pipeline
        self._poll_interval = poll_interval
        self._extensions = extensions
        self._tails: Dict[str, _FileTailHandler] = {}
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Block and watch until KeyboardInterrupt or stop() is called."""
        self._stop_event.clear()
        self._init_tails()
        console.rule(
            f"[bold green]AI Log Analyzer — Watching {self._watch_path}[/bold green]"
        )
        console.print("[dim]Press Ctrl-C to stop.[/dim]\n")
        try:
            while not self._stop_event.is_set():
                self._scan_for_new_files()
                self._poll_all()
                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            pass
        finally:
            console.print("\n[bold yellow]Monitor stopped.[/bold yellow]")

    def stop(self) -> None:
        """Signal the watch loop to exit cleanly."""
        self._stop_event.set()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _target_files(self):
        p = self._watch_path
        if p.is_file():
            return [str(p)]
        return [
            str(child)
            for child in p.iterdir()
            if child.is_file() and child.suffix in self._extensions
        ]

    def _init_tails(self) -> None:
        for path in self._target_files():
            if path not in self._tails:
                self._tails[path] = _FileTailHandler(path)
                logger.debug("Monitoring: %s", path)

    def _scan_for_new_files(self) -> None:
        """Pick up log files created after monitor start."""
        for path in self._target_files():
            if path not in self._tails:
                self._tails[path] = _FileTailHandler(path)
                console.print(f"[cyan]+ New file detected:[/cyan] {path}")

    def _poll_all(self) -> None:
        for path, tail in list(self._tails.items()):
            lines = list(tail.readnew())
            if not lines:
                continue
            for event in self._pipeline.run_stream(lines):
                self._render_alert(event)

    @staticmethod
    def _render_alert(event: dict) -> None:
        log = event.get("log", {})
        alerts = event.get("alerts", [])
        ts = log.get("timestamp", "")
        ip = log.get("ip", "—")
        msg = log.get("message", "")

        for alert in alerts:
            severity = alert.get("severity", "medium").lower()
            color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(
                severity, "white"
            )
            text = Text()
            text.append(f"[{ts}] ", style="dim")
            text.append(f"[{severity.upper()}] ", style=color)
            text.append(f"{alert.get('rule', '')} ", style="bold")
            text.append(f"ip={ip} ", style="cyan")
            text.append(msg, style="white")
            console.print(text)
