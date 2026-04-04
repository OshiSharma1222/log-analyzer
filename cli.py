"""
AI Log Analyzer — CLI (v2)
==========================
Fully upgraded command-line interface with Rich UI, pipeline orchestration,
IP intelligence, root-cause clusters, and multi-format export.

Usage examples
--------------
  python cli.py --sample
  python cli.py --input logs/sample.log
  python cli.py --input logs/sample.log --format html --output report.html
  python cli.py --input logs/sample.log --format json --output report.json
  python cli.py --watch logs/
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pipeline.log_monitor import LogMonitor
from pipeline.pipeline_manager import PipelineManager, PipelineResult
from reporter.export_engine import export_result

# ---------------------------------------------------------------------------
# Logging (file sink, not stdout — Rich owns the terminal)
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="analyzer.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

console = Console()

# ---------------------------------------------------------------------------
# Built-in sample data
# ---------------------------------------------------------------------------
SAMPLE_PAYLOAD = {
    "logs": [
        {"timestamp": "2026-03-14 12:20:01", "level": "ERROR",    "message": "Database timeout while processing checkout", "ip": "192.168.1.10", "source": "api-gateway"},
        {"timestamp": "2026-03-14 12:20:10", "level": "ERROR",    "message": "Authentication failure for admin user",        "ip": "192.168.1.10", "source": "auth-service"},
        {"timestamp": "2026-03-14 12:20:15", "level": "ERROR",    "message": "Authentication failure for admin user",        "ip": "192.168.1.10", "source": "auth-service"},
        {"timestamp": "2026-03-14 12:20:18", "level": "ERROR",    "message": "Authentication failure for admin user",        "ip": "192.168.1.10", "source": "auth-service"},
        {"timestamp": "2026-03-14 12:20:20", "level": "CRITICAL", "message": "Unauthorized access attempt detected on admin panel", "ip": "192.168.1.11", "source": "web-server"},
        {"timestamp": "2026-03-14 12:20:25", "level": "ERROR",    "message": "Authentication failure for admin user",        "ip": "192.168.1.10", "source": "auth-service"},
        {"timestamp": "2026-03-14 12:20:30", "level": "WARNING",  "message": "Database timeout while processing checkout",   "ip": "192.168.1.10", "source": "api-gateway"},
        {"timestamp": "2026-03-14 12:20:35", "level": "ERROR",    "message": "Authentication failure for admin user",        "ip": "192.168.1.10", "source": "auth-service"},
        {"timestamp": "2026-03-14 12:20:40", "level": "INFO",     "message": "Health check OK",                              "ip": "10.0.0.1",     "source": "monitor"},
    ],
    "features": [
        {"ip": "192.168.1.10", "request_rate": 120, "error_rate": 0.85, "data_transfer_rate": 15, "login_failures": 5, "log_length": 46},
        {"ip": "192.168.1.11", "request_rate": 12,  "error_rate": 0.2,  "data_transfer_rate": 4,  "login_failures": 0, "log_length": 39},
        {"ip": "10.0.0.1",     "request_rate": 3,   "error_rate": 0.0,  "data_transfer_rate": 1,  "login_failures": 0, "log_length": 14},
    ],
}


# ---------------------------------------------------------------------------
# Rich dashboard renderer
# ---------------------------------------------------------------------------

def _severity_color(s: str) -> str:
    return {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(s.lower(), "white")


def _flag_color(f: str) -> str:
    return {"malicious": "bold red", "suspicious": "yellow", "clean": "green"}.get(f.lower(), "white")


def render_dashboard(result: PipelineResult) -> None:
    """Render the full analysis dashboard to the terminal using Rich."""
    s = result.summary
    risk = s.get("risk_level", "low").upper()
    risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "white")

    # ── Header ──────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold bright_white]AI LOG ANALYZER[/bold bright_white]  [dim]v2.0[/dim]")

    # ── Summary cards ───────────────────────────────────────────────────────
    cards = [
        Panel(f"[bold blue]{s.get('total_logs', 0)}[/bold blue]",    title="Total Logs",        border_style="blue"),
        Panel(f"[bold red]{s.get('error_logs', 0)}[/bold red]",      title="Error Logs",        border_style="red"),
        Panel(f"[bold {risk_color}]{risk}[/bold {risk_color}]",      title="Risk Level",        border_style=risk_color),
        Panel(f"[bold red]{len(result.rule_alerts)}[/bold red]",      title="Rule Alerts",       border_style="red"),
        Panel(f"[bold yellow]{len(result.behavior_alerts)}[/bold yellow]", title="Behaviour",   border_style="yellow"),
        Panel(f"[bold yellow]{len(result.anomalies)}[/bold yellow]",  title="Anomalies",         border_style="yellow"),
        Panel(f"[bold cyan]{len(result.clusters)}[/bold cyan]",       title="Clusters",          border_style="cyan"),
        Panel(f"[bold green]{result.elapsed_ms} ms[/bold green]",     title="Pipeline Time",     border_style="green"),
    ]
    console.print(Columns(cards, equal=True, expand=True))
    console.print()

    # ── Rule Alerts Table ────────────────────────────────────────────────────
    if result.rule_alerts:
        tbl = Table(
            title=f"Rule Alerts ({len(result.rule_alerts)})",
            box=box.ROUNDED, border_style="dim", header_style="bold cyan",
            show_lines=False, expand=True,
        )
        tbl.add_column("Severity",  style="bold", width=10)
        tbl.add_column("Rule",      style="bright_white", width=24)
        tbl.add_column("IP",        style="cyan",  width=16)
        tbl.add_column("Message",   style="white")
        tbl.add_column("Timestamp", style="dim",   width=20)

        for a in result.rule_alerts[:15]:
            sev = a.get("severity", "?")
            tbl.add_row(
                Text(sev.upper(), style=_severity_color(sev)),
                a.get("rule", ""),
                a.get("ip", "—"),
                a.get("message", "")[:90],
                a.get("timestamp", ""),
            )
        if len(result.rule_alerts) > 15:
            tbl.add_row("…", f"+{len(result.rule_alerts)-15} more", "", "", "")
        console.print(tbl)
        console.print()

    # ── Behaviour Alerts ─────────────────────────────────────────────────────
    if result.behavior_alerts:
        tbl = Table(
            title=f"Behaviour Alerts ({len(result.behavior_alerts)})",
            box=box.ROUNDED, border_style="dim", header_style="bold yellow",
            expand=True,
        )
        tbl.add_column("Type",       style="yellow", width=22)
        tbl.add_column("IP",         style="cyan",   width=16)
        tbl.add_column("Severity",   style="bold",   width=10)
        tbl.add_column("Detail",     style="dim")

        for a in result.behavior_alerts:
            detail = (
                f"attempts={a.get('attempts','')} first={a.get('first_seen','')} last={a.get('last_seen','')}"
                if a.get("type") == "possible brute force"
                else f"window={a.get('time_window','')} count={a.get('request_count','')}"
            )
            sev = a.get("severity", "?")
            tbl.add_row(
                a.get("type", ""),
                a.get("ip", "—"),
                Text(sev.upper(), style=_severity_color(sev)),
                detail,
            )
        console.print(tbl)
        console.print()

    # ── IP Intelligence ──────────────────────────────────────────────────────
    suspicious = [p for p in result.ip_profiles if p.get("flag") != "clean"]
    if suspicious:
        tbl = Table(
            title=f"IP Intelligence — Flagged ({len(suspicious)})",
            box=box.ROUNDED, border_style="dim", header_style="bold magenta",
            expand=True,
        )
        tbl.add_column("IP",            style="cyan",  width=18)
        tbl.add_column("Flag",          style="bold",  width=12)
        tbl.add_column("Score",         style="white", width=8)
        tbl.add_column("Requests",      style="white", width=10)
        tbl.add_column("Failed Logins", style="red",   width=14)
        tbl.add_column("Req/s",         style="white", width=10)

        for p in suspicious[:10]:
            flag = p.get("flag", "clean")
            tbl.add_row(
                p["ip"],
                Text(flag.upper(), style=_flag_color(flag)),
                str(p.get("threat_score", "")),
                str(p.get("total_requests", "")),
                str(p.get("failed_logins", "")),
                str(p.get("requests_per_sec", "")),
            )
        console.print(tbl)
        console.print()
    
    # ── Anomalies ────────────────────────────────────────────────────────────
    if result.anomalies:
        tbl = Table(
            title=f"Anomalies ({len(result.anomalies)})",
            box=box.ROUNDED, border_style="dim", header_style="bold yellow",
            expand=True,
        )
        tbl.add_column("IP",           style="cyan",   width=18)
        tbl.add_column("Severity",     style="bold",   width=10)
        tbl.add_column("Score",        style="white",  width=10)
        tbl.add_column("Error Rate",   style="red",    width=12)
        tbl.add_column("Login Fails",  style="red",    width=14)
        tbl.add_column("Req Rate",     style="white",  width=12)

        for a in result.anomalies[:10]:
            sev = a.get("severity", "?")
            tbl.add_row(
                a.get("ip", "—"),
                Text(sev.upper(), style=_severity_color(sev)),
                str(a.get("anomaly_score", "")),
                str(a.get("error_rate", "")),
                str(a.get("login_failures", "")),
                str(a.get("request_rate", "")),
            )
        console.print(tbl)
        console.print()

    # ── Root-Cause Clusters ──────────────────────────────────────────────────
    if result.clusters:
        console.rule("[bold cyan]Root Cause Clusters[/bold cyan]")
        for c in result.clusters:
            rc = c.get("root_cause", "Unknown")
            conf = c.get("confidence", 0)
            size = c.get("size", 0)
            bar_color = "red" if conf < 0.4 else "yellow" if conf < 0.7 else "green"
            header = Text()
            header.append(f"  {rc}", style="bold bright_white")
            header.append(f"  ({size} logs)", style="dim")
            header.append(f"  confidence={conf:.0%}", style=bar_color)
            console.print(header)
            for msg in c.get("top_messages", [])[:3]:
                console.print(f"    [dim]•[/dim] {msg[:110]}")
        console.print()

    # ── Time-series ─────────────────────────────────────────────────────────
    ts = result.time_series
    if ts:
        console.rule("[bold cyan]Time-Series Metrics[/bold cyan]")
        console.print(
            f"  Window: [cyan]{ts.get('window_size_sec')}s[/cyan]  "
            f"Max Req/Window: [yellow]{ts.get('max_requests_per_window')}[/yellow]  "
            f"Avg Req/Window: [white]{ts.get('avg_requests_per_window')}[/white]  "
            f"Max Errors/Window: [red]{ts.get('max_errors_per_window')}[/red]"
        )
        login_map = ts.get("ip_login_attempts_overall", {})
        if login_map:
            console.print("  Login attempts per IP: " + "  ".join(
                f"[cyan]{ip}[/cyan]: {cnt}" for ip, cnt in login_map.items()
            ))
        console.print()

    console.rule("[dim]End of Report[/dim]")


# ---------------------------------------------------------------------------
# Payload loader for --input
# ---------------------------------------------------------------------------

def _load_payload(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, list):
        return {"logs": payload, "features": []}
    return payload


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-log-analyzer",
        description="AI Log Analyzer — production-grade intelligent log analysis",
    )
    group = p.add_mutually_exclusive_group()
    group.add_argument("--sample", action="store_true",
                       help="Run the built-in demo dataset")
    group.add_argument("--input",  metavar="FILE",
                       help="Path to a JSON or raw log file")
    group.add_argument("--watch",  metavar="PATH",
                       help="Directory or file to watch in real-time")

    p.add_argument("--format",  choices=["text", "json", "html"], default="text",
                   help="Report export format (default: text; only for batch modes)")
    p.add_argument("--output",  metavar="FILE",
                   help="Write exported report to this file")
    p.add_argument("--no-dashboard", action="store_true",
                   help="Skip Rich dashboard, only write --output")
    p.add_argument("--ts-window", type=int, default=60, metavar="SECONDS",
                   help="Time-series window size in seconds (default: 60)")
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not (args.sample or args.input or args.watch):
        parser.error("Provide one of: --sample  --input FILE  --watch PATH")

    pipeline = PipelineManager(ts_window_seconds=args.ts_window)

    # ── Watch mode ────────────────────────────────────────────────────────
    if args.watch:
        monitor = LogMonitor(args.watch, pipeline)
        monitor.start()
        return

    # ── Batch mode ────────────────────────────────────────────────────────
    with console.status("[bold green]Analyzing logs…[/bold green]", spinner="dots"):
        if args.sample:
            result = pipeline.run_payload(
                SAMPLE_PAYLOAD["logs"], SAMPLE_PAYLOAD["features"]
            )
        else:
            # Detect if it's a raw log file (.log, .txt, .jsonl) or a JSON payload
            input_path = args.input
            suffix = Path(input_path).suffix.lower()
            if suffix in {".log", ".txt", ".jsonl"}:
                result = pipeline.run_file(input_path)
            else:
                payload = _load_payload(input_path)
                result = pipeline.run_payload(
                    payload.get("logs", []), payload.get("features", [])
                )

    # ── Rich dashboard ────────────────────────────────────────────────────
    if not args.no_dashboard:
        render_dashboard(result)

    # ── Export ────────────────────────────────────────────────────────────
    if args.output or args.no_dashboard:
        exported = export_result(result, fmt=args.format)
        if args.output:
            Path(args.output).write_text(exported, encoding="utf-8")
            console.print(
                f"[bold green]✓[/bold green] Report written → [cyan]{args.output}[/cyan]"
            )
        else:
            print(exported)


if __name__ == "__main__":
    main()
