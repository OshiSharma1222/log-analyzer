"""
Export Engine
=============
Converts a PipelineResult into the requested output format:
  - text  : human-readable plain text (original behaviour)
  - json  : structured JSON
  - html  : self-contained HTML dashboard (no external JS/CSS dependencies)
"""

import json
from datetime import datetime
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def export_result(result: Any, fmt: str = "text") -> str:
    """
    Serialise a PipelineResult (or plain dict) to the specified format.

    Args:
        result : PipelineResult instance OR a plain dict.
        fmt    : 'text' | 'json' | 'html'

    Returns:
        String representation of the report.
    """
    data = result.to_dict() if hasattr(result, "to_dict") else result

    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    if fmt == "html":
        return _render_html(data)
    return _render_text(data)


# ---------------------------------------------------------------------------
# Text renderer (replaces old reporter/report_generator.py)
# ---------------------------------------------------------------------------


def _render_text(data: Dict[str, Any]) -> str:
    summary = data.get("summary", {})
    rule_alerts = data.get("rule_alerts", [])
    behavior_alerts = data.get("behavior_alerts", [])
    anomalies = data.get("anomalies", [])
    clusters = data.get("clusters", [])
    ip_profiles = data.get("ip_profiles", [])
    elapsed = data.get("meta", {}).get("elapsed_ms", "—")

    lines = [
        "=" * 60,
        "  AI LOG ANALYZER — ANALYSIS REPORT",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
        "SUMMARY",
        "-------",
        f"  Total Logs      : {summary.get('total_logs', 0)}",
        f"  Error Logs      : {summary.get('error_logs', 0)}",
        f"  Risk Level      : {summary.get('risk_level', 'unknown').upper()}",
        f"  Rule Alerts     : {len(rule_alerts)}",
        f"  Behaviour Alerts: {len(behavior_alerts)}",
        f"  Anomalies       : {len(anomalies)}",
        f"  Clusters        : {len(clusters)}",
        f"  Pipeline Time   : {elapsed} ms",
        "",
    ]

    # Rule alerts
    if rule_alerts:
        lines += ["RULE ALERTS", "-----------"]
        for a in rule_alerts[:10]:
            lines.append(
                f"  [{a.get('severity','?').upper()}] {a.get('rule','')} | "
                f"ip={a.get('ip','?')} | {a.get('message','')[:80]}"
            )
        if len(rule_alerts) > 10:
            lines.append(f"  … and {len(rule_alerts) - 10} more")
        lines.append("")

    # Behaviour alerts
    if behavior_alerts:
        lines += ["BEHAVIOUR ALERTS", "----------------"]
        for a in behavior_alerts:
            lines.append(
                f"  [{a.get('severity','?').upper()}] {a.get('type','')} | "
                f"ip={a.get('ip','?')}"
            )
        lines.append("")

    # IP profiles
    suspicious = [p for p in ip_profiles if p.get("flag") != "clean"]
    if suspicious:
        lines += ["IP INTELLIGENCE", "---------------"]
        for p in suspicious[:10]:
            lines.append(
                f"  {p['ip']:<18} flag={p['flag']:<12} "
                f"score={p['threat_score']:<6} "
                f"failed_logins={p['failed_logins']}  rps={p['requests_per_sec']}"
            )
        lines.append("")

    # Root-cause clusters
    if clusters:
        lines += ["ROOT CAUSE CLUSTERS", "-------------------"]
        for c in clusters:
            lines.append(
                f"  [{c['root_cause']}] "
                f"({c['size']} logs, confidence={c.get('confidence', '?')})"
            )
            for msg in c.get("top_messages", [])[:2]:
                lines.append(f"    • {msg[:100]}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AI Log Analyzer — Report</title>
  <style>
    :root {{
      --bg: #0f1117; --surface: #1a1d27; --border: #2e3147;
      --accent: #4f8ef7; --red: #f75f5f; --yellow: #f7c25f;
      --green: #5ff7a0; --text: #d4d8f0; --dim: #6b7099;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
    h1 {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); margin-bottom: .25rem; }}
    .meta {{ color: var(--dim); font-size: .85rem; margin-bottom: 2rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }}
    .card .label {{ font-size: .75rem; text-transform: uppercase; color: var(--dim); margin-bottom: .4rem; }}
    .card .value {{ font-size: 2rem; font-weight: 700; }}
    .card.red .value {{ color: var(--red); }}
    .card.yellow .value {{ color: var(--yellow); }}
    .card.green .value {{ color: var(--green); }}
    .card.blue .value {{ color: var(--accent); }}
    section {{ margin-bottom: 2.5rem; }}
    section h2 {{ font-size: 1rem; font-weight: 600; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: .5rem; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
    th {{ text-align: left; padding: .5rem .75rem; background: var(--surface); color: var(--dim); font-weight: 600; border-bottom: 1px solid var(--border); }}
    td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
    .badge.critical {{ background: rgba(247,95,95,.15); color: var(--red); }}
    .badge.high {{ background: rgba(247,95,95,.1); color: #f7a05f; }}
    .badge.medium {{ background: rgba(247,194,95,.1); color: var(--yellow); }}
    .badge.low {{ background: rgba(95,247,160,.1); color: var(--green); }}
    .badge.malicious {{ background: rgba(247,95,95,.2); color: var(--red); }}
    .badge.suspicious {{ background: rgba(247,194,95,.15); color: var(--yellow); }}
    .badge.clean {{ background: rgba(95,247,160,.1); color: var(--green); }}
    .cluster-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: .75rem; }}
    .cluster-box .rc {{ font-weight: 700; color: var(--accent); margin-bottom: .4rem; }}
    .cluster-box ul {{ padding-left: 1.2rem; color: var(--dim); font-size: .82rem; }}
    .cluster-box ul li {{ margin-bottom: .2rem; }}
  </style>
</head>
<body>
  <h1>AI Log Analyzer · Report</h1>
  <p class="meta">Generated: {generated} &nbsp;|&nbsp; Pipeline: {elapsed_ms} ms</p>

  <div class="grid">
    <div class="card blue"><div class="label">Total Logs</div><div class="value">{total_logs}</div></div>
    <div class="card red"><div class="label">Error Logs</div><div class="value">{error_logs}</div></div>
    <div class="card {risk_color}"><div class="label">Risk Level</div><div class="value">{risk_level}</div></div>
    <div class="card red"><div class="label">Rule Alerts</div><div class="value">{rule_alert_count}</div></div>
    <div class="card yellow"><div class="label">Behaviour Alerts</div><div class="value">{behavior_alert_count}</div></div>
    <div class="card yellow"><div class="label">Anomalies</div><div class="value">{anomaly_count}</div></div>
    <div class="card blue"><div class="label">Clusters</div><div class="value">{cluster_count}</div></div>
  </div>

  {rule_alerts_section}
  {ip_section}
  {cluster_section}
</body>
</html>
"""


def _badge(value: str, css_class: str | None = None) -> str:
    cls = css_class or value.lower()
    return f'<span class="badge {cls}">{value}</span>'


def _render_html(data: Dict[str, Any]) -> str:
    summary = data.get("summary", {})
    rule_alerts = data.get("rule_alerts", [])
    behavior_alerts = data.get("behavior_alerts", [])
    anomalies = data.get("anomalies", [])
    clusters = data.get("clusters", [])
    ip_profiles = data.get("ip_profiles", [])
    elapsed = data.get("meta", {}).get("elapsed_ms", "—")
    risk = summary.get("risk_level", "low").lower()

    risk_color = {"high": "red", "medium": "yellow"}.get(risk, "green")

    # -- Rule alerts table
    if rule_alerts:
        rows = "".join(
            f"<tr>"
            f"<td>{_badge(a.get('severity','?'), a.get('severity','medium').lower())}</td>"
            f"<td><code>{a.get('rule','')}</code></td>"
            f"<td>{a.get('ip','—')}</td>"
            f"<td style='max-width:400px;word-break:break-word'>{a.get('message','')[:120]}</td>"
            f"<td>{a.get('timestamp','')}</td>"
            f"</tr>"
            for a in rule_alerts[:50]
        )
        rule_alerts_section = f"""
  <section>
    <h2>Rule Alerts ({len(rule_alerts)})</h2>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>IP</th><th>Message</th><th>Timestamp</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>"""
    else:
        rule_alerts_section = ""

    # -- IP intelligence table
    suspicious_ips = [p for p in ip_profiles if p.get("flag") != "clean"]
    if suspicious_ips:
        rows = "".join(
            f"<tr>"
            f"<td><code>{p['ip']}</code></td>"
            f"<td>{_badge(p.get('flag','clean'))}</td>"
            f"<td>{p.get('threat_score','')}</td>"
            f"<td>{p.get('total_requests','')}</td>"
            f"<td>{p.get('failed_logins','')}</td>"
            f"<td>{p.get('requests_per_sec','')}</td>"
            f"</tr>"
            for p in suspicious_ips[:30]
        )
        ip_section = f"""
  <section>
    <h2>IP Intelligence — Suspicious IPs ({len(suspicious_ips)})</h2>
    <table>
      <thead><tr><th>IP</th><th>Flag</th><th>Threat Score</th><th>Requests</th><th>Failed Logins</th><th>Req/s</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>"""
    else:
        ip_section = ""

    # -- Root-cause clusters
    if clusters:
        boxes = "".join(
            f"""<div class="cluster-box">
            <div class="rc">{c.get('root_cause','Unknown')} 
              &nbsp;<small style="color:var(--dim);font-weight:400">
                {c.get('size',0)} logs · confidence {c.get('confidence',0):.0%}
              </small>
            </div>
            <ul>{''.join(f"<li>{m[:120]}</li>" for m in c.get('top_messages',[])[:3])}</ul>
          </div>"""
            for c in clusters
        )
        cluster_section = f"""
  <section>
    <h2>Root Cause Clusters ({len(clusters)})</h2>
    {boxes}
  </section>"""
    else:
        cluster_section = ""

    return _HTML_TEMPLATE.format(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        elapsed_ms=elapsed,
        total_logs=summary.get("total_logs", 0),
        error_logs=summary.get("error_logs", 0),
        risk_level=risk.upper(),
        risk_color=risk_color,
        rule_alert_count=len(rule_alerts),
        behavior_alert_count=len(behavior_alerts),
        anomaly_count=len(anomalies),
        cluster_count=len(clusters),
        rule_alerts_section=rule_alerts_section,
        ip_section=ip_section,
        cluster_section=cluster_section,
    )
