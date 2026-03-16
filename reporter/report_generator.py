import json


def _top_messages(result, limit=5):
    counts = {}
    for alert in result.get("rule_alerts", []) + result.get("behavior_alerts", []):
        message = alert.get("message") or alert.get("type") or alert.get("rule")
        counts[message] = counts.get(message, 0) + 1

    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]


def generate_report(result, output_format="text"):
    if output_format == "json":
        return json.dumps(result, indent=2)

    summary = result.get("summary", {})
    lines = [
        "Log Analysis Report",
        "-------------------",
        f"Total Logs: {summary.get('total_logs', 0)}",
        f"Error Logs: {summary.get('error_logs', 0)}",
        f"Risk Level: {summary.get('risk_level', 'unknown').upper()}",
        f"Rule Alerts: {len(result.get('rule_alerts', []))}",
        f"Behavior Alerts: {len(result.get('behavior_alerts', []))}",
        f"Anomalies: {len(result.get('anomalies', []))}",
        f"Clusters: {len(result.get('clusters', []))}",
        f"Suspicious IPs: {', '.join(summary.get('suspicious_ips', [])) or 'None'}",
        "",
        "Top Issues:",
    ]

    top_messages = _top_messages(result)
    if not top_messages:
        lines.append("- No alerting patterns detected")
    else:
        for message, count in top_messages:
            lines.append(f"- {message} ({count})")

    return "\n".join(lines)