def generate_report(result):

    print("\nLog Analysis Report")
    print("----------------------")

    print("Rule Alerts:", len(result["rule_alerts"]))
    print("Behavior Alerts:", len(result["behavior_alerts"]))
    print("Anomalies:", len(result["anomalies"]))
    print("Clusters:", len(result["clusters"]))