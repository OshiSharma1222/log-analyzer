from threat_engine.log_clustering import LogClustering


class DatabaseTimeoutCluster:
    def __init__(self):
        self.cluster_engine = LogClustering(max_clusters=2)

    def timeout(self, logs):
        database_logs = [
            log
            for log in logs
            if "database" in str(log.get("message", "")).lower()
            or "db" in str(log.get("message", "")).lower()
        ]
        return self.cluster_engine.cluster(database_logs)