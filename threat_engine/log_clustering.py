from collections import defaultdict
import importlib


class LogClustering:
    def __init__(self, max_clusters=3, random_state=42):
        self.max_clusters = max_clusters
        self.random_state = random_state

    def _cluster_with_sklearn(self, logs, messages, cluster_count):
        sklearn_cluster = importlib.import_module("sklearn.cluster")
        sklearn_text = importlib.import_module("sklearn.feature_extraction.text")
        vectorizer = sklearn_text.TfidfVectorizer(stop_words="english")
        matrix = vectorizer.fit_transform(messages)
        model = sklearn_cluster.KMeans(
            n_clusters=cluster_count,
            n_init="auto",
            random_state=self.random_state,
        )
        labels = model.fit_predict(matrix)

        grouped_logs = defaultdict(list)
        for index, label in enumerate(labels):
            grouped_logs[int(label)].append(logs[index])

        return grouped_logs

    def _cluster_with_keywords(self, logs):
        grouped_logs = defaultdict(list)
        for log in logs:
            message = str(log.get("message", "")).lower()
            if "database" in message or "db" in message:
                label = "database"
            elif "auth" in message or "login" in message:
                label = "authentication"
            elif "access" in message or "permission" in message:
                label = "access"
            else:
                label = message.strip() or "misc"

            grouped_logs[label].append(log)

        return grouped_logs

    def cluster(self, logs):
        if not logs:
            return []

        messages = [str(log.get("message", "")) for log in logs]
        unique_message_count = len(set(messages))
        cluster_count = max(1, min(self.max_clusters, len(logs), unique_message_count))

        if cluster_count == 1:
            return [
                {
                    "cluster_id": 0,
                    "size": len(logs),
                    "representative_message": messages[0] if messages else "",
                    "entries": logs,
                }
            ]

        try:
            grouped_logs = self._cluster_with_sklearn(logs, messages, cluster_count)
        except ModuleNotFoundError:
            grouped_logs = self._cluster_with_keywords(logs)

        clusters = []
        for label, entries in sorted(grouped_logs.items(), key=lambda item: len(item[1]), reverse=True):
            clusters.append(
                {
                    "cluster_id": label,
                    "size": len(entries),
                    "representative_message": entries[0].get("message", ""),
                    "entries": entries,
                }
            )

        return clusters