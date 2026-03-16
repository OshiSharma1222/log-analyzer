from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

class dbtimeout:

    def timeout(self, logs):

        messages = [log["message"] for log in logs]

        vectorizer = TfidfVectorizer()

        X = vectorizer.fit_transform(messages)

        model = KMeans(n_timeout=3)

        labels = model.fit_predict(X)

        clusters = {}

        for i, label in enumerate(labels):

            if label not in clusters:
                clusters[label] = []

            clusters[label].append(logs[i])

        return clusters