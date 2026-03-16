#this will detect unusal syatem behaviour
from pyexpat import features

from sklearn.ensemble import IsolationForest
import numpy as np

class AnomalyDetector:
    def  detect(self, features):
        x = []
        for f in features:
            
            x.append([
                f["request_rate"],
                f["error_rate"],
                f["data_transfer_rate"],
                f["login failures"],
                f["log_length"]
            ])
        X = np.array(X)
        model = IsolationForest(contamination = 0.05)
        predictions = model.fit_predict(X)
        anomalies =[]
        for i, p in enumerate(predictions):
            if p ==-1:
                anomalies.append(features[i])
        return anomalies