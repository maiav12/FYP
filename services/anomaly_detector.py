from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
import numpy as np

class AnomalyDetector:
    def __init__(self, n_components=6, contamination=0.1):
        self.n_components = n_components
        self.contamination = contamination
        self.pca = PCA(n_components=n_components)
        self.isolation_forest = IsolationForest(contamination=contamination, random_state=42)

    def detect_anomalies(self, process_df, original_data):
        """Detect anomalies using PCA and Isolation Forest."""
        if process_df.empty:
            print("No data to process.")
            return None, None

        n_components = min(self.n_components, process_df.shape[1])
        principal_components = self.pca.fit_transform(process_df)
        anomaly_labels = self.isolation_forest.fit_predict(principal_components)
        
        anomaly_indices = np.where(anomaly_labels == -1)[0]
        return anomaly_indices, original_data.iloc[anomaly_indices]
