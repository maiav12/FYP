from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GridSearchCV
import numpy as np
from sklearn.tree import _tree 

class AnomalyDetector:
    def __init__(self, contamination="auto", n_estimators=100):
        """
        Improved Anomaly Detector with:
        - Adaptive contamination
        - Optimized Isolation Forest parameters
        - Dynamic PCA component selection
        """
        self.contamination = contamination  # Now auto-adjusting
        self.n_estimators = n_estimators
        self.pca = None  # Will be initialized dynamically
        self.isolation_forest = None  # Will be tuned dynamically

    def detect_anomalies(self, process_df, original_data):
        """Detect anomalies using dynamically optimized PCA and Isolation Forest."""
        if process_df.empty:
            print("No data to process.")
            return None, None

        # ✅ Step 1: Dynamically Determine PCA Components
        explained_variance = []
        for n in range(1, min(10, process_df.shape[1] + 1)):  # Test up to 10 components
            pca = PCA(n_components=n)
            pca.fit(process_df)
            explained_variance.append(sum(pca.explained_variance_ratio_))

        # Choose the number of components that explains at least 95% variance
        best_n_components = next((i+1 for i, var in enumerate(explained_variance) if var > 0.95), min(6, process_df.shape[1]))
        self.pca = PCA(n_components=best_n_components)

        # ✅ Step 2: Transform Data with Optimized PCA
        principal_components = self.pca.fit_transform(process_df)

        # ✅ Step 3: Adaptive Contamination Threshold
        if self.contamination == "auto":
            q1, q3 = np.percentile(principal_components, [25, 75])
            iqr = q3 - q1
            adaptive_contamination = min(0.1, max(0.01, iqr / (q3 + 1e-6)))  # Scale based on IQR
        else:
            adaptive_contamination = self.contamination

        # ✅ Step 4: Optimize Isolation Forest Hyperparameters using GridSearchCV
        param_grid = {
            "n_estimators": [100, 200],
            "max_samples": ["auto", 256],
            "contamination": [adaptive_contamination],
            "bootstrap": [False, True]
        }
        forest = IsolationForest(random_state=42)
        grid_search = GridSearchCV(forest, param_grid, cv=3, scoring='accuracy', n_jobs=-1)
        grid_search.fit(principal_components)

        # ✅ Step 5: Train Final Model with Best Parameters
        self.isolation_forest = grid_search.best_estimator_
        anomaly_labels = self.isolation_forest.fit_predict(principal_components)

        # ✅ Step 6: Extract Anomalies
        anomaly_indices = np.where(anomaly_labels == -1)[0]
        return anomaly_indices, original_data.iloc[anomaly_indices]
 
    def tree_to_json(self, tree_index=0):
        """
        Convert one tree from the Isolation Forest to a JSON structure.
        """
        # Ensure the isolation forest is trained
        if not self.isolation_forest:
            raise Exception("Isolation Forest is not trained.")

        tree_estimator = self.isolation_forest.estimators_[tree_index]
        tree = tree_estimator.tree_
        
        # Use PCA components count (if available) to generate feature names
        n_components = self.pca.n_components_ if self.pca else tree_estimator.n_features_in_
        feature_names = [f"PC{i+1}" for i in range(n_components)]
        
        def recurse(node):
            if tree.feature[node] != _tree.TREE_UNDEFINED:
                return {
                    "node_id": int(node),
                    "feature": feature_names[tree.feature[node]] if tree.feature[node] < len(feature_names) else tree.feature[node],
                    "threshold": float(tree.threshold[node]),
                    "left": recurse(tree.children_left[node]),
                    "right": recurse(tree.children_right[node])
                }
            else:
                return {
                    "node_id": int(node),
                    "leaf": True,
                    "value": tree.value[node].tolist()
                }
        
        return recurse(0)