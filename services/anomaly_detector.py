from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS
from sklearn.model_selection import GridSearchCV, train_test_split
import numpy as np
import pandas as pd

class AnomalyDetector:
    def __init__(self, method="iforest", contamination="auto", n_estimators=100,
                 tuning_strategy="out-of-the-box", best_default_params=None, random_state=42):
        """
        Parameters:
          - method: One of "iforest", "lof", "ocsvm", "knn", "hbos"
          - contamination: "auto" to compute adaptively or a fixed value.
          - n_estimators: For Isolation Forest (default 100).
          - tuning_strategy: One of:
               "default"      → Out-of-the-box hyperparameters from the literature
               "peak"         → Exhaustively tune on the full dataset
               "best_default" → Use preset best-default parameters from prior experiments
               "tuned"        → Use a small validation set for tuning
          - best_default_params: A dict of preset best-default parameters for "best_default" strategy
          - random_state: For reproducibility
        """
        self.method = method.lower()
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.tuning_strategy = tuning_strategy
        self.best_default_params = best_default_params or {}
        self.random_state = random_state

        self.pca = None
        self.model = None

    # ---------------------------
    # 1) PCA & Contamination Utils
    # ---------------------------
    def _perform_pca(self, process_df):
        """
        Determine the optimal # of PCA components (up to 10) that explains >=95% variance,
        then transform the data accordingly.
        """
        explained_variance = []
        for n in range(1, min(10, process_df.shape[1] + 1)):
            pca = PCA(n_components=n)
            pca.fit(process_df)
            explained_variance.append(sum(pca.explained_variance_ratio_))

        best_n_components = next(
            (i + 1 for i, var in enumerate(explained_variance) if var > 0.95),
            min(6, process_df.shape[1])
        )
        self.pca = PCA(n_components=best_n_components)
        return self.pca.fit_transform(process_df)

    def _get_adaptive_contamination(self, principal_components):
        """
        If contamination="auto", compute contamination adaptively
        based on the IQR of PCA-transformed data.
        """
        if self.contamination == "auto":
            q1, q3 = np.percentile(principal_components, [25, 75])
            iqr = q3 - q1
            return min(0.1, max(0.01, iqr / (q3 + 1e-6)))
        return self.contamination

    # ---------------------------
    # 2) Building the Default Model
    # ---------------------------
    def _build_model(self, adaptive_contamination, process_df):
        """
        Build the model using out-of-the-box default hyperparameters.
        """
        if self.method == "iforest":
            # Default: 100 trees; optionally set max_samples=256
            return IsolationForest(
                n_estimators=100,
                contamination=adaptive_contamination,
                random_state=self.random_state
            )
        elif self.method in ["lof", "knn"]:
            # For kNN/LOF: k = max(10, 0.03 * |D|)
            k = max(10, int(0.03 * len(process_df)))
            if self.method == "lof":
                return LocalOutlierFactor(
                    n_neighbors=k,
                    contamination=adaptive_contamination
                )
            else:  # knn
                return KNN(n_neighbors=k, contamination=adaptive_contamination)
        elif self.method == "hbos":
            # HBOS default: number of bins = sqrt(|D|)
            n_bins = int(np.sqrt(len(process_df)))
            return HBOS(n_bins=n_bins, contamination=adaptive_contamination)
        elif self.method == "ocsvm":
            # OCSVM default: nu=0.5, rbf kernel, gamma=1/m
            m = process_df.shape[1]
            return OneClassSVM(
                nu=0.5, kernel="rbf",
                gamma=(1.0 / m),
            )
        else:
            raise ValueError(f"Unknown method: {self.method}")

    # ---------------------------
    # 3) Tuning Routines
    # ---------------------------
    def _tune_model_peak(self, X):
        """
        Exhaustively tune on the full dataset for 'peak' performance.
        Example: simple parameter grids for demonstration.
        """
        if self.method == "iforest":
            param_grid = {
                "n_estimators": [50, 100, 200],
                "contamination": [0.01, 0.05, 0.1]
            }
            base_model = IsolationForest(random_state=self.random_state)
        elif self.method == "lof":
            param_grid = {
                "n_neighbors": [5, 10, 20, 30],
            }
            # LOF does not have an official 'novelty=True' param in older versions,
            # but we can attempt to mimic it with fit_predict on the same data
            base_model = LocalOutlierFactor(contamination=0.05)  # dummy contamination
        elif self.method == "ocsvm":
            param_grid = {
                "nu": [0.1, 0.3, 0.5],
                "gamma": ["auto", "scale"]
            }
            base_model = OneClassSVM(kernel="rbf")
        elif self.method == "knn":
            param_grid = {
                "n_neighbors": [5, 10, 20],
            }
            base_model = KNN()
        elif self.method == "hbos":
            param_grid = {
                "n_bins": [5, 10, 20],
            }
            base_model = HBOS()
        else:
            raise ValueError(f"Unknown method: {self.method}")

        grid_search = GridSearchCV(
            estimator=base_model,
            param_grid=param_grid,
            cv=3,
            scoring="roc_auc",
            n_jobs=-1
        )

        dummy_y = np.zeros(len(X))  # For unsupervised, y is dummy
        grid_search.fit(X, dummy_y)

        return grid_search.best_estimator_

    def _tune_model_validation(self, X):
        """
        Tuning on a small validation set. Splits data into train & val,
        then does a narrower grid search for 'tuned' performance.
        """
        X_train, X_val = train_test_split(X, test_size=0.2, random_state=self.random_state)

        if self.method == "iforest":
            param_grid = {
                "n_estimators": [50, 100],
                "contamination": [0.01, 0.05]
            }
            base_model = IsolationForest(random_state=self.random_state)
        elif self.method == "lof":
            param_grid = {
                "n_neighbors": [5, 10],
            }
            base_model = LocalOutlierFactor()
        elif self.method == "ocsvm":
            param_grid = {
                "nu": [0.1, 0.5],
                "gamma": ["auto", "scale"]
            }
            base_model = OneClassSVM(kernel="rbf")
        elif self.method == "knn":
            param_grid = {
                "n_neighbors": [5, 10],
            }
            base_model = KNN()
        elif self.method == "hbos":
            param_grid = {
                "n_bins": [5, 10],
            }
            base_model = HBOS()
        else:
            raise ValueError(f"Unknown method: {self.method}")

        grid_search = GridSearchCV(
            estimator=base_model,
            param_grid=param_grid,
            cv=3,
            scoring="roc_auc",
            n_jobs=-1
        )

        dummy_y = np.zeros(len(X_train))
        grid_search.fit(X_train, dummy_y)

        return grid_search.best_estimator_

    # ---------------------------
    # 4) Main Detection Method
    # ---------------------------
    def detect_anomalies(self, process_df, original_data):
        """
        Detect anomalies using the selected method and hyperparameter strategy.
        Returns:
          anomaly_indices: Indices of detected anomalies
          anomaly_data: Rows from original_data for anomalies
        """
        if process_df.empty:
            print("No data to process.")
            return None, None

        # Step 1: PCA
        principal_components = self._perform_pca(process_df)

        # Step 2: Adaptive Contamination
        adaptive_contamination = self._get_adaptive_contamination(principal_components)

        # Step 3: Select / Tune Model
        if self.tuning_strategy == "out-of-the-box":
            self.model = self._build_model(adaptive_contamination, process_df)
        elif self.tuning_strategy == "peak":
            self.model = self._tune_model_peak(principal_components)
        elif self.tuning_strategy == "best_default":
            # Use best-default params if provided
            if self.best_default_params and self.method == "iforest":
                # Example for iforest; adapt for other methods as needed
                self.model = IsolationForest(random_state=self.random_state, **self.best_default_params)
            else:
                self.model = self._build_model(adaptive_contamination, process_df)
        elif self.tuning_strategy == "tuned":
            self.model = self._tune_model_validation(principal_components)
        else:
            raise ValueError(f"Unknown tuning strategy: {self.tuning_strategy}")

        # Step 4: Fit & Predict
        if self.method == "lof":
            # LOF uses fit_predict
            anomaly_labels = self.model.fit_predict(principal_components)
        else:
            self.model.fit(principal_components)
            anomaly_labels = self.model.predict(principal_components)

        # Step 5: Extract anomaly indices
        anomaly_indices = np.where(anomaly_labels == -1)[0]
        return anomaly_indices, original_data.iloc[anomaly_indices]
