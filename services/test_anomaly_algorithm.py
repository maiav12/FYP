# import pandas as pd
# from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
# from anomaly_detector import AnomalyDetector  # Import your updated class
# import matplotlib.pyplot as plt
# import seaborn as sns



# # ✅ Load Processed Data
# process_df = pd.read_csv("data/processed_data.csv")  
# original_data = pd.read_csv("data/original_logs.csv")

# # ✅ List of Algorithms to Compare
# algorithms = ["iforest", "lof", "ocsvm", "knn", "hbos"]
# results = {}

# # ✅ Run Each Algorithm & Store Results
# for algo in algorithms:
#     print(f"Running {algo}...")
#     detector = AnomalyDetector(method=algo)
#     anomaly_indices, anomalies = detector.detect_anomalies(process_df, original_data)
    
#     # Store detected anomalies
#     results[algo] = anomaly_indices  

# # ✅ Save Anomaly Detection Results
# results_df = pd.DataFrame({"Algorithm": list(results.keys()), "Anomalies Detected": [len(v) for v in results.values()]})
# results_df.to_csv("reports/anomaly_detection_results.csv", index=False)
# print("\n📁 Results saved in reports/anomaly_detection_results.csv")


# # ==============================
# # 🔬 **STEP 2: MODEL EVALUATION**
# # ==============================

# def evaluate_model(y_true, y_pred):
#     """
#     Compute evaluation metrics for anomaly detection.
#     """
#     precision = precision_score(y_true, y_pred, average="binary")
#     recall = recall_score(y_true, y_pred, average="binary")
#     f1 = f1_score(y_true, y_pred, average="binary")
#     auc = roc_auc_score(y_true, y_pred)

#     return {"Precision": precision, "Recall": recall, "F1-Score": f1, "AUC": auc}

# # ✅ Load Ground Truth Labels (1=anomaly, 0=normal)
# y_true = original_data["Anomaly_Label"].values  # Replace with actual column name

# # ✅ Evaluate Each Algorithm
# scores = {}
# for algo in algorithms:
#     y_pred = (original_data.index.isin(results[algo])).astype(int)
#     scores[algo] = evaluate_model(y_true, y_pred)

# # ✅ Convert Scores to DataFrame
# scores_df = pd.DataFrame(scores).T

# # ✅ Save Scores for Documentation
# scores_df.to_csv("reports/anomaly_detection_metrics.csv", index=True)

# # ✅ Display Results
# print("\n🔬 **Evaluation Results:**")
# print(scores_df)
# print("\n📁 Metrics saved in reports/anomaly_detection_metrics.csv")
# # Plot Bar Chart of AUC Scores
# sns.barplot(x=scores_df.index, y=scores_df["AUC"])
# plt.title("AUC Scores for Different Anomaly Detection Algorithms")
# plt.xlabel("Algorithm")
# plt.ylabel("AUC Score")
# plt.show()
