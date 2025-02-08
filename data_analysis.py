import pandas as pd
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.decomposition import PCA
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest


# Load the Excel file into a DataFrame
data = pd.read_excel('access_control_dataset.xlsx')

# Preprocess: Select relevant columns
key_columns = [
    'Authentication_Mechanisms', 'Authorization_Models', 'Compliance_Requirements', 
    'Network_Security_Controls', 'Data_Sensitivity_Classification', 'Access_Levels', 
    'User_Roles', 'Cloud_Service_Provider', 'Geolocation_Restrictions', 'Time_Based_Access'
]
data = data[key_columns]

# Map and fill missing values in 'Access_Levels'
access_level_mapping = {'Read': 1, 'Write': 2, 'Modify': 3, 'Admin': 4}
data['Access_Levels'] = data['Access_Levels'].map(access_level_mapping)
data['Access_Levels'].fillna(data['Access_Levels'].median(), inplace=True)

# Fill missing values in categorical columns
categorical_cols = ['User_Roles', 'Cloud_Service_Provider', 'Geolocation_Restrictions']
for col in categorical_cols:
    data[col].fillna(data[col].mode()[0], inplace=True)

# Convert categorical columns into numeric form using one-hot encoding
data = pd.get_dummies(data, columns=[
    'Authentication_Mechanisms', 'Authorization_Models', 
    'Compliance_Requirements', 'User_Roles', 
    'Cloud_Service_Provider', 'Geolocation_Restrictions', 
    'Network_Security_Controls', 'Data_Sensitivity_Classification'
])

# Standardize numerical columns
numerical_columns = ['Access_Levels', 'Time_Based_Access']
scaler = StandardScaler()
data[numerical_columns] = scaler.fit_transform(data[numerical_columns])

# Verify all columns are now numeric
non_numeric_cols = data.select_dtypes(exclude=[float, int])
print("Non-numeric columns after encoding:", non_numeric_cols.columns)  # Should be empty

# PCA Analysis with all features
standardized_data = scaler.fit_transform(data)
pca = PCA(n_components=min(6, standardized_data.shape[1]))  # Adjust components to fit dataset shape
principal_components = pca.fit_transform(standardized_data)

# Visualize cumulative explained variance
plt.figure(figsize=(10, 6))
plt.plot(np.cumsum(pca.explained_variance_ratio_) * 100, marker='o')
plt.xlabel('Number of Components')
plt.ylabel('Cumulative Explained Variance (%)')
plt.title('PCA - Cumulative Explained Variance')
plt.grid(True)
plt.show()

# Visualize the first two principal components
plt.figure(figsize=(10, 8))
scatter = plt.scatter(principal_components[:, 0], principal_components[:, 1], 
                      c=data['Access_Levels'], cmap='viridis', edgecolor='k', s=70, alpha=0.7)
plt.colorbar(scatter, label='Access Levels')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.title('PCA - 2D Visualization with All Features')
plt.grid(True)
plt.show()

# Isolation Forest Anomaly Detection on PCA-transformed Data
train_data, test_data, train_idx, test_idx = train_test_split(principal_components, 
                                                             range(len(principal_components)), 
                                                             test_size=0.2, random_state=42)
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(train_data)

# Predict anomalies on test data
anomalies = model.predict(test_data)
anomaly_indices = np.array(test_idx)[anomalies == -1]  # Use indices for test data

# Plot anomalies in the PCA-reduced 2D space
plt.figure(figsize=(10, 8))
plt.scatter(test_data[:, 0], test_data[:, 1], c=anomalies, cmap='coolwarm', edgecolor='k', s=70, alpha=0.7)
plt.title('Anomaly Detection using Isolation Forest on Principal Components')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.colorbar(label='Anomaly Status (1: Normal, -1: Anomaly)')
plt.grid(True)
plt.show()

# Moving Averages and Variance Trend Analysis for All PCs
principal_df = pd.DataFrame(principal_components, columns=[f'PC{i+1}' for i in range(principal_components.shape[1])])
moving_averages = principal_df.rolling(window=5).mean()
variance_trend = principal_df.rolling(window=5).var()
 #Step 1: Calculate moving averages for each principal component
# We use a rolling window of 5 observations (this can be adjusted)
moving_averages = principal_df.rolling(window=5).mean()

# Print the moving averages (you can print only the latest values to avoid large output)
print("Moving Averages:\n", moving_averages.tail())

# Step 2: Variance analysis over time (rolling window)
# We can track the variance in each principal component over time (e.g., using a window of 5)
variance_trend = principal_df.rolling(window=5).var()

# Print the variance trend for the principal components
print("Variance Trend:\n", variance_trend.tail())

# Step 3: Visualizing the Moving Averages and Variance Trends

# Plot the moving averages
plt.figure(figsize=(12, 8))
plt.plot(moving_averages, label='Moving Averages (5 window)')
plt.title('Moving Averages of Principal Components Over Time')
plt.xlabel('Time (Observations)')
plt.ylabel('Principal Component Values')
plt.legend()
plt.show()

# Plot the variance trend over time
plt.figure(figsize=(12, 8))
plt.plot(variance_trend, label='Variance Trend (5 window)', linestyle='--')
plt.title('Variance Trend of Principal Components Over Time')
plt.xlabel('Time (Observations)')
plt.ylabel('Variance')
plt.legend()
plt.show()
# Initialize risk scores with a baseline of 0
risk_scores = pd.Series(0, index=principal_df.index)

# Increment risk score based on anomaly detection
risk_scores.loc[anomaly_indices] += 1

# Define thresholds for adaptive scoring 
moving_avg_mean = moving_averages.mean().mean()
moving_avg_std = moving_averages.std().mean()
variance_mean = variance_trend.mean().mean()
variance_std = variance_trend.std().mean()

# Set thresholds based on standard deviations
moving_avg_threshold = moving_avg_mean + 2 * moving_avg_std
variance_threshold = variance_mean + 2 * variance_std

contamination_rate = 0.02   # Lowered from 0.05 in Isolation Forest

# Adjust the Isolation Forest model with a stricter contamination rate
model = IsolationForest(contamination=contamination_rate, random_state=42)
model.fit(train_data)


# Update risk scores based on moving averages and variance trends
for i in range(len(risk_scores)):
    if any(moving_averages.iloc[i].abs() > moving_avg_threshold):
        risk_scores[i] += 1
    if any(variance_trend.iloc[i] > variance_threshold):
        risk_scores[i] += 1

# Define a high-risk threshold for alerts
high_risk_threshold = 2  # Adjust according to scoring patterns

# Identify and display high-risk events
high_risk_events = risk_scores[risk_scores >= high_risk_threshold]
print("High-risk events detected at indices:", high_risk_events.index.tolist())

# Visualize high-risk events
plt.figure(figsize=(10, 8))
plt.scatter(principal_df.iloc[:, 0], principal_df.iloc[:, 1], c='grey', alpha=0.3, label='Normal Events', s=30)
plt.scatter(principal_df.iloc[high_risk_events.index, 0], principal_df.iloc[high_risk_events.index, 1],
            c='red', label='High-Risk Events', edgecolor='k', s=100)
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.title('High-Risk Events in Principal Component Space')
plt.legend()
plt.grid(True)
plt.show()


# Log reasons for high-risk events with feature-specific conditions

risk_log = []

# Iterate over high-risk events
for index in high_risk_events.index:
    reasons = []
    row = data.iloc[index]  # Encoded row data

    # PCA-based anomalies
    if index in anomaly_indices:
        reasons.append("Anomaly detected by Isolation Forest.")
    

    # Feature-specific anomalies
    # Authentication mechanisms missing
    auth_mech_columns = [
        'Authentication_Mechanisms_Biometric', 
        'Authentication_Mechanisms_MFA', 
        'Authentication_Mechanisms_Password', 
        'Authentication_Mechanisms_SSO'
    ]
    if row[auth_mech_columns].sum() == 1:
        reasons.append("Missing all authentication mechanisms.")

    # Authorization models missing
    auth_models_columns = [
        'Authorization_Models_ABAC', 
        'Authorization_Models_PBAC', 
        'Authorization_Models_RBAC'
    ]
    if row[auth_models_columns].sum() == 0:
        reasons.append("No authorization model applied.")

    # Non-compliance
    if row['Compliance_Requirements_False'] == 1:
        reasons.append("Non-compliance with required standards.")

    # Weak network security controls
    if row['Network_Security_Controls_False'] == 1:
        reasons.append("Weak or missing network security controls.")

    # Unknown geolocation
    geolocation_columns = [
        'Geolocation_Restrictions_Germany'
    ]
    if row[geolocation_columns].sum() == 0:
        reasons.append("Access from an unknown or restricted location.")

    # Elevated admin-level access
    if row['Access_Levels'] == 4:  # Admin level
        reasons.append("Elevated admin-level access.")

    # Combine reasons
    log_entry = f"Index {index}: {'; '.join(reasons)}"
    risk_log.append(log_entry)

# Print detailed log
print("\nDetailed Risk Log:")
print("\n".join(risk_log))

# Save risk logs to a file
with open("risk_log.txt", "w") as log_file:
    log_file.write("\n".join(risk_log))


def trigger_mitigation_actions(risk_log, data):
    for index, log_entry in enumerate(risk_log):
        row = data.iloc[index]  # Access data for the given index

        # Check for missing authentication mechanisms
        if "Missing all authentication mechanisms." in log_entry:
            print(f"Mitigation: Apply MFA or ensure authentication mechanisms for index {index}")
            # Implement security actions, like enforcing MFA or notification to admin
            # Example: Trigger a notification or update configuration (mock action)
            print(f"Admin alerted for missing authentication at index {index}.")

        # Check for non-compliance
        if "Non-compliance with required standards." in log_entry:
            print(f"Mitigation: Trigger compliance checks for index {index}")
            # Trigger a compliance check (mock action)
            print(f"Compliance check triggered for index {index}.")

        # Check for weak or missing network security controls
        if "Weak or missing network security controls." in log_entry:
            print(f"Mitigation: Strengthen network security controls for index {index}")
            # Implement actions to strengthen network security (mock action)
            print(f"Network security review initiated for index {index}.")
        
     
# Get high-risk events
high_risk_events = risk_scores[risk_scores >= high_risk_threshold]

# Trigger mitigation actions for high-risk events
trigger_mitigation_actions(risk_log, data)
def log_mitigation_actions(risk_log, mitigation_log_file="mitigation_log.txt"):
    with open(mitigation_log_file, "a") as log_file:
        for log_entry in risk_log:
            log_file.write(f"{log_entry}\n")

    print(f"Mitigation actions logged to {mitigation_log_file}")
