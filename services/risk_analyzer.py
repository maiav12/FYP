from matplotlib import pyplot as plt
from sklearn.ensemble import IsolationForest
from services.compliance_checker import ComplianceChecker
import seaborn as sns
from sklearn.cluster import KMeans
import numpy as np
import pandas as pd

class RiskAnalyzer:
    def __init__(self):
        self.compliance_checker = ComplianceChecker()

    def compute_dynamic_weights(self, df):
        """Compute dynamic weights for risk factors, including anomaly detection for access hours."""
        weights = {}

         # ✅ Step 1: Ensure 'Hour' and 'Username' Columns Exist
        if 'Hour' in df.columns and 'Username' in df.columns:
            df['UnusualHour'] = 0  # Default all as normal
            
            unique_users = df['Username'].unique()
            for user in unique_users:
                user_data = df[df['Username'] == user]  # Filter logs per user
                
                if len(user_data) < 5:  # Not enough data for proper anomaly detection
                    continue  

                hour_values = user_data['Hour'].values.reshape(-1, 1)

               
                isolation_forest = IsolationForest(contamination=0.1, random_state=42)
                anomaly_labels = isolation_forest.fit_predict(hour_values)

                # Mark anomalous login hours (-1 in Isolation Forest means anomaly)
                df.loc[df['Username'] == user, 'UnusualHour'] = (anomaly_labels == -1).astype(int)

            # Normalize hour weight (scales between 0 and 1)
            weights['hour_weight'] = df['UnusualHour'].mean() * 10  # Scale impact factor

        else:
            weights['hour_weight'] = df.shape[0] * 0.1  # Fallback if 'Hour' column is missing

        # ✅ Step 2: Compute Dynamic Weight for Event Frequency
        if 'EventFrequency' in df.columns:
            event_std = df['EventFrequency'].std()
            event_mean = df['EventFrequency'].mean()

            if event_mean > 0:
                weights['event_frequency_weight'] = (event_std / event_mean) * 10
            else:
                weights['event_frequency_weight'] = 1  # Default if mean is zero

            # 🧠 Detect Event Frequency Anomalies using Rolling Statistics
            df['RollingMean'] = df['EventFrequency'].rolling(window=5, min_periods=1).mean()
            df['RollingStd'] = df['EventFrequency'].rolling(window=5, min_periods=1).std()

            df['AnomalousEvent'] = (df['EventFrequency'] > (df['RollingMean'] + 2 * df['RollingStd'])).astype(int)
            weights['event_frequency_weight'] += df['AnomalousEvent'].mean() * 5  # Increase weight for anomalies
        else:
            weights['event_frequency_weight'] = df.shape[0] * 0.05  # Fallback based on dataset size

        # ✅ Step 3: Compute Dynamic Weights for User-Based Frequency
        if 'UserEventFrequency' in df.columns:
            user_std = df['UserEventFrequency'].std()
            user_mean = df['UserEventFrequency'].mean()

            weights['user_event_frequency_weight'] = (user_std / user_mean) * 5 if user_mean > 0 else 1
        else:
            weights['user_event_frequency_weight'] = df.shape[0] * 0.05  # Fallback

        # ✅ Step 4: Compute Dynamic Weights for IP-Based Frequency
        if 'IPEventFrequency' in df.columns:
            ip_std = df['IPEventFrequency'].std()
            ip_mean = df['IPEventFrequency'].mean()

            weights['ip_event_frequency_weight'] = (ip_std / ip_mean) * 5 if ip_mean > 0 else 1
        else:
            weights['ip_event_frequency_weight'] = df.shape[0] * 0.05  # Fallback

        # ✅ Step 5: Compute Weights for Critical Events
        if 'CriticalEvent' in df.columns:
            weights['critical_event_weight'] = df['CriticalEvent'].var() * 15 if df['CriticalEvent'].var() > 0 else 1
        else:
            weights['critical_event_weight'] = df.shape[0] * 0.1  # Fallback

        # ✅ Step 6: Compute Weights for Failed Login Attempts
        if 'FailedLogin' in df.columns:
            failed_login_rate = df['FailedLogin'].sum() / df.shape[0]  # Percentage of failed logins
            weights['failed_login_weight'] = failed_login_rate * 40
        else:
            weights['failed_login_weight'] = df.shape[0] * 0.1  # Fallback

        # ✅ Step 7: Compute Weights for Sensitive Data Access
        if 'SensitiveDataAccess' in df.columns:
            sensitive_data_access_rate = df['SensitiveDataAccess'].sum() / df.shape[0]
            weights['sensitive_data_access_weight'] = sensitive_data_access_rate * 30
        else:
            weights['sensitive_data_access_weight'] = df.shape[0] * 0.1  # Fallback

        return weights

    def calculate_risk_score(self, row, weights):
     """Calculate risk score for a single event with adaptive dynamic weighting."""
     score = 0
     reasons = []

     # ✅ Step 1: Compliance Violations
     compliance_violations = self.compliance_checker.check_all_compliance(row.to_dict())
     if compliance_violations:
        score += 30
        reasons.extend(compliance_violations)

     # ✅ Step 2: Time-based Risk (Unusual Access Hours)
     if row.get('UnusualHour', 0) == 1:
        previous_logins = row.get('PreviousLoginsAtHour', 0)  # How often user logged in at this hour
        adjustment_factor = 1 - (previous_logins / 10)  # Reduce weight if this is common for the user
        adjusted_weight = max(weights['hour_weight'] * adjustment_factor, weights['hour_weight'] * 0.3)
        score += adjusted_weight
        reasons.append(f"Unusual access time: {row['Hour']} (Previous logins: {previous_logins})")

     # ✅ Step 3: Frequency-Based Risk (Adjusted by Event Type)
     severity_multiplier = 2 if row['EventName'] in ["DeleteBucket", "StopInstances"] else 1  # High-risk events
     if row['EventFrequency'] > row['UpperThreshold']:
        adjusted_weight = weights['event_frequency_weight'] * severity_multiplier
        score += adjusted_weight
        reasons.append(f"Unusual frequency for {row['EventName']} (Severity: {severity_multiplier}x)")

    # ✅ Step 4: User-Based Frequency Risk (Adjust for Experienced Users)
     if row['UserEventFrequency'] > row['UserThreshold']:
        user_history_factor = 1 - min(row['UserEventFrequency'] / 20, 0.5)  # Reduce weight if user does this often
        adjusted_weight = weights['user_event_frequency_weight'] * user_history_factor
        score += adjusted_weight
        reasons.append(f"User {row['Username']} exceeded event frequency (Adjusted weight: {adjusted_weight:.2f})")

     # ✅ Step 5: IP-Based Frequency Risk (Consider Reputation)
     if row['IPEventFrequency'] > row['IPThreshold']:
        ip_reputation_factor = row.get('IPReputationScore', 1)  # Default to 1 if unknown
        adjusted_weight = weights['ip_event_frequency_weight'] * ip_reputation_factor
        score += adjusted_weight
        reasons.append(f"IP {row['SourceIPAddress']} shows unusual activity (Reputation Factor: {ip_reputation_factor})")

     # ✅ Step 6: Critical Event Detection (Scale with Recent Critical Events)
     recent_critical_events = row.get('RecentCriticalEvents', 0)  # How many in the past X hours?
     if row['EventName'] in ["DeleteBucket", "StopInstances"]:
        scaling_factor = 1 + (recent_critical_events / 5)  # Increase impact if multiple critical events occurred
        adjusted_weight = weights['critical_event_weight'] * scaling_factor
        score += adjusted_weight
        reasons.append(f"Critical event detected: {row['EventName']} (Scaling Factor: {scaling_factor:.2f})")

     # ✅ Step 7: Failed Login Attempts (Exponential Weighting)
     if row['FailedLoginAttempts'] > 3:
        failed_attempts = row['FailedLoginAttempts']
        adjusted_weight = weights['failed_login_weight'] * (1.2 ** (failed_attempts - 3))  # Exponential increase
        score += adjusted_weight
        reasons.append(f"Multiple failed login attempts: {failed_attempts} (Adjusted weight: {adjusted_weight:.2f})")

    # ✅ Step 8: Sensitive Data Access (Factor in User Role)
     if row.get('SensitiveDataAccess', 0) == 1:
        user_role_factor = 0.5 if row.get('UserRole') in ["Admin", "Security"] else 1  # Reduce weight for authorized users
        adjusted_weight = weights['sensitive_data_access_weight'] * user_role_factor
        score += adjusted_weight
        reasons.append(f"Access to sensitive data detected (User Role Factor: {user_role_factor})")

     return score, reasons

