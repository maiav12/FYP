import numpy as np
import pandas as pd
from services.compliance_checker import ComplianceChecker
from sklearn.ensemble import IsolationForest

class RiskAnalyzer:
    def __init__(self, parameters=None):
        self.compliance_checker = ComplianceChecker()
        self.parameters = parameters or {
            "baseline_risk": 5,
            "compliance_penalty": 30,
            "hour_weight_scale": 10,
            "unusual_hour_min": 0.3,
            "unusual_hour_divisor": 10,
            "event_frequency_multiplier": 15,
            "event_frequency_extra": 5,
            "user_event_multiplier": 10,
            "ip_event_multiplier": 8,
            "critical_event_multiplier": 20,
            "failed_login_multiplier": 40,
            "sensitive_data_multiplier": 30,
            "user_event_threshold_scale": 20,
            "user_event_max_factor": 0.5,
            "failed_login_base": 3,
            "failed_login_exp_base": 1.2,
            "anomaly_penalty": 35
        }

    def compute_dynamic_weights(self, df):
        weights = {}
        # -- Unusual hour detection --
        if 'Hour' in df.columns and 'Username' in df.columns:
            df['UnusualHour'] = 0
            unique_users = df['Username'].dropna().unique()
            for user in unique_users:
                user_data = df[df['Username'] == user]
                if len(user_data) < 5:
                    continue
                hour_values = user_data['Hour'].values.reshape(-1, 1)
                iso_forest = IsolationForest(contamination=0.1, random_state=42)
                anomaly_labels = iso_forest.fit_predict(hour_values)
                df.loc[df['Username'] == user, 'UnusualHour'] = (anomaly_labels == -1).astype(int)
            weights['hour_weight'] = df['UnusualHour'].mean() * self.parameters["hour_weight_scale"]
        else:
            weights['hour_weight'] = df.shape[0] * self.parameters.get("fallback_weight", 0.1)

        # -- Event Frequency weight --
        if 'EventFrequency' in df.columns:
            event_std = df['EventFrequency'].std() or 0
            event_mean = df['EventFrequency'].mean() or 0
            if event_mean > 0:
                weights['event_frequency_weight'] = (event_std / event_mean) * self.parameters["event_frequency_multiplier"]
            else:
                weights['event_frequency_weight'] = 1
            df['RollingMean'] = df['EventFrequency'].rolling(window=5, min_periods=1).mean()
            df['RollingStd'] = df['EventFrequency'].rolling(window=5, min_periods=1).std()
            df['AnomalousEvent'] = (df['EventFrequency'] > (df['RollingMean'] + 2 * df['RollingStd'])).astype(int)
            weights['event_frequency_weight'] += df['AnomalousEvent'].mean() * self.parameters["event_frequency_extra"]
        else:
            weights['event_frequency_weight'] = df.shape[0] * 0.05

        # -- User and IP event frequency weights --
        if 'UserEventFrequency' in df.columns:
            user_std = df['UserEventFrequency'].std() or 0
            user_mean = df['UserEventFrequency'].mean() or 0
            weights['user_event_frequency_weight'] = (user_std / user_mean) * self.parameters["user_event_multiplier"] if user_mean > 0 else 1
        else:
            weights['user_event_frequency_weight'] = df.shape[0] * 0.05

        if 'IPEventFrequency' in df.columns:
            ip_std = df['IPEventFrequency'].std() or 0
            ip_mean = df['IPEventFrequency'].mean() or 0
            weights['ip_event_frequency_weight'] = (ip_std / ip_mean) * self.parameters["ip_event_multiplier"] if ip_mean > 0 else 1
        else:
            weights['ip_event_frequency_weight'] = df.shape[0] * 0.05

        # -- Critical event weight --
        if 'CriticalEvent' in df.columns:
            var = df['CriticalEvent'].var() or 0
            weights['critical_event_weight'] = var * self.parameters["critical_event_multiplier"] if var > 0 else 1
        else:
            weights['critical_event_weight'] = df.shape[0] * 0.1

        # -- Failed login weight --
        if 'FailedLoginAttempts' in df.columns:
            total_failed = df['FailedLoginAttempts'].sum()
            failed_rate = total_failed / df.shape[0] if df.shape[0] > 0 else 0
            weights['failed_login_weight'] = failed_rate * self.parameters["failed_login_multiplier"]
        else:
            weights['failed_login_weight'] = df.shape[0] * 0.1

        # -- Sensitive data access weight --
        if 'SensitiveDataAccess' in df.columns:
            total_sensitive = df['SensitiveDataAccess'].sum()
            sens_rate = total_sensitive / df.shape[0] if df.shape[0] > 0 else 0
            weights['sensitive_data_access_weight'] = sens_rate * self.parameters["sensitive_data_multiplier"]
        else:
            weights['sensitive_data_access_weight'] = df.shape[0] * 0.1

        return weights

    def assign_likelihood(self, row):
        """
        Assign a likelihood score based on the chance of occurrence.
        For example, using EventFrequency:
          - Rare: < 5% chance → Score 1
          - Unlikely: 5%-9% → Score 3
          - Reasonably Possible: 10%-19% → Score 5
          - Likely: 20%-49% → Score 8
          - Almost Certain: > 50% → Score 13
        Here, we simulate this using thresholds on 'EventFrequency'.
        Adjust these thresholds as needed.
        """
        freq = row.get("EventFrequency", 0)
        # Example thresholds – adjust as per your dataset
        if freq < 3:
            return 1  # Rare
        elif freq < 5:
            return 3  # Unlikely
        elif freq < 8:
            return 5  # Reasonably Possible
        elif freq < 12:
            return 8  # Likely
        else:
            return 13  # Almost Certain

    def assign_impact(self, row):
        """
        Assign an impact score based on the potential damage if the event occurred.
        For example, base it on the EventName:
          - Low: Score 1
          - Minor: Score 3
          - Moderate: Score 5
          - Major: Score 8
          - Catastrophic: Score 13
        Adjust logic based on your risk assessment criteria.
        """
        event = row.get("EventName", "")
        # Example logic – adjust as needed:
        if event in ["DeleteBucket", "StopInstances"]:
            return 13  # Catastrophic impact
        elif event in ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]:
            return 8   # Major impact
        elif event in ["PutObject", "GetObject"]:
            return 5   # Moderate impact
        else:
            return 3   # Minor impact by default

    def calculate_risk_score(self, row, weights):
        """
        Calculate the risk score for a single event row.
        The final risk includes:
          - A baseline risk (ensuring no event scores 0)
          - Risk contributions from compliance, unusual access, frequency-based triggers, and more.
          - A likelihood-impact component based on the provided Likelihood and Impact ratings.
        """
        # Start with a baseline risk (to ensure non-zero)
        score = self.parameters.get("baseline_risk", 5)
        reasons = [f"Baseline risk: {score}"]

        # 1) Compliance Violations
        compliance_violations = self.compliance_checker.check_all_compliance(row.to_dict())
        if compliance_violations:
            score += self.parameters["compliance_penalty"]
            for viol in compliance_violations:
                if isinstance(viol, dict):
                    msg = viol.get('message', 'Unknown violation')
                    reasons.append(f"Compliance: {msg}")
                else:
                    reasons.append(f"Compliance: {viol}")

        # 2) Unusual Access Hours
        if row.get('UnusualHour', 0) == 1:
            previous_logins = row.get('PreviousLoginsAtHour', 0)
            hour_weight = weights.get('hour_weight', 1)
            adjustment_factor = 1 - (previous_logins / self.parameters["unusual_hour_divisor"])
            adjusted_weight = max(hour_weight * adjustment_factor,
                                  hour_weight * self.parameters["unusual_hour_min"])
            score += adjusted_weight
            reasons.append(f"Unusual hour access (Prev logins: {previous_logins})")

        # 3) Frequency-Based Risk
        event_name = row.get('EventName', '')
        severity_multiplier = 2 if event_name in ["DeleteBucket", "StopInstances"] else 1
        event_freq = row.get('EventFrequency', 0)
        upper_thresh = row.get('UpperThreshold', 1e6)
        if event_freq > upper_thresh:
            adjusted_weight = weights.get('event_frequency_weight', 1) * severity_multiplier
            score += adjusted_weight
            reasons.append(f"High event frequency for {event_name} (Severity {severity_multiplier}x)")

        # 4) User-Based Frequency Risk
        user_freq = row.get('UserEventFrequency', 0)
        user_thresh = row.get('UserThreshold', 1e6)
        if user_freq > user_thresh:
            user_history_factor = 1 - min(user_freq / self.parameters["user_event_threshold_scale"],
                                          self.parameters["user_event_max_factor"])
            adjusted_weight = weights.get('user_event_frequency_weight', 1) * user_history_factor
            score += adjusted_weight
            reasons.append(f"User frequency exceeded (Factor: {user_history_factor:.2f})")

        # 5) IP-Based Frequency Risk
        ip_freq = row.get('IPEventFrequency', 0)
        ip_thresh = row.get('IPThreshold', 1e6)
        if ip_freq > ip_thresh:
            ip_reputation_factor = row.get('IPReputationScore', 1)
            adjusted_weight = weights.get('ip_event_frequency_weight', 1) * ip_reputation_factor
            score += adjusted_weight
            reasons.append(f"IP activity high (Rep: {ip_reputation_factor})")

        # 6) Critical Event
        critical_flag = row.get('CriticalEvent', 0)
        if critical_flag == 1 or event_name in ["DeleteBucket", "StopInstances"]:
            recents = row.get('RecentCriticalEvents', 0)
            scaling_factor = 1 + (recents / 5)
            adjusted_weight = weights.get('critical_event_weight', 1) * scaling_factor
            score += adjusted_weight
            reasons.append(f"Critical event {event_name} (Scale: {scaling_factor:.2f})")

        # 7) Failed Login Attempts
        attempts = row.get('FailedLoginAttempts', 0)
        if attempts > self.parameters["failed_login_base"]:
            base_weight = weights.get('failed_login_weight', 1)
            exponent = self.parameters["failed_login_exp_base"] ** (attempts - self.parameters["failed_login_base"])
            adjusted_weight = base_weight * exponent
            score += adjusted_weight
            reasons.append(f"Failed logins: {attempts} (Weight: {adjusted_weight:.2f})")

        # 8) Sensitive Data Access
        if row.get('SensitiveDataAccess', 0) == 1:
            user_role_factor = 0.5 if row.get('UserRole') in ["Admin", "Security"] else 1
            adjusted_weight = weights.get('sensitive_data_access_weight', 1) * user_role_factor
            score += adjusted_weight
            reasons.append(f"Sensitive data (Role factor: {user_role_factor})")

        # 9) Likelihood and Impact Component
        likelihood = self.assign_likelihood(row)
        impact = self.assign_impact(row)
        li_component = likelihood * impact
        score += li_component
        reasons.append(f"Likelihood {likelihood} x Impact {impact} = {li_component}")

        return score, reasons

    def assign_likelihood(self, row):
        """
        Determine the likelihood rating (using scores from 1 to 13) based on EventFrequency.
        These thresholds are examples; adjust according to your data distribution.
        """
        freq = row.get("EventFrequency", 0)
        if freq < 3:
            return 1      # Rare (<5% chance)
        elif freq < 5:
            return 3      # Unlikely (5%-9%)
        elif freq < 8:
            return 5      # Reasonably Possible (10%-19%)
        elif freq < 12:
            return 8      # Likely (20%-49%)
        else:
            return 13     # Almost Certain (>50%)

    def assign_impact(self, row):
        """
        Determine the impact rating (using scores from 1 to 13) based on the event type.
        Adjust the mapping as needed.
        """
        event = row.get("EventName", "")
        if event in ["DeleteBucket", "StopInstances"]:
            return 13     # Catastrophic impact
        elif event in ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]:
            return 8      # Major impact
        elif event in ["PutObject", "GetObject"]:
            return 5      # Moderate impact
        else:
            return 3      # Minor impact by default

    def generate_risk_scores(self, df):
        """
        Processes the DataFrame to compute risk scores for each event.
        Adds 'RiskScore' and 'RiskReasons' columns to the DataFrame.
        """
        risk_scores = []
        risk_reasons = []
        weights = self.compute_dynamic_weights(df)
        for idx, row in df.iterrows():
            score, reasons = self.calculate_risk_score(row, weights)
            risk_scores.append(score)
            risk_reasons.append(reasons)
        df["RiskScore"] = risk_scores
        df["RiskReasons"] = risk_reasons
        return df

    def generate_risk_exposure_report(self, df, risk_threshold=20):
        """
        Computes the risk scores and aggregates the results into a summary report.
        Also simulates mitigation by scaling scores above the threshold by 0.6.
        """
        df = df.copy()  # avoid mutating original data
        df = self.generate_risk_scores(df)
        risk_array = df["RiskScore"].values.astype(float)
        total_events = len(risk_array)
        if total_events == 0:
            return {
                "total_events": 0,
                "totalRiskBefore": 0,
                "totalRiskAfter": 0,
                "averageRiskBefore": 0,
                "averageRiskAfter": 0,
                "highRiskPercentageBefore": 0,
                "highRiskPercentageAfter": 0,
                "riskReductionPercentage": 0
            }
        total_risk_before = float(risk_array.sum())
        average_risk_before = float(risk_array.mean())
        high_risk_percentage_before = float((risk_array > risk_threshold).sum() / total_events * 100)
        # Mitigation simulation: if risk is above threshold, scale by 0.6
        mitigated_scores = np.where(risk_array > risk_threshold, risk_array * 0.6, risk_array)
        total_risk_after = float(mitigated_scores.sum())
        average_risk_after = float(mitigated_scores.mean())
        high_risk_percentage_after = float((mitigated_scores > risk_threshold).sum() / total_events * 100)
        return {
            "total_events": total_events,
            "totalRiskBefore": total_risk_before,
            "totalRiskAfter": total_risk_after,
            "averageRiskBefore": average_risk_before,
            "averageRiskAfter": average_risk_after,
            "highRiskPercentageBefore": high_risk_percentage_before,
            "highRiskPercentageAfter": high_risk_percentage_after,
            "riskReductionPercentage": high_risk_percentage_before - high_risk_percentage_after
        }
