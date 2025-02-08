from services.compliance_checker import ComplianceChecker


class RiskAnalyzer:
    def __init__(self):
        self.compliance_checker = ComplianceChecker()

    def compute_dynamic_weights(self, df):
     """Compute dynamic weights for risk factors."""
     weights = {}

        # Dynamic weight for hour-based risk, calculated based on the spread of hour values
     if 'Hour' in df.columns:
         hour_range = df['Hour'].max() - df['Hour'].min()
         weights['hour_weight'] = (hour_range + 1) * 2  # Example dynamic calculation based on hour spread
     else:
        weights['hour_weight'] = df.shape[0] * 0.1  # Fallback if 'Hour' column is missing

    # Dynamic weight for EventFrequency, considering data distribution (std / mean ratio)
     if 'EventFrequency' in df.columns:
        weights['event_frequency_weight'] = (df['EventFrequency'].std() / df['EventFrequency'].mean()) * 10
     else:
        weights['event_frequency_weight'] = df.shape[0] * 0.05  # Fallback dynamic weight based on number of records

    # Dynamic weight for UserEventFrequency, calculated similarly to EventFrequency
     if 'UserEventFrequency' in df.columns:
        weights['user_event_frequency_weight'] = (df['UserEventFrequency'].std() / df['UserEventFrequency'].mean()) * 5
     else:
        weights['user_event_frequency_weight'] = df.shape[0] * 0.05  # Fallback dynamic weight

    # Dynamic weight for IPEventFrequency, calculated similarly
     if 'IPEventFrequency' in df.columns:
        weights['ip_event_frequency_weight'] = (df['IPEventFrequency'].std() / df['IPEventFrequency'].mean()) * 5
     else:
        weights['ip_event_frequency_weight'] = df.shape[0] * 0.05  # Fallback dynamic weight

    # Dynamic weight for critical events, using the variance of critical event occurrences
     if 'CriticalEvent' in df.columns:
        critical_event_variance = df['CriticalEvent'].var()
        weights['critical_event_weight'] = critical_event_variance * 15  # Example dynamic weight
     else:
        weights['critical_event_weight'] = df.shape[0] * 0.1  # Fallback based on number of records

    # Dynamic weight for failed login attempts, based on frequency of failed attempts
     if 'FailedLogin' in df.columns:
        failed_login_rate = df['FailedLogin'].sum() / df.shape[0]  # Frequency of failed logins
        weights['failed_login_weight'] = failed_login_rate * 40  # Scaled by failed login rate
     else:
        weights['failed_login_weight'] = df.shape[0] * 0.1  # Fallback dynamic weight

    # Dynamic weight for sensitive data access, based on frequency of access
     if 'SensitiveDataAccess' in df.columns:
        sensitive_data_access_rate = df['SensitiveDataAccess'].sum() / df.shape[0]
        weights['sensitive_data_access_weight'] = sensitive_data_access_rate * 30  # Scaled weight
     else:
        weights['sensitive_data_access_weight'] = df.shape[0] * 0.1  # Fallback dynamic weight

     return weights


    def calculate_risk_score(self, row, weights):
        """Calculate risk score for a single event."""
        score = 0
        reasons = []

        compliance_violations = self.compliance_checker.check_all_compliance(row.to_dict())
        if compliance_violations:
            score += 30
            reasons.extend(compliance_violations)

        # Time-based risk
        if row['Hour'] < 6 or row['Hour'] > 22:
            score += weights['hour_weight']
            reasons.append(f"Unusual time of day: {row['Hour']}")

        # Frequency-based risks
        if row['EventFrequency'] < row['LowerThreshold'] or row['EventFrequency'] > row['UpperThreshold']:
            score += weights['event_frequency_weight']
            reasons.append(f"Event {row['EventName']} has unusual frequency")

        # User-based frequency
        if row['UserEventFrequency'] > row['UserThreshold']:
            score += weights['user_event_frequency_weight']
            reasons.append(f"User {row['Username']} exceeded event frequency")

        # # IP-based frequency
        # if row['IPEventFrequency'] > row['IPThreshold']:
        #     score += weights['ip_event_frequency_weight']
        #     reasons.append(f"IP {row['IP']} shows unusual activity")

        # Critical event detection
        if row['EventName'] in ["DeleteBucket", "StopInstances"]:
            score += weights['critical_event_weight']
            reasons.append(f"Critical event detected: {row['EventName']}")

        # Failed login attempts
        if row['FailedLoginAttempts'] > 3:
            score += weights['failed_login_weight']
            reasons.append(f"Multiple failed login attempts: {row['FailedLoginAttempts']}")

        # # Sensitive data access
        # if row['SensitiveDataAccess']:
        #     score += weights['sensitive_data_access_weight']
        #     reasons.append("Access to sensitive data detected")

        return score, reasons
