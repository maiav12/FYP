import json
import pandas as pd
from sklearn.preprocessing import StandardScaler


class DataProcessor:
    def __init__(self):
        self.scaler = StandardScaler()

    def preprocess_logs(self, events, unauthorized_api_calls):
        """Preprocess logs and extract key features."""
        data = []
        for event in events:
            processed_event = self._process_single_event(event, unauthorized_api_calls)
            data.append(processed_event)

        df = pd.DataFrame(data)
        if df.empty:
            return pd.DataFrame(), pd.DataFrame()

        return self._create_features(df)

    def _process_single_event(self, event, unauthorized_api_calls):
        """Process a single event and extract relevant information."""
        try:
            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
        except json.JSONDecodeError:
            event_data = {}

        failed_login = 0
        if 'LoginFailure' in event.get('EventName', ''):
            failed_login = 1

        # Retain the original 'Resources' dict for downstream mitigation.
        return {
            'EventName': event.get('EventName', 'Unknown'),
            'Username': event.get('Username', 'Unknown'),
            'SourceIPAddress': event.get('SourceIPAddress', 'Unknown'),
            'EventTime': event.get('EventTime', None),
            'EventID': event.get('EventId', 'Unknown'),
            'CloudTrailEvent': event_data,
            'Resources': event.get('Resources', {}),
            'UnauthorizedCall': event.get('EventName', '') in unauthorized_api_calls,
            'FailedLoginAttempts': failed_login
        }

    def _create_features(self, df):
        """Create features from the processed data."""
        df['EventTime'] = pd.to_datetime(df['EventTime'], errors='coerce')

        # Drop rows with missing EventTime
        df.dropna(subset=['EventTime'], inplace=True)

        # Create temporal features
        df['Hour'] = df['EventTime'].dt.hour
        df['DayOfWeek'] = df['EventTime'].dt.dayofweek
        df['DayOfMonth'] = df['EventTime'].dt.day

        # Create frequency features
        self._add_frequency_features(df)

        # Prepare data for machine learning
        return self._prepare_for_ml(df)

    def _add_frequency_features(self, df):
        """Add frequency-based features to the dataframe."""
        df['EventFrequency'] = df.groupby('EventName')['EventName'].transform('count')
        df['UserEventFrequency'] = df.groupby(['Username', 'EventName'])['EventName'].transform('count')
        df['IPEventFrequency'] = df.groupby(['SourceIPAddress', 'EventName'])['EventName'].transform('count')

        # Calculate cumulative failed login attempts per user
        df['FailedLoginAttempts'] = df.groupby('Username')['FailedLoginAttempts'].transform('sum')

        # Calculate thresholds (handle small dataset cases)
        if len(df) > 1:
            event_mean = df['EventFrequency'].mean()
            event_std = df['EventFrequency'].std()
            df['LowerThreshold'] = event_mean - 2 * event_std
            df['UpperThreshold'] = event_mean + 2 * event_std
        else:
            df['LowerThreshold'] = df['EventFrequency']
            df['UpperThreshold'] = df['EventFrequency']

        # Calculate user-specific thresholds
        user_thresholds = (
            df.groupby('Username')['UserEventFrequency']
            .transform(lambda x: x.mean() + 2 * x.std())
            .fillna(df['UserEventFrequency'])
        )
        df['UserThreshold'] = user_thresholds

        # Calculate IP-specific thresholds
        ip_thresholds = (
            df.groupby('SourceIPAddress')['IPEventFrequency']
            .transform(lambda x: x.mean() + 2 * x.std())
            .fillna(df['IPEventFrequency'])
        )
        df['IPThreshold'] = ip_thresholds

    def _prepare_for_ml(self, df):
        """
        Prepare data for machine learning.
        Crucially, we drop 'Resources' to avoid having dict objects in our ML features.
        """
        # Drop unneeded columns from ML features, including 'Resources'
        process_df = pd.get_dummies(
            df.drop(['EventTime', 'EventID', 'CloudTrailEvent', 'Resources'], axis=1, errors='ignore'),
            columns=['EventName', 'Username', 'SourceIPAddress'],
            drop_first=True
        )

        # Standardize numeric columns
        numerical_columns = [
            'Hour', 'DayOfWeek', 'DayOfMonth',
            'EventFrequency', 'UserEventFrequency', 'IPEventFrequency'
        ]
        existing_columns = [col for col in numerical_columns if col in process_df.columns]
        process_df[existing_columns] = self.scaler.fit_transform(process_df[existing_columns])

        # Return tuple: (ML-friendly DataFrame, full original DataFrame)
        return process_df, df
