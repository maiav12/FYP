import pytest
import json
import pandas as pd
import sys
import os
# Insert the parent directory (project root) into the system path.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from services.data_processor import DataProcessor

from services.data_processor import DataProcessor

# Sample events for testing

# A valid event with a well-formed JSON string in 'CloudTrailEvent'
SAMPLE_EVENT_VALID = {
    "CloudTrailEvent": json.dumps({
        "requestParameters": {"encrypted": True}
    }),
    "EventName": "PutObject",
    "Username": "testuser",
    "SourceIPAddress": "1.2.3.4",
    "EventTime": "2023-04-26T12:34:56Z",
    "EventId": "event-001",
    "Resources": {"S3BucketName": "sample-bucket"}
}

# An event representing a login failure; should have FailedLoginAttempts set to 1
SAMPLE_EVENT_LOGIN_FAIL = {
    "CloudTrailEvent": json.dumps({
        "requestParameters": {"encrypted": True}
    }),
    "EventName": "LoginFailure",
    "Username": "testuser",
    "SourceIPAddress": "1.2.3.4",
    "EventTime": "2023-04-26T12:35:56Z",
    "EventId": "event-002",
    "Resources": {}
}

# An event with invalid JSON in 'CloudTrailEvent' which should be handled gracefully
SAMPLE_EVENT_INVALID_JSON = {
    "CloudTrailEvent": "{invalid_json: true",  # This will trigger a JSONDecodeError
    "EventName": "GetObject",
    "Username": "anotheruser",
    "SourceIPAddress": "5.6.7.8",
    "EventTime": "2023-04-26T12:40:00Z",
    "EventId": "event-003",
    "Resources": {}
}

# Create a pytest fixture to initialize the DataProcessor once for tests
@pytest.fixture
def processor():
    return DataProcessor()

def test_process_single_event_valid(processor):
    """Test that a valid event is processed correctly."""
    unauthorized_api_calls = {"DeleteBucket", "StopInstances"}
    result = processor._process_single_event(SAMPLE_EVENT_VALID, unauthorized_api_calls)
    # Verify the result is a dictionary with expected keys
    assert isinstance(result, dict)
    assert result['EventName'] == "PutObject"
    assert result['Username'] == "testuser"
    # Verify that JSON parsing succeeded for CloudTrailEvent
    assert isinstance(result['CloudTrailEvent'], dict)

def test_process_single_event_invalid_json(processor):
    """Test that an event with invalid JSON in 'CloudTrailEvent' is handled gracefully."""
    unauthorized_api_calls = set()
    result = processor._process_single_event(SAMPLE_EVENT_INVALID_JSON, unauthorized_api_calls)
    # When JSON decoding fails, the code should set 'CloudTrailEvent' to an empty dict
    assert result['CloudTrailEvent'] == {}

def test_preprocess_logs_empty(processor):
    """Test that passing an empty events list returns two empty DataFrames."""
    unauthorized_api_calls = set()
    process_df, original_df = processor.preprocess_logs([], unauthorized_api_calls)
    assert process_df.empty and original_df.empty

def test_preprocess_logs_structure(processor):
    """Test that preprocessing a set of events produces a DataFrame with expected features."""
    unauthorized_api_calls = {"DeleteBucket", "StopInstances"}
    events = [SAMPLE_EVENT_VALID, SAMPLE_EVENT_LOGIN_FAIL]
    process_df, original_df = processor.preprocess_logs(events, unauthorized_api_calls)
    
    # Verify that the original DataFrame includes key fields.
    for col in ['EventName', 'Username', 'EventTime', 'Resources']:
        assert col in original_df.columns
    
    # Verify that temporal features are created.
    for col in ['Hour', 'DayOfWeek', 'DayOfMonth']:
        assert col in original_df.columns

    # Check that frequency features exist and are not NaN.
    for feature in ['EventFrequency', 'UserEventFrequency', 'IPEventFrequency']:
        assert feature in original_df.columns
        assert original_df[feature].notna().all()

def test_prepare_for_ml_drops_resources(processor):
    """Test that _prepare_for_ml removes unnecessary columns (e.g., 'Resources')."""
    unauthorized_api_calls = {"DeleteBucket", "StopInstances"}
    events = [SAMPLE_EVENT_VALID]
    process_df, original_df = processor.preprocess_logs(events, unauthorized_api_calls)
    
    # Verify the ML-friendly DataFrame does not include the 'Resources' column.
    assert 'Resources' not in process_df.columns
