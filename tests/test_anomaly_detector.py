import numpy as np
import pandas as pd
import pytest
import warnings
warnings.filterwarnings("ignore", message="One or more of the test scores are non-finite: [nan nan nan nan nan nan nan nan]")
import sys
import os
# Insert the parent directory (project root) into the system path.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from services.anomaly_detector import AnomalyDetector

# Create a small synthetic dataset to simulate ML-friendly processed data.
# For simplicity, assume that the processed DataFrame has two feature columns.
@pytest.fixture
def sample_data():
    # Construct a DataFrame with two features (f1, f2).
    # Normal points (centered around 0) and one outlier.
    data = [
        {"f1": 0.1, "f2": -0.2},  # normal
        {"f1": -0.1, "f2": 0.2},  # normal
        {"f1": 5.0, "f2": 5.0}     # outlier (anomaly)
    ]
    return pd.DataFrame(data)

def test_empty_dataframe_returns_none():
    """Test that an empty DataFrame returns (None, None)."""
    ad = AnomalyDetector()
    empty_df = pd.DataFrame()
    original_df = pd.DataFrame()
    anomaly_indices, anomaly_events = ad.detect_anomalies(empty_df, original_df)
    assert anomaly_indices is None, "Expected None for anomaly indices with empty input"
    assert anomaly_events is None, "Expected None for anomaly events with empty input"

def test_detect_anomalies_on_sample_data(sample_data):
    """
    Test that the anomaly detector processes a small synthetic dataset and returns
    anomaly indices that are valid indexes of the original data.
    """
    # Instantiate AnomalyDetector with auto contamination.
    ad = AnomalyDetector(contamination="auto", n_estimators=100)
    # Use the sample_data as both the ML-friendly DataFrame (process_df) and the original data.
    anomaly_indices, anomaly_events = ad.detect_anomalies(sample_data, sample_data)
    
    # Check that the anomaly indices are returned as a NumPy array.
    assert isinstance(anomaly_indices, np.ndarray), "Anomaly indices should be a NumPy array"
    
    # Ensure that the indexes in anomaly_events (if any) are valid based on sample_data index.
    if anomaly_events is not None and not anomaly_events.empty:
        assert anomaly_events.index.isin(range(len(sample_data))).all(), "Anomaly indexes must be within the original data range"
    
    # Since the synthetic data includes an outlier, we expect at least one anomaly to be detected.
    assert len(anomaly_indices) >= 1, "At least one anomaly should be detected in the synthetic dataset"

def test_tree_to_json_returns_valid_structure(sample_data):
    """
    Test the tree_to_json functionality to ensure that it returns a well-structured JSON.
    This method requires that the anomaly detector is trained and then converted to JSON.
    """
    ad = AnomalyDetector(contamination="auto", n_estimators=100)
    # Train the model on our sample data.
    anomaly_indices, anomaly_events = ad.detect_anomalies(sample_data, sample_data)
    # Convert the first tree to JSON.
    tree_json = ad.tree_to_json(0)
    
    # Check that the result is a dictionary and contains a node_id key.
    assert isinstance(tree_json, dict), "Tree JSON output should be a dictionary"
    assert "node_id" in tree_json, "Tree JSON should contain a 'node_id' key"
