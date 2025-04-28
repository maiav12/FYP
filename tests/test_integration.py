import json
import pytest
import warnings
warnings.filterwarnings("ignore")

from app import app  # Ensure your Flask app instance is correctly imported from app.py

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_run_analysis_start_endpoint(client):
    """
    Test the /run_analysis_start endpoint:
    - Verify the endpoint returns a 200 status code.
    - Confirm that the response contains a simple confirmation message.
    """
    response = client.post("/run_analysis_start")
    data = json.loads(response.data)
    
    assert response.status_code == 200, "Expected status code 200"
    # Since the current endpoint returns only a message, check for 'message'
    assert "message" in data, "Response should include 'message'"
    assert data["message"] == "Analysis started", "Expected message 'Analysis started'"

def test_full_integration_flow(client):
    """
    End-to-end test for initiating the analysis process.
    Since the analysis is executed asynchronously in a separate thread,
    this test will verify that the endpoint initiates the process correctly.
    """
    response_run = client.post("/run_analysis_start")
    data_run = json.loads(response_run.data)
    
    assert response_run.status_code == 200, "Analysis endpoint should return status 200"
    # Verify that the response includes the confirmation message only.
    assert "message" in data_run, "Expected key 'message' in integration flow"
    assert data_run["message"] == "Analysis started", "Expected 'Analysis started' message"

    # Note:
    # For a full end-to-end test of the entire analysis workflow, you would typically need
    # to simulate waiting for the analysis to complete and then query endpoints such as /api/risk-report.
    # Since your current endpoint responds asynchronously with only a start message, further integration
    # tests might need to listen to the /analysis_progress stream or use another mechanism to capture full results.
