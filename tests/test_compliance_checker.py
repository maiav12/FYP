import json
import pytest
from datetime import datetime
from services.compliance_checker import ComplianceChecker

# --- Define Dummy Classes for Testing Purposes ---
class DummyGDPRRequirements:
    def __init__(self):
        # For testing, we define two GDPR requirements.
        self.requirements = {
            "data_encryption": "Require encryption on data at rest or in transit.",
            "access_control": "Enforce access control with a valid username."
        }

class DummyNIS2Requirements:
    def __init__(self):
        # For testing, we define one NIS2 requirement.
        self.requirements = {
            "incident_reporting": "Incidents must be properly reported."
        }

# --- Pytest Fixture for ComplianceChecker ---
@pytest.fixture
def compliance_checker(monkeypatch):
    # Replace the GDPRRequirements and NIS2Requirements in the module with our dummy ones.
    monkeypatch.setattr("services.compliance_checker.GDPRRequirements", DummyGDPRRequirements)
    monkeypatch.setattr("services.compliance_checker.NIS2Requirements", DummyNIS2Requirements)
    return ComplianceChecker()

# --- Test that rules load correctly ---
def test_load_rules(compliance_checker):
    rules = compliance_checker.rules
    # We expect three rules based on our dummy requirements:
    #   - "data_encryption" (GDPR)
    #   - "access_control" (GDPR)
    #   - "incident_reporting" (NIS2)
    assert isinstance(rules, list), "Rules should be stored in a list."
    keys = [rule["key"] for rule in rules]
    assert "data_encryption" in keys, "Expected 'data_encryption' rule to be loaded."
    assert "access_control" in keys, "Expected 'access_control' rule to be loaded."
    assert "incident_reporting" in keys, "Expected 'incident_reporting' rule to be loaded."

# --- Test individual compliance checks ---

def test_check_data_encryption_violation(compliance_checker):
    # Create an event where encryption is not enforced.
    event = {
        "CloudTrailEvent": {"requestParameters": {"encrypted": False}},
        "Username": "testuser"
    }
    violations = compliance_checker.check_all_compliance(event)
    # Expect at least one violation for data encryption.
    data_encryption_violations = [v for v in violations if v["ruleId"] == "data_encryption"]
    assert len(data_encryption_violations) > 0, "Should detect a data encryption violation."

def test_check_access_control_violation(compliance_checker):
    # Create an event with an empty Username, triggering an access control violation.
    event = {
        "CloudTrailEvent": {"requestParameters": {"encrypted": True}},
        "Username": ""
    }
    violations = compliance_checker.check_all_compliance(event)
    access_control_violations = [v for v in violations if v["ruleId"] == "access_control"]
    assert len(access_control_violations) > 0, "Should detect an access control violation."

def test_check_incident_reporting_violation(compliance_checker):
    # Create an event indicating an incident occurred but was not reported.
    event = {
        "SecurityIncident": True,
        "IncidentReported": False,
        "Username": "securityAdmin"
    }
    violations = compliance_checker.check_all_compliance(event)
    incident_reporting_violations = [v for v in violations if v["ruleId"] == "incident_reporting"]
    assert len(incident_reporting_violations) > 0, "Should detect an incident reporting violation."

# --- Test overall compliance assessment on a list of events ---
def test_get_compliance_assessment_for_events(compliance_checker):
    # Create two events: one violating rules and one compliant.
    event1 = {
        "CloudTrailEvent": json.dumps({"requestParameters": {"encrypted": False}}),
        "EventName": "TestEvent",
        "Username": ""  # Violates access_control as well.
    }
    event2 = {
        "CloudTrailEvent": json.dumps({"requestParameters": {"encrypted": True}}),
        "EventName": "TestEvent",
        "Username": "user1"  # Compliant.
    }
    events = [event1, event2]
    assessment = compliance_checker.get_compliance_assessment_for_events(events)
    # With our dummy requirements (2 GDPR + 1 NIS2 = 3 total), event1 will trigger 2 violations,
    # while event2 will be compliant. So total violations = 2, giving a compliance score of:
    # ((3 - 2) / 3) * 100 ≈ 33.33
    assert "score" in assessment, "Assessment should include a 'score'."
    assert isinstance(assessment["score"], float), "Score should be a float."
    assert "violations" in assessment, "Assessment should include a 'violations' list."

