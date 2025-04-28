import numpy as np
np.seterr(invalid='ignore')
import warnings
warnings.filterwarnings("ignore")
import pandas as pd
import pytest
from services.risk_analyzer import RiskAnalyzer

# Fixture to initialize RiskAnalyzer and override compliance checks
@pytest.fixture
def risk_analyzer(monkeypatch):
    ra = RiskAnalyzer()
    # Override compliance_checker.check_all_compliance to always return an empty list
    monkeypatch.setattr(ra.compliance_checker, "check_all_compliance", lambda event: [])
    return ra

def test_generate_risk_exposure_report(monkeypatch, risk_analyzer):
    # Create a DataFrame with predetermined risk scores.
    df = pd.DataFrame({
        "RiskScore": [10, 30]
    })

    # Monkey-patch generate_risk_scores to simply return the input df
    monkeypatch.setattr(risk_analyzer, "generate_risk_scores", lambda x: x)
    
    # Use a risk threshold of 20. With our two events:
    # - 10 is below the threshold, so it remains unchanged.
    # - 30 is above the threshold, so it gets scaled by 0.6 to become 18.
    # Therefore, total risk before = 10 + 30 = 40, and total risk after = 10 + 18 = 28.
    report = risk_analyzer.generate_risk_exposure_report(df, risk_threshold=20)

    # Expected total events = 2
    assert report["total_events"] == 2, "Total events should be 2."
    
    # Expected risk before = 10 + 30 = 40
    assert report["totalRiskBefore"] == 40, "Total risk before should equal 40."
    
    # Expected risk after = 10 + 18 = 28
    assert report["totalRiskAfter"] == 28, "Total risk after should equal 28."
    
    # Average risk before = 40 / 2 = 20, average risk after = 28 / 2 = 14
    assert report["averageRiskBefore"] == 20, "Average risk before should be 20."
    assert report["averageRiskAfter"] == 14, "Average risk after should be 14."
    
    # High risk: Only the event with risk 30 is above threshold initially (50% high risk).
    # After mitigation, 18 is below the threshold, so 0% high risk.
    assert report["highRiskPercentageBefore"] == 50.0, "High risk percentage before should be 50%."
    assert report["highRiskPercentageAfter"] == 0.0, "High risk percentage after should be 0%."
    
    # Risk reduction percentage = 50% - 0% = 50%
    assert report["riskReductionPercentage"] == 50.0, "Risk reduction percentage should be 50%."
