# services/compliance_checker.py

import json
from datetime import datetime
from datetime import timezone
from models.compliance import GDPRRequirements, NIS2Requirements

class ComplianceChecker:
    def __init__(self):
        self.gdpr = GDPRRequirements()
        self.nis2 = NIS2Requirements()

        # A list of rules your compliance checker will iterate over
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """
        Load or define all the GDPR and NIS2 rules you want to check.
        Each rule is a dict with:
          - 'regulation': e.g. 'GDPR' or 'NIS2'
          - 'key': A unique identifier (e.g. 'data_encryption')
          - 'message': Short explanation of violation
          - 'condition': A callable that returns True if the event violates the rule
        """
        # For example, if 'data_encryption' is in your GDPR requirements
        if "data_encryption" in self.gdpr.requirements:
            self.rules.append({
                "regulation": "GDPR",
                "key": "data_encryption",
                "message": "Data encryption is not enforced on data at rest or in transit.",
                "condition": lambda event: (
                    event.get("CloudTrailEvent", {})
                         .get("requestParameters", {})
                         .get("encrypted", True) is False
                )
            })

        # If 'access_control' is in GDPR
        if "access_control" in self.gdpr.requirements:
            self.rules.append({
                "regulation": "GDPR",
                "key": "access_control",
                "message": "Access control measures may be insufficient (missing username).",
                "condition": lambda event: not event.get("Username")
            })

        # If 'incident_reporting' is in NIS2
        if "incident_reporting" in self.nis2.requirements:
            self.rules.append({
                "regulation": "NIS2",
                "key": "incident_reporting",
                "message": "Incident was not properly reported per NIS2 guidelines.",
                "condition": lambda event: (
                    event.get("SecurityIncident") is True
                    and not event.get("IncidentReported")
                )
            })

        # ...Add more for the other GDPR/NIS2 keys you want to enforce

    def check_all_compliance(self, event_dict):
        """
        Checks a single event (dict) against all the loaded rules.
        Returns a list of violations found.
        """
        violations = []
        for rule in self.rules:
            if rule["condition"](event_dict):
                violations.append({
                    "regulation": rule["regulation"],
                    "ruleId": rule["key"],
                    "message": rule["message"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        return violations

    def get_compliance_assessment_for_events(self, events):
        """
        Checks a list of events for any rule violations, then computes a
        compliance score EXACTLY like your original code did:
          score = ((total_requirements - violated_count) / total_requirements) * 100
        """
        # 1) Collect all violations from all events
        all_violations = []
        for evt in events:
            # If the CloudTrailEvent is a JSON string, parse it
            if isinstance(evt.get("CloudTrailEvent"), str):
                try:
                    evt["CloudTrailEvent"] = json.loads(evt["CloudTrailEvent"])
                except json.JSONDecodeError:
                    evt["CloudTrailEvent"] = {}

            # Check compliance for this single event
            violations = self.check_all_compliance(evt)
            if violations:
                all_violations.extend(violations)

        # 2) Same formula as your old code
        #    total_requirements = number of GDPR + NIS2 items
        total_requirements = len(self.gdpr.requirements) + len(self.nis2.requirements)
        violated_count = len(all_violations)  # total number of found violations

        if total_requirements > 0:
            score = ((total_requirements - violated_count) / total_requirements) * 100
        else:
            score = 100  # If no rules at all, assume 100% compliance by default

        return {
            "score": round(score, 2),
            "violations": all_violations
        }

    def get_all_requirements(self):
        """
        (Optional) If your /api/compliance/standards endpoint needs a dictionary of
        textual requirements for the UI, you can return them here.
        """
        return {
            "GDPR": self.gdpr.requirements,
            "NIS2": self.nis2.requirements
        }
