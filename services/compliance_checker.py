import json
import boto3
from models.compliance import GDPRRequirements, NIS2Requirements

def parse_cloudtrail_event(event):
    """
    Ensures that the CloudTrailEvent is a dictionary.
    If it's a JSON string, parse it; if it's already a dict, return as is.
    Otherwise, return an empty dict.
    """
    cte = event.get('CloudTrailEvent', {})
    if isinstance(cte, str):
        try:
            return json.loads(cte)
        except Exception as e:
            print("Error parsing CloudTrailEvent:", e)
            return {}
    elif isinstance(cte, dict):
        return cte
    return {}

class ComplianceRule:
    def __init__(self, regulation, key, message, severity, condition):
        """
        regulation: e.g., "GDPR" or "NIS2".
        key: Unique rule identifier.
        message: Descriptive violation message.
        severity: e.g., "High", "Medium", "Low".
        condition: A callable that accepts an event and returns True if violation exists.
        """
        self.regulation = regulation
        self.key = key
        self.message = message
        self.severity = severity
        self.condition = condition

    def check(self, event):
        if self.condition(event):
            return {
                "regulation": self.regulation,
                "rule": self.key,
                "message": self.message,
                "severity": self.severity
            }
        return None

class ComplianceChecker:
    def __init__(self):
        self.gdpr = GDPRRequirements().requirements
        self.nis2 = NIS2Requirements().requirements
        self.s3 = boto3.client('s3')
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        # GDPR Rules
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="data_encryption",
            message=self.gdpr.get('data_encryption', "Data must be encrypted at rest and in transit."),
            severity="High",
            condition=lambda event: event.get('encrypted') is False
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="access_control",
            message=self.gdpr.get('access_control', "Access control measures must be implemented."),
            severity="Medium",
            condition=lambda event: event.get('Username', '').strip() in ["", "Unknown"]
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="data_minimization",
            message=self.gdpr.get('data_minimization', "Data minimization should be observed."),
            severity="Low",
            condition=lambda event: (
                event.get('EventName') in ["LaunchInstance", "TerminateInstances"] and
                len(parse_cloudtrail_event(event).get('data', [])) > 5
            )
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="breach_notifications",
            message=self.gdpr.get('breach_notifications', "Breach notifications must be issued."),
            severity="High",
            condition=lambda event: event.get('DataBreachDetected', False) is True
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="consent_management",
            message=self.gdpr.get('consent_management', "Consent must be obtained."),
            severity="Medium",
            condition=lambda event: event.get('ConsentGiven') is False
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="data_retention",
            message=self.gdpr.get('data_retention', "Data retention period should not exceed 365 days."),
            severity="Low",
            condition=lambda event: (event.get('DataRetentionPeriod') is not None and event.get('DataRetentionPeriod') > 365)
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="audit_trail",
            message=self.gdpr.get('audit_trail', "Audit logs must be maintained."),
            severity="Medium",
            condition=lambda event: 'audit_failure' in event.get('AuditLog', {})
        ))
        self.rules.append(ComplianceRule(
            regulation="GDPR",
            key="data_subject_rights",
            message=self.gdpr.get('data_subject_rights', "Data subject requests must be honored."),
            severity="High",
            condition=lambda event: event.get('DataSubjectRequest') == 'Denied'
        ))
        # NIS2 Rules
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="incident_reporting",
            message=self.nis2.get('incident_reporting', "Incident reporting is required."),
            severity="High",
            condition=lambda event: (
                event.get('EventName') in ["StopInstances", "DeleteBucket", "ModifyNetworkAcl"] and
                (event.get('EventName') != "DeleteBucket" or not self._has_deny_deletebucket(event))
            )
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="vulnerability_management",
            message=self.nis2.get('vulnerability_management', "Vulnerability management must be enforced."),
            severity="High",
            condition=lambda event: (
                event.get('EventName') in ["LaunchInstance", "StopInstances"] and
                'critical_vuln' in parse_cloudtrail_event(event)
            )
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="critical_infra_protection",
            message=self.nis2.get('critical_infra_protection', "Critical infrastructure must be protected."),
            severity="High",
            condition=lambda event: event.get('CriticalResourceAccessed', False)
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="network_security",
            message=self.nis2.get('network_security', "Firewall and network security must be enabled."),
            severity="Medium",
            condition=lambda event: not event.get('FirewallEnabled', False)
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="business_continuity_planning",
            message=self.nis2.get('business_continuity_planning', "Business continuity plans must be tested."),
            severity="Medium",
            condition=lambda event: not event.get('BCPTested', False)
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="access_management",
            message=self.nis2.get('access_management', "Unauthorized access must be prevented."),
            severity="High",
            condition=lambda event: 'unauthorized_access' in event.get('AccessLog', {})
        ))
        self.rules.append(ComplianceRule(
            regulation="NIS2",
            key="monitoring_and_detection",
            message=self.nis2.get('monitoring_and_detection', "Monitoring must be enabled."),
            severity="Medium",
            condition=lambda event: not event.get('MonitoringEnabled', False)
        ))

    def _has_deny_deletebucket(self, event):
        resources = event.get('Resources', {})
        bucket_name = resources.get('S3BucketName')
        if not bucket_name:
            return False
        try:
            policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get('Policy', '{}')
            policy = json.loads(policy_str)
        except self.s3.exceptions.NoSuchBucketPolicy:
            return False
        except self.s3.exceptions.ClientError:
            return False

        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "s3:DeleteBucket" in actions:
                    return True
        return False

    def check_all_compliance(self, event):
        """Check an event against all compliance rules and return a list of violations."""
        violations = []
        for rule in self.rules:
            result = rule.check(event)
            if result:
                violations.append(result)
        return violations
