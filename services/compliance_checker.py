import json
import boto3
from models.compliance import GDPRRequirements, NIS2Requirements

class ComplianceChecker:
    def __init__(self):
        self.gdpr = GDPRRequirements()
        self.nis2 = NIS2Requirements()
        self.s3 = boto3.client('s3')

    def check_gdpr_compliance(self, event):
        violations = []
        
        if not event.get('encrypted', False):
            violations.append(self.gdpr.requirements['data_encryption'])
        
        if event.get('Username') == 'Unknown':
            violations.append(self.gdpr.requirements['access_control'])
        
        if event.get('EventName') in ["LaunchInstance", "TerminateInstances"] \
           and len(event.get('CloudTrailEvent', {}).get('data', [])) > 5:
            violations.append(self.gdpr.requirements['data_minimization'])

        if event.get('DataBreachDetected', False):
            violations.append(self.gdpr.requirements['breach_notifications'])
        
        if not event.get('ConsentGiven', True):
            violations.append(self.gdpr.requirements['consent_management'])

        if event.get('DataRetentionPeriod') and event.get('DataRetentionPeriod') > 365:
            violations.append(self.gdpr.requirements['data_retention'])
        
        if 'audit_failure' in event.get('AuditLog', {}):
            violations.append(self.gdpr.requirements['audit_trail'])
        
        if event.get('DataSubjectRequest') == 'Denied':
            violations.append(self.gdpr.requirements['data_subject_rights'])

        return violations

    def check_nis2_compliance(self, event):
        violations = []
        
        # If event is StopInstances, DeleteBucket, or ModifyNetworkAcl => incident_reporting
        # But skip DeleteBucket if there's already a Deny policy in place
        if event.get('EventName') in ["StopInstances", "DeleteBucket", "ModifyNetworkAcl"]:
            if event['EventName'] == "DeleteBucket":
                # Only add violation if there's NO deny policy yet
                if not self._has_deny_deletebucket(event):
                    violations.append(self.nis2.requirements['incident_reporting'])
            else:
                # For StopInstances/ModifyNetworkAcl, do the original logic
                violations.append(self.nis2.requirements['incident_reporting'])
        
        # If event is LaunchInstance or StopInstances with 'critical_vuln' => vulnerability_management
        if event.get('EventName') in ["LaunchInstance", "StopInstances"] \
           and 'critical_vuln' in event.get('CloudTrailEvent', {}):
            violations.append(self.nis2.requirements['vulnerability_management'])
        
        if event.get('CriticalResourceAccessed', False):
            violations.append(self.nis2.requirements['critical_infra_protection'])
        
        if not event.get('FirewallEnabled', False):
            violations.append(self.nis2.requirements['network_security'])
        
        if not event.get('BCPTested', False):
            violations.append(self.nis2.requirements['business_continuity_planning'])
        
        if 'unauthorized_access' in event.get('AccessLog', {}):
            violations.append(self.nis2.requirements['access_management'])
        
        # if event.get('SupplierRisk') > 70:
        #     violations.append(self.nis2.requirements['supplier_management'])
        
        if not event.get('MonitoringEnabled', False):
            violations.append(self.nis2.requirements['monitoring_and_detection'])

        return violations

    def check_all_compliance(self, event):
        violations = []
        violations.extend(self.check_gdpr_compliance(event))
        violations.extend(self.check_nis2_compliance(event))
        return violations
    
    # ---------------- HELPER METHOD ----------------
    def _has_deny_deletebucket(self, event):
        """
        Returns True if the bucket in this DeleteBucket event already has a Deny s3:DeleteBucket policy.
        Otherwise, returns False.
        """
        # Extract the bucket name from event
        resources = event.get('Resources', {})
        bucket_name = resources.get('S3BucketName')
        if not bucket_name:
            return False  # No bucket => can't have a Deny policy

        try:
            policy_str = self.s3.get_bucket_policy(Bucket=bucket_name)['Policy']
            policy = json.loads(policy_str)
        except self.s3.exceptions.NoSuchBucketPolicy:
            # No existing policy => definitely no Deny statement
            return False
        except self.s3.exceptions.ClientError:
            # If any other error (e.g., no such bucket), treat as not having a Deny
            return False

        # Check if any statement is "Effect": "Deny" with "Action": "s3:DeleteBucket"
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                # 'Action' can be a string or a list
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "s3:DeleteBucket" in actions:
                    return True

        return False
