
import io
import os
import warnings
from statsmodels.tsa.arima.model import ARIMA
import statsmodels.tsa.api as smt
import numpy as np
import matplotlib.pyplot as plt
import boto3
import json
from datetime import datetime


import pandas as pd
from anomaly_saver import save_anomalies_to_dynamodb
from services.data_processor import DataProcessor
from services.anomaly_detector import AnomalyDetector
from services.risk_analyzer import RiskAnalyzer
from services.compliance_checker import ComplianceChecker
sns = boto3.client('sns')
topic_arn = 'arn:aws:sns:eu-north-1:699475953257:cloudtrail-alerts'

class RiskForecaster:
    def __init__(self):
        self.model = None

    def train_model(self, risk_scores):
        """Train an ARIMA model on historical risk scores."""
        try:
            # Convert risk scores to a Pandas Series
            risk_series = pd.Series(risk_scores)

            # Train ARIMA model (p=2, d=1, q=2)
            self.model = ARIMA(risk_series, order=(2, 1, 2))
            self.model = self.model.fit()

            print("ARIMA model trained successfully!")

        except Exception as e:
            print(f"Error training ARIMA model: {e}")

    def predict_future_risk(self, steps=10):
        """Predict future risk scores using the trained ARIMA model."""
        if self.model is None:
            print("No trained model found. Please train the model first.")
            return None

        try:
            # Forecast future risk scores
            forecast = self.model.forecast(steps=steps)
            return forecast

        except Exception as e:
            print(f"Error predicting future risk: {e}")
            return None

    # def visualize_risk_trend(self, past_risk_scores, future_risk_scores):
    #     """Plot historical risk scores and overlay predicted risk scores."""
    #     try:
    #         # Create time indexes
    #         past_time = np.arange(len(past_risk_scores))
    #         future_time = np.arange(len(past_risk_scores), len(past_risk_scores) + len(future_risk_scores))

    #         # Plot historical risk scores
    #         plt.figure(figsize=(10, 5))
    #         plt.plot(past_time, past_risk_scores, label="Historical Risk Score", marker='o')

    #         # Plot predicted future risk scores
    #         plt.plot(future_time, future_risk_scores, label="Predicted Risk Score", linestyle="dashed", marker='x')

    #         # Highlight high-risk threshold (e.g., risk > 40)
    #         plt.axhline(y=40, color="red", linestyle="--", label="High-Risk Threshold")

    #         # Labels and legend
    #         plt.xlabel("Time")
    #         plt.ylabel("Risk Score")
    #         plt.title("Risk Score Trend (Historical vs. Predicted)")
    #         plt.legend()
    #         plt.grid()

    #         # Show plot
    #         plt.show()

    #     except Exception as e:
    #         print(f"Error visualizing risk trend: {e}")

class CloudTrailAnalyzer:
    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail')
        self.unauthorized_api_calls = {"DeleteBucket", "StopInstances", "DetachPolicy"}
        self.data_processor = DataProcessor()
        self.anomaly_detector = AnomalyDetector()
        self.risk_analyzer = RiskAnalyzer()
        self.compliance_checker = ComplianceChecker()
        self.risk_forecaster = RiskForecaster()  
        self.mitigated_anomalies = set()
        self.mitigation_actions = {
     'CreateBucket': self.notify_admin_bucket_creation,
      'StopInstances': self.restrict_stop_instances_permission,
    'AuthorizeSecurityGroupIngress': self.restrict_security_group_ingress_permission,

    'PutObject': self.block_s3_upload,
     'StartInstances': self.stop_unauthorized_instance,
     'DescribeInstances': self.restrict_describe_instances_permission,
     'AttachVolume': self.restrict_attach_volume_permission,
     'DetachVolume': self.restrict_detach_volume_permission,
     'DeleteBucket': self.prevent_bucket_deletion,
     'GetObject': self.prevent_object_access,
     'ListBuckets': self.limit_bucket_listing_permissions,
}
        self.mitigation_log = []




    def notify_admin(self, message, subject="CloudTrail Anomaly Detected"):
        try:
          response = sns.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject
            )
          print("Notification sent. Response:", response)
      
        except Exception as e: print(f"Failed to send notification: {e}")

    def collect_logs(self):
     
     """Collect CloudTrail logs from AWS."""
     try:
        response = self.cloudtrail.lookup_events(
            MaxResults=50
        )
        events = response.get('Events', [])
        return events
     except Exception as e:
        error_message = f"Failed to collect CloudTrail logs: {e}"
        print(error_message)
        self.notify_admin(message=error_message, subject="Log Collection Failure")
        return []

 
    def mitigate_anomalies(self, anomalies):
     for _, anomaly in anomalies.iterrows():
        # Convert anomaly to JSON-serializable dictionary
        anomaly_dict = anomaly.to_dict()
        anomaly_dict = {k: (v.isoformat() if isinstance(v, pd.Timestamp) else v) for k, v in anomaly_dict.items()}
        
        anomaly_id = hash(json.dumps(anomaly_dict, sort_keys=True))
        if anomaly_id in self.mitigated_anomalies:
            print(f"Anomaly {anomaly_id} already mitigated. Skipping.")
            # No email on second pass
            continue

        self.mitigated_anomalies.add(anomaly_id)
        event_name = anomaly['EventName']
        mitigation_handler = self.mitigation_actions.get(event_name)
        if event_name == "CreateBucket":
            # Special case: we only want a minimal email with "Bucket X was created by user Y."
            action_result = mitigation_handler(anomaly)  # notify_admin_bucket_creation
            # This method can call `self.notify_admin` itself or simply return the string
            # Then we skip the standard "before/after" email
            # Mark anomaly as mitigated
            self.mitigated_anomalies.add(anomaly_id)
            continue
        if mitigation_handler:
            try:
                # Log the state before mitigation
                before_state = self.get_resource_state(anomaly)
                print(f"Before mitigation: {before_state}")

                # Execute the mitigation action AND CAPTURE THE RESULT
                print(f"Mitigating anomaly: {event_name}")
                action_result = mitigation_handler(anomaly)  # <-- capture the returned string

                # Log the state after mitigation
                after_state = self.get_resource_state(anomaly)
                print(f"After mitigation: {after_state}")

                # Record mitigation details
                self.mitigation_log.append({
                    'EventName': event_name,
                    'AnomalyDetails': anomaly_dict,
                    'BeforeState': before_state,
                    'AfterState': after_state,
                    'ActionResult': action_result,
                    'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })

                # Include the 'action_result' in the email
                self.notify_admin(
                    message=(
                        f"Mitigation action executed for anomaly: {event_name}.\n"
                        f"{action_result}\n"            # <--- inserted here
                        f"Before: {before_state}\n"
                        f"After: {after_state}"
                    ),
                    subject="Anomaly Mitigation Report"
                )
            except Exception as e:
                print(f"Failed to mitigate anomaly {event_name}: {e}")
                self.notify_admin(
                    message=f"Failed to mitigate anomaly: {event_name}. Error: {e}",
                    subject="Mitigation Failure"
                )
        else:
            print(f"No predefined action for anomaly: {event_name}. Tagging for manual review.")
            # self.tag_anomaly_for_review(anomaly)
            # self.notify_admin(
                # message=f"Anomaly detected with no predefined action: {event_name}. Tagged for review.",
                # subject="Manual Review Required"
            # )



    def get_resource_state(self, anomaly):
  
     try:
        event_name = anomaly['EventName']
        resource = anomaly.get('Resources', {})

        # if event_name == "DescribeInstances":

        #     ec2 = boto3.client('ec2')
        #     instance_id = resource.get('EC2InstanceId')
        #     if instance_id:
        #         response = ec2.describe_instances(InstanceIds=[instance_id])
        #         return response.get('Reservations', [{}])[0].get('Instances', [{}])[0]
        #     else:
        #         return "No EC2 instance ID provided in the anomaly resources."
    
        if event_name in ["DeleteBucket"]:
            bucket_name = resource.get('S3BucketName')
            if bucket_name:
                s3 = boto3.client('s3')
                try:
                    # 1) Check if the bucket exists
                    s3.head_bucket(Bucket=bucket_name)
                    bucket_exists = True
                except s3.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == '404':
                        bucket_exists = False
                    else:
                        return f"Error checking bucket {bucket_name}: {e}"

                # If bucket doesn't exist, we can just note that
                if not bucket_exists:
                    return f"Bucket {bucket_name} does not exist."

                # 2) Check the bucket's policy
                try:
                    response = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_str = response.get('Policy', '{}')
                    policy = json.loads(policy_str)
                except s3.exceptions.from_code('NoSuchBucketPolicy'):
                    # If there's no policy at all, just note it
                    policy = {"Statement": []}
                except s3.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        policy = {"Statement": []}
                    else:
                        return f"Error fetching policy for bucket {bucket_name}: {e}"

                # 3) Determine if there's a Deny rule for s3:DeleteBucket
                has_deny_delete = False
                for stmt in policy.get('Statement', []):
                    # 'Action' could be a string or a list. Convert to list for easy check.
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]

                    # Check if Effect is 'Deny' and 's3:DeleteBucket' in the Action list
                    if (stmt.get('Effect') == 'Deny'
                        and 's3:DeleteBucket' in actions):
                        has_deny_delete = True
                        break

                if has_deny_delete:
                    return f"Bucket {bucket_name} exists with a Deny policy on DeleteBucket."
                else:
                    return f"Bucket {bucket_name} exists with no Deny policy on DeleteBucket."

            else:
                return "No S3 bucket name provided in the anomaly resources."
            
        elif event_name == "AuthorizeSecurityGroupIngress":
            security_group_id = resource.get("SecurityGroupId")
            if not security_group_id:
                return "No Security Group ID provided in the anomaly resources."

            ec2 = boto3.client("ec2")
            try:
             #  Check if the Security Group exists
                response = ec2.describe_security_groups(GroupIds=[security_group_id])
                security_group_exists = bool(response["SecurityGroups"])
            except ec2.exceptions.ClientError as e:
                if "InvalidGroup.NotFound" in str(e):
                    return f"Security Group {security_group_id} does not exist."
                return f"Error checking Security Group {security_group_id}: {e}"

            if not security_group_exists:
                return f"Security Group {security_group_id} does not exist."

            # Check if an unauthorized rule exists
            security_group = response["SecurityGroups"][0]
            ingress_rules = security_group.get("IpPermissions", [])

            unauthorized_rules = [
                rule for rule in ingress_rules if any(
                ip_range.get("CidrIp") == "0.0.0.0/0" for ip_range in rule.get("IpRanges", [])
             )
            ]

            if unauthorized_rules:
                return f"Security Group {security_group_id} exists with unauthorized ingress rules."

            return f"Security Group {security_group_id} exists with no unauthorized ingress rules."

        elif event_name == "AttachVolume":
            volume_id = resource.get("EBSVolumeId")
            if not volume_id:
                return "No EBS volume ID provided in the anomaly resources."

            ec2 = boto3.client("ec2")
            try:
               
                response = ec2.describe_volumes(VolumeIds=[volume_id])
                volume_exists = bool(response["Volumes"])
            except ec2.exceptions.ClientError as e:
                if "InvalidVolume.NotFound" in str(e):
                    return f"EBS Volume {volume_id} does not exist."
                return f"Error checking EBS volume {volume_id}: {e}"

            if not volume_exists:
                return f"EBS Volume {volume_id} does not exist."

      
            iam = boto3.client("iam")
            user_name = resource.get("UserName")
            if user_name:
                try:
                    policies = iam.list_user_policies(UserName=user_name)
                    if "RestrictAttachVolume" in policies.get("PolicyNames", []):
                        return f"EBS Volume {volume_id} exists, but AttachVolume is restricted for user {user_name}."
                except iam.exceptions.NoSuchEntityException:
                    return f"EBS Volume {volume_id} exists, but user {user_name} has no IAM policies."

            return f"EBS Volume {volume_id} exists with no restrictions on AttachVolume."
    
        elif event_name == "DescribeInstances":
            instance_id = resource.get('EC2InstanceId')

            if not instance_id:
                return "No EC2 instance ID provided in the anomaly resources for DescribeInstances."

            ec2 = boto3.client('ec2')

            try:
                # Describe the instance from AWS
                response = ec2.describe_instances(InstanceIds=[instance_id])

                # Extract instance details
                reservations = response.get('Reservations', [])
                if not reservations:
                    return f"Instance {instance_id} does not exist or is terminated."

                instance_details = reservations[0].get('Instances', [{}])[0]
                instance_state = instance_details.get('State', {}).get('Name', 'Unknown')
                instance_type = instance_details.get('InstanceType', 'Unknown')
                launch_time = instance_details.get('LaunchTime', 'Unknown')
                availability_zone = instance_details.get('Placement', {}).get('AvailabilityZone', 'Unknown')

                # Summarized response
                return (
                    f"Instance {instance_id} is in {instance_state} state.\n"
                    f"Type: {instance_type}, Launched: {launch_time}, AZ: {availability_zone}"
                )

            except ec2.exceptions.ClientError as e:
                if "InvalidInstanceID.NotFound" in str(e):
                    return f"Instance {instance_id} does not exist."
                else:
                     return f"Error retrieving instance {instance_id}: {e}"

        elif event_name == "DetachVolume":
         volume_id = resource.get("EBSVolumeId")
         if not volume_id:
                return "No EBS volume ID provided in the anomaly resources."

         ec2 = boto3.client("ec2")
         try:
       
            response = ec2.describe_volumes(VolumeIds=[volume_id])
            volume_exists = bool(response["Volumes"])
            volume_state = response["Volumes"][0]["State"] if volume_exists else "Unknown"
         except ec2.exceptions.ClientError as e:
            if "InvalidVolume.NotFound" in str(e):
                return f"EBS Volume {volume_id} does not exist."
            return f"Error checking EBS volume {volume_id}: {e}"

         if not volume_exists:
            return f"EBS Volume {volume_id} does not exist."

    
         iam = boto3.client("iam")
         user_name = resource.get("UserName")
         if user_name:
            try:
                    policies = iam.list_user_policies(UserName=user_name)
                    if "RestrictDetachVolume" in policies.get("PolicyNames", []):
                        return f"EBS Volume {volume_id} exists in state '{volume_state}', but DetachVolume is restricted for user {user_name}."
            except iam.exceptions.NoSuchEntityException:
                return f"EBS Volume {volume_id} exists, but user {user_name} has no IAM policies."

            return f"EBS Volume {volume_id} exists in state '{volume_state}' with no restrictions on DetachVolume."

        elif event_name == "StopInstances":
            user_name = resource.get('UserName')
            if not user_name:
                return "No user name provided in the anomaly resources for StopInstances."

            iam = boto3.client('iam')
            policy_name = "RestrictStopInstances"

            try:
                # 1) Check if the user has an inline policy named 'RestrictStopInstances'
                existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
                if policy_name not in existing_policies:
                    # Means the user is not blocked from ec2:StopInstances
                    return f"User {user_name} is allowed to stop instances (no deny policy)."

                # 2) If the policy exists, fetch it
                response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_doc = response['PolicyDocument']

                # 3) Check if there's a Deny on ec2:StopInstances
                has_deny_stop = False
                for stmt in policy_doc.get('Statement', []):
                    if stmt.get('Effect') == 'Deny':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if "ec2:StopInstances" in actions:
                            has_deny_stop = True
                            break

                if has_deny_stop:
                    return f"User {user_name} has a Deny policy on ec2:StopInstances."
                else:
                    return f"User {user_name} has a policy but no Deny on ec2:StopInstances."

            except iam.exceptions.NoSuchEntityException:
                # The user or policy doesn't exist
                return f"User {user_name} not found or policy doesn't exist."
            except Exception as e:
                return f"Error fetching IAM policy for user {user_name}: {e}"

        elif event_name == "StartInstances":
            user_name = resource.get('UserName')
            if not user_name:
                return "No user name provided in the anomaly resources for StartInstances."

            iam = boto3.client('iam')
            policy_name = "RestrictStartInstances"

            try:
                # 1) Check if the user has an inline policy named 'RestrictStartInstances'
                existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
                if policy_name not in existing_policies:
                    # Means the user is not blocked from ec2:StartInstances
                    return f"User {user_name} is allowed to start instances (no deny policy)."

                # 2) If the policy exists, fetch it
                response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_doc = response['PolicyDocument']

                # 3) Check if there's a Deny on ec2:StartInstances
                has_deny_start = False
                for stmt in policy_doc.get('Statement', []):
                    if stmt.get('Effect') == 'Deny':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if "ec2:StartInstances" in actions:
                            has_deny_start = True
                            break

                if has_deny_start:
                    return f"User {user_name} has a Deny policy on ec2:StartInstances."
                else:
                    return f"User {user_name} has a policy but no Deny on ec2:StartInstances."

            except iam.exceptions.NoSuchEntityException:
                # The user or policy doesn't exist
                return f"User {user_name} not found in IAM or no policy."
            except Exception as e:
                return f"Error fetching IAM policy for user {user_name}: {e}"

        elif event_name == "PutObject":
            # -- The NEW block for PutObject --
            bucket_name = resource.get('S3BucketName')
            if not bucket_name:
                return "No S3 bucket name provided in the anomaly resources."

            s3 = boto3.client('s3')
            try:
                # 1) Check if the bucket exists
                s3.head_bucket(Bucket=bucket_name)
                bucket_exists = True
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == '404':
                    bucket_exists = False
                else:
                    return f"Error checking bucket {bucket_name}: {e}"

            if not bucket_exists:
                return f"Bucket {bucket_name} does not exist."

            # 2) Fetch the bucket's policy
            try:
                response = s3.get_bucket_policy(Bucket=bucket_name)
                policy_str = response.get('Policy', '{}')
                policy = json.loads(policy_str)
            except s3.exceptions.from_code('NoSuchBucketPolicy'):
                policy = {"Statement": []}
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    policy = {"Statement": []}
                else:
                    return f"Error fetching policy for bucket {bucket_name}: {e}"

            # 3) Check if there's a Deny on s3:PutObject
            has_deny_putobject = False
            for stmt in policy.get('Statement', []):
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                # If 'Effect' == 'Deny' and 's3:PutObject' is in actions
                if stmt.get('Effect') == 'Deny' and "s3:PutObject" in actions:
                    has_deny_putobject = True
                    break

            if has_deny_putobject:
                return f"Bucket {bucket_name} exists with a Deny policy on PutObject."
            else:
                return f"Bucket {bucket_name} exists with no Deny policy on PutObject."
        elif event_name == "GetObject":
            bucket_name = resource.get('S3BucketName')
            object_key = resource.get('ObjectKey')
            if not bucket_name or not object_key:
                return "No S3 bucket name or object key provided in the anomaly resources."

            s3 = boto3.client('s3')
            try:
                # 1) Check if the bucket exists
                s3.head_bucket(Bucket=bucket_name)
                bucket_exists = True
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == '404':
                    bucket_exists = False
                else:
                    return f"Error checking bucket {bucket_name}: {e}"

            if not bucket_exists:
                return f"Bucket {bucket_name} does not exist."

            # 2) Fetch the bucket's policy
            try:
                response = s3.get_bucket_policy(Bucket=bucket_name)
                policy_str = response.get('Policy', '{}')
                policy = json.loads(policy_str)
            except s3.exceptions.from_code('NoSuchBucketPolicy'):
                # If no existing policy, make a blank one
                policy = {"Statement": []}
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                     policy = {"Statement": []}
                else:
                     return f"Error fetching policy for bucket {bucket_name}: {e}"

            # 3) Check if there's a Deny on s3:GetObject for this specific object
            has_deny_getobject = False
            target_arn = f"arn:aws:s3:::{bucket_name}/{object_key}"

            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') == 'Deny':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "s3:GetObject" in actions:
                        # Resource might be a string or a list
                        stmt_resource = stmt.get('Resource', [])
                        if isinstance(stmt_resource, str):
                            stmt_resource = [stmt_resource]
                        # Check if the target ARN is among the resources
                        if target_arn in stmt_resource:
                            has_deny_getobject = True
                            break

            if has_deny_getobject:
                return f"Bucket {bucket_name} has a Deny policy on GetObject for '{object_key}'."
            else:
                 return f"Bucket {bucket_name} has no Deny policy on GetObject for '{object_key}'."
        elif event_name == "ListBuckets":
            user_name = resource.get('UserName')
            if not user_name:
                return "No user name provided in the anomaly resources."

            iam = boto3.client('iam')

            # Step 1) Attempt to fetch the user policy named "RestrictListBuckets"
            policy_name = "RestrictListBuckets"

            try:
                existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
                if policy_name not in existing_policies:
                    # No policy with that name means definitely no Deny for s3:ListBucket
                    return f"User {user_name} has no deny policy on ListBucket."
                
                # If the policy exists, fetch it
                policy_document_str = iam.get_user_policy(
                    UserName=user_name, 
                    PolicyName=policy_name
                )['PolicyDocument']
                
                # policy_document_str is already a dict, but sometimes you have a JSON string.
                # Usually in IAM APIs, it's already parsed. If needed, do:
                # policy_document = json.loads(policy_document_str)
                policy_document = policy_document_str

                # Step 2) Check if there's a Deny statement for s3:ListBucket
                has_deny_listbucket = False
                for stmt in policy_document.get('Statement', []):
                    if stmt.get('Effect') == 'Deny':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        if "s3:ListBucket" in actions:
                            has_deny_listbucket = True
                            break

                if has_deny_listbucket:
                    return f"User {user_name} has a deny policy on ListBucket."
                else:
                    return f"User {user_name} has no deny policy on ListBucket."

            except iam.exceptions.NoSuchEntityException:
                # The user or the policy doesn't exist
             return f"No policy named {policy_name} found for user {user_name}."
            
        elif event_name == "CreateBucket":
            user_name = resource.get('UserName')
            bucket_name = resource.get('S3BucketName')
            if not user_name or not bucket_name:
             return "No user name or bucket name provided in the anomaly resources for CreateBucket."

        elif event_name == "RevokeSecurityGroupIngress":
            security_group_id = resource.get("SecurityGroupId")
            if not security_group_id:
                return "No Security Group ID provided in the anomaly resources."

            ec2 = boto3.client("ec2")
            try:
                # 1️⃣ Check if the Security Group exists
                response = ec2.describe_security_groups(GroupIds=[security_group_id])
                security_group_exists = bool(response["SecurityGroups"])
            except ec2.exceptions.ClientError as e:
                if "InvalidGroup.NotFound" in str(e):
                    return f"Security Group {security_group_id} does not exist."
                return f"Error checking Security Group {security_group_id}: {e}"

            if not security_group_exists:
                return f"Security Group {security_group_id} does not exist."

            # 2️⃣ Check if important ingress rules were removed
            security_group = response["SecurityGroups"][0]
            ingress_rules = security_group.get("IpPermissions", [])

            important_ports = {22, 3389, 5432, 3306}  # SSH, RDP, PostgreSQL, MySQL
            removed_critical_rules = [
                rule for rule in ingress_rules if any(
                ip_range.get("CidrIp") == "0.0.0.0/0" and rule.get("FromPort") in important_ports
                for ip_range in rule.get("IpRanges", [])
            )
        ]

            if removed_critical_rules:
                return f"Security Group {security_group_id} exists with critical rules removed."

            return f"Security Group {security_group_id} exists with no unauthorized rule revocations."


        # Add more cases for different event types
        return f"No state fetch logic for event: {event_name}"

     except Exception as e:
        print(f"Failed to fetch resource state for anomaly: {e}")
        return f"Error fetching state: {e}"


    def tag_anomaly_for_review(self, anomaly):
     try:
        anomaly_details = anomaly.to_dict()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_name = f'anomalies_review_{timestamp}.csv'

        # Check if the file exists
        if os.path.exists(file_name):
            # Append to the existing file
            df = pd.read_csv(file_name)
            df = pd.concat([df, pd.DataFrame([anomaly_details])], ignore_index=True)
        else:
            # Create a new file
            df = pd.DataFrame([anomaly_details])
        
        df.to_csv(file_name, index=False)
        print(f"Anomaly tagged and saved for review in {file_name}.")
     except Exception as e:
        print(f"Failed to save anomaly for review: {e}")


    def restrict_detach_volume_permission(self, anomaly):
     user_name = anomaly.get("Resources", {}).get("UserName")
     volume_id = anomaly.get("Resources", {}).get("EBSVolumeId")

     if not user_name or not volume_id:
        msg = "UserName or VolumeId missing in anomaly details for DetachVolume."
        print(msg)
        return msg

     iam = boto3.client("iam")
     policy_name = "RestrictDetachVolume"

     policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "ec2:DetachVolume",
                "Resource": f"arn:aws:ec2:*:*:volume/{volume_id}"
            }
        ]
     }

     try:
        # Check if policy already exists
        response = iam.list_user_policies(UserName=user_name)
        if policy_name in response.get("PolicyNames", []):
            msg = f"DetachVolume policy already in place for user {user_name}. Skipping."
            print(msg)
            return msg

        # Apply policy if not already present
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )

        msg = f"DetachVolume permission restricted for user {user_name}."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to restrict DetachVolume for user {user_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=f"Failed to restrict DetachVolume for user {user_name}. Error: {e}",
            subject="Mitigation Failure"
        )
        return error_msg

    def notify_admin_bucket_creation(self, anomaly):
        bucket_name = anomaly.get('Resources', {}).get('S3BucketName', 'Unknown')
        user_name = anomaly.get('Resources', {}).get('UserName', 'Unknown')

         # Minimal message
        msg = f"Bucket '{bucket_name}' was created by user '{user_name}'."
        print(f"[CreateBucket Notification] {msg}")

         # Send minimal email:
        self.notify_admin(
        message=msg,
        subject="New Bucket Created"
    )

        return msg

    def restrict_stop_instances_permission(self, anomaly):
    
     user_name = anomaly.get('Resources', {}).get('UserName')
     if not user_name:
        msg = "User name missing in anomaly details for StopInstances."
        print(msg)
        return msg

     try:
        iam = boto3.client('iam')
        policy_name = "RestrictStopInstances"

        # 1) See if the user already has an inline policy named 'RestrictStopInstances'
        existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
        if policy_name in existing_policies:
            # Fetch the existing doc
            response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_document = response['PolicyDocument']
        else:
            # Start with a minimal blank doc
            policy_document = {
                "Version": "2012-10-17",
                "Statement": []
            }

        # 2) Check if Deny ec2:StopInstances is already in the statements
        already_deny_stop = False
        for stmt in policy_document.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "ec2:StopInstances" in actions:
                    already_deny_stop = True
                    break

        if already_deny_stop:
            msg = f"User {user_name} already has a deny policy on ec2:StopInstances."
            print(msg)
            return msg

        # 3) Append the new Deny statement
        policy_document['Statement'].append({
            "Effect": "Deny",
            "Action": "ec2:StopInstances",
            "Resource": "*"
        })

        # 4) Put the updated policy
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )

        msg = f"User {user_name} is now denied from calling ec2:StopInstances."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to restrict StopInstances for user {user_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=error_msg,
            subject="Mitigation Failure"
        )
        return error_msg


    def prevent_object_access(self, anomaly):
     bucket_name = anomaly.get('Resources', {}).get('S3BucketName')
     object_key = anomaly.get('Resources', {}).get('ObjectKey')

     if not bucket_name or not object_key:
        msg = "Bucket name or object key missing in anomaly details."
        print(msg)
        return msg

     try:
        s3 = boto3.client('s3')

        # 1) Attempt to fetch the existing bucket policy
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
            policy = json.loads(policy_str)
        except s3.exceptions.from_code('NoSuchBucketPolicy'):
            # If there's no existing policy, create an empty one
            policy = {
                "Version": "2012-10-17",
                "Statement": []
            }

        # 2) Check if there's already a Deny s3:GetObject for this exact object
        already_deny_get = False
        target_arn = f"arn:aws:s3:::{bucket_name}/{object_key}"

        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "s3:GetObject" in actions:
                    # Check resources
                    stmt_resource = stmt.get('Resource', [])
                    if isinstance(stmt_resource, str):
                        stmt_resource = [stmt_resource]
                    if target_arn in stmt_resource:
                        already_deny_get = True
                        break

        if already_deny_get:
            msg = f"Access to object '{object_key}' in bucket '{bucket_name}' is already blocked."
            print(msg)
            return msg

        # 3) Append the new Deny statement
        policy['Statement'].append({
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": target_arn
        })

        # 4) Put the updated policy
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        # 5) (Optional) verify the updated policy
        updated_policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
        updated_policy = json.loads(updated_policy_str)

        if updated_policy == policy:
            msg = f"Access to object '{object_key}' in bucket '{bucket_name}' has been blocked."
            print(msg)
            return msg
        else:
            msg = f"Policy verification failed for object '{object_key}' in bucket '{bucket_name}'."
            print(msg)
            return msg

     except Exception as e:
        error_msg = f"Failed to block object access for {object_key} in {bucket_name}. Error: {e}"
        print(error_msg)
        self.notify_admin(message=error_msg, subject="Mitigation Failure")
        return error_msg


    def limit_bucket_listing_permissions(self, anomaly):
     user_name = anomaly.get('Resources', {}).get('UserName')
     if not user_name:
        msg = "User name missing in anomaly details."
        print(msg)
        return msg

     try:
        iam = boto3.client('iam')
        policy_name = "RestrictListBuckets"

        # 1) Check if the user already has an inline policy named "RestrictListBuckets"
        existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
        
        if policy_name in existing_policies:
            # Fetch the existing policy doc
            response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_document = response['PolicyDocument']
        else:
            # Create a minimal policy with no statements
            policy_document = {
                "Version": "2012-10-17",
                "Statement": []
            }

        # 2) Check if a Deny statement for s3:ListBucket is already present
        already_deny_listbucket = False
        for stmt in policy_document.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "s3:ListBucket" in actions:
                    already_deny_listbucket = True
                    break

        if already_deny_listbucket:
            msg = f"User {user_name} already has a deny policy on s3:ListBucket. Skipping."
            print(msg)
            return msg

        # 3) Append the Deny statement
        policy_document['Statement'].append({
            "Effect": "Deny",
            "Action": "s3:ListBucket",
            "Resource": "*"
        })

        # 4) Put the updated policy
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )

        msg = f"List bucket permissions restricted for user {user_name}."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to restrict bucket listing for user {user_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=error_msg,
            subject="Mitigation Failure"
        )
        return error_msg



    def restrict_security_group_ingress_permission(self, anomaly):
     user_name = anomaly.get("Resources", {}).get("UserName")
     security_group_id = anomaly.get("Resources", {}).get("SecurityGroupId")

     if not user_name or not security_group_id:
        msg = "UserName or SecurityGroupId missing in anomaly details for AuthorizeSecurityGroupIngress."
        print(msg)
        return msg

     iam = boto3.client("iam")
     policy_name = "RestrictSecurityGroupIngress"

     policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "ec2:AuthorizeSecurityGroupIngress",
                "Resource": f"arn:aws:ec2:*:*:security-group/{security_group_id}"
            }
        ]
     }

     try:
        # Check if policy already exists
        response = iam.list_user_policies(UserName=user_name)
        if policy_name in response.get("PolicyNames", []):
            msg = f"AuthorizeSecurityGroupIngress policy already in place for user {user_name}. Skipping."
            print(msg)
            return msg

        # Apply policy if not already present
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )

        msg = f"AuthorizeSecurityGroupIngress permission restricted for user {user_name}."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to restrict AuthorizeSecurityGroupIngress for user {user_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=f"Failed to restrict AuthorizeSecurityGroupIngress for user {user_name}. Error: {e}",
            subject="Mitigation Failure"
        )
        return error_msg

        
    def block_s3_upload(self, anomaly):
   
     bucket_name = anomaly.get('Resources', {}).get('S3BucketName')
     if not bucket_name:
        msg = "Bucket name missing in anomaly details."
        print(msg)
        return msg

     try:
        s3 = boto3.client('s3')

        # 1) Attempt to fetch the existing bucket policy
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
            policy = json.loads(policy_str)
        except s3.exceptions.from_code('NoSuchBucketPolicy'):
            # If there's no existing policy, create an empty one
            policy = {
                "Version": "2012-10-17",
                "Statement": []
            }

        # 2) Check if a Deny statement for PutObject already exists
        already_deny_put = False
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                # If 's3:PutObject' is in the list, we already have a deny
                if "s3:PutObject" in actions:
                    already_deny_put = True
                    break

        if already_deny_put:
            msg = f"Bucket '{bucket_name}' already has a Deny PutObject policy. Skipping."
            print(msg)
            return msg

        # 3) Append the new Deny statement
        policy['Statement'].append({
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*"
        })

        # 4) Put the updated policy
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        # 5) Verify the updated policy if desired (optional)
        updated_policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
        updated_policy = json.loads(updated_policy_str)

        # Compare statement arrays or just assume success
        if updated_policy == policy:
            msg = f"PutObject action blocked for bucket '{bucket_name}'. Policy verified."
            print(msg)
            return msg
        else:
            msg = f"Policy verification failed for bucket '{bucket_name}'."
            print(msg)
            return msg

     except Exception as e:
        error_msg = f"Failed to apply block policy to {bucket_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=error_msg,
            subject="Mitigation Failure"
        )
        return error_msg

        

    def restrict_attach_volume_permission(self, anomaly):
        user_name = anomaly.get("Resources", {}).get("UserName")
        volume_id = anomaly.get("Resources", {}).get("EBSVolumeId")

        if not user_name or not volume_id:
            msg = "UserName or VolumeId missing in anomaly details for AttachVolume."
            print(msg)
            return msg

        iam = boto3.client("iam")
        policy_name = "RestrictAttachVolume"

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
             {
                "Effect": "Deny",
                "Action": "ec2:AttachVolume",
                "Resource": f"arn:aws:ec2:*:*:volume/{volume_id}"
            }
        ]
    }

        try:
         # Check if policy already exists
         response = iam.list_user_policies(UserName=user_name)
         if policy_name in response.get("PolicyNames", []):
             msg = f"AttachVolume policy already in place for user {user_name}. Skipping."
             print(msg)
             return msg

            # Apply policy if not already present
         iam.put_user_policy(
             UserName=user_name,
             PolicyName=policy_name,
             PolicyDocument=json.dumps(policy_document)
        )

         msg = f"AttachVolume permission restricted for user {user_name}."
         print(msg)
         return msg

        except Exception as e:
         error_msg = f"Failed to restrict AttachVolume for user {user_name}: {e}"
         print(error_msg)
         self.notify_admin(
             message=f"Failed to restrict AttachVolume for user {user_name}. Error: {e}",
             subject="Mitigation Failure"
         )
         return error_msg



    def stop_unauthorized_instance(self, anomaly):
        user_name = anomaly.get('Resources', {}).get('UserName')
        if not user_name:
            msg = "User name missing in anomaly details for StartInstances."
            print(msg)
            return msg

        try:
            iam = boto3.client('iam')
            policy_name = "RestrictStartInstances"

             # 1) See if the user already has an inline policy by this name
            existing_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
            if policy_name in existing_policies:
                # Fetch the existing doc
                response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_document = response['PolicyDocument']
            else:
                # Start with a minimal blank doc
                 policy_document = {
                "Version": "2012-10-17",
                "Statement": []
            }

            # 2) Check if Deny ec2:StartInstances is already in the statements
            already_deny_start = False
            for stmt in policy_document.get('Statement', []):
                if stmt.get('Effect') == 'Deny':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "ec2:StartInstances" in actions:
                        already_deny_start = True
                        break

            if already_deny_start:
                msg = f"User {user_name} already has a deny policy on ec2:StartInstances."
                print(msg)
                return msg

            # 3) Append the new Deny statement
            policy_document['Statement'].append({
                "Effect": "Deny",
                "Action": "ec2:StartInstances",
                "Resource": "*"
            })

            # 4) Put the updated policy
            iam.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )

            msg = f"User {user_name} is now denied from calling ec2:StartInstances."
            print(msg)
            return msg

        except Exception as e:
            error_msg = f"Failed to restrict StartInstances for user {user_name}: {e}"
            print(error_msg)
            self.notify_admin(message=error_msg, subject="Mitigation Failure")
            return error_msg

    def restrict_describe_instances_permission(self, anomaly):
     user_name = anomaly.get('Resources', {}).get('UserName')

     if not user_name:
        msg = "UserName missing in anomaly details for DescribeInstances."
        print(msg)
        return msg  # Returning the message for logging and email inclusion

     iam = boto3.client('iam')
     policy_name = "RestrictDescribeInstances"

     policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "ec2:DescribeInstances",
                "Resource": "*"
            }
        ]
    }

     try:
        # Check if policy already exists
        response = iam.list_user_policies(UserName=user_name)
        if policy_name in response.get('PolicyNames', []):
            msg = f"DescribeInstances policy already in place for user {user_name}. Skipping."
            print(msg)
            return msg  # Returning the message

        # Apply policy if not already present
        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )

        msg = f"DescribeInstances permission restricted for user {user_name}."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to restrict DescribeInstances for user {user_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=f"Failed to restrict DescribeInstances for user {user_name}. Error: {e}",
            subject="Mitigation Failure"
        )
        return error_msg


    def revert_iam_policy_changes(self, anomaly):
     policy_arn = anomaly.get('Resources', {}).get('PolicyArn')
     if not policy_arn:
        print("Policy ARN missing in anomaly details.")
        return

     try:
        iam = boto3.client('iam')
        policy_versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
        latest_version = [v for v in policy_versions if v['IsDefaultVersion']][0]

        if not latest_version.get('VersionId'):
            raise Exception("No valid default policy version found.")

        iam.delete_policy_version(
            PolicyArn=policy_arn,
            VersionId=latest_version['VersionId']
        )
        print(f"Reverted IAM policy {policy_arn} to previous version.")
     except Exception as e:
        print(f"Failed to revert IAM policy changes for {policy_arn}: {e}")
    def log_actual_risk_scores(self, actual_risks):
        """ Save actual risk scores after new logs are processed. """
        actual_timestamps = pd.date_range(start=pd.Timestamp.now(), periods=len(actual_risks), freq='H')
        
        actual_risks_df = pd.DataFrame({
            "Time": actual_timestamps,
            "ActualRiskScore": actual_risks
        })
        actual_risks_df.to_csv("actual_risk_scores.csv", index=False)
        print("📌 Actual Risk Scores saved.")
    def compare_predictions():
    
    
     # Load predicted and actual risk scores
     if not os.path.exists("predicted_risk_scores.csv") or not os.path.exists("actual_risk_scores.csv"):
        print("⚠️ No data available for comparison yet.")
        return

     predicted_risks_df = pd.read_csv("predicted_risk_scores.csv")
     actual_risks_df = pd.read_csv("actual_risk_scores.csv")

     # Merge by time for direct comparison
     comparison = pd.merge(predicted_risks_df, actual_risks_df, on="Time", how="inner")

     # Compute error
     comparison["Error"] = abs(comparison["PredictedRiskScore"] - comparison["ActualRiskScore"])

     print("🔍 Prediction Accuracy Report:")
     print(comparison)

     # Save comparison results
     comparison.to_csv("risk_prediction_comparison.csv", index=False)
     print("✅ Comparison results saved to 'risk_prediction_comparison.csv'.")

     # Run comparison
    compare_predictions()    
    
    def prevent_bucket_deletion(self, anomaly):
     bucket_name = anomaly.get('Resources', {}).get('S3BucketName')
     if not bucket_name:
        msg = "Bucket name missing in anomaly details."
        print(msg)
        return msg  # Return the message

     try:
        s3 = boto3.client('s3')

        # 1) Attempt to fetch the existing bucket policy
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
            policy = json.loads(policy_str)
        except s3.exceptions.from_code('NoSuchBucketPolicy'):
            # If there's no existing policy, create an empty one
            policy = {
                "Version": "2012-10-17",
                "Statement": []
            }

        # 2) Check if a Deny statement for DeleteBucket already exists
        already_deny_delete = False
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Deny':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if "s3:DeleteBucket" in actions:
                    already_deny_delete = True
                    break

        if already_deny_delete:
            msg = f"DeleteBucket policy already in place for bucket {bucket_name}. Skipping."
            print(msg)
            return msg

        # 3) Append the new Deny statement
        policy['Statement'].append({
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:DeleteBucket",
            "Resource": f"arn:aws:s3:::{bucket_name}"
        })

        # 4) Put the updated policy back
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        # Print & return final success message
        msg = f"DeleteBucket action blocked for bucket {bucket_name}."
        print(msg)
        return msg

     except Exception as e:
        error_msg = f"Failed to apply deletion prevention for {bucket_name}: {e}"
        print(error_msg)
        self.notify_admin(
            message=f"Failed to block DeleteBucket for {bucket_name}. Error: {e}",
            subject="Mitigation Failure"
        )
        return error_msg

        

    def run(self):
        import secrets

        secret_key = secrets.token_hex(32)  # This generates a 64-character hexadecimal string
        print(secret_key)

        print("🔍 Running CloudTrail Analysis...")

        # Step 1: Collect logs
        events = self.collect_logs()

        # Step 2: Preprocess logs
        process_df, original_data = self.data_processor.preprocess_logs(
            events,
            self.unauthorized_api_calls
        )

        # Ensure 'Resources' column is correctly formatted
        if 'Resources' in original_data.columns:
            original_data['Resources'] = original_data['Resources'].apply(
                lambda x: json.loads(x) if isinstance(x, str) else x
            )
        
        self.X = process_df.to_numpy()  

        # Step 3: Compute dynamic risk weights
        weights = self.risk_analyzer.compute_dynamic_weights(original_data)

        # Step 4: Calculate risk scores
        past_risk_scores = []
        for idx, row in original_data.iterrows():
            score, reasons = self.risk_analyzer.calculate_risk_score(row, weights)
            original_data.at[idx, 'RiskScore'] = score
            original_data.at[idx, 'RiskReasons'] = '; '.join([str(v.get('message', '')) for v in reasons if isinstance(v, dict)])

            past_risk_scores.append(score)  # Store for forecasting

        # self.risk_analyzer.visualize_unusual_hours(original_data)

        # ✅ Step 5: Predict Future Risks
        risk_forecaster = RiskForecaster()
        if past_risk_scores:
            print("📊 Training risk forecasting model...")
            risk_forecaster.train_model(past_risk_scores)
            future_risks = risk_forecaster.predict_future_risk(steps=10)

            # Visualize the risk trend
#            risk_forecaster.visualize_risk_trend(past_risk_scores, future_risks)

            # Save Predictions for comparison later
            future_timestamps = pd.date_range(start=pd.Timestamp.now(), periods=len(future_risks), freq='H')
            predicted_risks_df = pd.DataFrame({
                "Time": future_timestamps,
                "PredictedRiskScore": future_risks
            })
            predicted_risks_df.to_csv("predicted_risk_scores.csv", index=False)
            print("🔮 Predicted Risk Scores saved.")

            # Check max predicted risk and trigger alert if needed
            predicted_risk = max(future_risks) if any(future_risks) else 0
            risk_threshold = 50
            if predicted_risk > risk_threshold:
                alert_message = f"🚨 Future Risk Alert: Predicted risk score of {predicted_risk} exceeds threshold!"
                print(alert_message)
                self.notify_admin(alert_message, subject="High Risk Prediction")

        # ✅ Step 6: Compliance Check
        compliance_checker = ComplianceChecker()
        original_data['ComplianceReasons'] = original_data.apply(
  lambda row: "; ".join(
    [v if isinstance(v, str) else str(v.get('message', '')) for v in compliance_checker.check_all_compliance(row)]
  ),
  axis=1
)

        original_data['ComplianceCheck'] = original_data['ComplianceReasons'].apply(
            lambda reasons: "Compliant" if reasons == "" else "Non-compliant"
        )

        # ✅ Step 7: Detect anomalies
        anomaly_indices, anomaly_events = self.anomaly_detector.detect_anomalies(process_df, original_data)

        if anomaly_events is not None and not anomaly_events.empty:
            anomaly_count = len(anomaly_events)
            anomalies_json = anomaly_events.to_dict(orient='records')
            print("🚨 Anomalies Detected! Count:", anomaly_count)

            print("🚨 Anomalies Detected! Saving and mitigating...")
            print(anomaly_events[['EventName', 'Resources']].head())

            # # Save to CSV
            # timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            # anomaly_events.to_csv(f"anomalies_{timestamp}.csv", index=False)
            # print(f"Anomalies saved to anomalies_{timestamp}.csv")

            # Also create an in-memory CSV string for UI return
            csv_buffer = io.StringIO()
            anomaly_events.to_csv(csv_buffer, index=False)
            self.csv_output = csv_buffer.getvalue()

            # Mitigate anomalies
            self.mitigate_anomalies(anomaly_events)
            try:
             save_anomalies_to_dynamodb(anomaly_events)
             print("Anomalies saved to DynamoDB successfully.")
            except Exception as e:
             print("Failed to save anomalies to DynamoDB:", e)
        else:
            print("✅ No anomalies found.")
            anomaly_count = 0
            anomalies_json =[]
            self.csv_output = "No anomalies found.\n"


        return {
      "original_data": original_data.to_dict(orient='records'),
      "anomaly_count": anomaly_count,
      "csv_output": self.csv_output,
      "anomalies_json": anomalies_json
}