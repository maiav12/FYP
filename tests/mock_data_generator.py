import random
import os
import json
import sys
import boto3
import warnings
import pandas as pd
from datetime import datetime, timedelta
from matplotlib import pyplot as plt
warnings.filterwarnings("ignore", category=UserWarning, module="pyod.models.base")

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import CloudTrailAnalyzer

def generate_mock_data():
    """Generate mock CloudTrail event data with likely higher risk scores."""
    event_names = [
        "ListBuckets", 
        "DeleteBucket", 
        "PutObject",
        "GetObject",
        "CreateBucket",
        "StartInstances",
        "StopInstances",
        "DescribeInstances",
        "AttachVolume",
        "DetachVolume",
        "AuthorizeSecurityGroupIngress",
        "LookupEvents",
        "RevokeSecurityGroupIngress"
    ]
    
    usernames = ["Alice", "Charlie"]
    source_ips = ["192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.2", "203.0.113.5"]
    base_time = datetime.now()

    mock_events = []
    for i in range(50):
        event_name = random.choice(event_names)
        username = random.choice(usernames)
        source_ip = random.choice(source_ips)
        event_time = base_time - timedelta(minutes=random.randint(0, 1440))

        event_id = f"event-{i}"
        event_source = (
            "ec2.amazonaws.com"
            if event_name in ["StartInstances", "StopInstances", "DescribeInstances", "AttachVolume", "DetachVolume"]
            else "s3.amazonaws.com"
        )
        
        # Additional random fields to boost risk:
        # 1) Frequency-based
        event_frequency = random.randint(1, 15)    # random 1..15
        upper_threshold = random.randint(5, 10)    # random 5..10
        user_event_freq = random.randint(1, 10)    # random 1..10
        user_threshold = random.randint(3, 8)      # random 3..8
        ip_event_freq = random.randint(1, 15)      # random 1..15
        ip_threshold = random.randint(5, 12)       # random 5..12

        # 2) Failed login attempts
        failed_attempts = random.randint(0, 8)     # up to 8 attempts
        # 3) Sensitive data
        sensitive_data = random.choice([ 1])     # 50% chance
        # 4) CriticalEvent if "DeleteBucket" or "StopInstances"
        critical_event = 0
        if event_name in ["DeleteBucket", "StopInstances"] and random.random() < 0.5:
            # 50% chance we consider these events "critical"
            critical_event = 1

        # We'll also create a moderate chance of a "force_violation" for encryption or compliance
        force_violation = (random.random() < 0.25)  # 25% chance

        user_agent = random.choice([
            "aws-cli/2.0",
            "aws-sdk-java/1.11.842",
            "aws-sdk-python/1.14.0",
            "aws-console",
            "aws-sdk-go/1.34.0"
        ])

        request_parameters = {}
        response_elements = {}

        if event_name == "PutObject":
            bucket_name = f"compliant-bucket-4"
            object_key = f"data/{random.randint(1, 100)}.csv"
            request_parameters = {
                "bucketName": bucket_name,
                "objectKey": object_key,
                "objectSize": random.randint(1, 10000)
            }
            # If forcing violation => no encryption
            request_parameters["encrypted"] = not force_violation
            response_elements = {"status": "success", "objectKey": object_key}

        elif event_name == "LookupEvents":
            # If forcing violation => no encryption
            request_parameters["encrypted"] = not force_violation

        elif event_name == "GetObject":
            bucket_name = "compliant-bucket-4"
            object_key = f"data/{random.randint(1, 100)}.csv"
            request_parameters = {
                "bucketName": bucket_name,
                "objectKey": object_key
            }
            response_elements = {"status": "success", "objectKey": object_key}

        elif event_name == "DeleteBucket":
            bucket_name = "compliant-bucket-4"
            request_parameters = {"bucketName": bucket_name}
            response_elements = {"status": "failed", "reason": "Bucket contains data"}

        # Mark unauthorized calls
        unauthorized = event_name in {"DeleteBucket", "StopInstances"}
        if event_name in ["DeleteBucket", "StopInstances"]:
            compliance_check = "Non-compliant"
        else:
            compliance_check = "Compliant"
        
        # Just for example breach notification messages
        if event_name == "DeleteBucket":
            breach_notification = "Violation of GDPR: Data deletion without proper consent."
        elif event_name == "StopInstances":
            breach_notification = "Violation of GDPR: Stopping cloud instances without due process."
        else:
            breach_notification = "Compliant operation."

        # Build up the 'Resources' dict
        resources = {}
        if event_name in ["PutObject", "GetObject", "DeleteBucket"]:
            bucket_name = request_parameters.get("bucketName")
            object_key = request_parameters.get("objectKey")
            resources = {"S3BucketName": bucket_name, "ObjectKey": object_key}

        elif event_name == "ListBuckets":
            resources = {"UserName": username}

        elif event_name in ["DescribeInstances", "StartInstances", "StopInstances"]:
            ec2 = boto3.client('ec2')
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            )
            if instances['Reservations']:
                instance_id = instances['Reservations'][0]['Instances'][0]['InstanceId']
            else:
                instance_id = f"i-{random.randint(10000000, 99999999)}"
            resources = {"UserName": username, "EC2InstanceId": instance_id}

        elif event_name == "AttachVolume":
            ec2 = boto3.client("ec2")
            volumes = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
            if volumes["Volumes"]:
                volume_id = volumes["Volumes"][0]["VolumeId"]
            else:
                volume_id = f"vol-{random.randint(10000000, 99999999)}"
            resources = {"UserName": username, "EBSVolumeId": volume_id}

        elif event_name == "DetachVolume":
            ec2 = boto3.client("ec2")
            volumes = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["in-use"]}])
            if volumes["Volumes"]:
                volume_id = volumes["Volumes"][0]["VolumeId"]
            else:
                volume_id = f"vol-{random.randint(10000000, 99999999)}"
            resources = {"UserName": username, "EBSVolumeId": volume_id}

        elif event_name == "CreateBucket":
            bucket_name = request_parameters.get("bucketName", "test-bucket")
            resources = {"S3BucketName": bucket_name, "UserName": username}

        elif event_name == "AuthorizeSecurityGroupIngress":
            ec2 = boto3.client("ec2")
            security_groups = ec2.describe_security_groups()
            if security_groups["SecurityGroups"]:
                sg_id = security_groups["SecurityGroups"][0]["GroupId"]
            else:
                sg_id = f"sg-{random.randint(10000000, 99999999)}"
            resources = {"UserName": username, "SecurityGroupId": sg_id}

        elif event_name == "RevokeSecurityGroupIngress":
            ec2 = boto3.client("ec2")
            security_groups = ec2.describe_security_groups()
            if security_groups["SecurityGroups"]:
                sg_id = security_groups["SecurityGroups"][0]["GroupId"]
            else:
                sg_id = f"sg-{random.randint(10000000, 99999999)}"
            resources = {"UserName": username, "SecurityGroupId": sg_id}

        # Build final mock event
        mock_events.append({
            "EventName": event_name,
            "Username": username,
            "SourceIPAddress": source_ip,
            "EventTime": event_time.isoformat(),
            "EventId": event_id,
            "Resources": resources,

            # Additional fields to boost risk
            "EventFrequency": event_frequency,
            "UpperThreshold": upper_threshold,
            "UserEventFrequency": user_event_freq,
            "UserThreshold": user_threshold,
            "IPEventFrequency": ip_event_freq,
            "IPThreshold": ip_threshold,
            "FailedLoginAttempts": failed_attempts,
            "SensitiveDataAccess": sensitive_data,
            "CriticalEvent": critical_event,

            "CloudTrailEvent": json.dumps({
                "eventVersion": "1.08",
                "userIdentity": {"type": "IAMUser", "userName": username},
                "eventTime": event_time.isoformat(),
                "eventSource": event_source,
                "eventName": event_name,
                "awsRegion": "us-east-1",
                "sourceIPAddress": source_ip,
                "userAgent": user_agent,
                "requestParameters": request_parameters,
                "responseElements": response_elements,
                "resources": resources
            }),
            "UnauthorizedCall": unauthorized,
            "ComplianceCheck": compliance_check,
            "BreachNotification": breach_notification
        })

    return mock_events

mock_events = generate_mock_data()

if __name__ == "__main__":
    from main import CloudTrailAnalyzer
    analyzer = CloudTrailAnalyzer()
    print("Using mock data for testing...")

    analyzer.collect_logs = lambda: mock_events
    results = analyzer.run()

    if results is not None:
        data_df = pd.DataFrame(results["original_data"])
        print(data_df[[
            "EventName","Username","SourceIPAddress",
            "EventFrequency","UpperThreshold",
            "UserEventFrequency","UserThreshold",
            "IPEventFrequency","IPThreshold",
            "FailedLoginAttempts","SensitiveDataAccess",
            "CriticalEvent","RiskScore","RiskReasons"
        ]].head(10))
