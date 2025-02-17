from datetime import datetime, timedelta
import json
import random
import sys
import os
import boto3
import seaborn as sns
import pandas as pd
from matplotlib import pyplot as plt

# Add the parent directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import CloudTrailAnalyzer

def generate_mock_data():
    """Generate mock CloudTrail event data with realistic events."""
    event_names = [
        "ListBuckets", # mitigated
        "DeleteBucket", #mitigated
        "PutObject",# mitigated
        "GetObject",# mitigated 
        "CreateBucket", # mitigated
        "StartInstances",# mitigated
        "StopInstances",# mitigated
        "DescribeInstances",
        "AttachVolume",# mitigated
        "DetachVolume", # mitigated
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress"]
    
    
    usernames = ["Alice", "Charlie"]
    source_ips = ["192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.2", "203.0.113.5"]
    base_time = datetime.now()

    mock_events = []
    for i in range(100):
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
            response_elements = {"status": "success", "objectKey": object_key}

        elif event_name == "GetObject":
            bucket_name = f"compliant-bucket-4"
            object_key = f"data/{random.randint(1, 100)}.csv"
            request_parameters = {
                "bucketName": bucket_name,
                "objectKey": object_key
            }
            response_elements = {"status": "success", "objectKey": object_key}

        elif event_name == "DeleteBucket":
            bucket_name = f"compliant-bucket-4"
            request_parameters = {"bucketName": bucket_name}
            response_elements = {"status": "failed", "reason": "Bucket contains data"}

        unauthorized = event_name in {"DeleteBucket", "StopInstances"}
        if event_name in ["DeleteBucket", "StopInstances"]:
            compliance_check = "Non-compliant"
        else:
            compliance_check = "Compliant"
        
        if event_name == "DeleteBucket":
            breach_notification = "Violation of GDPR: Data deletion without proper consent."
        elif event_name == "StopInstances":
            breach_notification = "Violation of GDPR: Stopping cloud instances without due process."
        else:
            breach_notification = "Compliant operation."

        resources = {}
        if event_name in ["PutObject", "GetObject", "DeleteBucket"]:
         # Use the same bucket name used in request_parameters for S3 operations
         bucket_name = request_parameters.get("bucketName")
         object_key = request_parameters.get("objectKey")
         resources = {"S3BucketName": bucket_name, "ObjectKey": object_key}

        elif event_name == "ListBuckets":
         # For 'ListBuckets', we store the user name in 'Resources'
         # so the analyzer can restrict that user's ListBucket permission
         resources = {"UserName": username}

        elif event_name in ["DescribeInstances", "StartInstances", "StopInstances"]:
        # Retrieve a real instance from AWS (if available)
         ec2 = boto3.client('ec2')
         instances = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}])
    
         if instances['Reservations']:
            instance_id = instances['Reservations'][0]['Instances'][0]['InstanceId']
         else:
            instance_id = f"i-{random.randint(10000000, 99999999)}"  # Fallback fake ID if no real instances

         resources = {"UserName": username,"EC2InstanceId": instance_id}


        elif event_name == "AttachVolume":
         ec2 = boto3.client("ec2")
         volumes = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])

         if volumes["Volumes"]:
          volume_id = volumes["Volumes"][0]["VolumeId"]
         else:
            volume_id = f"vol-{random.randint(10000000, 99999999)}"  # Fallback ID

         resources = {"UserName": username, "EBSVolumeId": volume_id}

        elif event_name == "DetachVolume":
         ec2 = boto3.client("ec2")
         volumes = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["in-use"]}])

         if volumes["Volumes"]:
                volume_id = volumes["Volumes"][0]["VolumeId"]
         else:
                volume_id = f"vol-{random.randint(10000000, 99999999)}"  # Fallback ID

         resources = {"UserName": username, "EBSVolumeId": volume_id}

        elif event_name == "CreateBucket":
         bucket_name = request_parameters.get("bucketName")
         # Possibly store both bucket name and user name for clarity
         resources = {
         "S3BucketName": bucket_name,
            "UserName": username
            }
         
        elif event_name == "AuthorizeSecurityGroupIngress":
            ec2 = boto3.client("ec2")
            security_groups = ec2.describe_security_groups()

            if security_groups["SecurityGroups"]:
                security_group_id = security_groups["SecurityGroups"][0]["GroupId"]
            else:
                security_group_id = f"sg-{random.randint(10000000, 99999999)}"  # Fallback ID

            resources = {"UserName": username, "SecurityGroupId": security_group_id}
 
        elif event_name == "RevokeSecurityGroupIngress":
            ec2 = boto3.client("ec2")
            security_groups = ec2.describe_security_groups()

            if security_groups["SecurityGroups"]:
                security_group_id = security_groups["SecurityGroups"][0]["GroupId"]
            else:
                security_group_id = f"sg-{random.randint(10000000, 99999999)}"  # Fallback ID

            resources = {"UserName": username, "SecurityGroupId": security_group_id}



        mock_events.append({
            "EventName": event_name,
            "Username": username,
            "SourceIPAddress": source_ip,
            "EventTime": event_time.isoformat(),
            "EventId": event_id,
            "Resources": resources,
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

for evt in mock_events:
    if evt["EventName"] == "DeleteBucket":
        print("SAMPLE DELETE BUCKET EVENT:\n", json.dumps(evt, indent=2))
        break

if __name__ == "__main__":
    # 1) Create Analyzer
    analyzer = CloudTrailAnalyzer()
    print("Using mock data for testing...")

    # 2) Override collect_logs
    analyzer.collect_logs = lambda: mock_events

    # 3) Convert to DataFrame (or done in your main code)
    #    But if done inside the analyzer, let's just run `analyzer.run()`.

    results = analyzer.run()

    # 4) CHECKPOINT: Inspect final DataFrame if you want
    # print(results.head())

    if results is not None:
        print(results[["EventName", "Username", "SourceIPAddress", "RiskScore", "RiskReasons"]].head())

# if __name__ == "__main__":
#     analyzer = CloudTrailAnalyzer() 
#     results = analyzer.run()
#     if results is not None:
#         print(results[['EventName', 'Username', 'SourceIPAddress', 'RiskScore', 'RiskReasons']].head())
#         # Visualize Risk Categories
#         results['RiskCategory'] = results['RiskScore'].apply(
#             lambda x: "High" if x > 40 else "Medium" if x > 20 else "Low"
#         )
#         sns.countplot(data=results, x='RiskCategory', palette='viridis')
#         plt.title("Risk Category Distribution")
#         plt.xlabel("Risk Category")
#         plt.ylabel("Count")
#         plt.show()


#  How to Modify It to Use Real CloudTrail Logs
# Right now, the script replaces CloudTrail logs with mock data. To use real logs:

# ✅ Remove the Override of collect_logs()
# Replace:


# analyzer.collect_logs = lambda: mock_events
# With:


# # Use real AWS CloudTrail logs instead of mock data
# analyzer = CloudTrailAnalyzer()
# results = analyzer.run()
# This will allow CloudTrailAnalyzer to fetch real AWS CloudTrail logs.