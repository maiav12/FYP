import boto3
from datetime import datetime
import json
import pandas as pd
from decimal import Decimal

def get_severity(risk_score):
    if risk_score >= 70:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    else:
        return "Low"
def convert_floats_to_decimal(obj):
     if isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
     elif isinstance(obj, list):
        return [convert_floats_to_decimal(elem) for elem in obj]
     elif isinstance(obj, float):
        return Decimal(str(obj))
     elif isinstance(obj, (pd.Timestamp, datetime)):
        return obj.isoformat()
     else:
        return obj
def save_anomalies_to_dynamodb(anomaly_events):
    dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
    table = dynamodb.Table('Anomalies')

    for index, row in anomaly_events.iterrows():
        try:
            event_time = row.get('EventTime')
            # Check if event_time is a string, pandas Timestamp, or datetime, and convert to ISO format
            if isinstance(event_time, str):
                # Attempt to parse if necessary (you may adjust format if needed)
                event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S').isoformat()
            elif isinstance(event_time, pd.Timestamp):
                event_time = event_time.isoformat()
            elif isinstance(event_time, datetime):
                event_time = event_time.isoformat()
                
            record_id = f"{index}-{datetime.now().isoformat()}"
           

            item = {
    'id': record_id,
    'EventName': row.get('EventName'),
    'EventTime': (row.get('EventTime').isoformat() 
                  if isinstance(row.get('EventTime'), (pd.Timestamp, datetime)) 
                  else row.get('EventTime')),
    'Username': row.get('Username'),
    'RiskScore': Decimal(str(row.get('RiskScore'))),
    'Severity': get_severity(row.get('RiskScore')),
    'Details': convert_floats_to_decimal(row.to_dict())
}


            table.put_item(Item=item)
            print(f"Saved anomaly: {row.get('EventName')}")
        except Exception as e:
            print("Error saving anomaly:", e)
