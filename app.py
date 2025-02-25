import json
from decimal import Decimal
import boto3
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import pandas as pd
import time
from anomaly_saver import convert_floats_to_decimal
from main import CloudTrailAnalyzer
from tests.mock_data_generator import generate_mock_data
import logging
import os
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

AWS_REGION = os.getenv('AWS_REGION', 'us-west-2')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', 'Anomalies')
# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

def get_severity(risk_score):
    if risk_score >= 70:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    else:
        return "Low"

def save_anomalies_to_dynamodb(anomaly_events):
    for index, row in anomaly_events.iterrows():
        try:
            event_time = row.get('EventTime')
            # Convert event_time to ISO format if needed
            if isinstance(event_time, str):
                event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S').isoformat()
            from decimal import Decimal
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
            logger.info(f"Saved anomaly: {row.get('EventName')}")
        except Exception as e:
            logger.error("Error saving anomaly: %s", e)

@app.route('/save_anomalies', methods=['POST'])
def save_anomalies():
    try:
        data = request.get_json()
        # Convert JSON data to a pandas DataFrame
        anomaly_events = pd.DataFrame(data)
        save_anomalies_to_dynamodb(anomaly_events)
        return jsonify({"message": "Anomalies saved successfully"}), 200
    except Exception as e:
        logger.error("Error in /save_anomalies endpoint: %s", e)
        return jsonify({"error": str(e)}), 500
    
analyzer = CloudTrailAnalyzer()
import math
global_mitigation_log = []

def replace_nan(obj):
    if isinstance(obj, float) and math.isnan(obj):
        return None
    elif isinstance(obj, list):
        return [replace_nan(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: replace_nan(value) for key, value in obj.items()}
    else:
        return obj

@app.route('/get_logs', methods=['GET'])
def get_logs():
    try:
        # Use mock data in this example
        mock_events = generate_mock_data()
        
        # Return the raw events as JSON
        return jsonify(mock_events), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

from datetime import datetime


@app.route('/run_analysis_start', methods=['POST'])
def run_analysis():
    global global_mitigation_log
    try:
        mock_events = generate_mock_data()  # or real events
        analyzer = CloudTrailAnalyzer()
        analyzer.collect_logs = lambda: mock_events
        results = analyzer.run()  # results should now include anomaly_count and (optionally) anomalies
        global_mitigation_log = analyzer.mitigation_log
        # Assume your run() method now returns a dict that includes "anomaly_count" and "anomalies_json"
        anomaly_count = results.get("anomaly_count", 0)
        anomalies_json = results.get("anomalies_json", [])
       
        # Generate a timestamp for when the analysis finished.
        last_run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
       
        return jsonify({
            "message": "Analysis complete!",
            "anomaly_count": anomaly_count,
            "data": anomalies_json,
            "last_run_timestamp": last_run_timestamp
        }), 200
    except Exception as e:
        print("Error in /run_analysis_start:", str(e))
        return jsonify({"error": str(e)}), 500
    
# New endpoint to view the mitigation log.
@app.route('/get_mitigation_log', methods=['GET'])
def get_mitigation_log():
    try:
        print("Mitigation log:", global_mitigation_log)
        return jsonify({"mitigation_log": global_mitigation_log}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mitigate_anomaly', methods=['POST'])
def mitigate_anomaly():
    try:
        data = request.get_json()
        anomaly_id = data.get('anomaly_id')

        # In a real scenario, you would identify the correct event from your DataFrame
        # Then call `mitigate_anomalies` with the relevant row or ID
        # For demonstration, we’ll just return a success message

        return jsonify({'message': f'Mitigation executed for anomaly {anomaly_id}'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/get_compliance_data', methods=['GET'])
def get_compliance_data():
    try:
        # Suppose you have a DataFrame containing compliance info (original_data from run())
        # For a short demo, let's assume you store it in memory or re-run analysis to get it.

        # Option A: If you store the last analysis results in your Flask code
        # Option B: Re-run the analyzer

        # For demonstration, we re-run or read from a CSV:
        analyzer = CloudTrailAnalyzer()
        events = analyzer.collect_logs()  # or generate_mock_data
        process_df, original_data = analyzer.data_processor.preprocess_logs(events, analyzer.unauthorized_api_calls)
        
        # For each row, you presumably have 'ComplianceCheck' (Compliant/Non-compliant)
        # or 'ComplianceReasons'. We'll convert to JSON:
        data_json = original_data.to_dict(orient='records')
        
        return jsonify({"complianceData": data_json}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
  
@app.route("/analysis_progress")
def analysis_progress():
    def generate():
        steps = [
            "Collecting logs...",
            "Preprocessing data...",
            "Running PCA...",
            "Tuning hyperparameters...",
            "Detecting anomalies..."
        ]
        for step in steps:
            yield f"data: {step}\n\n"
            time.sleep(2)
        yield "event: done\ndata: Analysis complete!\n\n"
    return Response(stream_with_context(generate()), mimetype="text/event-stream")





if __name__ == '__main__':
    app.run(debug=True)
