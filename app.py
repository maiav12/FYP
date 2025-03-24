import json
from decimal import Decimal
import boto3
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import pandas as pd
import time

import pytz
from anomaly_saver import convert_floats_to_decimal
from main import CloudTrailAnalyzer
from tests.mock_data_generator import generate_mock_data
import logging
import os
from datetime import datetime, timedelta, timezone 
import math
from boto3.dynamodb.conditions import Attr
from sklearn.tree import _tree
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
import bcrypt 
from functools import wraps
from dotenv import load_dotenv
from services.compliance_checker import ComplianceChecker
import threading 
from services.data_processor import DataProcessor
from services.risk_analyzer import RiskAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

progress_data = {
    "log": "",
    "progress": 0,
    "done": False
}

global_analysis_results = {}  # Now it's defined at the module level

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])
risk_analyzer=RiskAnalyzer()

app.config["JWT_SECRET_KEY"] = "72f4c48c0ff0a3f961329207785257c227828321a71569cf769e2f9a0ea05efc"
jwt = JWTManager(app)


AWS_REGION = os.getenv('AWS_REGION', 'eu-north-1')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', 'Anomalies')
AUDIT_TABLE = os.getenv('AUDIT_TABLE', 'AuditTrail')

# Initialize DynamoDB resource and tables
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
table = dynamodb.Table('Anomalies')
users_table = dynamodb.Table('Users')
audit_table = dynamodb.Table(AUDIT_TABLE)

def get_severity(risk_score):
    if risk_score >= 70:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    else:
        return "Low"

def convert_to_local(utc_time_str):
    # Parse the ISO format timestamp
    utc_dt = datetime.fromisoformat(utc_time_str)
    # Assume the original timestamp is in UTC
    utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    # Convert to desired timezone, e.g., Eastern Time
    local_tz = pytz.timezone("America/New_York")
    local_dt = utc_dt.astimezone(local_tz)
    return local_dt.isoformat()

def save_anomalies_to_dynamodb(anomaly_events):
    for index, row in anomaly_events.iterrows():
        try:
            event_time = row.get('EventTime')
            if isinstance(event_time, str):
    # Convert to local time before saving
                event_time = convert_to_local(event_time)
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
import numpy as np

def convert_np_types(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_np_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_np_types(item) for item in obj]
    else:
        return obj

@app.route('/api/risk-report', methods=['GET'])
def get_risk_report():
    try:
       mock_events = generate_mock_data()  # or real logs if you prefer
       analyzer = CloudTrailAnalyzer()
       analyzer.collect_logs = lambda: mock_events
        
       process_df, original_data = analyzer.data_processor.preprocess_logs(
            mock_events, analyzer.unauthorized_api_calls
        )
       risk_report = risk_analyzer.generate_risk_exposure_report(original_data)
        # Convert all np.int64/np.float64 values to native types.
       risk_report = convert_np_types(risk_report)
       return jsonify(risk_report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/compliance/standards", methods=["GET"])
def get_compliance_standards():
    checker = ComplianceChecker()
    return jsonify(checker.get_all_requirements()), 200

@app.route("/api/compliance/assessment", methods=["GET"])
def get_compliance_assessment():
    global global_analysis_results
    if "original_data_json" not in global_analysis_results:
        return jsonify({"error": "No analysis data found yet. Please run analysis first."}), 400

    event_dicts = global_analysis_results["original_data_json"]

    checker = ComplianceChecker()
    assessment = checker.get_compliance_assessment_for_events(event_dicts)
    return jsonify(assessment), 200

@app.route('/get_isolation_tree', methods=['POST'])
def get_isolation_tree():
    try:
        analyzer = CloudTrailAnalyzer()
        results = analyzer.run()  # This should train the Isolation Forest
        
        # Check that the isolation forest is not None
        if not analyzer.anomaly_detector.isolation_forest:
            logger.error("Isolation Forest is not trained")
            return jsonify({"error": "Isolation Forest is not trained"}), 500

        tree_structure = analyzer.anomaly_detector.tree_to_json(tree_index=0)
        logger.info(f"Tree structure: {tree_structure}")
        return jsonify({"tree_structure": tree_structure}), 200
    except Exception as e:
        logger.error("Error in get_isolation_tree: %s", e)
        return jsonify({"error": str(e)}), 500
@app.route('/stream_isolation_tree', methods=['GET'])
def stream_isolation_tree():
     return Response(stream_with_context(generator()), mimetype='text/event-stream')
def generate_tree(node, tree, feature_names, X):
    # If node is -1, then no valid node exists. Stop recursion.
    if node == -1:
        return

    # Retrieve the number of samples that reached this node.
    n_samples = int(tree.n_node_samples[node])
    
    # Create a detailed explanation for this node.
    explanation = (
        f"This node received <b>{n_samples}</b> sample(s). "
        "Isolation Forest splits data recursively by randomly selecting a feature and a threshold. "
        "Anomalies tend to be isolated with fewer splits."
    )
    log_msg = (
        f"<b>Processing Node {node}</b>: Splitting data into two groups. "
        f"<br>Left Child: {tree.children_left[node]}, Right Child: {tree.children_right[node]}. "
        f"<br><i>{explanation}</i>"
    )
    yield f"event: log\ndata: {json.dumps({'log': log_msg})}\n\n"

    # For a split node, calculate which samples went left/right using the training data.
    if tree.feature[node] != _tree.TREE_UNDEFINED:
        feature_index = tree.feature[node]
        threshold = float(tree.threshold[node])
        
        # Compute indices for samples going left and right.
        samples_left = [i for i, x in enumerate(X[:, feature_index]) if x < threshold]
        samples_right = [i for i, x in enumerate(X[:, feature_index]) if x >= threshold]

        split_explanation = (
            f"<b>Split Node {node}</b>: The algorithm uses feature <i>{feature_names[feature_index]}</i> "
            f"with a threshold of <i>{threshold:.4f}</i>. {n_samples} sample(s) reached this node. "
            f"Samples that went left: <i>{samples_left}</i> and samples that went right: <i>{samples_right}</i>. "
            "This random splitting helps quickly isolate anomalies."
        )
        node_info = {
            "node_id": node,
            "type": "split",
            "feature": feature_names[feature_index],
            "threshold": threshold,
            "left_child": int(tree.children_left[node]),
            "right_child": int(tree.children_right[node]),
            "n_samples": n_samples
        }
        yield f"event: log\ndata: {json.dumps({'log': 'Yielding Split Node: ' + split_explanation})}\n\n"
        yield f"data: {json.dumps(node_info)}\n\n"
        time.sleep(0.5)
        # Recurse for left and right children, passing the same training data X.
        yield from generate_tree(tree.children_left[node], tree, feature_names, X)
        yield from generate_tree(tree.children_right[node], tree, feature_names, X)
    else:
        # For a leaf node, no further splitting occurs.
        leaf_explanation = (
            f"<b>Leaf Node {node}</b>: No further splits occur at this node. "
            f"<br>{n_samples} sample(s) have been isolated here. "
            "A quick isolation is a common sign of an anomaly."
        )
        leaf_info = {
            "node_id": node,
            "type": "leaf",
            "value": tree.value[node].tolist(),
            "n_samples": n_samples
        }
        yield f"event: log\ndata: {json.dumps({'log': 'Yielding Leaf Node: ' + leaf_explanation})}\n\n"
        yield f"data: {json.dumps(leaf_info)}\n\n"
        time.sleep(0.5)

def generator():
    try:
        analyzer = CloudTrailAnalyzer()
        results = analyzer.run()  # This trains the Isolation Forest and stores self.X
        # Get the first tree from the trained Isolation Forest.
        tree_estimator = analyzer.anomaly_detector.isolation_forest.estimators_[0]
        tree = tree_estimator.tree_
        total_nodes = tree.node_count

        # Log an overview message.
        yield f"event: log\ndata: {json.dumps({'log': f'<b>Total Nodes in Tree:</b> {total_nodes}'})}\n\n"
        overview = (
            "<b>Isolation Forest Overview:</b> This algorithm isolates anomalies by recursively splitting "
            "the data using randomly selected features and thresholds. Nodes that receive fewer samples often "
            "indicate that an anomaly has been isolated quickly."
        )
        yield f"event: log\ndata: {json.dumps({'log': overview})}\n\n"

        # Prepare human-friendly feature names.
        feature_names = [f"PC{i+1}" for i in range(tree_estimator.n_features_in_)]
        # Use the stored training data from the analysis.
        X = analyzer.X  
        yield from generate_tree(0, tree, feature_names, X)
        yield "event: done\ndata: <b>Tree construction complete!</b>\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"



@app.route('/save_anomalies', methods=['POST'])
def save_anomalies():
    try:
        data = request.get_json()
        anomaly_events = pd.DataFrame(data)
        save_anomalies_to_dynamodb(anomaly_events)
        return jsonify({"message": "Anomalies saved successfully"}), 200
    except Exception as e:
        logger.error("Error in /save_anomalies endpoint: %s", e)
        return jsonify({"error": str(e)}), 500

# Global variable to store mitigation log from analysis
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
        mock_events = generate_mock_data()       
        return jsonify(mock_events), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/get_all_anomalies', methods=['GET'])
def get_all_anomalies():
    try:
        anomalies = []
        response = table.scan()
        anomalies.extend(response.get("Items", []))
        
        # Loop to handle pagination in case there are more records.
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            anomalies.extend(response.get("Items", []))
        
        return jsonify({"anomalies": anomalies}), 200
    except Exception as e:
        logger.error("Error fetching all anomalies: %s", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/get_today_anomalies', methods=['GET'])
def get_today_anomalies():
     try:
        # Use UTC if your EventTime is stored in UTC; adjust if using local time.
        now = datetime.utcnow()
        start_time = (now - timedelta(hours=24)).isoformat()
        end_time = now.isoformat()

        response = table.scan(
            FilterExpression=Attr('EventTime').between(start_time, end_time)
        )
        items = response.get("Items", [])
        return jsonify({"anomalies": items}), 200
     except Exception as e:
        logger.error("Error fetching last 24hr anomalies: %s", str(e))
        return jsonify({"error": str(e)}), 500
   
def analysis_task():
    global progress_data, global_mitigation_log, global_analysis_results
    try:
        # Reset progress data
        progress_data = {"log": "", "progress": 0, "done": False}

        # Step 1: Collect Logs
        progress_data["log"] = "Step 1/6: Collecting logs from AWS CloudTrail..."
        progress_data["progress"] = 5
        mock_events = generate_mock_data()  # or real events
        time.sleep(1)  # simulate some delay

        # Step 2: Preprocessing Data
        progress_data["log"] = "Step 2/6: Preprocessing data (cleaning, feature extraction)..."
        progress_data["progress"] = 15
        analyzer = CloudTrailAnalyzer()
        analyzer.collect_logs = lambda: mock_events
        # Optionally: process_df, original_data = analyzer.data_processor.preprocess_logs(...)
        time.sleep(2)  # simulate delay

        # Step 3: Applying PCA
        progress_data["log"] = "Step 3/6: Applying PCA for dimensionality reduction..."
        progress_data["progress"] = 30
        # Suppose analyzer.run() internally applies PCA
        time.sleep(2)  # simulate delay

        # Step 4: Tuning Hyperparameters
        progress_data["log"] = "Step 4/6: Tuning hyperparameters for Isolation Forest..."
        progress_data["progress"] = 45
        time.sleep(2)  # simulate delay

        # Step 5: Detecting Anomalies
        progress_data["log"] = "Step 5/6: Detecting anomalies..."
        progress_data["progress"] = 60
        results = analyzer.run() 
        anomalies_df = results.get("anomalies_df")  # Get the DataFrame if it exists
        if anomalies_df is not None:
         anomalies_json = anomalies_df.to_dict(orient='records')
         for anomaly in anomalies_json:
            table.put_item(Item={
            "EventId": anomaly.get("EventId"),
            "EventTime": anomaly.get("EventTime"),
            "EventName": anomaly.get("EventName"),
            "Username": anomaly.get("Username"),
            "SourceIPAddress": anomaly.get("SourceIPAddress"),
            "RiskScore": float(anomaly.get("RiskScore", 0)),
            "RiskReasons": anomaly.get("RiskReasons", []),
            "ComplianceCheck": anomaly.get("ComplianceCheck", ""),
            "Resources": anomaly.get("Resources", {}),
            "BreachNotification": anomaly.get("BreachNotification", "")
        })

        else:
            anomalies_json = results.get("anomalies_json", [])
      
 # heavy processing step that returns a dictionary of results
        global_mitigation_log = analyzer.mitigation_log
        time.sleep(2)  # simulate delay

        # Step 6: Mitigating Anomalies
        progress_data["log"] = "Step 6/6: Mitigating anomalies (applying auto-remediation)..."
        progress_data["progress"] = 80
        time.sleep(2)  # simulate delay

        # Final Step: Finalizing Results and Saving Audit Record
        progress_data["log"] = "Finalizing results and saving audit record..."
        progress_data["progress"] = 90
        time.sleep(2)  # simulate delay
        
        # Compute final results:
        anomaly_count = results.get("anomaly_count", 0)
        last_run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        anomalies_json = results.get("anomalies_json", [])
        if hasattr(anomalies_json, "to_dict"):
            anomalies_json = anomalies_json.to_dict(orient='records')
       
        # Optionally, process csv_output if needed
        csv_output = results.get("csv_output", "")
        if isinstance(csv_output, list):
            csv_output = "\n".join([json.dumps(item, default=str) for item in csv_output])
       
        # Save audit record (if needed)
        audit_record = {
            'id': f"{last_run_timestamp}-{anomaly_count}",
            'timestamp': last_run_timestamp,
            'anomaly_count': anomaly_count,
            'csv_output': csv_output,
            'original_data': json.dumps(results.get("original_data", {}), default=str),
            'mitigation_log': json.dumps(global_mitigation_log, default=str)
        }
        audit_table.put_item(Item=audit_record)
        logger.info("Audit record saved: %s", audit_record['id'])
        
        # Save final results into global_analysis_results so the client can display them
        global_analysis_results = {
            "anomaly_count": anomaly_count,
            "last_run_timestamp": last_run_timestamp,
            "anomalies_json": anomalies_json,
            "original_data_json":results.get("original_data_json", [])
        }
       
        progress_data["log"] = "Analysis complete! All steps finished successfully."
        progress_data["progress"] = 100
        progress_data["done"] = True
    except Exception as e:
        progress_data["log"] = f"Error during analysis: {str(e)}"
        progress_data["done"] = True

@app.route('/run_analysis_start', methods=['POST'])

def run_analysis_start():
    global progress_data
    progress_data = {"log": "", "progress": 0, "done": False}
    thread = threading.Thread(target=analysis_task)
    thread.start()
    return jsonify({"message": "Analysis started"}), 200

# New endpoint: Retrieve full audit trail
@app.route('/get_audit_trail', methods=['GET'])
def get_audit_trail():
    try:
        response = table.scan()
        items = response.get("Items", [])
        return jsonify({"audit_trail": items}), 200
    except Exception as e:
        logger.error("Error fetching audit trail: %s", str(e))
        return jsonify({"error": str(e)}), 500

# New endpoint: Retrieve only today's audit records
@app.route('/get_today_audit', methods=['GET'])
def get_today_audit():
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        response = audit_table.scan(
            FilterExpression=Attr('timestamp').begins_with(today)
        )
        items = response.get("Items", [])
        return jsonify({"today_audit": items}), 200
    except Exception as e:
        logger.error("Error fetching today's audit records: %s", str(e))
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
import traceback

@app.route('/get_compliance_data', methods=['GET'])
def get_compliance_data():
    try:
        analyzer = CloudTrailAnalyzer()
        events = analyzer.collect_logs()  
        process_df, original_data = analyzer.data_processor.preprocess_logs(
            events, analyzer.unauthorized_api_calls
        )
        data_json = original_data.to_dict(orient='records')
        
        # Instantiate the compliance checker.
        compliance_checker = ComplianceChecker()

        # Process each event to add compliance details.
        for event in data_json:
            violations = compliance_checker.check_all_compliance(event)
            if violations:
                event["ComplianceCheck"] = "Non-compliant"
                # Create an array of detailed messages from the violations.
                event["ComplianceDetails"] = [
                    f"({v['regulation']}) {v['rule']}: {v['message']} (Severity: {v['severity']})"
                    for v in violations
                ]
            else:
                event["ComplianceCheck"] = "Compliant"
                event["ComplianceDetails"] = []
        
        # Optionally, calculate a compliance score or further aggregate details.
        total_records = len(data_json)
        non_compliant_count = sum(1 for e in data_json if e["ComplianceCheck"] == "Non-compliant")
        score = 100 if total_records == 0 else 100 * (total_records - non_compliant_count) / total_records

        return jsonify({
            "score": score,
            "data": data_json
        }), 200
    except Exception as e:
        import traceback
        print("Error in /get_compliance_data:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
@app.route("/analysis_progress")
def analysis_progress():
    def generate():
        global progress_data, global_analysis_results
        last_log = None
        last_progress = None
        while not progress_data.get("done"):
            current_log = progress_data.get("log")
            current_progress = progress_data.get("progress")
            if current_log != last_log or current_progress != last_progress:
                yield f"data: {json.dumps(progress_data)}\n\n"
                last_log = current_log
                last_progress = current_progress
            time.sleep(1)
        # Merge final results into the last event
        final_data = {**progress_data, **global_analysis_results}
        yield f"data: {json.dumps(final_data, default=str)}\n\n"

        yield "event: done\ndata: Analysis complete!\n\n"
    return Response(stream_with_context(generate()), mimetype="text/event-stream")
@app.route('/get_impact_analysis', methods=['GET'])
def get_impact_analysis():
    try:
        # Sample data for testing (or replace with your actual data retrieval)
        sample_events = [
            {
                "EventName": "DeleteBucket",
                "Username": "user1",
                "SourceIPAddress": "192.168.1.1",
                "EventTime": "2025-03-12T20:00:00Z",
                "EventId": "evt1",
                "CloudTrailEvent": "{\"detail\": \"sample\"}",
                "Resources": {"S3BucketName": "example-bucket"},
                "FailedLogin": 0,
                "EventFrequency": 10,
                "UpperThreshold": 12,
                "UserEventFrequency": 5,
                "UserThreshold": 6,
                "IPEventFrequency": 3,
                "IPThreshold": 4,
                "FailedLoginAttempts": 0,
                "SensitiveDataAccess": 0,
                "Hour": 20
            },
            {
                "EventName": "StopInstances",
                "Username": "user2",
                "SourceIPAddress": "192.168.1.2",
                "EventTime": "2025-03-12T20:05:00Z",
                "EventId": "evt2",
                "CloudTrailEvent": "{\"detail\": \"sample2\"}",
                "Resources": {"S3BucketName": "another-bucket"},
                "FailedLogin": 2,
                "EventFrequency": 15,
                "UpperThreshold": 16,
                "UserEventFrequency": 7,
                "UserThreshold": 8,
                "IPEventFrequency": 4,
                "IPThreshold": 5,
                "FailedLoginAttempts": 4,
                "SensitiveDataAccess": 1,
                "Hour": 20
            }
        ]
        unauthorized_api_calls = {"DeleteBucket", "StopInstances", "DetachPolicy"}
        data_processor = DataProcessor()
        process_df, full_df = data_processor.preprocess_logs(sample_events, unauthorized_api_calls)
        if full_df.empty:
            return jsonify({"error": "No log data found"}), 404

        risk_analyzer = RiskAnalyzer()
        # Use the new method
        impact_report = risk_analyzer.generate_risk_exposure_report(full_df, risk_threshold=50)
        return jsonify(impact_report), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Retrieve user account from DynamoDB
    try:
        response = users_table.get_item(Key={'username': username})
        user = response.get('Item')
        if not user:
            return jsonify({"msg": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"msg": "Server error", "error": str(e)}), 500

    # Compare hashed password (assuming user['password'] is stored as a bcrypt hash)
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"msg": "Invalid credentials"}), 401

    # Create a JWT token with the user's role included in additional claims.
    access_token = create_access_token(identity=username, additional_claims={"role": user["role"]})
    return jsonify({"token": access_token}), 200


def hash_password(plain_password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  # store as string
def create_user(username, plain_password, role):
    # Hash the user's password
    hashed = hash_password(plain_password)
    
    # Prepare the user item
    user_item = {
        'username': username,
        'password': hashed,
        'role': role  # e.g., "user", "admin", or "management"
    }
    
    # Insert the item into DynamoDB
    table = dynamodb.Table('Users')
    table.put_item(Item=user_item)
    print(f"User {username} created successfully.")




# Custom decorator to enforce role-based access
def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            # Ensure a valid JWT is present.
            jwt_required()(lambda: None)()
            claims = get_jwt()
            if claims.get("role") != required_role:
                # Return a message if the current user's role is insufficient.
                return jsonify({"msg": "Please contact your administrator."}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Example protected route for admins
@app.route("/admin", methods=["GET"])
@jwt_required()
@role_required("admin")
def admin_dashboard():
    return jsonify({"msg": "Welcome, admin! Here are all the details and isolation forest process data."}), 200

# Example protected route for management
@app.route("/management", methods=["GET"])
@jwt_required()
@role_required("management")
def management_dashboard():
    return jsonify({"msg": "Welcome, management! Here are the details."}), 200

# Basic user endpoint (basic view for normal users)
@app.route("/user", methods=["GET"])
@jwt_required()
def user_dashboard():
    return jsonify({"msg": "Welcome, user! Here is your basic view."}), 200
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"msg": "Please contact your administrator."}), 403
        return fn(*args, **kwargs)
    return wrapper

def hash_password(plain_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

@app.route("/admin/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json()
    username = data.get("username")
    plain_password = data.get("password")
    role = data.get("role")
    
    if not username or not plain_password or not role:
        return jsonify({"msg": "Missing required fields."}), 400

    # Hash the password before storing
    hashed = hash_password(plain_password)
    user_item = {
        "username": username,
        "password": hashed,
        "role": role
    }
    try:
        users_table.put_item(Item=user_item)
        return jsonify({"msg": "User created successfully."}), 201
    except Exception as e:
        return jsonify({"msg": "Error creating user", "error": str(e)}), 500

@app.route("/account/reset-password", methods=["POST"])
@jwt_required()
def reset_password():
    current_user = get_jwt_identity()
    data = request.get_json()
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"msg": "Both current and new passwords are required."}), 400

    # Retrieve the user from DynamoDB
    try:
        response = users_table.get_item(Key={'username': current_user})
    except Exception as e:
        return jsonify({"msg": "Error accessing user data.", "error": str(e)}), 500

    user = response.get('Item')
    if not user:
        return jsonify({"msg": "User not found."}), 404

    # Verify the current password
    if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"].encode('utf-8')):
        return jsonify({"msg": "Current password is incorrect."}), 401

    # Hash the new password and update the record
    new_hashed = hash_password(new_password)
    try:
        users_table.update_item(
            Key={'username': current_user},
            UpdateExpression="SET password = :new",
            ExpressionAttributeValues={':new': new_hashed}
        )
    except Exception as e:
        return jsonify({"msg": "Failed to update password.", "error": str(e)}), 500

    return jsonify({"msg": "Password updated successfully."}), 200
if __name__ == '__main__':
    app.run(debug=True)
