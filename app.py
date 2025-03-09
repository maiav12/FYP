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
from datetime import datetime
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


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])

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

def save_anomalies_to_dynamodb(anomaly_events):
    for index, row in anomaly_events.iterrows():
        try:
            event_time = row.get('EventTime')
            if isinstance(event_time, str):
                event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S').isoformat()
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
        today = datetime.now().strftime("%Y-%m-%d")
        response = table.scan(
            FilterExpression=Attr('EventTime').begins_with(today)
        )
        items = response.get("Items", [])
        return jsonify({"anomalies": items}), 200
    except Exception as e:
        logger.error("Error fetching today’s anomalies: %s", str(e))
        return jsonify({"error": str(e)}), 500
@app.route('/run_analysis_start', methods=['POST'])
def run_analysis():
    global global_mitigation_log
    try:
        mock_events = generate_mock_data()  # or real events
        analyzer = CloudTrailAnalyzer()
        analyzer.collect_logs = lambda: mock_events
        results = analyzer.run()  # This method runs analysis and automatically mitigates anomalies
        global_mitigation_log = analyzer.mitigation_log
       
        anomaly_count = results.get("anomaly_count", 0)
        anomalies_json = results.get("anomalies_json", [])
        if hasattr(anomalies_json, "to_dict"):
            anomalies_json = anomalies_json.to_dict(orient='records')
       
        last_run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
       
        # Process csv_output in case it is a list of dictionaries.
        csv_output = results.get("csv_output", "")
        if isinstance(csv_output, list):
            # Debug: print the type of items in csv_output.
            for i, item in enumerate(csv_output):
                logger.info("csv_output[%d] type: %s", i, type(item))
            csv_output = "\n".join([json.dumps(item, default=str) for item in csv_output])
       
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
       
        return jsonify({
            "message": "Analysis complete!",
            "anomaly_count": anomaly_count,
            "data": anomalies_json,
            "last_run_timestamp": last_run_timestamp
        }), 200
    except Exception as e:
        logger.error("Error in /run_analysis_start: %s", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



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
