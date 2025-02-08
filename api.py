from flask import Flask, jsonify, request
import pandas as pd
from main import CloudTrailAnalyzer
from tests.mock_data_generator import generate_mock_data

app = Flask(__name__)
analyzer = CloudTrailAnalyzer()

@app.route('/get_logs', methods=['GET'])
def get_logs():
    try:
        # Use mock data in this example
        mock_events = generate_mock_data()
        
        # Return the raw events as JSON
        return jsonify(mock_events), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/run_analysis', methods=['POST'])
def run_analysis():
    try:
        # 1) Run the analysis
        mock_events = generate_mock_data()  # or real events
        analyzer = CloudTrailAnalyzer()
        analyzer.collect_logs = lambda: mock_events
        results = analyzer.run()
        print("DEBUG: run_analysis endpoint reached. Returning success message.")

        # 2) Instead of returning CSV, just send a success message
        return jsonify({"message": "Analysis complete!"}), 200
        
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


if __name__ == '__main__':
    app.run(debug=True)
