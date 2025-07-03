import os
import logging
import time

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
from caldera.py_caldera import run_operation, check_operation_run

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Flask app
app = Flask(__name__)

# Constants
SESSION_XML_PATH = "/dcloud/session.xml"

def read_session_xml_as_json(xml_path):
    """
    Reads the session.xml file and converts its data to JSON.
    :param xml_path: Path to the XML file.
    :return: JSON representation of the XML data.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        session_data = {child.tag: child.text for child in root}
        return session_data
    except Exception as e:
        logger.error(f"Error reading or parsing XML file: {e}")
        return None


def retry_run_operation(operation_name, adversary, group, retries=3, delay=5):
    """
    Retry mechanism for running a Caldera operation.
    """
    for attempt in range(retries):
        try:
            response = run_operation(operation_name, adversary, group)
            if response:
                return response
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
        time.sleep(delay)
    return None


def post_caldera_status(api_server_url, api_token, session_id, operation_name, operation_id, status):
    """
    Posts the operation status to the /caldera endpoint.
    """
    headers = {"Authorization": f'Bearer {api_token}'}
    payload = {
        "session_id": session_id,
        "operation_name": operation_name,
        "operation_id": operation_id,
        "status": status
    }
    try:
        logger.info(f"Posting status update to {api_server_url}/caldera with payload: {payload}")
        response = requests.post(f"{api_server_url}/caldera", json=payload, headers=headers)
        if response.status_code == 200:
            logger.info(f"Successfully updated operation '{operation_name}' with status '{status}'.")
        else:
            logger.error(f"Failed to update operation '{operation_name}' with status '{status}'. Response: {response.text}")
    except Exception as e:
        logger.error(f"Error posting operation status for '{operation_name}': {e}")


@app.route("/coins", methods=["POST"])
def coins_endpoint():
    """
    Endpoint for processing incoming requests from devices.
    """
    try:
        # Load environment variables
        api_server_url = os.getenv("API_SERVER_URL")
        api_token = os.getenv("API_TOKEN")

        if not all([api_server_url, api_token]):
            return jsonify({"error": "API_SERVER_URL and API_TOKEN environment variables must be set."}), 500

        # Parse the incoming request
        data = request.get_json()
        if not data or "source" not in data:
            return jsonify({"error": "Invalid payload. 'source' key is required."}), 400

            # Read session.xml and convert to JSON
        session_data = read_session_xml_as_json(SESSION_XML_PATH)
        if not session_data:
            logger.error("Failed to read session.xml or parse it into JSON.")
            return jsonify({"error": "Unable to obtain dcloud session id"}), 400

        session_id = session_data.get("id")
        source = data["source"]

        # Make a POST request to the API_SERVER_URL with the session payload
        payload = {"session": session_id}
        headers = {"Authorization": f'Bearer {api_token}'}

        logger.info(f"Processing session: {session_id}")
        response = requests.post(f"{api_server_url}/coin", json=payload, headers=headers)

        if response.status_code == 200:
            response_data = response.json()
            logger.info("POST request to API_SERVER_URL successful!")

            # Process actions in the response
            if 'actions' in response_data and isinstance(response_data['actions'], list):
                for action in response_data['actions']:
                    if 'service' not in action:
                        continue

                    # Handle run_operation task
                    if action['service'] == 'caldera' and action['task'] == 'run_operation':
                        adversary = action.get('adversary')
                        group = action.get('group', '')
                        operation_name = action.get('operation_name')

                        if not all([adversary, operation_name]):
                            logger.warning(f"Invalid parameters in action: {action}")
                            continue

                        try:
                            operation_response = retry_run_operation(operation_name, adversary, group)
                            if operation_response:
                                operation_id = operation_response.get('id')
                                logger.info(f"Operation '{operation_name}' started with ID: {operation_id}")
                                post_caldera_status(api_server_url, api_token, session_id, operation_name, operation_id, "started")
                            else:
                                logger.error(f"Failed to start operation '{operation_name}'.")
                        except Exception as e:
                            logger.error(f"Error running operation '{operation_name}': {e}")

                    # Handle check_operation task
                    elif action['service'] == 'caldera' and action['task'] == 'check_operation':
                        operation_id = action.get('operation_id')

                        if not operation_id:
                            logger.warning(f"Invalid parameters in action: {action}")
                            continue

                        try:
                            operation_status = check_operation_run(operation_id)
                            if operation_status:
                                status = operation_status.get('status')
                                logger.info(f"Operation '{operation_id}' checked with current status: {status}")
                                post_caldera_status(api_server_url, api_token, session_id, action.get('operation_name'), operation_id, status)
                            else:
                                logger.error(f"Failed to check operation '{operation_id}'.")
                        except Exception as e:
                            logger.error(f"Error checking operation '{operation_id}': {e}")

            return jsonify({"message": "Session processed successfully."}), 200
        else:
            logger.error(f"POST request to API_SERVER_URL failed with status code {response.status_code}: {response.text}")
            return jsonify({"error": f"Failed to process session with status code {response.status_code}."}), response.status_code

    except Exception as e:
        logger.error(f"Error during processing: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting Flask app with Waitress...")
    serve(app, host="0.0.0.0", port=5001)