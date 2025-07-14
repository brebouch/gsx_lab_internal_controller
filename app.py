import logging
import os
import time
import xml.etree.ElementTree as ET
import threading

import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify

# Mocking caldera and dcloud_session for standalone execution if actual modules are not present
class MockCaldera:
    def run_operation(self, operation_name, adversary, group):
        logging.info(f"Mock Caldera: Running operation {operation_name} with adversary {adversary} and group {group}")
        time.sleep(0.1)
        return {"id": "mock_op_id_123"}

    def check_operation_run(self, operation_id):
        logging.info(f"Mock Caldera: Checking operation {operation_id}")
        time.sleep(0.05)
        return {"status": "completed"}

class MockDcloudSession:
    def get_dcloud_session_xml(self):
        logging.info("Mock dCloud: Getting session XML.")
        with open("session.xml", "w") as f:
            f.write("<session><id>mock_session_123</id></session>")

caldera_mock = MockCaldera()
dcloud_session_mock = MockDcloudSession()

# Replace actual imports with mocks if needed for testing without full environment
run_operation = caldera_mock.run_operation
check_operation_run = caldera_mock.check_operation_run
get_dcloud_session_xml = dcloud_session_mock.get_dcloud_session_xml


# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# --- Define default fallback devices template ---
# Initialize with a last_updated timestamp. This will be updated when a real health check comes in.
DEFAULT_FALLBACK_DEVICES_TEMPLATE = {
    "198.18.5.154": {
        "reachable": False,
        "ip": "198.18.5.154",
        "hostname": "CoinForge-1",
        "cpu_utilization": "0.0",
        "memory_used_mb": "0",
        "memory_total_mb": "0",
        "network_bytes_in": "0",
        "network_bytes_out": "0",
        "remote_connection": False,
        "last_updated": 0.0 # Will be set to time.time() on app start or when reset
    },
    "198.18.5.155": {
        "reachable": False,
        "ip": "198.18.5.155",
        "hostname": "CoinForge-2",
        "cpu_utilization": "0.0",
        "memory_used_mb": "0",
        "memory_total_mb": "0",
        "network_bytes_in": "0",
        "network_bytes_out": "0",
        "remote_connection": False,
        "last_updated": 0.0 # Will be set to time.time() on app start or when reset
    },
    "198.18.5.156": {
        "reachable": False,
        "ip": "198.18.5.156",
        "hostname": "CoinForge-3",
        "cpu_utilization": "0.0",
        "memory_used_mb": "0",
        "memory_total_mb": "0",
        "network_bytes_in": "0",
        "network_bytes_out": "0",
        "remote_connection": False,
        "last_updated": 0.0 # Will be set to time.time() on app start or when reset
    }
}

# --- Global health dictionaries and variables ---
# Initialize coin_forge_health with a deep copy of the default fallback devices template
# and set initial last_updated time.
coin_forge_health = {}
for ip, data in DEFAULT_FALLBACK_DEVICES_TEMPLATE.items():
    coin_forge_health[ip] = data.copy()
    coin_forge_health[ip]["last_updated"] = time.time() # Set initial last_updated

health_lock = threading.Lock() # Lock for coin_forge_health dictionary

# Global variables for external service status
external_svc_reachable = False
external_svc_timeouts = 0
external_svc_response_time = 0.0 # in milliseconds
external_svc_lock = threading.Lock() # Lock for external service status variables

# Flask app
app = Flask(__name__)

# Constants
SESSION_XML_PATH = "session.xml"
DEVICE_HEALTH_TIMEOUT_SECONDS = 65


def read_session_xml_as_json(xml_path):
    """
    Reads the session.xml file and converts its data to JSON.
    :param xml_path: Path to the XML file.
    :return: JSON representation of the XML data.
    """
    if not (os.path.isfile(xml_path)):
        get_dcloud_session_xml()
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
            logger.error(
                f"Failed to update operation '{operation_name}' with status '{status}'. Response: {response.text}")
    except Exception as e:
        logger.error(f"Error posting operation status for '{operation_name}': {e}")


@app.route("/health-check", methods=["POST", "GET"])
def health_check():
    if request.method == "POST":
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid JSON payload."}), 400

            device_ip = data.get("ip")
            if not device_ip:
                return jsonify({"error": "Payload missing 'ip' field."}), 400

            # Create a copy of the incoming data and add 'reachable: True' and 'last_updated'
            device_health_data = data.copy()
            device_health_data["reachable"] = True
            device_health_data["last_updated"] = time.time() # Update timestamp on successful post

            with health_lock:
                coin_forge_health[device_ip] = device_health_data
            logger.info(f"Updated coin_forge_health for device IP {device_ip}.")
            return jsonify({"message": "Health-check received.", "device_ip": device_ip}), 200
        except Exception as e:
            logger.error(f"Error in health_check POST endpoint: {e}")
            return jsonify({"error": str(e)}), 500

    elif request.method == "GET":
        current_time = time.time()

        with health_lock:
            # Iterate over a copy of keys to safely modify the dictionary during iteration
            for ip in list(coin_forge_health.keys()):
                device_data = coin_forge_health[ip]
                last_updated = device_data.get("last_updated", 0) # Default to 0 if not present

                if (current_time - last_updated) > DEVICE_HEALTH_TIMEOUT_SECONDS:
                    logger.warning(f"Device {ip} health data is stale (last updated {current_time - last_updated:.2f}s ago). Resetting.")
                    # Reset to default values for this specific device
                    if ip in DEFAULT_FALLBACK_DEVICES_TEMPLATE:
                        reset_data = DEFAULT_FALLBACK_DEVICES_TEMPLATE[ip].copy()
                        reset_data["reachable"] = False # Explicitly set to false if stale
                        reset_data["last_updated"] = current_time # Update reset timestamp
                        coin_forge_health[ip] = reset_data
                    else:
                        # If an IP not in our default template somehow got in and went stale,
                        # mark it unreachable and reset its timestamp and basic values.
                        coin_forge_health[ip]["reachable"] = False
                        coin_forge_health[ip]["cpu_utilization"] = "0.0"
                        coin_forge_health[ip]["memory_used_mb"] = "0"
                        coin_forge_health[ip]["memory_total_mb"] = "0"
                        coin_forge_health[ip]["network_bytes_in"] = "0"
                        coin_forge_health[ip]["network_bytes_out"] = "0"
                        coin_forge_health[ip]["remote_connection"] = False
                        coin_forge_health[ip]["last_updated"] = current_time
                        logger.warning(f"Stale device {ip} not in default template; marking unreachable and resetting basic stats.")


        with external_svc_lock:
            current_external_svc_reachable = external_svc_reachable
            current_external_svc_timeouts = external_svc_timeouts
            current_external_svc_response_time = external_svc_response_time

        response_data = {
            "external_svc_reachable": current_external_svc_reachable,
            "external_svc_timeouts": current_external_svc_timeouts,
            "external_svc_response_time": current_external_svc_response_time,
        }

        with health_lock:
            response_data.update(coin_forge_health)

        return jsonify(response_data), 200


@app.route("/coins", methods=["POST"])
def coins_endpoint():
    """
    Endpoint for processing incoming requests from devices.
    """
    global external_svc_reachable, external_svc_timeouts, external_svc_response_time

    try:
        api_server_url = os.getenv("API_SERVER_URL")
        api_token = os.getenv("API_TOKEN")

        if not all([api_server_url, api_token]):
            with external_svc_lock:
                external_svc_reachable = False
                external_svc_timeouts = 0
                external_svc_response_time = 0.0
            return jsonify({"error": "API_SERVER_URL and API_TOKEN environment variables must be set."}), 500

        data = request.get_json()
        if not data or "source" not in data:
            return jsonify({"error": "Invalid payload. 'source' key is required."}), 400

        session_data = read_session_xml_as_json(SESSION_XML_PATH)
        if not session_data:
            logger.error("Failed to read session.xml or parse it into JSON.")
            return jsonify({"error": "Unable to obtain dcloud session id"}), 400

        session_id = session_data.get("id")
        source = data["source"]

        payload = {"session": session_id}
        headers = {"Authorization": f'Bearer {api_token}'}

        logger.info(f"Processing session: {session_id}. Making outgoing call to {api_server_url}/coin")

        start_time = time.perf_counter()
        try:
            response = requests.post(f"{api_server_url}/coin", json=payload, headers=headers, timeout=10)
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000

            with external_svc_lock:
                if 200 <= response.status_code < 300:
                    external_svc_reachable = True
                    external_svc_response_time = response_time_ms # Keep actual response time on success
                    logger.info("POST request to API_SERVER_URL successful!")
                else:
                    # Non-2xx response: reset external service status
                    external_svc_reachable = False
                    external_svc_timeouts = 0 # Reset timeouts
                    external_svc_response_time = 0.0 # Reset response time as per user request
                    logger.error(
                        f"POST request to API_SERVER_URL failed with status code {response.status_code}: {response.text}. Resetting external service data.")
                    return jsonify({"error": f"Failed to process session with status code {response.status_code}."}), response.status_code

        except requests.exceptions.Timeout:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            with external_svc_lock:
                external_svc_reachable = False
                external_svc_timeouts = 0 # Reset timeouts
                external_svc_response_time = 0.0 # Reset response time as per user request
            logger.error(f"POST request to API_SERVER_URL timed out after {response_time_ms:.2f} ms. Resetting external service data.")
            return jsonify({"error": f"Failed to process session: Request to external service timed out."}), 504

        except requests.exceptions.ConnectionError as ce:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            with external_svc_lock:
                external_svc_reachable = False
                external_svc_timeouts = 0 # Reset timeouts
                external_svc_response_time = 0.0 # Reset response time as per user request
            logger.error(f"POST request to API_SERVER_URL failed to connect: {ce}. Resetting external service data.")
            return jsonify({"error": f"Failed to process session: Connection to external service failed."}), 503

        except requests.exceptions.RequestException as e:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            with external_svc_lock:
                external_svc_reachable = False
                external_svc_timeouts = 0 # Reset timeouts
                external_svc_response_time = 0.0 # Reset response time as per user request
            logger.error(f"An unexpected error occurred during POST request to API_SERVER_URL: {e}. Resetting external service data.")
            return jsonify({"error": f"Failed to process session: An unexpected error occurred with external service."}), 500

        # Process actions in the response (only if the request to API_SERVER_URL was successful)
        if 'actions' in response.json() and isinstance(response.json()['actions'], list):
            try:
                for action in response.json()['actions']:
                    if 'service' not in action:
                        continue

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
                                post_caldera_status(api_server_url, api_token, session_id, operation_name,
                                                    operation_id, "started")
                            else:
                                logger.error(f"Failed to start operation '{operation_name}'.")
                        except Exception as e:
                            logger.error(f"Error running operation '{operation_name}': {e}")

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
                                post_caldera_status(api_server_url, api_token, session_id,
                                                    action.get('operation_name'), operation_id, status)
                            else:
                                logger.error(f"Failed to check operation '{operation_id}'.")
                        except Exception as e:
                            logger.error(f"Error checking operation '{operation_id}': {e}")
            except Exception as e:
                logger.error(f"Error running action: {e}")

        return jsonify({"message": "Session processed successfully."}), 200

    except Exception as e:
        logger.error(f"Error during processing: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    from waitress import serve

    logger.info("Starting Flask app with Waitress...")
    if not os.path.exists(SESSION_XML_PATH):
        dcloud_session_mock.get_dcloud_session_xml()
    serve(app, host="0.0.0.0", port=5001)