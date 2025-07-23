import logging
import os
import time
import xml.etree.ElementTree as ET
import threading
import sqlite3

import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS

import system_info

app = Flask(__name__)
CORS(app, origins=["http://198.18.5.179"])


DEBOUNCE_FAIL_THRESHOLD = 4  # Number of missed checks before "down"
DEBOUNCE_SUCCESS_THRESHOLD = 1  # Number of successful checks before "up"

# --- SQLite configuration for external health ---
DB_PATH = "/tmp/health_status.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY, last_success REAL, response_time REAL)")
    c.execute("INSERT OR IGNORE INTO health (id, last_success, response_time) VALUES (1, 0, 0)")
    conn.commit()
    conn.close()

def set_health(last_success, response_time):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE health SET last_success=?, response_time=? WHERE id=1", (last_success, response_time))
    conn.commit()
    conn.close()

def get_health():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_success, response_time FROM health WHERE id=1")
    row = c.fetchone()
    conn.close()
    if row:
        return float(row[0]), float(row[1])
    else:
        return 0.0, 0.0

# Initialize DB at startup
init_db()


def check_external_service_health(api_server_url, timeout=3):
    """Ping the external API root and return (reachable, response_time_ms)."""
    logger.info(f"Checking health of external API at {api_server_url} with timeout {timeout}s")
    try:
        start = time.perf_counter()
        resp = requests.get(api_server_url, timeout=timeout)
        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.info(f"Got response from {api_server_url} in {elapsed_ms:.2f} ms with status {resp.status_code}")
        if 200 <= resp.status_code < 300:
            return True, elapsed_ms
        else:
            logger.warning(f"Received unexpected status code {resp.status_code} from external API")
            return False, elapsed_ms
    except requests.exceptions.Timeout:
        logger.error(f"Timeout when connecting to external API at {api_server_url}")
        return False, 0.0
    except requests.exceptions.ConnectionError as ce:
        logger.error(f"Connection error when connecting to external API at {api_server_url}: {ce}")
        return False, 0.0
    except Exception as e:
        logger.error(f"Unexpected error when checking external API health: {e}")
        return False, 0.0

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

run_operation = caldera_mock.run_operation
check_operation_run = caldera_mock.check_operation_run
get_dcloud_session_xml = dcloud_session_mock.get_dcloud_session_xml

# Load environment variables
load_dotenv()

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# --- Define default fallback devices template ---
DEFAULT_FALLBACK_DEVICES_TEMPLATE = {
    "198.18.135.155": {
        "reachable": False,
        "ip": "198.18.13.155",
        "hostname": "CoinForge-1",
        "cpu_utilization": "0.0",
        "memory_used_mb": "0",
        "memory_total_mb": "0",
        "network_bytes_in": "0",
        "network_bytes_out": "0",
        "remote_connection": False,
        "last_updated": 0.0
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
        "last_updated": 0.0
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
        "last_updated": 0.0
    }
}

# --- Global device health state (in memory) ---
coin_forge_health = {}
for ip, data in DEFAULT_FALLBACK_DEVICES_TEMPLATE.items():
    coin_forge_health[ip] = data.copy()
    coin_forge_health[ip]["last_updated"] = time.time()

health_lock = threading.Lock()

# Flask app

# Constants
SESSION_XML_PATH = "/dcloud/session.xml"
DEVICE_HEALTH_TIMEOUT_SECONDS = 900

def read_session_xml_as_json(xml_path):
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

            now = time.time()
            # Get or initialize device state
            with health_lock:
                device_state = coin_forge_health.get(device_ip, DEFAULT_FALLBACK_DEVICES_TEMPLATE.get(device_ip, {})).copy()
                device_state.setdefault("consecutive_failures", 0)
                device_state.setdefault("consecutive_successes", 0)
                device_state.setdefault("state", "down")
                # Update health data fields from incoming data
                for key, value in data.items():
                    device_state[key] = value

                device_state["last_updated"] = now
                device_state["consecutive_failures"] = 0
                device_state["consecutive_successes"] += 1

                # Debounce: Only mark up after threshold
                if device_state["state"] != "up" and device_state["consecutive_successes"] >= DEBOUNCE_SUCCESS_THRESHOLD:
                    device_state["state"] = "up"
                    # Optional: Reset counter on state change
                    device_state["consecutive_successes"] = 0

                device_state["reachable"] = (device_state["state"] == "up")
                coin_forge_health[device_ip] = device_state

            logger.info(f"Updated debounced coin_forge_health for device IP {device_ip}.")
            return jsonify({"message": "Health-check received.", "device_ip": device_ip}), 200
        except Exception as e:
            logger.error(f"Error in health_check POST endpoint: {e}")
            return jsonify({"error": str(e)}), 500

    elif request.method == "GET":
        current_time = time.time()
        with health_lock:
            for ip, device_data in coin_forge_health.items():
                last_updated = device_data.get("last_updated", 0)
                device_data.setdefault("consecutive_failures", 0)
                device_data.setdefault("consecutive_successes", 0)
                device_data.setdefault("state", "up")
                if (current_time - last_updated) > DEVICE_HEALTH_TIMEOUT_SECONDS:
                    device_data["consecutive_failures"] += 1
                    device_data["consecutive_successes"] = 0
                    # Debounce: Only mark down after threshold
                    if device_data["state"] != "down" and device_data["consecutive_failures"] >= DEBOUNCE_FAIL_THRESHOLD:
                        device_data["state"] = "down"
                        # Optional: Reset counter on state change
                        device_data["consecutive_failures"] = 0
                    device_data["reachable"] = (device_data["state"] == "up")
                # else: success handled in POST
                coin_forge_health[ip] = device_data

        # Check external API health
        api_server_url = os.getenv("API_SERVER_URL")
        if not api_server_url:
            logger.warning("API_SERVER_URL environment variable is not set.")
            external_svc_reachable = False
            external_svc_response_time = 0.0
        else:
            external_svc_reachable, external_svc_response_time = check_external_service_health(api_server_url, timeout=1)

        response_data = {
            "external_svc_reachable": external_svc_reachable,
            "external_svc_timeouts": 0,  # Optionally track real timeouts
            "external_svc_response_time": external_svc_response_time,
        }

        with health_lock:
            # Exclude debounce counters from output if you wish
            response_data.update({
                ip: {k: v for k, v in data.items() if k not in ("consecutive_failures", "consecutive_successes", "state")}
                for ip, data in coin_forge_health.items()
            })

        response_data.update({'controller_health': system_info.get_sys_info()})

        return jsonify(response_data), 200

@app.route("/coins", methods=["POST"])
def coins_endpoint():
    try:
        api_server_url = os.getenv("API_SERVER_URL")
        api_token = os.getenv("API_TOKEN")

        if not all([api_server_url, api_token]):
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

            if 200 <= response.status_code < 300:
                now = time.time()
                set_health(now, response_time_ms)
                logger.info(f"/coins: Success! Setting last_success = {now}, response_time = {response_time_ms}")
            else:
                logger.error(
                    f"POST request to API_SERVER_URL failed with status code {response.status_code}: {response.text}.")
                return jsonify({"error": f"Failed to process session with status code {response.status_code}."}), response.status_code

        except requests.exceptions.Timeout:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            logger.error(f"POST request to API_SERVER_URL timed out after {response_time_ms:.2f} ms.")
            return jsonify({"error": f"Failed to process session: Request to external service timed out."}), 504

        except requests.exceptions.ConnectionError as ce:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            logger.error(f"POST request to API_SERVER_URL failed to connect: {ce}.")
            return jsonify({"error": f"Failed to process session: Connection to external service failed."}), 503

        except requests.exceptions.RequestException as e:
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            logger.error(f"An unexpected error occurred during POST request to API_SERVER_URL: {e}.")
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