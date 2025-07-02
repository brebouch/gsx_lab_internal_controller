import os
import requests
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Constants
caldera_server = os.environ.get('CALDERA_SERVER')
base_url = f'{caldera_server}:8888/api/v2'

STATUS_CODES = {
    0: 'Fail',
    1: 'Pass',
    124: 'Pass'
}


def get_header():
    return {
        'KEY': os.environ.get('CALDERA_API_TOKEN'),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


def get_response_json(response):
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        return None


def rest_get(endpoint, **kwargs):
    url = f'{base_url}/{endpoint}'
    if kwargs:
        query_params = '&'.join([f"{key}={value}" for key, value in kwargs.items()])
        url = f"{url}?{query_params}"
    return get_response_json(requests.get(url, headers=get_header(), verify=False))


def rest_post(endpoint, data, **kwargs):
    url = f'{base_url}/{endpoint}'
    if kwargs:
        query_params = '&'.join([f"{key}={value}" for key, value in kwargs.items()])
        url = f"{url}?{query_params}"
    return get_response_json(requests.post(url, json=data, headers=get_header(), verify=False))


def run_operation(name, adversary_id, group='', auto_close='true'):
    operation = {
        'name': name,
        'adversary': {
            'adversary_id': adversary_id
        },
        'group': group,
        'auto_close': auto_close
    }
    return rest_post('operations', operation)


def check_operation_run(operation_id):
    return rest_get(f'operations/{operation_id}')


def is_operation_complete(operation_id):
    status = check_operation_run(operation_id).get('state')
    return status in ['completed', 'finished']


if __name__ == '__main__':
    operation_id = run_operation('TestOp1', '89d971f4-fab8-4c15-bc8f-d64b26728c81').get('id')
    if operation_id:
        logger.info(f"Started operation with ID: {operation_id}")
        logger.info(f"Operation completed: {is_operation_complete(operation_id)}")