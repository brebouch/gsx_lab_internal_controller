import requests


import requests

def is_secure_access_tunnel_up(vmanage_host, username, password, branch_name):
    """
    Checks if the Cisco Secure Access tunnel to a specified branch is up and active.

    Args:
        vmanage_host (str): vManage URL, e.g. 'https://vmanage.example.com'
        username (str): vManage username
        password (str): vManage password
        branch_name (str): The vdevice-host-name of the branch, e.g. 'BRANCH-SITE-105-C8Kv'

    Returns:
        bool: True if an 'active' Cisco Secure Access tunnel is 'Up' and sig-state is 'UP', else False
    """
    # Authenticate to vManage
    session = requests.session()
    auth_url = f"{vmanage_host}/j_security_check"
    auth_data = {'j_username': username, 'j_password': password}
    auth_response = session.post(auth_url, data=auth_data, verify=False)
    if auth_response.status_code != 200 or 'html' in auth_response.text:
        raise Exception("Failed to authenticate to vManage. Check credentials.")

    # Get token if required
    token_url = f"{vmanage_host}/dataservice/client/token"
    token_response = session.get(token_url, verify=False)
    if token_response.status_code == 200:
        session.headers['X-XSRF-TOKEN'] = token_response.text

    # Query SIG/SSE tunnels
    tunnels_url = f"{vmanage_host}/dataservice/device/sig/getSigTunnelList?lastNHours=1"
    response = session.get(tunnels_url, verify=False)
    if response.status_code != 200:
        raise Exception("Failed to retrieve tunnels from vManage.")
    tunnels = response.json().get('data', [])

    # Check for an active, up tunnel for the given branch and Cisco Secure Access
    for tunnel in tunnels:
        if (tunnel.get('vdevice-host-name') == branch_name and
            tunnel.get('provider') == 'Cisco Secure Access' and
            tunnel.get('ha-pair', '').lower() == 'active' and
            tunnel.get('device-state', '').lower() == 'up' and
            tunnel.get('sig-state', '').upper() == 'UP'):
            return True
    return False

# Example usage:
sig_sse_tunnels = is_secure_access_tunnel_up('https://198.18.133.10', 'admin', 'C1sco12345', "BRANCH-SITE-105-C8Kv")
print(sig_sse_tunnels)