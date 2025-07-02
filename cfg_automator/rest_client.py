import requests
import base64



class RestAuth:


    def get_bearer_token(self, token_url, username, password, method='POST', payload='form', verify_ssl=True, token_key='access_token', token_location='body'):
        body = None
        if payload == 'form' and method == 'POST':
            response = requests.post(token_url, auth=(username, password), verify=verify_ssl)
            response.raise_for_status()
            if token_location == ' headers':




    def get_auth_header(self):
        if self.auth_type == 'basic':
            return { 'Authorization': 'Basic %s' % base64.b64encode((self.username + ':' + self.password).encode()).decode()}
        elif self.auth_type == 'api_key':
            return { self.header_key: f'{self.api_key_prefix} {self.api_key}'}
        elif self.auth_type == 'bearer':


    def __init__(self, auth_type, **kwargs):
        self.username = None
        self.password = None
        self.basic_auth = None
        self.token = None
        self.api_key = None
        self.api_key_prefix = 'Bearer'
        self.header_key = 'Authorization'
        self.auth_type = auth_type
        self.bearer_basic_authenticated = False
        if self.auth_type == 'basic':
            if 'username' in kwargs and 'password' in kwargs:
                self.username = kwargs['username']
                self.password = kwargs['password']
        elif self.auth_type == 'api_key':
            if 'header_key' in kwargs:
                self.header_key = kwargs['header_key']
            if 'api_key' in kwargs:
                self.api_key = kwargs['api_key']
                if 'api_key_prefix' in kwargs:
                    self.api_key_prefix = kwargs['api_key_prefix']
        elif self.auth_type == 'bearer':



class RestClient(object):


class FMC:
    def __init__(self, base_url, username, password, verify_ssl=True):
        """
        Initialize the FMC API client.

        :param base_url: Base URL of the FMC API.
        :param username: Username for FMC authentication.
        :param password: Password for FMC authentication.
        :param verify_ssl: Whether to verify SSL certificates.
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.headers = {}
        self._authenticate()

    def _authenticate(self):
        """
        Authenticate with the FMC API and set the headers for future requests.
        """
        auth_url = f"{self.base_url}/api/fmc_platform/v1/auth/generatetoken"
        response = requests.post(auth_url, auth=(self.username, self.password), verify=self.verify_ssl)

        if response.status_code == 204:
            self.headers['X-auth-access-token'] = response.headers.get('X-auth-access-token')
            self.headers['Content-Type'] = 'application/json'
        else:
            raise Exception(f"Authentication failed with status code {response.status_code}: {response.text}")

    def get(self, endpoint):
        """
        Perform a GET request to the specified FMC API endpoint.

        :param endpoint: API endpoint to send the request to.
        :return: JSON response from the API.
        """
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        return self._handle_response(response)

    def post(self, endpoint, data):
        """
        Perform a POST request to the specified FMC API endpoint.

        :param endpoint: API endpoint to send the request to.
        :param data: Data to include in the POST request.
        :return: JSON response from the API.
        """
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, headers=self.headers, json=data, verify=self.verify_ssl)
        return self._handle_response(response)

    def _handle_response(self, response):
        """
        Handle the API response, checking for errors.

        :param response: Response object from the requests library.
        :return: JSON data if the response is successful.
        """
        if response.ok:
            return response.json()
        else:
            raise Exception(f"API request failed with status code {response.status_code}: {response.text}")



# Example usage:
fmc_client = FMC(base_url='https://198.18.133.124', username='admin', password='F!rep0wer')
response = fmc_client.get('api/fmc_config/v1/domain/default/policy/accesspolicies')
print(response)
