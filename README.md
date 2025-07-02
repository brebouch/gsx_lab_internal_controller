  Setting Up Python Script as a Service

Setting Up Python Script as a Service
=====================================

Setting Up the Script as a Service on CentOS
--------------------------------------------

1.  **Place the Script:**
    
    Save the Python script as `/usr/local/bin/service_script.py` and make it executable:
    
        chmod +x /usr/local/bin/service_script.py
    
2.  **Create a Systemd Service File:**
    
    Create a service file at `/etc/systemd/system/service_script.service`:
    
        sudo nano /etc/systemd/system/service_script.service
    
    Add the following content:
    
        [Unit]
        Description=Custom Python Script Service
        After=network.target
        
        [Service]
        ExecStart=/usr/bin/python3 /usr/local/bin/service_script.py
        Restart=always
        User=root
        Environment="ACCESS_TARGET_URL=http://example.com"
        Environment="API_SERVER_URL=http://api.example.com"
        Environment="API_TOKEN=your_api_token_here"
        
        [Install]
        WantedBy=multi-user.target
    
3.  **Reload Systemd and Start the Service:**
    
    Run the following commands:
    
        sudo systemctl daemon-reload
        sudo systemctl enable service_script.service
        sudo systemctl start service_script.service
    
4.  **Check the Service Status:**
    
    Verify that the service is running:
    
        sudo systemctl status service_script.service
    
5.  **Logs:**
    
    View logs for debugging:
    
        journalctl -u service_script.service -f
    

Explanation of the Script and Service
-------------------------------------

*   **XML to JSON Conversion:**
    
    The script reads the `session.xml` file and parses its contents into a JSON object using the `xml.etree.ElementTree` library.
    
*   **Environment Variables:**
    
    The environment variables `ACCESS_TARGET_URL`, `API_SERVER_URL`, and `API_TOKEN` are loaded to provide dynamic configuration.
    
*   **Web Requests:**
    *   A `GET` request is sent to the `ACCESS_TARGET_URL` every 10 seconds.
    *   If successful, a `POST` request is sent to the `/coin` endpoint of `API_SERVER_URL` with a payload of `{"session": "SESSION_ID_123"}`.
    *   If the response includes `actions` for the `caldera` service, the script initiates operations such as `run_operation`.
*   **Caldera Operations:**
    *   The script uses the updated `run_operation` function to handle Caldera operations with retry mechanisms for reliability.
    *   Operation statuses are checked using the `check_operation_run` function, ensuring proper handling of operation completion.
*   **Service Behavior:**
    
    The service is set to run on system startup and restart automatically if it crashes (`Restart=always`).
    
*   **Security:**
    
    The service runs as `root` to ensure it can access the required files. Sensitive environment variables (e.g., `API_TOKEN`) are defined in the service file.
    

Example Logs
------------

If everything is configured correctly, you should see logs like this when the service runs:

### If the `session.xml` and endpoints are working:

    Loaded session data: {'session_id': 'SESSION_ID_123', 'user': 'user1'}
    Checking URL: http://example.com
    Successfully accessed http://example.com
    Sending POST request to http://api.example.com/coin with payload: {'session': 'SESSION_ID_123'}
    POST request successful!

### If there is an issue with the `ACCESS_TARGET_URL`:

    Checking URL: http://example.com
    GET request failed with status code 404: Not Found

Notes
-----

*   **Error Handling:**
    
    The script gracefully handles errors, including issues with reading the `session.xml` file, HTTP request failures, and Caldera operation errors.
    
*   **Testing:**
    
    Test the script manually before configuring it as a service:
    
        ACCESS_TARGET_URL=http://example.com API_SERVER_URL=http://api.example.com API_TOKEN=your_api_token_here python3 /usr/local/bin/service_script.py
    
*   **Adjusting Intervals:**
    
    Modify the `CHECK_INTERVAL` constant in the script to change the frequency of checks.