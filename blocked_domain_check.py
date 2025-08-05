import requests

def is_umbrella_blocked(domain):
    """
    Makes an HTTPS request to the domain and returns True if the response HTML
    matches a Cisco Umbrella block page, otherwise returns False.
    """
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=5, verify=True)
        html = response.text

        # Check for both block indicators in the HTML
        if "<title>Site Blocked</title>" in html and "This site is blocked." in html:
            return True
        else:
            return False
    except requests.RequestException:
        # If the request fails (timeout, connection error, etc.), consider it not blocked
        return False

# Example usage
if __name__ == "__main__":
    domain = "internetbadguys.com"
    result = is_umbrella_blocked(domain)
    print(f"Domain {domain} is blocked by Umbrella: {result}")