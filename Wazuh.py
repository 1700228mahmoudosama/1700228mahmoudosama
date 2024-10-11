import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings()
# Wazuh API endpoint and credentials
WAZUH_API_URL = "https://<Wazuh_manger_ip>:55000/security/user/authenticate"
WAZUH_USER = "<API_username"
WAZUH_PASSWORD = "<API_password"


# Function to authenticate and retrieve token
def authenticate():
    try:
        response = requests.post(
            WAZUH_API_URL, auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD), verify=False
        )
        response.raise_for_status()
        token = response.json().get("data").get("token")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Wazuh: {e}")
        return None


# Function to use the token to get active agents
def get_active_agents(token):
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        endpoint = "https://40.85.114.253:55000/agents?status=active"  # Replace with actual host and port
        try:
            response = requests.get(endpoint, headers=headers, verify=False)
            response.raise_for_status()
            agents_data = response.json()
            return agents_data.get("data").get("affected_items")
        except requests.exceptions.RequestException as e:
            print(f"Error using token: {e}")
            return None
    else:
        print("No token available")
        return None


# Example usage
if __name__ == "__main__":
    token = authenticate()
    if token:
        active_agents = get_active_agents(token)
        if active_agents:
            print(f"Number of active agents: {len(active_agents)}")
            for agent in active_agents:
                print(f"Agent ID: {agent['id']}, Platform: {agent.get('os').get('platform')}")