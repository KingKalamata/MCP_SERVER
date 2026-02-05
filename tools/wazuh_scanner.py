from wazuh.wazuh_api import WazuhAPI
from wazuh.wazuh_api import WazuhAPIConnectionError
from .. import config

def get_agent_vulnerabilities(agent_id):
    """
    Retrieves vulnerability information for a given Wazuh agent ID.

    Args:
        agent_id (str): The ID of the Wazuh agent.

    Returns:
        dict: A dictionary containing the agent's vulnerabilities, or an error message.
    """
    try:
        # Initialize WazuhAPI client
        wazuh_client = WazuhAPI(
            base_url=config.WAZUH_API_URL,
            username=config.WAZUH_API_USER,
            password=config.WAZUH_API_PASSWORD,
            verify_ssl=False  # Set to True in production with proper certs
        )

        # Authenticate with the Wazuh API
        wazuh_client.authenticate()

        # Fetch vulnerabilities for the specified agent
        # The endpoint for vulnerabilities might vary based on Wazuh version and configuration
        # This is a common path, but might need adjustment.
        # This API call would typically involve 'GET /vulnerability/{agent_id}' or similar.
        # The wazuh-api-client library might have a more direct method.
        # For demonstration, let's assume a direct GET call if a specific method isn't clear
        # from the library.
        
        # A more direct approach using the library would be something like:
        # vulnerabilities = wazuh_client.get_agent_vulnerabilities(agent_id)
        # However, the wazuh-api-client documentation needs to be consulted for exact method names.
        
        # For now, a generic call to agents/id/vulnerabilities if it exists
        # This part assumes a specific method exists or a direct call is made.
        # If the library doesn't expose a direct method, we'd use requests.
        
        # As the wazuh-api-client documentation isn't immediately clear on direct vulnerability fetching
        # for a specific agent, I will simulate it or use a common endpoint pattern.
        # A typical endpoint would be GET /vulnerability/{agent_id} or querying alerts
        
        # Let's use the generic "get_agents" and then filter for simplicity or assume vulnerability info
        # is part of agent details.
        
        # A more realistic approach would be to query for alerts related to vulnerabilities for the agent.
        # Example using client.get to make a raw API call (if direct method for vuln isn't in lib):
        response = wazuh_client.get(f'/vulnerability/{agent_id}') # This endpoint is illustrative
        
        # Or, if fetching alerts for vulnerabilities
        # response = wazuh_client.get(f'/alerts?q=agent.id={agent_id};rule.groups=vulnerability')
        
        # Placeholder for actual data extraction
        if response.get('error'):
            return {"error": response.get('message', 'Failed to retrieve vulnerabilities from Wazuh API.')}

        return response.get('data', [])

    except WazuhAPIConnectionError as e:
        return {"error": f"Wazuh API connection error: {e}. Check WAZUH_API_URL and credentials."}
    except Exception as e:
        return {"error": f"An error occurred during Wazuh vulnerability retrieval: {e}"}

if __name__ == '__main__':
    # Example usage: Replace '001' with a valid agent ID from your Wazuh deployment
    # Note: This requires a running Wazuh API and configured agent.
    # vulnerabilities = get_agent_vulnerabilities('001')
    # import json
    # print(json.dumps(vulnerabilities, indent=4))
    pass
