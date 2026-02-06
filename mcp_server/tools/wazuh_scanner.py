from wazuh_api_client import AsyncWazuhClient
import logging
from .. import config

logger = logging.getLogger(__name__)

async def get_agent_vulnerabilities(agent_id):
    """
    Retrieves vulnerability information for a given Wazuh agent ID.

    Args:
        agent_id (str): The ID of the Wazuh agent.

    Returns:
        dict: A dictionary containing the agent's vulnerabilities, or an error message.
    """
    try:
        # Initialize WazuhAPI client
        async with AsyncWazuhClient(
            base_url=config.WAZUH_API_URL,
            version="", # Let it detect the version
            username=config.WAZUH_API_USER,
            password=config.WAZUH_API_PASSWORD,
            verify=False  # Set to True in production with proper certs
        ) as wazuh_client:

            logger.info(f"Fetching vulnerabilities for agent {agent_id} from Wazuh")
            # Using the direct request method as specific managers might be version-dependent
            # Vulnerability endpoint in Wazuh v4
            endpoint = f"/vulnerability/{agent_id}"
            response = await wazuh_client.request("GET", endpoint)

            if response.get('error') != 0:
                return {"error": response.get('message', 'Failed to retrieve vulnerabilities from Wazuh API.')}

            return response.get('data', {}).get('affected_items', [])

    except Exception as e:
        logger.exception(f"An error occurred during Wazuh vulnerability retrieval for agent {agent_id}")
        return {"error": f"An error occurred: {e}"}
