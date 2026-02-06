import httpx
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

async def search_cve_mitre(keyword):
    """
    Searches for CVEs on cve.mitre.org based on a keyword.

    Args:
        keyword (str): The keyword to search for.

    Returns:
        list: A list of dictionaries, where each dictionary represents a CVE.
    """
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')
        
        cve_list = []
        # Find the table with the CVE results
        table = soup.find('div', {'id': 'TableWithRules'})
        if not table:
            return []

        rows = table.find_all('tr')
        for row in rows[1:]:  # Skip the header row
            cols = row.find_all('td')
            if len(cols) == 2:
                cve_id = cols[0].text.strip()
                description = cols[1].text.strip()
                cve_list.append({"cve_id": cve_id, "description": description})
        
        return cve_list
    except httpx.HTTPError as e:
        logger.error(f"HTTP error occurred while searching CVE: {e}")
        return {"error": f"An error occurred: {e}"}
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return {"error": f"An unexpected error occurred: {e}"}
