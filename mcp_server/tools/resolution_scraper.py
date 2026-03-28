import httpx
from bs4 import BeautifulSoup
import urllib.parse
import logging

logger = logging.getLogger(__name__)

async def search_vulnerability_resolution(query):
    """
    Searches for resolutions to vulnerabilities based on a query (CVE ID or description).

    Args:
        query (str): The CVE ID or a description of the vulnerability.

    Returns:
        list: A list of dictionaries, where each dictionary contains a title and URL of a potential resolution.
    """
    search_results = []
    
    # Generic Google search for resolution
    encoded_query = urllib.parse.quote_plus(f"{query} vulnerability resolution patch")
    google_search_url = f"https://www.google.com/search?q={encoded_query}"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(google_search_url, headers=headers)
            response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        # Google search results often have 'a' tags with class 'tF2CMy'
        for g_result in soup.find_all('div', class_='tF2CMy'):
            link = g_result.find('a')
            if link and 'href' in link.attrs:
                title_tag = g_result.find('h3')
                title = title_tag.text if title_tag else link.text
                search_results.append({"title": title, "url": link['href']})

    except httpx.HTTPError as e:
        logger.error(f"Failed to perform Google search: {e}")
        search_results.append({"error": f"Failed to perform Google search: {e}"})
    except Exception as e:
        logger.error(f"An unexpected error occurred during resolution search: {e}")
        search_results.append({"error": f"An unexpected error occurred: {e}"})
    
    return search_results
