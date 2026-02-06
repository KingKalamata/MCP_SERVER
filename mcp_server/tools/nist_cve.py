import nvdlib
import asyncio
import logging
from .. import config

logger = logging.getLogger(__name__)

async def get_cve_details(cve_id):
    """
    Fetches details for a given CVE ID from the NIST NVD.

    Args:
        cve_id (str): The CVE ID (e.g., 'CVE-2023-12345').

    Returns:
        dict: A dictionary containing the CVE details, or an error message.
    """
    try:
        # nvdlib.searchCVE is synchronous, so we run it in a thread to avoid blocking the event loop
        r = await asyncio.to_thread(nvdlib.searchCVE, cveId=cve_id, key=config.NIST_API_KEY, exactMatch=True)

        if not r:
            return {"error": f"CVE ID '{cve_id}' not found."}
        
        cve = r[0]
        return {
            "id": cve.id,
            "sourceIdentifier": cve.sourceIdentifier,
            "published": cve.published,
            "lastModified": cve.lastModified,
            "vulnStatus": cve.vulnStatus,
            "descriptions": [desc.value for desc in cve.descriptions],
            "metrics": getattr(cve, 'metrics', {}),
            "weaknesses": getattr(cve, 'weaknesses', []),
            "configurations": getattr(cve, 'configurations', []),
            "references": [ref.url for ref in cve.references]
        }
    except Exception as e:
        logger.error(f"Error fetching CVE details for {cve_id}: {e}")
        return {"error": f"An error occurred: {e}"}
