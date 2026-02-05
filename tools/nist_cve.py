import nvdlib
from .. import config

def get_cve_details(cve_id):
    """
    Fetches details for a given CVE ID from the NIST NVD.

    Args:
        cve_id (str): The CVE ID (e.g., 'CVE-2023-12345').

    Returns:
        dict: A dictionary containing the CVE details, or an error message.
    """
    try:
        r = nvdlib.searchCVE(cveId=cve_id, key=config.NIST_API_KEY, exactMatch=True)
        if not r:
            return {"error": f"CVE ID '{cve_id}' not found."}
        
        cve = r[0]
        # The library returns a class object. We need to convert it to a dict to be able to return it from the API
        return {
            "id": cve.id,
            "sourceIdentifier": cve.sourceIdentifier,
            "published": cve.published,
            "lastModified": cve.lastModified,
            "vulnStatus": cve.vulnStatus,
            "descriptions": [desc.value for desc in cve.descriptions],
            "metrics": cve.metrics,
            "weaknesses": cve.weaknesses,
            "configurations": cve.configurations,
            "references": [ref.url for ref in cve.references]
        }
    except Exception as e:
        return {"error": f"An error occurred: {e}"}

if __name__ == '__main__':
    # Example usage
    # You need to have a valid NIST_API_KEY in your config.py or environment variables
    # to run this example successfully.
    cve_id = 'CVE-2020-8200'  # Example CVE
    cve_details = get_cve_details(cve_id)
    import json
    print(json.dumps(cve_details, indent=4))
