from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSS3MalformedError, CVSS2MalformedError
import logging

logger = logging.getLogger(__name__)

def get_cvss_scores(vector: str):
    """
    Calculates CVSS scores for a given vector.

    Args:
        vector (str): The CVSS vector (e.g., 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').

    Returns:
        dict: A dictionary containing the CVSS scores, or an error message.
    """
    def safe_float(v):
        return float(v) if v is not None else None

    try:
        if vector.startswith('CVSS:3'):
            c = CVSS3(vector)
            sev = c.severities()
            return {
                "base_score": safe_float(c.base_score),
                "temporal_score": safe_float(c.temporal_score),
                "environmental_score": safe_float(c.environmental_score),
                "severity": sev[0],
            }
        elif vector.startswith('CVSS:2'):
            v2_vector = vector
            if vector.startswith('CVSS:2.0/'):
                v2_vector = vector[9:]

            c = CVSS2(v2_vector)
            return {
                "base_score": safe_float(c.base_score),
                "temporal_score": safe_float(c.temporal_score),
                "environmental_score": safe_float(c.environmental_score),
            }
        else:
            return {"error": "Invalid or unsupported CVSS vector format."}
    except (CVSS3MalformedError, CVSS2MalformedError) as e:
        logger.error(f"Malformed CVSS vector {vector}: {e}")
        return {"error": f"Malformed CVSS vector: {e}"}
    except Exception as e:
        logger.exception(f"An error occurred while calculating CVSS for {vector}")
        return {"error": f"An error occurred: {e}"}
