from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSS3MalformedError, CVSS2MalformedError

def get_cvss_scores(vector: str):
    """
    Calculates CVSS scores for a given vector.

    Args:
        vector (str): The CVSS vector (e.g., 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').

    Returns:
        dict: A dictionary containing the CVSS scores, or an error message.
    """
    try:
        if vector.startswith('CVSS:3'):
            c = CVSS3(vector)
            return {
                "base_score": c.base_score,
                "temporal_score": c.temporal_score,
                "environmental_score": c.environmental_score,
                "severity": c.severity,
            }
        elif vector.startswith('CVSS:2'):
            c = CVSS2(vector)
            return {
                "base_score": c.base_score,
                "temporal_score": c.temporal_score,
                "environmental_score": c.environmental_score,
            }
        else:
            return {"error": "Invalid or unsupported CVSS vector format."}
    except (CVSS3MalformedError, CVSS2MalformedError) as e:
        return {"error": f"Malformed CVSS vector: {e}"}
    except Exception as e:
        return {"error": f"An error occurred: {e}"}

if __name__ == '__main__':
    # Example usage
    vector_v3 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    scores_v3 = get_cvss_scores(vector_v3)
    print(f"CVSS v3 Scores for {vector_v3}: {scores_v3}")

    vector_v2 = 'AV:L/AC:M/Au:N/C:P/I:P/A:P'
    scores_v2 = get_cvss_scores(f"CVSS:2.0/{vector_v2}")
    print(f"CVSS v2 Scores for {vector_v2}: {scores_v2}")
