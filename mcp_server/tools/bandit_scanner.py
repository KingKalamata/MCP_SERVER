import subprocess
import json
import os
import logging

logger = logging.getLogger(__name__)

def run_bandit_scan(path):
    """
    Runs a Bandit scan on the specified file or directory.

    Args:
        path (str): The path to the file or directory to scan.

    Returns:
        dict: A dictionary containing the Bandit findings, or an error message.
    """
    if not os.path.exists(path):
        return {"error": f"Path '{path}' does not exist."}

    try:
        # Use subprocess to run bandit and capture its JSON output
        # Using -- to ensure path is not interpreted as a flag
        command = ['bandit', '-r', '-f', 'json', '--', path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Bandit scan failed: {e.stderr}")
        try:
            return json.loads(e.stdout) # Bandit returns findings even on "failure" (non-zero exit code if findings exist)
        except:
            return {"error": f"Bandit scan failed with error: {e.stderr}"}
    except FileNotFoundError:
        return {"error": "Bandit command not found. Please ensure Bandit is installed and in your PATH."}
    except json.JSONDecodeError:
        return {"error": "Failed to decode Bandit JSON output."}
    except Exception as e:
        logger.exception("An unexpected error occurred during Bandit scan")
        return {"error": f"An unexpected error occurred: {e}"}
