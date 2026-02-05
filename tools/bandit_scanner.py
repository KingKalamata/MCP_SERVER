import subprocess
import json
import os

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
        command = ['bandit', '-r', path, '-f', 'json']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        return {"error": f"Bandit scan failed with error: {e.stderr}"}
    except FileNotFoundError:
        return {"error": "Bandit command not found. Please ensure Bandit is installed and in your PATH."}
    except json.JSONDecodeError:
        return {"error": "Failed to decode Bandit JSON output."}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

if __name__ == '__main__':
    # Example usage: Replace '.' with a specific file or directory you want to scan.
    # Note: For this example to work, you need to have Bandit installed (`pip install bandit`)
    # and some Python code in the current directory or specified path.
    test_path = './' 
    if os.path.exists(test_path):
        findings = run_bandit_scan(test_path)
        print(json.dumps(findings, indent=4))
    else:
        print(f"Path not found: {test_path}")
