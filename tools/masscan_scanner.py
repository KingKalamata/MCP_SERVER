import masscan
import subprocess
import json

def is_masscan_installed():
    """Check if masscan is installed and in the system's PATH."""
    try:
        subprocess.run(['masscan', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def scan_target(target, ports='0-65535', rate=1000):
    """
    Performs a masscan on the specified target.

    Args:
        target (str): The target IP address or network range.
        ports (str): The ports to scan (e.g., '0-65535', '80,443').
        rate (int): The packet rate for the scan.

    Returns:
        dict: A dictionary containing the scan results, or an error message.
    """
    if not is_masscan_installed():
        return {"error": "Masscan is not installed or not in the system's PATH."}

    scanner = masscan.PortScanner()
    try:
        scanner.scan(target, ports=ports, arguments=f'--rate={rate}')
        return json.loads(scanner.scan_result)
    except Exception as e:
        return {"error": f"An error occurred during the scan: {e}"}

if __name__ == '__main__':
    # Example usage
    target_ip = '127.0.0.1'  # Replace with a target you are authorized to scan
    scan_results = scan_target(target_ip, ports='80,443', rate=100)
    print(scan_results)
