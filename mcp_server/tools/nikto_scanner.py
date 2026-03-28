import subprocess
import json
import os
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

def run_nikto_scan(target_url, output_format='json'):
    """
    Runs a Nikto scan on the specified target URL.

    Args:
        target_url (str): The URL to scan.
        output_format (str): The desired output format ('json' or 'txt').

    Returns:
        dict or str: A dictionary containing the scan results if 'json' format,
                     or a string for 'txt' format, or an error message.
    """
    temp_output_file = f"nikto_scan_result_{os.urandom(8).hex()}.xml"
    
    try:
        # Command to run Nikto and output to XML
        command = ['nikto', '-h', target_url, '-o', temp_output_file, '-Format', 'xml']
        
        logger.info(f"Starting Nikto scan on {target_url}...")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info("Nikto scan finished.")

        if output_format == 'json':
            if not os.path.exists(temp_output_file):
                return {"error": "Nikto output file was not created."}

            tree = ET.parse(temp_output_file)
            root = tree.getroot()
            
            findings = []
            for item in root.findall('.//item'):
                finding = {child.tag: child.text for child in item}
                findings.append(finding)
            
            return {"target": target_url, "findings": findings}
        else:
            if not os.path.exists(temp_output_file):
                return {"error": "Nikto output file was not created."}
            with open(temp_output_file, 'r') as f:
                xml_content = f.read()
            return {"target": target_url, "raw_xml_output": xml_content}
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Nikto scan failed: {e.stderr}")
        return {"error": f"Nikto scan failed with error: {e.stderr}"}
    except FileNotFoundError:
        return {"error": "Nikto command not found. Please ensure Nikto is installed and in your PATH."}
    except Exception as e:
        logger.exception("An unexpected error occurred during Nikto scan")
        return {"error": f"An unexpected error occurred: {e}"}
    finally:
        # Clean up the temporary output file
        if os.path.exists(temp_output_file):
            try:
                os.remove(temp_output_file)
            except OSError:
                pass
